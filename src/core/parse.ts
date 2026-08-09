import type { Indicator, IndicatorType } from './types'

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/

/** Undo the common defanging conventions found in threat reports. */
export function refang(s: string): string {
  return s
    .replace(/h(?:xx|XX|Xx|xX)(p|P)(s|S)?:/g, (_m, p: string, sec?: string) =>
      `htt${p.toLowerCase()}${sec ? 's' : ''}:`)
    .replace(/[[({]\s*\.\s*[\])}]/g, '.')
    .replace(/\\\./g, '.')
    .replace(/[[({]\s*:\s*[\])}]/g, ':')
    .replace(/[[({]\s*\/\/\s*[\])}]/g, '//')
    .replace(/[[({]\s*at\s*[\])}]/gi, '@')
}

function isIpv4(s: string): boolean {
  const m = IPV4_RE.exec(s)
  if (!m) return false
  return m.slice(1).every((o) => Number(o) <= 255 && !(o.length > 1 && o.startsWith('0')))
}

/**
 * Structural IPv6 check. Full numeric validation lives in ip.ts; here we only
 * need enough to route the value to the right matcher.
 */
function isIpv6(s: string): boolean {
  if (!s.includes(':')) return false
  if (!/^[0-9a-f:.]+$/i.test(s)) return false
  const doubles = s.match(/::/g)
  if (doubles && doubles.length > 1) return false
  const groups = s.split(':').filter((g) => g.length > 0)
  if (groups.length > 8) return false
  // An embedded IPv4 group is only legal as the *final* group ("::ffff:1.2.3.4").
  // Without the position check, un-port-stripped input like "8.8.8.8:53" would
  // read as IPv6 — which matters now that classify() runs on hosts pulled out
  // of URLs, not just on already-port-stripped tokens.
  return groups.every((g, i) =>
    /^[0-9a-f]{1,4}$/i.test(g) || (isIpv4(g) && i === groups.length - 1))
}

export function classify(s: string): IndicatorType {
  if (!s) return 'unparseable'
  if (isIpv4(s)) return 'ipv4'
  if (isIpv6(s)) return 'ipv6'
  // Bracketed IPv6 with an optional trailing port, e.g. "[2001:db8::1]:443".
  const bracketed = /^\[([0-9a-f:.]+)\](?::\d{1,5})?$/i.exec(s)
  if (bracketed && isIpv6(bracketed[1]!)) return 'ipv6'
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return 'url'
  if (s.includes('/')) return 'url'
  if (DOMAIN_RE.test(s.toLowerCase())) return 'domain'
  return 'unparseable'
}

/** Reduce a URL to the hostname the warninglists actually match against. */
function hostnameOf(s: string): string | null {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `http://${s}`
  try {
    const u = new URL(withScheme)
    // URL keeps IPv6 hosts bracketed; strip for matching.
    return u.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  } catch {
    return null
  }
}

/** Strip a trailing :port from a bare host, leaving IPv6 alone. */
function stripPort(s: string): string {
  if (s.startsWith('[')) {
    const close = s.indexOf(']')
    if (close !== -1) return s.slice(1, close)
  }
  const colons = (s.match(/:/g) ?? []).length
  if (colons === 1) {
    const [host, port] = s.split(':')
    if (host && port && /^\d{1,5}$/.test(port)) return host
  }
  return s
}

// Note: square brackets are deliberately excluded from stripping — they carry
// meaning for bracketed IPv6 host[:port] notation and must survive to stripPort.
function tidy(token: string): string {
  return token
    .replace(/^["'`<(]+/, '')
    .replace(/["'`>)]+$/, '')
    .replace(/[.,;]+$/, '')
    .trim()
}

export function parseInput(raw: string): {
  indicators: Indicator[]
  unparseable: string[]
} {
  const tokens = raw
    .split(/[\s,;]+/)
    .map(tidy)
    .filter((t) => t.length > 0)

  const byNormalized = new Map<string, Indicator>()
  const unparseable: string[] = []

  for (const token of tokens) {
    const refanged = refang(token)
    // Strip a bare host's port before classifying, so "8.8.8.8:53" isn't
    // misread as IPv6 and "[::1]:443" isn't misread as unparseable. Full URLs
    // (which have more than one colon) pass through untouched here and are
    // resolved to a hostname below instead.
    const candidate = stripPort(refanged)
    let type = classify(candidate)

    if (type === 'unparseable') {
      unparseable.push(token)
      continue
    }

    let normalized: string
    if (type === 'url') {
      const host = hostnameOf(refanged)
      if (!host) {
        unparseable.push(token)
        continue
      }
      // Re-derive the type from the host we actually match on. A URL is only a
      // carrier: "http://1.1.1.1/x" reduces to an IP literal, and if the type
      // stayed 'url' it would be excluded from every CIDR list by both
      // appliesTo() and the CIDR matcher — consulted against nothing, and so
      // reported with the reserved word "clean" at full coverage. Re-deriving
      // also keeps dedupe consistent: a URL and a bare IP for the same host
      // collapse into one indicator with one correct type.
      //
      // If the host is not itself a valid indicator, the token was never one.
      // classify() sends anything containing "/" down this path, so plain text
      // like "coverage=123/123" or "foo/bar" arrives here and the URL parser
      // happily yields a "host" of "coverage=123". Reporting that as an
      // indicator is worse than useless: it can match no list, so it renders
      // as a confident zero-hit result. Treat it as unparseable instead, which
      // surfaces it to the analyst rather than dropping it.
      const hostType = classify(host)
      if (hostType === 'unparseable') {
        unparseable.push(token)
        continue
      }
      normalized = host
      type = hostType
    } else {
      normalized = candidate.toLowerCase()
    }

    const existing = byNormalized.get(normalized)
    if (existing) {
      existing.count += 1
    } else {
      byNormalized.set(normalized, { original: token, normalized, type, count: 1 })
    }
  }

  return { indicators: [...byNormalized.values()], unparseable }
}
