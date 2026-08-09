import type { IndicatorType, Matcher } from '../types'

// Contract: `match()` receives a value already refanged, lowercased and
// port-stripped by parse.ts. Matchers lowercase their own entries (upstream
// list data is not guaranteed lowercase) but never re-normalize the
// indicator itself — that would be redundant work on a hot path.

function isHostLike(type: IndicatorType): boolean {
  return type === 'domain' || type === 'url'
}

export function buildStringMatcher(entries: string[]): Matcher {
  const set = new Set(entries.map((e) => e.trim().toLowerCase()).filter(Boolean))
  return {
    match(normalized: string): boolean {
      return set.has(normalized)
    },
  }
}

/**
 * Matches the entry itself or any subdomain of it. Probes each parent suffix
 * rather than using endsWith, so "evilexample.com" cannot match "example.com".
 */
export function buildHostnameMatcher(entries: string[]): Matcher {
  const set = new Set(entries.map((e) => e.trim().toLowerCase()).filter(Boolean))
  return {
    match(normalized: string, type: IndicatorType): boolean {
      if (!isHostLike(type)) return false
      if (set.has(normalized)) return true
      let idx = normalized.indexOf('.')
      while (idx !== -1) {
        if (set.has(normalized.slice(idx + 1))) return true
        idx = normalized.indexOf('.', idx + 1)
      }
      return false
    },
  }
}

export function buildSubstringMatcher(entries: string[]): Matcher {
  const list = entries.map((e) => e.trim().toLowerCase()).filter(Boolean)
  return {
    match(normalized: string): boolean {
      for (const e of list) {
        if (normalized.includes(e)) return true
      }
      return false
    },
  }
}

export function buildRegexMatcher(entries: string[]): Matcher {
  const patterns: RegExp[] = []
  for (const e of entries) {
    const src = e.trim()
    if (!src) continue
    try {
      patterns.push(new RegExp(src, 'i'))
    } catch {
      // Upstream pattern does not compile in JS — skip it rather than fail the list.
    }
  }
  return {
    match(normalized: string): boolean {
      for (const p of patterns) {
        if (p.test(normalized)) return true
      }
      return false
    },
  }
}
