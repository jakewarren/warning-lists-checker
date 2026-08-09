/** Dotted-quad to unsigned 32-bit. Returns null on anything malformed. */
export function ipv4ToInt(addr: string): number | null {
  const parts = addr.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    out = out * 256 + n
  }
  return out >>> 0
}

/**
 * IPv6 text to a 128-bit BigInt. Handles :: compression, embedded IPv4 tails,
 * surrounding brackets and %zone suffixes. Returns null on anything malformed.
 */
export function ipv6ToBigInt(addr: string): bigint | null {
  let s = addr.trim().toLowerCase()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)

  const pct = s.indexOf('%')
  if (pct !== -1) s = s.slice(0, pct)

  if (!s.includes(':')) return null

  // Fold an embedded IPv4 tail into two hex groups.
  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':')
    const v4 = s.slice(lastColon + 1)
    const n = ipv4ToInt(v4)
    if (n === null) return null
    const hi = ((n >>> 16) & 0xffff).toString(16)
    const lo = (n & 0xffff).toString(16)
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`
  }

  const doubles = s.match(/::/g)
  if (doubles && doubles.length > 1) return null

  const dbl = s.indexOf('::')
  let head: string[]
  let tail: string[]
  if (dbl === -1) {
    head = s.split(':')
    tail = []
    if (head.length !== 8) return null
  } else {
    const left = s.slice(0, dbl)
    const right = s.slice(dbl + 2)
    head = left ? left.split(':') : []
    tail = right ? right.split(':') : []
    if (head.length + tail.length > 7) return null
  }

  const fill = 8 - head.length - tail.length
  if (fill < 0) return null
  const groups = [...head, ...Array<string>(fill).fill('0'), ...tail]

  let out = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    out = (out << 16n) | BigInt(parseInt(g, 16))
  }
  return out
}
