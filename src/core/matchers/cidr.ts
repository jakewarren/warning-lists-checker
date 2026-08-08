import { ipv4ToInt, ipv6ToBigInt } from '../ip'
import type { IndicatorType, Matcher } from '../types'

interface V6Range {
  start: bigint
  end: bigint
}

function parseV4Cidr(entry: string): [number, number] | null {
  const slash = entry.indexOf('/')
  const addr = slash === -1 ? entry : entry.slice(0, slash)
  const base = ipv4ToInt(addr)
  if (base === null) return null

  const prefixStr = slash === -1 ? null : entry.slice(slash + 1)
  if (prefixStr !== null && !/^\d+$/.test(prefixStr)) return null
  const prefix = prefixStr === null ? 32 : Number(prefixStr)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null

  // Avoid the undefined behaviour of << 32 in JS by special-casing /0.
  const size = prefix === 0 ? 4294967296 : 2 ** (32 - prefix)
  const start = Math.floor(base / size) * size
  return [start, start + size - 1]
}

function parseV6Cidr(entry: string): V6Range | null {
  const slash = entry.indexOf('/')
  const addr = slash === -1 ? entry : entry.slice(0, slash)
  const base = ipv6ToBigInt(addr)
  if (base === null) return null

  const prefixStr = slash === -1 ? null : entry.slice(slash + 1)
  if (prefixStr !== null && !/^\d+$/.test(prefixStr)) return null
  const prefix = prefixStr === null ? 128 : Number(prefixStr)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null

  const hostBits = BigInt(128 - prefix)
  const size = 1n << hostBits
  const start = (base >> hostBits) << hostBits
  return { start, end: start + size - 1n }
}

/** Sort by start, then merge overlapping or adjacent ranges. */
function mergeV4(ranges: Array<[number, number]>): Array<[number, number]> {
  ranges.sort((a, b) => a[0] - b[0])
  const out: Array<[number, number]> = []
  for (const r of ranges) {
    const last = out[out.length - 1]
    if (last && r[0] <= last[1] + 1) {
      if (r[1] > last[1]) last[1] = r[1]
    } else {
      out.push([r[0], r[1]])
    }
  }
  return out
}

function mergeV6(ranges: V6Range[]): V6Range[] {
  ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0))
  const out: V6Range[] = []
  for (const r of ranges) {
    const last = out[out.length - 1]
    if (last && r.start <= last.end + 1n) {
      if (r.end > last.end) last.end = r.end
    } else {
      out.push({ start: r.start, end: r.end })
    }
  }
  return out
}

export function buildCidrMatcher(entries: string[]): Matcher {
  const v4raw: Array<[number, number]> = []
  const v6raw: V6Range[] = []

  for (const entry of entries) {
    const e = entry.trim()
    if (!e) continue
    if (e.includes(':')) {
      const r = parseV6Cidr(e)
      if (r) v6raw.push(r)
    } else {
      const r = parseV4Cidr(e)
      if (r) v4raw.push(r)
    }
  }

  const v4 = mergeV4(v4raw)
  const v6 = mergeV6(v6raw)

  // Flatten IPv4 into a typed array: [start0, end0, start1, end1, ...].
  const v4flat = new Uint32Array(v4.length * 2)
  for (let i = 0; i < v4.length; i++) {
    v4flat[i * 2] = v4[i]![0]
    v4flat[i * 2 + 1] = v4[i]![1]
  }

  function containsV4(n: number): boolean {
    let lo = 0
    let hi = v4.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const start = v4flat[mid * 2]!
      const end = v4flat[mid * 2 + 1]!
      if (n < start) hi = mid - 1
      else if (n > end) lo = mid + 1
      else return true
    }
    return false
  }

  function containsV6(n: bigint): boolean {
    let lo = 0
    let hi = v6.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const r = v6[mid]!
      if (n < r.start) hi = mid - 1
      else if (n > r.end) lo = mid + 1
      else return true
    }
    return false
  }

  return {
    match(normalized: string, type: IndicatorType): boolean {
      if (type === 'ipv4') {
        if (v4.length === 0) return false
        const n = ipv4ToInt(normalized)
        return n === null ? false : containsV4(n)
      }
      if (type === 'ipv6') {
        if (v6.length === 0) return false
        const n = ipv6ToBigInt(normalized)
        return n === null ? false : containsV6(n)
      }
      return false
    },
  }
}
