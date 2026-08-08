import { describe, it, expect } from 'vitest'
import { buildCidrMatcher } from './cidr'

describe('buildCidrMatcher — IPv4', () => {
  const m = buildCidrMatcher(['10.0.0.0/8', '192.168.0.0/16', '8.8.8.8'])

  it('matches an address inside a range', () => {
    expect(m.match('10.1.2.3', 'ipv4')).toBe(true)
    expect(m.match('192.168.50.1', 'ipv4')).toBe(true)
  })

  it('matches the network and broadcast addresses', () => {
    expect(m.match('10.0.0.0', 'ipv4')).toBe(true)
    expect(m.match('10.255.255.255', 'ipv4')).toBe(true)
  })

  it('rejects addresses just outside a range', () => {
    expect(m.match('9.255.255.255', 'ipv4')).toBe(false)
    expect(m.match('11.0.0.0', 'ipv4')).toBe(false)
    expect(m.match('192.167.255.255', 'ipv4')).toBe(false)
    expect(m.match('192.169.0.0', 'ipv4')).toBe(false)
  })

  it('treats a bare IP entry as /32', () => {
    expect(m.match('8.8.8.8', 'ipv4')).toBe(true)
    expect(m.match('8.8.8.9', 'ipv4')).toBe(false)
    expect(m.match('8.8.8.7', 'ipv4')).toBe(false)
  })

  it('handles /32 and /0 explicitly', () => {
    expect(buildCidrMatcher(['1.2.3.4/32']).match('1.2.3.4', 'ipv4')).toBe(true)
    expect(buildCidrMatcher(['1.2.3.4/32']).match('1.2.3.5', 'ipv4')).toBe(false)
    const all = buildCidrMatcher(['0.0.0.0/0'])
    expect(all.match('0.0.0.0', 'ipv4')).toBe(true)
    expect(all.match('255.255.255.255', 'ipv4')).toBe(true)
  })

  it('handles addresses above 2^31 without sign errors', () => {
    const high = buildCidrMatcher(['200.0.0.0/8'])
    expect(high.match('200.1.2.3', 'ipv4')).toBe(true)
    expect(high.match('199.255.255.255', 'ipv4')).toBe(false)
  })

  it('merges adjacent and overlapping ranges without losing coverage', () => {
    const merged = buildCidrMatcher(['10.0.0.0/9', '10.128.0.0/9', '10.0.0.0/8'])
    expect(merged.match('10.0.0.0', 'ipv4')).toBe(true)
    expect(merged.match('10.127.255.255', 'ipv4')).toBe(true)
    expect(merged.match('10.128.0.0', 'ipv4')).toBe(true)
    expect(merged.match('10.255.255.255', 'ipv4')).toBe(true)
    expect(merged.match('11.0.0.0', 'ipv4')).toBe(false)
  })

  it('ignores unparseable entries instead of throwing', () => {
    const m2 = buildCidrMatcher(['garbage', '10.0.0.0/8', '999.0.0.0/8'])
    expect(m2.match('10.0.0.1', 'ipv4')).toBe(true)
    expect(m2.match('1.1.1.1', 'ipv4')).toBe(false)
  })

  it('returns false for an empty list', () => {
    expect(buildCidrMatcher([]).match('8.8.8.8', 'ipv4')).toBe(false)
  })

  it('rejects an entry with an empty or non-digit prefix instead of treating it as /0', () => {
    const m3 = buildCidrMatcher(['10.0.0.0/'])
    expect(m3.match('1.1.1.1', 'ipv4')).toBe(false)
    expect(m3.match('10.0.0.0', 'ipv4')).toBe(false)

    const m4 = buildCidrMatcher(['10.0.0.0/1e1'])
    expect(m4.match('1.1.1.1', 'ipv4')).toBe(false)
    expect(m4.match('10.0.0.0', 'ipv4')).toBe(false)
  })

  it('still matches everything for an explicit /0', () => {
    const all = buildCidrMatcher(['0.0.0.0/0'])
    expect(all.match('1.1.1.1', 'ipv4')).toBe(true)
    expect(all.match('255.255.255.255', 'ipv4')).toBe(true)
  })
})

describe('buildCidrMatcher — IPv6', () => {
  const m = buildCidrMatcher(['2001:db8::/32', '::1/128', '2600:1f00::/24'])

  it('matches inside an IPv6 range', () => {
    expect(m.match('2001:db8::1', 'ipv6')).toBe(true)
    expect(m.match('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')).toBe(true)
  })

  it('rejects just outside an IPv6 range', () => {
    expect(m.match('2001:db9::1', 'ipv6')).toBe(false)
    expect(m.match('2001:db7:ffff::1', 'ipv6')).toBe(false)
  })

  it('handles /128 host routes', () => {
    expect(m.match('::1', 'ipv6')).toBe(true)
    expect(m.match('::2', 'ipv6')).toBe(false)
  })

  it('matches regardless of compressed or expanded input form', () => {
    expect(m.match('2001:0db8:0000:0000:0000:0000:0000:0001', 'ipv6')).toBe(true)
  })

  it('rejects an entry with an empty prefix instead of treating it as /0', () => {
    const m5 = buildCidrMatcher(['2001:db8::/'])
    expect(m5.match('::1', 'ipv6')).toBe(false)
    expect(m5.match('2001:db8::1', 'ipv6')).toBe(false)
  })
})

describe('buildCidrMatcher — type routing', () => {
  const m = buildCidrMatcher(['10.0.0.0/8', '2001:db8::/32'])

  it('never matches domain or url indicators', () => {
    expect(m.match('example.com', 'domain')).toBe(false)
    expect(m.match('example.com', 'url')).toBe(false)
  })

  it('does not cross v4 and v6 families', () => {
    expect(m.match('2001:db8::1', 'ipv4')).toBe(false)
    expect(m.match('10.0.0.1', 'ipv6')).toBe(false)
  })
})
