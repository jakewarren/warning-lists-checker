import { describe, it, expect } from 'vitest'
import { ipv4ToInt, ipv6ToBigInt } from './ip'

describe('ipv4ToInt', () => {
  it('converts boundary addresses', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0)
    expect(ipv4ToInt('255.255.255.255')).toBe(4294967295)
  })

  it('converts a normal address without sign overflow', () => {
    expect(ipv4ToInt('192.168.1.1')).toBe(3232235777)
    expect(ipv4ToInt('8.8.8.8')).toBe(134744072)
    // Above 2^31 — must not come back negative.
    expect(ipv4ToInt('200.0.0.1')).toBe(3355443201)
  })

  it('rejects malformed input', () => {
    expect(ipv4ToInt('256.0.0.1')).toBeNull()
    expect(ipv4ToInt('1.2.3')).toBeNull()
    expect(ipv4ToInt('1.2.3.4.5')).toBeNull()
    expect(ipv4ToInt('a.b.c.d')).toBeNull()
    expect(ipv4ToInt('')).toBeNull()
  })
})

describe('ipv6ToBigInt', () => {
  it('converts loopback and unspecified', () => {
    expect(ipv6ToBigInt('::1')).toBe(1n)
    expect(ipv6ToBigInt('::')).toBe(0n)
  })

  it('converts a full uncompressed address', () => {
    expect(ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(
      0x20010db8000000000000000000000001n,
    )
  })

  it('treats compressed and uncompressed forms as equal', () => {
    expect(ipv6ToBigInt('2001:db8::1')).toBe(
      ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'),
    )
  })

  it('is case insensitive', () => {
    expect(ipv6ToBigInt('2001:DB8::1')).toBe(ipv6ToBigInt('2001:db8::1'))
  })

  it('handles an embedded IPv4 tail', () => {
    expect(ipv6ToBigInt('::ffff:192.168.1.1')).toBe(0xffffc0a80101n)
  })

  it('strips brackets and zone identifiers', () => {
    expect(ipv6ToBigInt('[2001:db8::1]')).toBe(ipv6ToBigInt('2001:db8::1'))
    expect(ipv6ToBigInt('fe80::1%eth0')).toBe(ipv6ToBigInt('fe80::1'))
  })

  it('rejects malformed input', () => {
    expect(ipv6ToBigInt('2001:db8::1::2')).toBeNull()
    expect(ipv6ToBigInt('gggg::1')).toBeNull()
    expect(ipv6ToBigInt('1:2:3:4:5:6:7')).toBeNull()
    expect(ipv6ToBigInt('1:2:3:4:5:6:7:8:9')).toBeNull()
  })
})
