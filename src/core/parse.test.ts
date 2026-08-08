import { describe, it, expect } from 'vitest'
import { parseInput, refang, classify } from './parse'

describe('refang', () => {
  it('restores bracketed and braced dots', () => {
    expect(refang('evil[.]com')).toBe('evil.com')
    expect(refang('evil(.)com')).toBe('evil.com')
    expect(refang('evil{.}com')).toBe('evil.com')
    expect(refang('evil\\.com')).toBe('evil.com')
  })

  it('restores defanged schemes case-insensitively', () => {
    expect(refang('hxxp://evil.com')).toBe('http://evil.com')
    expect(refang('hXXps://evil.com')).toBe('https://evil.com')
    expect(refang('hxxps://evil.com')).toBe('https://evil.com')
  })

  it('restores bracketed colons and slashes', () => {
    expect(refang('http[:]//evil.com')).toBe('http://evil.com')
    expect(refang('http:[//]evil.com')).toBe('http://evil.com')
  })

  it('restores defanged at-signs', () => {
    expect(refang('user[at]evil.com')).toBe('user@evil.com')
    expect(refang('user(at)evil.com')).toBe('user@evil.com')
  })

  it('leaves clean input untouched', () => {
    expect(refang('https://example.com/a')).toBe('https://example.com/a')
    expect(refang('8.8.8.8')).toBe('8.8.8.8')
  })
})

describe('classify', () => {
  it('identifies IPv4', () => {
    expect(classify('8.8.8.8')).toBe('ipv4')
    expect(classify('192.168.0.1')).toBe('ipv4')
  })

  it('rejects malformed IPv4 as domain or unparseable', () => {
    expect(classify('999.1.1.1')).not.toBe('ipv4')
    expect(classify('1.2.3')).not.toBe('ipv4')
  })

  it('identifies IPv6 in compressed, full and bracketed forms', () => {
    expect(classify('::1')).toBe('ipv6')
    expect(classify('2001:db8::1')).toBe('ipv6')
    expect(classify('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('ipv6')
    expect(classify('[2001:db8::1]:443')).toBe('ipv6')
  })

  it('identifies URLs', () => {
    expect(classify('https://example.com/path')).toBe('url')
    expect(classify('example.com/path')).toBe('url')
  })

  it('identifies bare domains', () => {
    expect(classify('example.com')).toBe('domain')
    expect(classify('a.b.example.co.uk')).toBe('domain')
  })

  it('rejects junk', () => {
    expect(classify('not a domain!')).toBe('unparseable')
    expect(classify('')).toBe('unparseable')
  })
})

describe('parseInput', () => {
  it('splits on newlines, commas, semicolons and whitespace', () => {
    const { indicators } = parseInput('8.8.8.8\n1.1.1.1, 9.9.9.9; 8.8.4.4 4.4.4.4')
    expect(indicators.map((i) => i.normalized)).toEqual([
      '8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4', '4.4.4.4',
    ])
  })

  it('refangs before classifying', () => {
    const { indicators } = parseInput('hxxps://evil[.]com/payload')
    expect(indicators[0]!.type).toBe('url')
    expect(indicators[0]!.normalized).toBe('evil.com')
  })

  it('preserves the original text exactly as pasted', () => {
    const { indicators } = parseInput('hxxps://evil[.]com/payload')
    expect(indicators[0]!.original).toBe('hxxps://evil[.]com/payload')
  })

  it('reduces URLs to their hostname for matching', () => {
    const { indicators } = parseInput('https://sub.example.com:8443/a/b?c=d')
    expect(indicators[0]!.normalized).toBe('sub.example.com')
  })

  it('strips a port from a bare IPv4', () => {
    const { indicators } = parseInput('8.8.8.8:53')
    expect(indicators[0]!.normalized).toBe('8.8.8.8')
    expect(indicators[0]!.type).toBe('ipv4')
  })

  it('strips brackets and port from IPv6', () => {
    const { indicators } = parseInput('[2001:db8::1]:443')
    expect(indicators[0]!.normalized).toBe('2001:db8::1')
    expect(indicators[0]!.type).toBe('ipv6')
  })

  it('lowercases the normalized value but not the original', () => {
    const { indicators } = parseInput('EXAMPLE.COM')
    expect(indicators[0]!.normalized).toBe('example.com')
    expect(indicators[0]!.original).toBe('EXAMPLE.COM')
  })

  it('dedupes on normalized value, keeping first-seen order and a count', () => {
    const { indicators } = parseInput('example.com\nEXAMPLE.com\n8.8.8.8\nexample.com')
    expect(indicators.map((i) => i.normalized)).toEqual(['example.com', '8.8.8.8'])
    expect(indicators[0]!.count).toBe(3)
    expect(indicators[1]!.count).toBe(1)
  })

  it('collects unparseable lines separately rather than dropping them', () => {
    const { indicators, unparseable } = parseInput('8.8.8.8\nd41d8cd98f00b204e9800998ecf8427e\n???')
    expect(indicators.map((i) => i.normalized)).toEqual(['8.8.8.8'])
    expect(unparseable).toEqual(['d41d8cd98f00b204e9800998ecf8427e', '???'])
  })

  it('strips surrounding quotes and trailing punctuation', () => {
    const { indicators } = parseInput('"example.com", \'8.8.8.8\'')
    expect(indicators.map((i) => i.normalized)).toEqual(['example.com', '8.8.8.8'])
  })

  it('returns empty results for empty input', () => {
    expect(parseInput('')).toEqual({ indicators: [], unparseable: [] })
    expect(parseInput('   \n  \n')).toEqual({ indicators: [], unparseable: [] })
  })
})
