import { describe, it, expect } from 'vitest'
import {
  buildStringMatcher,
  buildHostnameMatcher,
  buildSubstringMatcher,
  buildRegexMatcher,
} from './simple'
import { buildMatcher } from './index'

describe('buildStringMatcher', () => {
  const m = buildStringMatcher(['example.com', 'Test.COM'])

  it('matches exactly, case-insensitively', () => {
    expect(m.match('example.com', 'domain')).toBe(true)
    expect(m.match('test.com', 'domain')).toBe(true)
  })

  it('does not match subdomains', () => {
    expect(m.match('a.example.com', 'domain')).toBe(false)
  })

  it('does not match superstrings', () => {
    expect(m.match('notexample.com', 'domain')).toBe(false)
  })
})

describe('buildHostnameMatcher', () => {
  const m = buildHostnameMatcher(['example.com', 'co.uk'])

  it('matches the exact entry', () => {
    expect(m.match('example.com', 'domain')).toBe(true)
  })

  it('matches subdomains at any depth', () => {
    expect(m.match('a.example.com', 'domain')).toBe(true)
    expect(m.match('a.b.c.example.com', 'domain')).toBe(true)
  })

  it('does NOT match a domain that merely ends with the entry text', () => {
    expect(m.match('evilexample.com', 'domain')).toBe(false)
    expect(m.match('notexample.com', 'domain')).toBe(false)
    expect(m.match('xco.uk', 'domain')).toBe(false)
  })

  it('does not match a parent of the entry', () => {
    expect(m.match('com', 'domain')).toBe(false)
  })

  it('is case-insensitive on both sides', () => {
    const u = buildHostnameMatcher(['EXAMPLE.com'])
    expect(u.match('A.Example.COM', 'domain')).toBe(true)
  })

  it('never matches IP indicators', () => {
    expect(m.match('8.8.8.8', 'ipv4')).toBe(false)
  })
})

describe('buildSubstringMatcher', () => {
  const m = buildSubstringMatcher(['sandbox', 'malware-analysis'])

  it('matches when the entry appears anywhere', () => {
    expect(m.match('my-sandbox.example.com', 'domain')).toBe(true)
    expect(m.match('a.malware-analysis.net', 'domain')).toBe(true)
  })

  it('does not match when absent', () => {
    expect(m.match('example.com', 'domain')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(m.match('MY-SANDBOX.example.com', 'domain')).toBe(true)
  })
})

describe('buildRegexMatcher', () => {
  const m = buildRegexMatcher(['^abuse@', '^postmaster@'])

  it('matches a compiled pattern', () => {
    expect(m.match('abuse@example.com', 'domain')).toBe(true)
  })

  it('does not match a non-matching value', () => {
    expect(m.match('sales@example.com', 'domain')).toBe(false)
  })

  it('ignores invalid patterns instead of throwing', () => {
    const bad = buildRegexMatcher(['([unclosed', 'ok'])
    expect(bad.match('ok', 'domain')).toBe(true)
    expect(bad.match('nope', 'domain')).toBe(false)
  })
})

describe('buildMatcher factory', () => {
  it('routes each list type to the right implementation', () => {
    expect(buildMatcher('cidr', ['10.0.0.0/8']).match('10.0.0.1', 'ipv4')).toBe(true)
    expect(buildMatcher('string', ['a.com']).match('a.com', 'domain')).toBe(true)
    expect(buildMatcher('hostname', ['a.com']).match('x.a.com', 'domain')).toBe(true)
    expect(buildMatcher('substring', ['abc']).match('xabcx.com', 'domain')).toBe(true)
    expect(buildMatcher('regex', ['^z']).match('z.com', 'domain')).toBe(true)
  })
})
