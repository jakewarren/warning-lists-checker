import { describe, it, expect } from 'vitest'
import { appliesTo } from './applicability'
import type { CatalogEntry } from './types'
import catalog from '../catalog.json'

function entry(over: Partial<CatalogEntry>): CatalogEntry {
  return {
    name: 'x', title: 'X', description: '', type: 'string',
    matchingAttributes: [], tier: 'neutral', loadTier: 'core', bytes: 0,
    ...over,
  }
}

describe('appliesTo', () => {
  const cidrList = entry({
    name: 'rfc1918', type: 'cidr',
    matchingAttributes: ['ip-src', 'ip-dst', 'domain|ip', 'ip-dst|port', 'ip-src|port'],
  })
  const hostnameList = entry({
    name: 'url-shortener', type: 'hostname',
    matchingAttributes: ['domain', 'hostname', 'domain|ip', 'url', 'uri'],
  })
  const hashList = entry({
    name: 'empty-hashes', type: 'string',
    matchingAttributes: ['md5', 'sha1', 'sha256', 'filename|md5'],
  })
  const emailRegexList = entry({
    name: 'common-contact-emails', type: 'regex',
    matchingAttributes: ['email-src', 'email-dst', 'target-email'],
  })
  const phoneRegexList = entry({
    name: 'phone_numbers', type: 'regex',
    matchingAttributes: ['phone-number', 'whois-registrant-phone'],
  })

  it('sends IP indicators to CIDR lists only', () => {
    expect(appliesTo(cidrList, 'ipv4')).toBe(true)
    expect(appliesTo(cidrList, 'ipv6')).toBe(true)
    expect(appliesTo(hostnameList, 'ipv4')).toBe(false)
    expect(appliesTo(hostnameList, 'ipv6')).toBe(false)
  })

  it('sends domain and url indicators to host lists only', () => {
    expect(appliesTo(hostnameList, 'domain')).toBe(true)
    expect(appliesTo(hostnameList, 'url')).toBe(true)
    expect(appliesTo(cidrList, 'domain')).toBe(false)
    expect(appliesTo(cidrList, 'url')).toBe(false)
  })

  it('excludes hash lists from every in-scope indicator type', () => {
    for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
      expect(appliesTo(hashList, t)).toBe(false)
    }
  })

  it('excludes email and phone regex lists from every in-scope type', () => {
    for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
      expect(appliesTo(emailRegexList, t)).toBe(false)
      expect(appliesTo(phoneRegexList, t)).toBe(false)
    }
  })

  it('applies a non-cidr list of IPs to IP indicators', () => {
    const stringIps = entry({
      name: 'some-ip-strings', type: 'string',
      matchingAttributes: ['ip-src', 'ip-dst'],
    })
    expect(appliesTo(stringIps, 'ipv4')).toBe(true)
    expect(appliesTo(stringIps, 'domain')).toBe(false)
  })

  it('never applies anything to unparseable indicators', () => {
    expect(appliesTo(cidrList, 'unparseable')).toBe(false)
    expect(appliesTo(hostnameList, 'unparseable')).toBe(false)
  })

  it('disambiguates the domain|ip composite attribute by list type', () => {
    // domain|ip covers both families, so on its own it must never pull a list
    // into the wrong family.
    const cidrComposite = entry({ type: 'cidr', matchingAttributes: ['domain|ip'] })
    const hostComposite = entry({ type: 'hostname', matchingAttributes: ['domain|ip'] })

    expect(appliesTo(cidrComposite, 'ipv4')).toBe(true)
    expect(appliesTo(cidrComposite, 'domain')).toBe(false)

    expect(appliesTo(hostComposite, 'domain')).toBe(true)
    expect(appliesTo(hostComposite, 'ipv4')).toBe(false)
  })
})

describe('appliesTo against the real catalog', () => {
  const entries = catalog as CatalogEntry[]

  it('never routes an IP indicator to a hostname-typed list', () => {
    for (const e of entries) {
      if (e.type === 'hostname' && appliesTo(e, 'ipv4')) {
        throw new Error(`hostname list ${e.name} incorrectly applies to ipv4`)
      }
    }
  })

  it('never routes a domain indicator to a cidr-typed list', () => {
    for (const e of entries) {
      if (e.type === 'cidr' && appliesTo(e, 'domain')) {
        throw new Error(`cidr list ${e.name} incorrectly applies to domain`)
      }
    }
  })

  it('excludes both regex lists from all in-scope types', () => {
    for (const e of entries.filter((x) => x.type === 'regex')) {
      for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
        expect(appliesTo(e, t)).toBe(false)
      }
    }
  })
})
