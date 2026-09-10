import { describe, it, expect } from 'vitest'
import { assignTier, assignLoadTier } from '../../scripts/build-catalog'
import catalog from '../catalog.json'
import { LOAD_TIERS, TIERS, type CatalogEntry } from './types'

describe('assignTier', () => {
  it('classifies cloud and CDN ranges as infrastructure', () => {
    expect(assignTier('cloudflare', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('amazon-aws', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('microsoft-azure', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('public-dns-v4', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('apple-domains', 'hostname', ['domain'])).toBe('infrastructure')
    expect(assignTier('apple-ipv4', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('apple-ipv6', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('oracle-oci', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('bunny-net', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('microsoft-mdca-proxy', 'hostname', ['domain'])).toBe('infrastructure')
    expect(assignTier('palo-alto-networks-cortex-cloud', 'cidr', ['ip-src'])).toBe('infrastructure')
  })

  it('classifies curated false-positive lists as known-fp', () => {
    expect(assignTier('ti-falsepositives', 'hostname', ['domain'])).toBe('known-fp')
    expect(assignTier('common-ioc-false-positive', 'string', ['domain'])).toBe('known-fp')
    expect(assignTier('rfc1918', 'cidr', ['ip-src'])).toBe('known-fp')
  })

  it('classifies popularity rankings as popularity', () => {
    expect(assignTier('tranco', 'hostname', ['domain'])).toBe('popularity')
    expect(assignTier('alexa', 'string', ['domain'])).toBe('popularity')
    expect(assignTier('cisco_top10k', 'string', ['domain'])).toBe('popularity')
    expect(assignTier('cisco_top1m', 'string', ['domain'])).toBe('popularity')
  })

  it.each([
    'cloudflare-top200', 'cloudflare-top1k', 'cloudflare-top2k',
    'cloudflare-top5k', 'cloudflare-top10k', 'cloudflare-top20k',
    'cloudflare-top50k', 'cloudflare-top100k', 'cloudflare-top200k',
    'cloudflare-top500k', 'cloudflare-top1m',
  ])('classifies %s as a popularity ranking', (name) => {
    expect(assignTier(name, 'string', ['domain'])).toBe('popularity')
  })

  it('auto-classifies any scanner list as context via name suffix', () => {
    expect(assignTier('shodan-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('censys-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('rapid7-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('rapid7-scanning', 'cidr', ['ip-src'])).toBe('context')
    // A scanner list added upstream tomorrow must self-classify.
    expect(assignTier('brandnew-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
  })

  it('classifies investigative-lead lists as context', () => {
    expect(assignTier('dynamic-dns', 'hostname', ['domain'])).toBe('context')
    expect(assignTier('vpn-ipv4', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('url-shortener', 'hostname', ['domain'])).toBe('context')
  })

  it.each(['tor-exit-nodes', 'icloud-private-relay', 'driftnet'])(
    'classifies %s as context to investigate', (name) => {
      expect(assignTier(name, 'cidr', ['ip-src'])).toBe('context')
    },
  )

  it('falls through to neutral for unrecognised lists', () => {
    expect(assignTier('some-future-list', 'string', ['domain'])).toBe('neutral')
  })
})

describe('assignLoadTier', () => {
  it.each([
    'tranco', 'google-chrome-crux-1million', 'cisco_top1m',
    'cloudflare-top100k', 'cloudflare-top200k', 'cloudflare-top500k',
    'cloudflare-top1m',
  ])('defers the multi-megabyte %s ranking behind the opt-in', (name) => {
    expect(assignLoadTier(name)).toBe('heavy')
  })

  it('keeps small popularity lists in core', () => {
    expect(assignLoadTier('alexa')).toBe('core')
    expect(assignLoadTier('majestic_million')).toBe('core')
    expect(assignLoadTier('tranco10k')).toBe('core')
    expect(assignLoadTier('cloudflare')).toBe('core')
    expect(assignLoadTier('cloudflare-top200')).toBe('core')
    expect(assignLoadTier('cloudflare-top50k')).toBe('core')
  })
})

describe('generated catalog.json', () => {
  const entries = catalog as CatalogEntry[]

  it('contains all 223 non-hash lists from the September 2026 refresh', () => {
    expect(entries.length).toBe(223)
    expect(new Set(entries.map((e) => e.name)).size).toBe(entries.length)
  })

  it('keeps overlapping upstream lists as separate sources', () => {
    expect(entries.map((e) => e.name)).toEqual(expect.arrayContaining([
      'apple', 'apple-domains', 'apple-ipv4', 'apple-ipv6',
      'cybergreen-nt-scanning', 'cybergreen-scanning',
      'rapid7-nt-scanning', 'rapid7-scanning',
    ]))
  })

  it('excludes the out-of-scope hash lists', () => {
    const names = entries.map((e) => e.name)
    expect(names).not.toContain('windows-binary-hashes')
    expect(names).not.toContain('nioc-filehash')
  })

  it('has 216 core lists and 7 heavy lists', () => {
    expect(entries.filter((e) => e.loadTier === 'core').length).toBe(216)
    expect(entries.filter((e) => e.loadTier === 'heavy').length).toBe(7)
  })

  it('matches generator tier assignments for every catalog entry', () => {
    for (const e of entries) {
      expect(e.tier, e.name).toBe(assignTier(e.name, e.type, e.matchingAttributes))
      expect(e.loadTier, e.name).toBe(assignLoadTier(e.name))
    }
  })

  it('assigns valid tiers and defers only popularity lists', () => {
    for (const e of entries) {
      expect(TIERS).toContain(e.tier)
      expect(LOAD_TIERS).toContain(e.loadTier)
      if (e.loadTier === 'heavy') expect(e.tier, e.name).toBe('popularity')
    }
  })

  it('keeps popularity rankings larger than 2 MB out of the startup download', () => {
    for (const e of entries.filter((e) => e.tier === 'popularity' && e.bytes > 2_000_000)) {
      expect(e.loadTier, e.name).toBe('heavy')
    }
  })

  it('assigns every entry a known list type', () => {
    for (const e of entries) {
      expect(['cidr', 'string', 'hostname', 'substring', 'regex']).toContain(e.type)
    }
  })

  it('gives every entry a non-empty name, title and matchingAttributes', () => {
    for (const e of entries) {
      expect(e.name.length).toBeGreaterThan(0)
      expect(e.title.length).toBeGreaterThan(0)
      expect(e.matchingAttributes.length).toBeGreaterThan(0)
    }
  })
})
