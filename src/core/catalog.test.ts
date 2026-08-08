import { describe, it, expect } from 'vitest'
import { assignTier, assignLoadTier } from '../../scripts/build-catalog'
import catalog from '../catalog.json'
import type { CatalogEntry } from './types'

describe('assignTier', () => {
  it('classifies cloud and CDN ranges as infrastructure', () => {
    expect(assignTier('cloudflare', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('amazon-aws', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('microsoft-azure', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('public-dns-v4', 'cidr', ['ip-src'])).toBe('infrastructure')
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
  })

  it('auto-classifies any scanner list as context via name suffix', () => {
    expect(assignTier('shodan-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('censys-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('rapid7-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
    // A scanner list added upstream tomorrow must self-classify.
    expect(assignTier('brandnew-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
  })

  it('classifies investigative-lead lists as context', () => {
    expect(assignTier('dynamic-dns', 'hostname', ['domain'])).toBe('context')
    expect(assignTier('vpn-ipv4', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('url-shortener', 'hostname', ['domain'])).toBe('context')
  })

  it('falls through to neutral for unrecognised lists', () => {
    expect(assignTier('some-future-list', 'string', ['domain'])).toBe('neutral')
  })
})

describe('assignLoadTier', () => {
  it('marks only the two multi-megabyte popularity lists as heavy', () => {
    expect(assignLoadTier('tranco')).toBe('heavy')
    expect(assignLoadTier('google-chrome-crux-1million')).toBe('heavy')
  })

  it('keeps small popularity lists in core', () => {
    expect(assignLoadTier('alexa')).toBe('core')
    expect(assignLoadTier('majestic_million')).toBe('core')
    expect(assignLoadTier('tranco10k')).toBe('core')
    expect(assignLoadTier('cloudflare')).toBe('core')
  })
})

describe('generated catalog.json', () => {
  const entries = catalog as CatalogEntry[]

  it('contains every non-hash upstream list', () => {
    expect(entries.length).toBe(123)
  })

  it('excludes the out-of-scope hash lists', () => {
    const names = entries.map((e) => e.name)
    expect(names).not.toContain('windows-binary-hashes')
    expect(names).not.toContain('nioc-filehash')
  })

  it('has exactly 121 core lists and 2 heavy lists', () => {
    expect(entries.filter((e) => e.loadTier === 'core').length).toBe(121)
    expect(entries.filter((e) => e.loadTier === 'heavy').length).toBe(2)
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
