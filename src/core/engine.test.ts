import { describe, it, expect } from 'vitest'
import { createEngine, coverageLabel } from './engine'
import type { CachedList } from './listStore'
import type { CatalogEntry, Coverage } from './types'

function cat(over: Partial<CatalogEntry>): CatalogEntry {
  return {
    name: 'x', title: 'X', description: 'desc', type: 'cidr',
    matchingAttributes: ['ip-src'], tier: 'neutral', loadTier: 'core', bytes: 0,
    ...over,
  }
}

function cached(name: string, entries: string[]): CachedList {
  return { name, entries, version: 7, fetchedAt: 1000 }
}

const CATALOG: CatalogEntry[] = [
  cat({ name: 'cloudflare', title: 'Cloudflare ranges', type: 'cidr',
        matchingAttributes: ['ip-src', 'ip-dst'], tier: 'infrastructure' }),
  cat({ name: 'rfc1918', title: 'RFC1918', type: 'cidr',
        matchingAttributes: ['ip-src', 'ip-dst'], tier: 'known-fp' }),
  cat({ name: 'tranco', title: 'Tranco 1M', type: 'hostname',
        matchingAttributes: ['domain', 'hostname'], tier: 'popularity', loadTier: 'heavy' }),
  cat({ name: 'dynamic-dns', title: 'Dynamic DNS', type: 'hostname',
        matchingAttributes: ['domain', 'hostname'], tier: 'context' }),
]

const FULL: Coverage = {
  loaded: 4, total: 4, failed: [], heavyLoaded: true, oldestFetchedAt: 1000,
}

function engineWith(lists: Array<[string, string[]]>) {
  const e = createEngine(CATALOG)
  e.ingest(new Map(lists.map(([n, v]) => [n, cached(n, v)])))
  return e
}

describe('engine.run', () => {
  it('reports hits with tier, title, description and version', () => {
    const e = engineWith([['rfc1918', ['10.0.0.0/8']]])
    const rep = e.run('10.1.2.3', FULL)

    expect(rep.results).toHaveLength(1)
    const hits = rep.results[0]!.hits
    expect(hits).toHaveLength(1)
    expect(hits[0]).toEqual({
      list: 'rfc1918', title: 'RFC1918', description: 'desc',
      tier: 'known-fp', version: 7,
    })
  })

  it('records every matching list, not just the strongest', () => {
    const e = engineWith([
      ['cloudflare', ['1.1.1.0/24']],
      ['rfc1918', ['1.1.1.0/24']],
    ])
    const rep = e.run('1.1.1.1', FULL)
    expect(rep.results[0]!.hits.map((h) => h.list).sort()).toEqual(['cloudflare', 'rfc1918'])
  })

  it('returns an empty hits array for an indicator that matches nothing', () => {
    const e = engineWith([['rfc1918', ['10.0.0.0/8']]])
    const rep = e.run('8.8.8.8', FULL)
    expect(rep.results[0]!.hits).toEqual([])
  })

  it('does not consult lists that failed to load', () => {
    const e = engineWith([])
    const rep = e.run('10.1.2.3', FULL)
    expect(rep.results[0]!.hits).toEqual([])
  })

  it('applies the applicability filter — a domain never hits a cidr list', () => {
    const e = engineWith([
      ['rfc1918', ['10.0.0.0/8']],
      ['dynamic-dns', ['no-ip.com']],
    ])
    const rep = e.run('sub.no-ip.com', FULL)
    expect(rep.results[0]!.hits.map((h) => h.list)).toEqual(['dynamic-dns'])
  })

  it('consults CIDR lists for an IP-literal URL instead of calling it clean', () => {
    const e = engineWith([['cloudflare', ['1.1.1.0/24']]])
    const rep = e.run('http://1.1.1.1/payload.exe', FULL)
    expect(rep.results[0]!.type).toBe('ipv4')
    expect(rep.results[0]!.hits.map((h) => h.list)).toEqual(['cloudflare'])
  })

  it('consults CIDR lists for a defanged IP-literal URL', () => {
    const e = engineWith([['cloudflare', ['185.220.101.0/24']]])
    const rep = e.run('hxxps://185[.]220[.]101[.]5/x', FULL)
    expect(rep.results[0]!.hits.map((h) => h.list)).toEqual(['cloudflare'])
  })

  it('does not fold a bare IP into a same-host URL and lose its hits', () => {
    const e = engineWith([['cloudflare', ['1.1.1.0/24']]])
    const rep = e.run('http://1.1.1.1/x\n1.1.1.1', FULL)
    expect(rep.results).toHaveLength(1)
    expect(rep.results[0]!.count).toBe(2)
    expect(rep.results[0]!.hits.map((h) => h.list)).toEqual(['cloudflare'])
  })

  it('surfaces how many input lines collapsed into each result', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8\n8.8.8.8\n1.1.1.1', FULL)
    expect(rep.results.map((r) => r.count)).toEqual([2, 1])
  })

  it('passes unparseable lines through to the report', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8\nd41d8cd98f00b204e9800998ecf8427e', FULL)
    expect(rep.unparseable).toEqual(['d41d8cd98f00b204e9800998ecf8427e'])
  })

  it('preserves input order and dedupe', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8\n1.1.1.1\n8.8.8.8', FULL)
    expect(rep.results.map((r) => r.normalized)).toEqual(['8.8.8.8', '1.1.1.1'])
  })

  it('carries coverage through to the report', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8', FULL)
    expect(rep.coverage).toEqual(FULL)
  })
})

describe('coverageLabel', () => {
  it('says clean only when every in-scope list loaded', () => {
    expect(coverageLabel({ loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: 1 }))
      .toBe('clean')
  })

  it('refuses to say clean when any list failed', () => {
    expect(coverageLabel({ loaded: 120, total: 121, failed: ['rfc1918'], heavyLoaded: false, oldestFetchedAt: 1 }))
      .toBe('no hits (120/121 lists)')
  })
})

describe('engine performance', () => {
  it('matches 10,000 IPs against 159 CIDR lists in under 2 seconds', () => {
    const bigCatalog: CatalogEntry[] = Array.from({ length: 159 }, (_, i) =>
      cat({ name: `list${i}`, type: 'cidr', matchingAttributes: ['ip-src'] }),
    )
    const engine = createEngine(bigCatalog)

    // 1,000 ranges per list, non-overlapping.
    const lists = new Map<string, CachedList>()
    for (let i = 0; i < 159; i++) {
      const entries = Array.from({ length: 1000 }, (_, j) => `${(j % 200) + 10}.${i}.${j % 256}.0/24`)
      lists.set(`list${i}`, cached(`list${i}`, entries))
    }
    engine.ingest(lists)

    const input = Array.from({ length: 10_000 }, (_, i) =>
      `${(i % 200) + 10}.${i % 159}.${i % 256}.${i % 254}`,
    ).join('\n')

    const cov: Coverage = { loaded: 159, total: 159, failed: [], heavyLoaded: false, oldestFetchedAt: 1 }
    const t0 = performance.now()
    const rep = engine.run(input, cov)
    const elapsed = performance.now() - t0

    expect(rep.results.length).toBeGreaterThan(0)
    expect(elapsed).toBeLessThan(2000)
  })
})
