// src/ui/export.test.ts
import { describe, it, expect } from 'vitest'
import { toTsv, toCsv, toJson, cleanOnly } from './export'
import type { Coverage, MatchReport } from '../core/types'

const FULL: Coverage = {
  loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: 1000,
}
const DEGRADED: Coverage = {
  loaded: 119, total: 121, failed: ['rfc1918'], heavyLoaded: false, oldestFetchedAt: 1000,
}

const REPORT: MatchReport = {
  coverage: FULL,
  unparseable: ['junk'],
  results: [
    {
      original: '1.1.1.1', normalized: '1.1.1.1', type: 'ipv4',
      hits: [
        { list: 'cloudflare', title: 'CF', description: 'd', tier: 'infrastructure', version: 1 },
        { list: 'public-dns-v4', title: 'DNS', description: 'd', tier: 'infrastructure', version: 2 },
      ],
    },
    { original: '9.9.9.9', normalized: '9.9.9.9', type: 'ipv4', hits: [] },
    { original: 'evil.test', normalized: 'evil.test', type: 'domain', hits: [] },
  ],
}

describe('toTsv', () => {
  it('emits a coverage header comment', () => {
    expect(toTsv(REPORT).split('\n')[0]).toContain('121/121')
  })

  it('emits a tab-separated column header', () => {
    const header = toTsv(REPORT).split('\n')[1]!
    expect(header.split('\t')).toEqual(['indicator', 'type', 'verdict', 'lists', 'tiers'])
  })

  it('joins multiple list hits in one cell', () => {
    const row = toTsv(REPORT).split('\n').find((l) => l.startsWith('1.1.1.1'))!
    expect(row).toContain('cloudflare,public-dns-v4')
  })

  it('writes clean for zero hits at full coverage', () => {
    const row = toTsv(REPORT).split('\n').find((l) => l.startsWith('9.9.9.9'))!
    expect(row.split('\t')[2]).toBe('clean')
  })

  it('writes the degraded verdict when coverage is incomplete', () => {
    const row = toTsv({ ...REPORT, coverage: DEGRADED })
      .split('\n').find((l) => l.startsWith('9.9.9.9'))!
    expect(row.split('\t')[2]).toBe('no hits (119/121 lists)')
  })
})

describe('toCsv', () => {
  it('quotes fields containing commas', () => {
    const row = toCsv(REPORT).split('\n').find((l) => l.startsWith('1.1.1.1'))!
    expect(row).toContain('"cloudflare,public-dns-v4"')
  })

  it('escapes embedded double quotes by doubling them', () => {
    const r: MatchReport = {
      ...REPORT,
      results: [{ original: 'a"b.com', normalized: 'a"b.com', type: 'domain', hits: [] }],
    }
    expect(toCsv(r)).toContain('"a""b.com"')
  })
})

describe('toJson', () => {
  it('round-trips to an object carrying coverage and results', () => {
    const parsed = JSON.parse(toJson(REPORT))
    expect(parsed.coverage.loaded).toBe(121)
    expect(parsed.results).toHaveLength(3)
    expect(parsed.results[0].hits[0].list).toBe('cloudflare')
  })

  it('includes unparseable input', () => {
    expect(JSON.parse(toJson(REPORT)).unparseable).toEqual(['junk'])
  })
})

describe('cleanOnly', () => {
  it('returns only the indicators that hit nothing, one per line', () => {
    expect(cleanOnly(REPORT)).toBe('9.9.9.9\nevil.test')
  })

  it('returns an empty string when everything hit something', () => {
    expect(cleanOnly({ ...REPORT, results: [REPORT.results[0]!] })).toBe('')
  })
})
