import { describe, it, expect } from 'vitest'
import { renderCoverage, renderResults, TIER_META } from './render'
import type { Coverage, MatchReport } from '../core/types'

const FULL: Coverage = {
  loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: Date.now(),
}
const DEGRADED: Coverage = {
  loaded: 119, total: 121, failed: ['rfc1918', 'cloudflare'],
  heavyLoaded: false, oldestFetchedAt: Date.now(),
}

function report(over: Partial<MatchReport> = {}): MatchReport {
  return { results: [], unparseable: [], coverage: FULL, ...over }
}

describe('TIER_META', () => {
  it('warns that popularity is not benignness', () => {
    expect(TIER_META.popularity.caption.toLowerCase()).toContain('not benignness')
  })

  it('frames context hits as a reason to look closer', () => {
    expect(TIER_META.context.caption.toLowerCase()).toContain('look closer')
  })

  it('orders strong false-positive signals before informational ones', () => {
    expect(TIER_META['known-fp'].order).toBeLessThan(TIER_META.popularity.order)
    expect(TIER_META.infrastructure.order).toBeLessThan(TIER_META.popularity.order)
  })
})

describe('renderCoverage', () => {
  it('shows the loaded fraction', () => {
    expect(renderCoverage(FULL)).toContain('121/121')
  })

  it('names the failed lists when coverage is degraded', () => {
    const html = renderCoverage(DEGRADED)
    expect(html).toContain('119/121')
    expect(html).toContain('rfc1918')
    expect(html).toContain('cloudflare')
  })

  it('warns when the cache is stale', () => {
    const old = { ...FULL, oldestFetchedAt: Date.now() - 40 * 24 * 60 * 60 * 1000 }
    expect(renderCoverage(old)).toMatch(/40 days old|stale/i)
  })
})

describe('renderResults', () => {
  it('labels a zero-hit indicator clean at full coverage', () => {
    const html = renderResults(report({
      results: [{ original: '8.8.8.8', normalized: '8.8.8.8', type: 'ipv4', count: 1, hits: [] }],
    }))
    expect(html).toContain('clean')
    expect(html).not.toContain('no hits (')
  })

  it('refuses to say clean when coverage is degraded', () => {
    const html = renderResults(report({
      coverage: DEGRADED,
      results: [{ original: '8.8.8.8', normalized: '8.8.8.8', type: 'ipv4', count: 1, hits: [] }],
    }))
    expect(html).toContain('no hits (119/121 lists)')
    expect(html).not.toMatch(/>\s*clean\s*</)
  })

  it('renders every hit, grouped by tier', () => {
    const html = renderResults(report({
      results: [{
        original: '1.1.1.1', normalized: '1.1.1.1', type: 'ipv4', count: 1,
        hits: [
          { list: 'cloudflare', title: 'CF', description: 'd', tier: 'infrastructure', version: 1 },
          { list: 'tranco', title: 'Tranco', description: 'd', tier: 'popularity', version: 2 },
        ],
      }],
    }))
    expect(html).toContain('cloudflare')
    expect(html).toContain('tranco')
    expect(html).toContain(TIER_META.infrastructure.label)
    expect(html).toContain(TIER_META.popularity.label)
  })

  it('escapes HTML in indicator text', () => {
    const html = renderResults(report({
      results: [{
        original: '<img src=x onerror=alert(1)>', normalized: 'x.com',
        type: 'domain', count: 1, hits: [],
      }],
    }))
    expect(html).not.toContain('<img')
    expect(html).toContain('&lt;img')
  })

  it('shows a multiplier when input lines were folded into one row', () => {
    const html = renderResults(report({
      results: [{ original: 'a.test', normalized: 'a.test', type: 'domain', count: 3, hits: [] }],
    }))
    expect(html).toContain('×3')
  })

  it('stays uncluttered for a single occurrence', () => {
    const html = renderResults(report({
      results: [{ original: 'a.test', normalized: 'a.test', type: 'domain', count: 1, hits: [] }],
    }))
    expect(html).not.toContain('×')
  })

  it('lists unparseable input in its own section', () => {
    const html = renderResults(report({ unparseable: ['d41d8cd98f00b204e9800998ecf8427e'] }))
    expect(html).toMatch(/unparseable|not recognised/i)
    expect(html).toContain('d41d8cd98f00b204e9800998ecf8427e')
  })

  it('handles an empty report without crashing', () => {
    expect(() => renderResults(report())).not.toThrow()
  })
})
