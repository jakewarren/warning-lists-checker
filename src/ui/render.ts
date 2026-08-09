import { coverageLabel } from '../core/engine'
import type { Coverage, IndicatorResult, MatchReport, Tier } from '../core/types'

export const TIER_META: Record<Tier, { label: string; caption: string; order: number }> = {
  'known-fp': {
    label: 'Known false positive',
    caption: 'Curated as a common false positive. Strong reason to deprioritise.',
    order: 0,
  },
  infrastructure: {
    label: 'Known infrastructure',
    caption: 'Belongs to a major cloud, CDN, or public resolver. Strong reason to deprioritise.',
    order: 1,
  },
  context: {
    label: 'Context — look closer',
    caption: 'Not a false-positive signal. This is a reason to look closer, not to dismiss.',
    order: 2,
  },
  popularity: {
    label: 'High-traffic site (informational)',
    caption: 'Ranked by traffic alone — popular does not mean safe. These lists contain malicious infrastructure.',
    order: 3,
  },
  neutral: {
    label: 'Other',
    caption: 'Matched a list with no assigned category.',
    order: 4,
  },
}

const DAY_MS = 24 * 60 * 60 * 1000

export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function renderCoverage(c: Coverage): string {
  const parts: string[] = [
    `<span class="cov-count">${c.loaded}/${c.total} lists loaded</span>`,
  ]

  if (c.failed.length > 0) {
    parts.push(
      `<span class="cov-warn">${c.failed.length} failed: ${esc(c.failed.join(', '))}</span>`,
    )
  }

  if (c.oldestFetchedAt !== null) {
    const days = Math.floor((Date.now() - c.oldestFetchedAt) / DAY_MS)
    if (days >= 7) {
      parts.push(`<span class="cov-warn">lists up to ${days} days old — refresh failed</span>`)
    }
  }

  if (!c.heavyLoaded) {
    parts.push('<span class="cov-note">popularity tier not loaded</span>')
  }

  return `<div class="coverage">${parts.join(' · ')}</div>`
}

function renderHits(r: IndicatorResult, coverage: Coverage): string {
  if (r.hits.length === 0) {
    const label = coverageLabel(coverage)
    const cls = label === 'clean' ? 'clean' : 'nohits'
    return `<span class="verdict ${cls}">${esc(label)}</span>`
  }

  const byTier = new Map<Tier, typeof r.hits>()
  for (const h of r.hits) {
    const bucket = byTier.get(h.tier) ?? []
    bucket.push(h)
    byTier.set(h.tier, bucket)
  }

  const groups = [...byTier.entries()].sort(
    (a, b) => TIER_META[a[0]].order - TIER_META[b[0]].order,
  )

  return groups
    .map(([tier, hits]) => {
      const meta = TIER_META[tier]
      const badges = hits
        .map(
          (h) =>
            `<li class="hit" title="${esc(h.description)}">` +
            `<code>${esc(h.list)}</code> <span class="hit-title">${esc(h.title)}</span></li>`,
        )
        .join('')
      return (
        `<div class="tier tier-${tier}">` +
        `<div class="tier-label">${esc(meta.label)}</div>` +
        `<div class="tier-caption">${esc(meta.caption)}</div>` +
        `<ul class="hits">${badges}</ul></div>`
      )
    })
    .join('')
}

export function renderResults(report: MatchReport): string {
  const rows = report.results
    .map((r) => {
      // Only shown when lines were folded away, so the common case stays quiet.
      const dupes = r.count > 1 ? ` <span class="ind-count">×${r.count}</span>` : ''
      return (
        `<tr><td class="ind"><code>${esc(r.original)}</code>` +
        `<span class="ind-type">${esc(r.type)}${dupes}</span></td>` +
        `<td class="res">${renderHits(r, report.coverage)}</td></tr>`
      )
    })
    .join('')

  const table = report.results.length
    ? `<table class="results"><tbody>${rows}</tbody></table>`
    : '<p class="empty">No indicators parsed yet.</p>'

  const unparseable = report.unparseable.length
    ? `<section class="unparseable"><h3>Not recognised as an IP, domain or URL ` +
      `(${report.unparseable.length})</h3><ul>` +
      report.unparseable.map((u) => `<li><code>${esc(u)}</code></li>`).join('') +
      '</ul></section>'
    : ''

  return table + unparseable
}
