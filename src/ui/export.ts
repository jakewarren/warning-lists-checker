import { coverageLabel } from '../core/engine'
import type { Coverage, MatchReport } from '../core/types'

function header(c: Coverage): string {
  const age = c.oldestFetchedAt === null
    ? 'unknown'
    : new Date(c.oldestFetchedAt).toISOString()
  const failed = c.failed.length ? ` failed=${c.failed.join(',')}` : ''
  const heavy = c.heavyLoaded ? ' popularity-tier=loaded' : ' popularity-tier=not-loaded'
  return `# misp-warninglists-checker coverage=${c.loaded}/${c.total}${failed}${heavy} oldest-list=${age}`
}

function verdict(r: MatchReport['results'][number], c: Coverage): string {
  return r.hits.length === 0 ? coverageLabel(c) : `${r.hits.length} hit(s)`
}

export function toTsv(report: MatchReport): string {
  const lines = [header(report.coverage), ['indicator', 'type', 'verdict', 'lists', 'tiers'].join('\t')]
  for (const r of report.results) {
    lines.push([
      r.original,
      r.type,
      verdict(r, report.coverage),
      r.hits.map((h) => h.list).join(','),
      [...new Set(r.hits.map((h) => h.tier))].join(','),
    ].join('\t'))
  }
  return lines.join('\n')
}

function csvCell(s: string): string {
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function toCsv(report: MatchReport): string {
  const lines = [header(report.coverage), ['indicator', 'type', 'verdict', 'lists', 'tiers'].join(',')]
  for (const r of report.results) {
    lines.push([
      r.original,
      r.type,
      verdict(r, report.coverage),
      r.hits.map((h) => h.list).join(','),
      [...new Set(r.hits.map((h) => h.tier))].join(','),
    ].map(csvCell).join(','))
  }
  return lines.join('\n')
}

export function toJson(report: MatchReport): string {
  return JSON.stringify(report, null, 2)
}

export function cleanOnly(report: MatchReport): string {
  return report.results
    .filter((r) => r.hits.length === 0)
    .map((r) => r.original)
    .join('\n')
}

export function download(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
