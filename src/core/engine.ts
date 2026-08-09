import { appliesTo } from './applicability'
import type { CachedList } from './listStore'
import { buildMatcher } from './matchers'
import { parseInput } from './parse'
import type {
  CatalogEntry, Coverage, Hit, IndicatorResult, MatchReport, Matcher,
} from './types'

interface Compiled {
  entry: CatalogEntry
  matcher: Matcher
  version: number
}

export interface Engine {
  /** Compile the loaded list bodies into matchers. Call once per load. */
  ingest(lists: Map<string, CachedList>): void
  run(raw: string, coverage: Coverage): MatchReport
}

/**
 * The single place the "clean" rule lives: the word is reserved for full
 * coverage, because a false clean verdict is the worst output this tool can
 * produce.
 */
export function coverageLabel(c: Coverage): string {
  if (c.failed.length === 0 && c.loaded === c.total) return 'clean'
  return `no hits (${c.loaded}/${c.total} lists)`
}

export function createEngine(catalog: CatalogEntry[]): Engine {
  const byName = new Map(catalog.map((e) => [e.name, e]))
  let compiled: Compiled[] = []

  return {
    ingest(lists) {
      const next: Compiled[] = []
      for (const [name, cached] of lists) {
        const entry = byName.get(name)
        if (!entry) continue
        next.push({
          entry,
          matcher: buildMatcher(entry.type, cached.entries),
          version: cached.version,
        })
      }
      compiled = next
    },

    run(raw, coverage) {
      const { indicators, unparseable } = parseInput(raw)

      const results: IndicatorResult[] = indicators.map((ind) => {
        const hits: Hit[] = []
        for (const c of compiled) {
          if (!appliesTo(c.entry, ind.type)) continue
          if (!c.matcher.match(ind.normalized, ind.type)) continue
          hits.push({
            list: c.entry.name,
            title: c.entry.title,
            description: c.entry.description,
            tier: c.entry.tier,
            version: c.version,
          })
        }
        return {
          original: ind.original,
          normalized: ind.normalized,
          type: ind.type,
          count: ind.count,
          hits,
        }
      })

      return { results, unparseable, coverage }
    },
  }
}
