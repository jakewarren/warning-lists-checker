export type IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'unparseable'
export type Tier = 'infrastructure' | 'known-fp' | 'popularity' | 'context' | 'neutral'
export type LoadTier = 'core' | 'heavy'
export type ListType = 'cidr' | 'string' | 'hostname' | 'substring' | 'regex'

/** One entry in the shipped catalog.json. Mirrors upstream metadata plus our tiers. */
export interface CatalogEntry {
  /** Upstream directory name, e.g. "public-dns-v4". Used to build the fetch URL. */
  name: string
  /** Upstream "name" field, a human sentence, e.g. "List of RFC 1918 CIDR blocks". */
  title: string
  description: string
  type: ListType
  matchingAttributes: string[]
  tier: Tier
  loadTier: LoadTier
  /** Raw byte size upstream, used to show download size on the opt-in button. */
  bytes: number
}

/** A single parsed input line. */
export interface Indicator {
  /** Exactly what the analyst pasted, before refanging. */
  original: string
  /** Refanged, lowercased value used for matching. For URLs this is the hostname. */
  normalized: string
  type: IndicatorType
  /** How many times this normalized value appeared in the input. */
  count: number
}

export interface Hit {
  list: string
  title: string
  description: string
  tier: Tier
  version: number
}

export interface IndicatorResult {
  original: string
  normalized: string
  type: IndicatorType
  hits: Hit[]
}

export interface Coverage {
  loaded: number
  total: number
  failed: string[]
  heavyLoaded: boolean
  /** Oldest fetchedAt across loaded lists, epoch ms. Drives the staleness banner. */
  oldestFetchedAt: number | null
}

export interface MatchReport {
  results: IndicatorResult[]
  unparseable: string[]
  coverage: Coverage
}

/** Built once per list per session, then queried per indicator. */
export interface Matcher {
  match(normalized: string, type: IndicatorType): boolean
}

export const TIERS: readonly Tier[] = [
  'infrastructure', 'known-fp', 'popularity', 'context', 'neutral',
] as const

export const LOAD_TIERS: readonly LoadTier[] = ['core', 'heavy'] as const
