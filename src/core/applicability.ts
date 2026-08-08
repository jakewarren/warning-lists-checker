import type { CatalogEntry, IndicatorType } from './types'

/**
 * Attributes that unambiguously mean "this list is about IP addresses".
 * `domain|ip` is deliberately absent — see COMPOSITE below.
 */
export const IP_ATTRS = new Set([
  'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port',
])

/** Attributes that unambiguously mean "this list is about hostnames". */
export const HOST_ATTRS = new Set([
  'hostname', 'domain', 'hostname|port', 'url', 'uri',
])

/**
 * A composite attribute covering both families at once. It appears on 105 of
 * 123 lists, so it carries almost no signal on its own and must be
 * disambiguated by the list's own type in both directions.
 */
const COMPOSITE = 'domain|ip'

function intersects(attrs: string[], set: Set<string>): boolean {
  for (const a of attrs) {
    if (set.has(a)) return true
  }
  return false
}

export function appliesTo(entry: CatalogEntry, type: IndicatorType): boolean {
  if (type === 'unparseable') return false

  const composite = entry.matchingAttributes.includes(COMPOSITE)

  if (type === 'ipv4' || type === 'ipv6') {
    if (intersects(entry.matchingAttributes, IP_ATTRS)) return true
    return composite && entry.type === 'cidr'
  }

  // domain | url
  if (entry.type === 'cidr') return false
  if (intersects(entry.matchingAttributes, HOST_ATTRS)) return true
  return composite
}
