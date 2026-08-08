import type { ListType, Matcher } from '../types'
import { buildCidrMatcher } from './cidr'
import {
  buildHostnameMatcher,
  buildRegexMatcher,
  buildStringMatcher,
  buildSubstringMatcher,
} from './simple'

export function buildMatcher(type: ListType, entries: string[]): Matcher {
  switch (type) {
    case 'cidr':
      return buildCidrMatcher(entries)
    case 'string':
      return buildStringMatcher(entries)
    case 'hostname':
      return buildHostnameMatcher(entries)
    case 'substring':
      return buildSubstringMatcher(entries)
    case 'regex':
      return buildRegexMatcher(entries)
  }
}

export { buildCidrMatcher } from './cidr'
export * from './simple'
