import { describe, it, expect } from 'vitest'
import { TIERS, LOAD_TIERS } from './types'

describe('type vocabulary', () => {
  it('exposes the five presentation tiers', () => {
    expect(TIERS).toEqual(['infrastructure', 'known-fp', 'popularity', 'context', 'neutral'])
  })

  it('exposes the two load tiers', () => {
    expect(LOAD_TIERS).toEqual(['core', 'heavy'])
  })
})
