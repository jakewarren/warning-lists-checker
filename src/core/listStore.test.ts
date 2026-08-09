import { describe, it, expect, beforeEach, vi } from 'vitest'
import 'fake-indexeddb/auto'
import { IDBFactory } from 'fake-indexeddb'
import { createListStore, FRESH_MS, STALE_MS } from './listStore'
import type { CatalogEntry } from './types'

function entry(name: string): CatalogEntry {
  return {
    name, title: name, description: '', type: 'cidr',
    matchingAttributes: ['ip-src'], tier: 'neutral', loadTier: 'core', bytes: 100,
  }
}

function body(list: string[], version = 1) {
  return {
    ok: true,
    json: async () => ({
      description: 'd', list, matching_attributes: ['ip-src'],
      name: 'n', type: 'cidr', version,
    }),
  } as unknown as Response
}

let now = 1_000_000_000_000

describe('createListStore', () => {
  let idb: IDBFactory

  beforeEach(() => {
    idb = new IDBFactory()
    now = 1_000_000_000_000
  })

  it('fetches on a cold cache and returns entries', async () => {
    const fetchMock = vi.fn(async () => body(['10.0.0.0/8']))
    const store = createListStore({ fetch: fetchMock as never, idb, now: () => now })

    const res = await store.load([entry('a')])

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(res.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])
    expect(res.failed).toEqual([])
  })

  it('requests the correct upstream URL', async () => {
    const fetchMock = vi.fn(async () => body([]))
    const store = createListStore({ fetch: fetchMock as never, idb, now: () => now })
    await store.load([entry('public-dns-v4')])
    expect(fetchMock).toHaveBeenCalledWith(
      'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/public-dns-v4/list.json',
    )
  })

  it('serves from cache without fetching when under 24h old', async () => {
    const fetchMock = vi.fn(async () => body(['10.0.0.0/8']))
    const deps = { fetch: fetchMock as never, idb, now: () => now }

    await createListStore(deps).load([entry('a')])
    now += FRESH_MS - 1
    const res = await createListStore(deps).load([entry('a')])

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(res.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])
  })

  it('serves stale data immediately between 24h and 7d, then revalidates', async () => {
    let payload = ['10.0.0.0/8']
    const fetchMock = vi.fn(async () => body(payload))
    const deps = { fetch: fetchMock as never, idb, now: () => now }

    await createListStore(deps).load([entry('a')])
    now += FRESH_MS + 1
    payload = ['192.168.0.0/16']

    const res = await createListStore(deps).load([entry('a')])
    // Served from cache — the caller does not wait on the network.
    expect(res.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])

    // Background revalidation lands, so the next load sees fresh data.
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2))
    const res2 = await createListStore(deps).load([entry('a')])
    expect(res2.lists.get('a')!.entries).toEqual(['192.168.0.0/16'])
  })

  it('blocks on refetch when older than 7d', async () => {
    let payload = ['10.0.0.0/8']
    const fetchMock = vi.fn(async () => body(payload))
    const deps = { fetch: fetchMock as never, idb, now: () => now }

    await createListStore(deps).load([entry('a')])
    now += STALE_MS + 1
    payload = ['192.168.0.0/16']

    const res = await createListStore(deps).load([entry('a')])
    expect(res.lists.get('a')!.entries).toEqual(['192.168.0.0/16'])
  })

  it('falls back to stale data when a blocking refetch fails', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(body(['10.0.0.0/8']))
      .mockRejectedValueOnce(new Error('network down'))
    const deps = { fetch: fetchMock as never, idb, now: () => now }

    await createListStore(deps).load([entry('a')])
    now += STALE_MS + 1

    const res = await createListStore(deps).load([entry('a')])
    expect(res.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])
    expect(res.failed).toEqual([])
    expect(res.oldestFetchedAt).toBe(1_000_000_000_000)
  })

  it('isolates a single list failure without losing the others', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes('/bad/')) return { ok: false, status: 404 } as Response
      return body(['10.0.0.0/8'])
    })
    const store = createListStore({ fetch: fetchMock as never, idb, now: () => now })

    const res = await store.load([entry('good'), entry('bad'), entry('good2')])

    expect(res.failed).toEqual(['bad'])
    expect(res.lists.has('good')).toBe(true)
    expect(res.lists.has('good2')).toBe(true)
    expect(res.lists.has('bad')).toBe(false)
  })

  it('treats malformed JSON as a failed list', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ nope: true }),
    }) as unknown as Response)
    const store = createListStore({ fetch: fetchMock as never, idb, now: () => now })

    const res = await store.load([entry('a')])
    expect(res.failed).toEqual(['a'])
  })

  it('reports progress as lists resolve', async () => {
    const fetchMock = vi.fn(async () => body([]))
    const store = createListStore({ fetch: fetchMock as never, idb, now: () => now })
    const seen: Array<[number, number]> = []

    await store.load([entry('a'), entry('b'), entry('c')], (d, t) => seen.push([d, t]))

    expect(seen[seen.length - 1]).toEqual([3, 3])
  })

  it('reports the oldest fetchedAt across all loaded lists', async () => {
    const fetchMock = vi.fn(async () => body([]))
    const deps = { fetch: fetchMock as never, idb, now: () => now }

    await createListStore(deps).load([entry('a')])
    now += 1000
    await createListStore(deps).load([entry('b')])

    const res = await createListStore(deps).load([entry('a'), entry('b')])
    expect(res.oldestFetchedAt).toBe(1_000_000_000_000)
  })

  it('falls back to memory when IndexedDB is unavailable', async () => {
    const brokenIdb = {
      open: () => { throw new Error('SecurityError: private browsing') },
    } as unknown as IDBFactory
    const fetchMock = vi.fn(async () => body(['10.0.0.0/8']))
    const store = createListStore({ fetch: fetchMock as never, idb: brokenIdb, now: () => now })

    const res = await store.load([entry('a')])
    expect(res.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])
    expect(res.failed).toEqual([])
  })

  it('serves the in-memory fallback on the second load when IndexedDB is unavailable', async () => {
    const brokenIdb = {
      open: () => { throw new Error('SecurityError: private browsing') },
    } as unknown as IDBFactory
    let payload = ['10.0.0.0/8']
    const fetchMock = vi.fn(async () => body(payload))
    const store = createListStore({ fetch: fetchMock as never, idb: brokenIdb, now: () => now })

    const res1 = await store.load([entry('a')])
    expect(res1.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])

    now += FRESH_MS - 1
    payload = ['192.168.0.0/16']

    const res2 = await store.load([entry('a')])
    // Still served from the in-memory fallback, not refetched.
    expect(res2.lists.get('a')!.entries).toEqual(['10.0.0.0/8'])
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
