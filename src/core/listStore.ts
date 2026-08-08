import type { CatalogEntry } from './types'

const RAW_BASE = 'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists'
const DB_NAME = 'warning-lists-checker'
const DB_VERSION = 1
const STORE = 'lists'

export const FRESH_MS = 24 * 60 * 60 * 1000
export const STALE_MS = 7 * 24 * 60 * 60 * 1000

export interface CachedList {
  name: string
  entries: string[]
  version: number
  fetchedAt: number
}

export interface StoreDeps {
  fetch: typeof fetch
  idb: IDBFactory
  now: () => number
}

export interface LoadResult {
  lists: Map<string, CachedList>
  failed: string[]
  oldestFetchedAt: number | null
}

export interface ListStore {
  load(
    entries: CatalogEntry[],
    onProgress?: (done: number, total: number) => void,
  ): Promise<LoadResult>
}

function promisify<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function openDb(idb: IDBFactory): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    let req: IDBOpenDBRequest
    try {
      req = idb.open(DB_NAME, DB_VERSION)
    } catch {
      // Private browsing, disabled storage, or a hostile environment.
      resolve(null)
      return
    }
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'name' })
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => resolve(null)
    req.onblocked = () => resolve(null)
  })
}

async function readCached(
  db: IDBDatabase | null,
  memory: Map<string, CachedList>,
  name: string,
): Promise<CachedList | null> {
  if (!db) {
    // IndexedDB unavailable (private browsing, disabled storage) or over
    // quota: fall back to an in-memory cache for the session rather than
    // refetching every list on every load.
    return memory.get(name) ?? null
  }
  try {
    const tx = db.transaction(STORE, 'readonly')
    const got = await promisify(tx.objectStore(STORE).get(name) as IDBRequest<CachedList>)
    return got ?? null
  } catch {
    // Transaction failure mid-session (e.g. store deleted underneath us) degrades
    // to a cold cache for this list rather than failing the whole load.
    return null
  }
}

async function writeCached(
  db: IDBDatabase | null,
  memory: Map<string, CachedList>,
  value: CachedList,
): Promise<void> {
  if (!db) {
    // Same in-memory fallback as readCached — a session-scoped cache, not a
    // write-through layer, so this only runs when there is no real db.
    memory.set(value.name, value)
    return
  }
  try {
    const tx = db.transaction(STORE, 'readwrite')
    await promisify(tx.objectStore(STORE).put(value) as unknown as IDBRequest<IDBValidKey>)
  } catch {
    // Quota exceeded or storage revoked mid-session. Matching still works from
    // memory for this session, so this is not worth surfacing as a list failure.
  }
}

interface UpstreamList {
  list: string[]
  version: number
}

function isUpstreamList(v: unknown): v is UpstreamList {
  return (
    typeof v === 'object' && v !== null &&
    Array.isArray((v as UpstreamList).list) &&
    typeof (v as UpstreamList).version === 'number'
  )
}

export function createListStore(deps: StoreDeps): ListStore {
  const { fetch: doFetch, idb, now } = deps
  // Session-scoped fallback used only when IndexedDB is unavailable. Lives on
  // the store instance so repeated load() calls on the same store still see
  // the three-tier decay behavior even with zero persistence.
  const memory = new Map<string, CachedList>()

  async function fetchList(name: string): Promise<CachedList> {
    const res = await doFetch(`${RAW_BASE}/${name}/list.json`)
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`)
    const json: unknown = await res.json()
    if (!isUpstreamList(json)) throw new Error(`${name}: malformed list.json`)
    return { name, entries: json.list, version: json.version, fetchedAt: now() }
  }

  async function resolveOne(
    db: IDBDatabase | null,
    entry: CatalogEntry,
  ): Promise<CachedList | null> {
    const cached = await readCached(db, memory, entry.name)
    const age = cached ? now() - cached.fetchedAt : Infinity

    if (cached && age < FRESH_MS) return cached

    if (cached && age < STALE_MS) {
      // Stale-while-revalidate: return now, refresh in the background. The
      // caller must not await this — that is the whole point of this tier.
      void fetchList(entry.name)
        .then((fresh) => writeCached(db, memory, fresh))
        .catch(() => {
          // Background revalidation failed silently; the cached value we
          // already returned to the caller remains valid until next load.
        })
      return cached
    }

    try {
      const fresh = await fetchList(entry.name)
      await writeCached(db, memory, fresh)
      return fresh
    } catch (err) {
      // Never fail hard when we have something usable on disk.
      if (cached) return cached
      throw err
    }
  }

  return {
    async load(entries, onProgress) {
      const db = await openDb(idb)
      const lists = new Map<string, CachedList>()
      const failed: string[] = []
      let done = 0

      const settled = await Promise.allSettled(
        entries.map(async (e) => {
          const r = await resolveOne(db, e)
          done += 1
          onProgress?.(done, entries.length)
          return r
        }),
      )

      settled.forEach((s, i) => {
        const name = entries[i]!.name
        if (s.status === 'fulfilled' && s.value) lists.set(name, s.value)
        else failed.push(name)
      })

      let oldest: number | null = null
      for (const l of lists.values()) {
        if (oldest === null || l.fetchedAt < oldest) oldest = l.fetchedAt
      }

      return { lists, failed, oldestFetchedAt: oldest }
    },
  }
}
