import catalogJson from './catalog.json'
import { createEngine } from './core/engine'
import { createListStore } from './core/listStore'
import type { CatalogEntry, Coverage } from './core/types'
import type { WorkerRequest, WorkerResponse } from './workerProtocol'

const catalog = catalogJson as CatalogEntry[]
const engine = createEngine(catalog)
const store = createListStore({
  fetch: globalThis.fetch.bind(globalThis),
  idb: globalThis.indexedDB,
  now: () => Date.now(),
})

let coverage: Coverage = {
  loaded: 0, total: 0, failed: [], heavyLoaded: false, oldestFetchedAt: null,
}

function reply(msg: WorkerResponse): void {
  ;(globalThis as unknown as DedicatedWorkerGlobalScope).postMessage(msg)
}

async function handleLoad(id: number, heavy: boolean): Promise<void> {
  const wanted = catalog.filter((e) => (heavy ? true : e.loadTier === 'core'))
  const res = await store.load(wanted, (done, total) =>
    reply({ id, kind: 'progress', done, total }),
  )

  engine.ingest(res.lists)
  coverage = {
    loaded: res.lists.size,
    total: wanted.length,
    failed: res.failed,
    heavyLoaded: heavy,
    oldestFetchedAt: res.oldestFetchedAt,
  }
  reply({ id, kind: 'loaded', coverage })
}

globalThis.addEventListener('message', (e: MessageEvent<WorkerRequest>) => {
  const req = e.data
  void (async () => {
    try {
      if (req.kind === 'load') {
        await handleLoad(req.id, req.heavy)
      } else {
        reply({ id: req.id, kind: 'report', report: engine.run(req.raw, coverage) })
      }
    } catch (err) {
      reply({ id: req.id, kind: 'error', message: (err as Error).message })
    }
  })()
})
