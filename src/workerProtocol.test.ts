import { describe, it, expect, vi } from 'vitest'
import { createWorkerClient } from './ui/workerClient'
import type { WorkerRequest, WorkerResponse } from './workerProtocol'
import type { Coverage, MatchReport } from './core/types'

const COVERAGE: Coverage = {
  loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: 1000,
}

/** Minimal stand-in for a Worker that replies according to a scripted handler. */
function fakeWorker(handler: (req: WorkerRequest, reply: (r: WorkerResponse) => void) => void) {
  const listeners: Array<(e: MessageEvent<WorkerResponse>) => void> = []
  return {
    addEventListener: (_t: string, fn: (e: MessageEvent<WorkerResponse>) => void) => {
      listeners.push(fn)
    },
    postMessage: (req: WorkerRequest) => {
      handler(req, (r) => {
        for (const l of listeners) l({ data: r } as MessageEvent<WorkerResponse>)
      })
    },
  } as unknown as Worker
}

describe('createWorkerClient', () => {
  it('resolves load() with the coverage the worker reports', async () => {
    const w = fakeWorker((req, reply) => {
      reply({ id: req.id, kind: 'loaded', coverage: COVERAGE })
    })
    const client = createWorkerClient(w)
    await expect(client.load(false, () => {})).resolves.toEqual(COVERAGE)
  })

  it('forwards progress events without resolving', async () => {
    const w = fakeWorker((req, reply) => {
      reply({ id: req.id, kind: 'progress', done: 1, total: 2 })
      reply({ id: req.id, kind: 'progress', done: 2, total: 2 })
      reply({ id: req.id, kind: 'loaded', coverage: COVERAGE })
    })
    const onProgress = vi.fn()
    await createWorkerClient(w).load(false, onProgress)
    expect(onProgress).toHaveBeenCalledTimes(2)
    expect(onProgress).toHaveBeenLastCalledWith(2, 2)
  })

  it('resolves match() with the report', async () => {
    const report: MatchReport = { results: [], unparseable: [], coverage: COVERAGE }
    const w = fakeWorker((req, reply) => {
      reply({ id: req.id, kind: 'report', report })
    })
    await expect(createWorkerClient(w).match('8.8.8.8')).resolves.toEqual(report)
  })

  it('rejects when the worker reports an error', async () => {
    const w = fakeWorker((req, reply) => {
      reply({ id: req.id, kind: 'error', message: 'boom' })
    })
    await expect(createWorkerClient(w).match('x')).rejects.toThrow('boom')
  })

  it('routes concurrent requests to the right caller by id', async () => {
    const pending: Array<(r: WorkerResponse) => void> = []
    const seen: WorkerRequest[] = []
    const w = fakeWorker((req, reply) => {
      seen.push(req)
      pending.push(reply)
    })
    const client = createWorkerClient(w)

    const a = client.match('a')
    const b = client.match('b')

    const reportFor = (id: number, normalized: string): WorkerResponse => ({
      id, kind: 'report',
      report: {
        results: [{ original: normalized, normalized, type: 'domain', hits: [] }],
        unparseable: [], coverage: COVERAGE,
      },
    })

    // Reply out of order: second request first.
    pending[1]!(reportFor(seen[1]!.id, 'b'))
    pending[0]!(reportFor(seen[0]!.id, 'a'))

    expect((await a).results[0]!.normalized).toBe('a')
    expect((await b).results[0]!.normalized).toBe('b')
  })
})
