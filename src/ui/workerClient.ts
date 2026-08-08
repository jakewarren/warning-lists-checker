import type { Coverage, MatchReport } from '../core/types'
import type { WorkerRequest, WorkerResponse } from '../workerProtocol'

export interface WorkerClient {
  load(heavy: boolean, onProgress: (done: number, total: number) => void): Promise<Coverage>
  match(raw: string): Promise<MatchReport>
}

interface Pending {
  resolve: (v: never) => void
  reject: (e: Error) => void
  onProgress?: (done: number, total: number) => void
}

// Omit<Union, K> collapses to the union's common keys instead of distributing
// over each member, which drops the payload fields ('heavy', 'raw'). This
// distributes explicitly so each request variant keeps its own fields.
type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never

export function createWorkerClient(worker: Worker): WorkerClient {
  const pending = new Map<number, Pending>()
  let nextId = 1

  worker.addEventListener('message', (e: MessageEvent<WorkerResponse>) => {
    const msg = e.data
    const p = pending.get(msg.id)
    if (!p) return

    switch (msg.kind) {
      case 'progress':
        p.onProgress?.(msg.done, msg.total)
        return
      case 'loaded':
        pending.delete(msg.id)
        ;(p.resolve as (v: Coverage) => void)(msg.coverage)
        return
      case 'report':
        pending.delete(msg.id)
        ;(p.resolve as (v: MatchReport) => void)(msg.report)
        return
      case 'error':
        pending.delete(msg.id)
        p.reject(new Error(msg.message))
        return
    }
  })

  function send<T>(req: DistributiveOmit<WorkerRequest, 'id'>, onProgress?: Pending['onProgress']): Promise<T> {
    const id = nextId++
    return new Promise<T>((resolve, reject) => {
      pending.set(id, {
        resolve: resolve as Pending['resolve'],
        reject,
        onProgress,
      })
      worker.postMessage({ ...req, id } as WorkerRequest)
    })
  }

  return {
    load: (heavy, onProgress) => send<Coverage>({ kind: 'load', heavy }, onProgress),
    match: (raw) => send<MatchReport>({ kind: 'match', raw }),
  }
}
