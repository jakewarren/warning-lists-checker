import type { Coverage, MatchReport } from './core/types'

export type WorkerRequest =
  | { id: number; kind: 'load'; heavy: boolean }
  | { id: number; kind: 'match'; raw: string }

export type WorkerResponse =
  | { id: number; kind: 'progress'; done: number; total: number }
  | { id: number; kind: 'loaded'; coverage: Coverage }
  | { id: number; kind: 'report'; report: MatchReport }
  | { id: number; kind: 'error'; message: string }
