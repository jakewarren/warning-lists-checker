import { mountApp } from './ui/app'

const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
mountApp(document.querySelector<HTMLDivElement>('#app')!, worker)
