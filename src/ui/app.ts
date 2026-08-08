import catalogJson from '../catalog.json'
import type { CatalogEntry, Coverage, MatchReport } from '../core/types'
import { cleanOnly, download, toCsv, toJson, toTsv } from './export'
import { renderCoverage, renderResults } from './render'
import { createWorkerClient } from './workerClient'

const catalog = catalogJson as CatalogEntry[]
const heavyBytes = catalog
  .filter((e) => e.loadTier === 'heavy')
  .reduce((n, e) => n + e.bytes, 0)

const SHELL = `
  <h1>MISP Warninglists Checker</h1>
  <p class="sub">Paste IPs, domains or URLs. Everything is matched in your browser —
     nothing you paste is ever sent anywhere.</p>
  <textarea id="input" spellcheck="false"
    placeholder="8.8.8.8&#10;hxxps://evil[.]com/payload&#10;1.1.1.1"></textarea>
  <div class="toolbar">
    <button id="check" class="primary" disabled>Loading lists…</button>
    <button id="load-heavy">Add popularity lists (${Math.round(heavyBytes / 1e6)} MB)</button>
    <button id="copy-tsv" disabled>Copy TSV</button>
    <button id="copy-clean" disabled>Copy clean only</button>
    <button id="dl-csv" disabled>CSV</button>
    <button id="dl-json" disabled>JSON</button>
  </div>
  <div id="coverage"></div>
  <div id="results"></div>
`

export function mountApp(root: HTMLElement, worker: Worker): void {
  root.innerHTML = SHELL

  const $ = <T extends HTMLElement>(id: string): T =>
    root.querySelector<T>(`#${id}`)!

  const input = $<HTMLTextAreaElement>('input')
  const checkBtn = $<HTMLButtonElement>('check')
  const heavyBtn = $<HTMLButtonElement>('load-heavy')
  const coverageEl = $<HTMLDivElement>('coverage')
  const resultsEl = $<HTMLDivElement>('results')

  const exportBtns = ['copy-tsv', 'copy-clean', 'dl-csv', 'dl-json']
    .map((id) => $<HTMLButtonElement>(id))

  const client = createWorkerClient(worker)
  let report: MatchReport | null = null

  function setExportsEnabled(on: boolean): void {
    for (const b of exportBtns) b.disabled = !on
  }

  async function loadLists(heavy: boolean): Promise<void> {
    checkBtn.disabled = true
    heavyBtn.disabled = true
    let coverage: Coverage
    try {
      coverage = await client.load(heavy, (done, total) => {
        checkBtn.textContent = `Loading lists… ${done}/${total}`
      })
    } catch (err) {
      if (heavy) {
        // Core lists are already loaded and usable — an optional-tier
        // failure must not take down a working tool.
        coverageEl.innerHTML =
          `<div class="coverage"><span class="cov-warn">Could not load the popularity ` +
          `lists: ${(err as Error).message}. Checking will continue without them.</span></div>`
        checkBtn.textContent = 'Check indicators'
        checkBtn.disabled = false
        heavyBtn.disabled = false
      } else {
        coverageEl.innerHTML =
          `<div class="coverage"><span class="cov-warn">Could not load any lists: ` +
          `${(err as Error).message}. Checking is disabled until lists load.</span></div>`
        checkBtn.textContent = 'Lists unavailable'
      }
      return
    }

    checkBtn.textContent = 'Check indicators'
    checkBtn.disabled = false
    heavyBtn.disabled = heavy
    if (heavy) heavyBtn.textContent = 'Popularity lists loaded'
    coverageEl.innerHTML = renderCoverage(coverage)
  }

  async function runCheck(): Promise<void> {
    checkBtn.disabled = true
    checkBtn.textContent = 'Checking…'
    try {
      report = await client.match(input.value)
      resultsEl.innerHTML = renderResults(report)
      coverageEl.innerHTML = renderCoverage(report.coverage)
      setExportsEnabled(report.results.length > 0)
    } finally {
      checkBtn.disabled = false
      checkBtn.textContent = 'Check indicators'
    }
  }

  checkBtn.addEventListener('click', () => void runCheck())
  heavyBtn.addEventListener('click', () => void loadLists(true))

  input.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && !checkBtn.disabled) void runCheck()
  })

  $<HTMLButtonElement>('copy-tsv').addEventListener('click', () => {
    if (report) void navigator.clipboard.writeText(toTsv(report))
  })
  $<HTMLButtonElement>('copy-clean').addEventListener('click', () => {
    if (report) void navigator.clipboard.writeText(cleanOnly(report))
  })
  $<HTMLButtonElement>('dl-csv').addEventListener('click', () => {
    if (report) download('warninglist-check.csv', 'text/csv', toCsv(report))
  })
  $<HTMLButtonElement>('dl-json').addEventListener('click', () => {
    if (report) download('warninglist-check.json', 'application/json', toJson(report))
  })

  void loadLists(false)
}
