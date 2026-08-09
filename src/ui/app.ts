import catalogJson from '../catalog.json'
import type { CatalogEntry, Coverage, MatchReport } from '../core/types'
import { cleanOnly, download, toCsv, toJson, toTsv } from './export'
import { esc, renderCoverage, renderResults } from './render'
import { createWorkerClient } from './workerClient'

const catalog = catalogJson as CatalogEntry[]
const heavyBytes = catalog
  .filter((e) => e.loadTier === 'heavy')
  .reduce((n, e) => n + e.bytes, 0)

// Inline SVG rather than an icon font or library — this project ships zero
// runtime dependencies. Both are 16x16 on a 24-unit grid, stroked with
// currentColor so they inherit the button's colour in light and dark themes
// and dim correctly with :disabled. Decorative only: the button text carries
// the meaning, so they are aria-hidden.
const ICON_COPY = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"
  fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="9" y="9" width="11" height="11" rx="2"/>
  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
</svg>`

const ICON_DOWNLOAD = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"
  fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
  <polyline points="7 10 12 15 17 10"/>
  <line x1="12" y1="15" x2="12" y2="3"/>
</svg>`

const SHELL = `
  <h1>MISP Warninglists Checker</h1>
  <p class="sub">Paste IPs, domains or URLs. Everything is matched in your browser —
     nothing you paste is ever sent anywhere.</p>
  <textarea id="input" spellcheck="false"
    placeholder="8.8.8.8&#10;hxxps://evil[.]com/payload&#10;1.1.1.1"></textarea>
  <div class="toolbar">
    <button id="check" class="primary" disabled>Loading lists…</button>
    <button id="load-heavy">Add popularity lists (${Math.round(heavyBytes / 1e6)} MB)</button>
    <button id="copy-tsv" disabled>${ICON_COPY}Copy TSV</button>
    <button id="copy-clean" disabled>${ICON_COPY}Copy clean only</button>
    <button id="dl-csv" disabled>${ICON_DOWNLOAD}CSV</button>
    <button id="dl-json" disabled>${ICON_DOWNLOAD}JSON</button>
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
  // Tracked explicitly rather than read back off checkBtn.disabled, which
  // runCheck also owns — inferring load state from that bit is what let a
  // finished check re-enable the button in the middle of a list load.
  let loading = false

  function setExportsEnabled(on: boolean): void {
    for (const b of exportBtns) b.disabled = !on
  }

  async function loadLists(heavy: boolean): Promise<void> {
    loading = true
    checkBtn.disabled = true
    heavyBtn.disabled = true
    let coverage: Coverage
    try {
      coverage = await client.load(heavy, (done, total) => {
        checkBtn.textContent = `Loading lists… ${done}/${total}`
      })
    } catch (err) {
      loading = false
      if (heavy) {
        // Core lists are already loaded and usable — an optional-tier
        // failure must not take down a working tool.
        coverageEl.innerHTML =
          `<div class="coverage"><span class="cov-warn">Could not load the popularity ` +
          `lists: ${esc((err as Error).message)}. Checking will continue without them.</span></div>`
        checkBtn.textContent = 'Check indicators'
        checkBtn.disabled = false
        heavyBtn.disabled = false
      } else {
        coverageEl.innerHTML =
          `<div class="coverage"><span class="cov-warn">Could not load any lists: ` +
          `${esc((err as Error).message)}. Checking is disabled until lists load.</span></div>`
        checkBtn.textContent = 'Lists unavailable'
      }
      return
    }

    loading = false
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
      // A load started while this check was in flight owns the button now;
      // restoring it here would re-enable it mid-load and stomp its label.
      if (!loading) {
        checkBtn.disabled = false
        checkBtn.textContent = 'Check indicators'
      }
    }
  }

  checkBtn.addEventListener('click', () => void runCheck())
  heavyBtn.addEventListener('click', () => void loadLists(true))

  // The held report describes the previous input; once the text changes it is
  // stale, and exporting it would put the last batch's verdicts in a ticket.
  input.addEventListener('input', () => setExportsEnabled(false))

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
