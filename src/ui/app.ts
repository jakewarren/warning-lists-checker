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

const ICON_SUN = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"
  fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="4"/>
  <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>
</svg>`

const ICON_MOON = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"
  fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>
</svg>`

// GitHub's mark, used to link to the project's own repository. The 80x80
// triangle is drawn by us; the mark is GitHub's standard 24-unit path, scaled
// and nudged to sit optically centred inside the triangle.
const GH_CORNER = `
  <a class="gh-corner" href="https://github.com/jakewarren/warning-lists-checker"
     target="_blank" rel="noopener noreferrer" aria-label="View this project on GitHub">
    <svg viewBox="0 0 80 80" aria-hidden="true" focusable="false">
      <path class="gh-bg" d="M0 0 L80 0 L80 80 Z"/>
      <g class="gh-mark" transform="translate(43.5 10.5) scale(1.15)">
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577
          0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729
          1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93
          0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405
          2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81
          1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
      </g>
    </svg>
  </a>`

const SHELL = `
  ${GH_CORNER}
  <div class="header">
    <div>
      <h1>MISP Warninglists Checker</h1>
      <p class="sub">Paste IPs, domains or URLs. Everything is matched in your browser —
         nothing you paste is ever sent anywhere.</p>
    </div>
    <button id="theme-toggle" type="button"></button>
  </div>
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

const THEME_KEY = 'warning-lists-checker:theme'

/**
 * Wire the light/dark toggle.
 *
 * With no stored choice the page follows `prefers-color-scheme` and no
 * `data-theme` attribute is set, so the system setting keeps applying if the
 * user changes it mid-session. The first click resolves the currently rendered
 * theme and flips to the opposite, pinning it from then on.
 *
 * localStorage is wrapped because it throws outright in some privacy modes —
 * losing the preference is acceptable, breaking the page is not.
 */
function setupThemeToggle(btn: HTMLButtonElement): void {
  const prefersDark = (): boolean =>
    window.matchMedia('(prefers-color-scheme: dark)').matches

  const current = (): 'light' | 'dark' => {
    const attr = document.documentElement.dataset.theme
    if (attr === 'light' || attr === 'dark') return attr
    return prefersDark() ? 'dark' : 'light'
  }

  const paint = (): void => {
    const isDark = current() === 'dark'
    // Show the destination, not the current state: clicking gives you this.
    btn.innerHTML = isDark ? ICON_SUN : ICON_MOON
    const label = `Switch to ${isDark ? 'light' : 'dark'} theme`
    btn.setAttribute('aria-label', label)
    btn.setAttribute('title', label)
  }

  btn.addEventListener('click', () => {
    const next = current() === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    try {
      localStorage.setItem(THEME_KEY, next)
    } catch {
      // Storage unavailable (private mode, disabled). The choice still applies
      // for this session; it just will not survive a reload.
    }
    paint()
  })

  // Keep the icon honest if the OS theme flips while no explicit choice is set.
  window
    .matchMedia('(prefers-color-scheme: dark)')
    .addEventListener('change', () => {
      if (!document.documentElement.dataset.theme) paint()
    })

  paint()
}

export function mountApp(root: HTMLElement, worker: Worker): void {
  root.innerHTML = SHELL

  const $ = <T extends HTMLElement>(id: string): T =>
    root.querySelector<T>(`#${id}`)!

  setupThemeToggle($<HTMLButtonElement>('theme-toggle'))

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
