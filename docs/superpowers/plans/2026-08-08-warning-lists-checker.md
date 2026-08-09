# MISP Warninglists Checker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a browser-only SOC tool where an analyst pastes IPs, domains, and URLs and gets back which MISP warninglists each one hits, so likely false positives are identified before investigation starts.

**Architecture:** A static single-page app on GitHub Pages. A shipped `catalog.json` describes the 125 upstream lists; a `ListStore` fetches list bodies directly from `raw.githubusercontent.com` into an IndexedDB cache with age-based decay; a Web Worker compiles each list into a type-appropriate matcher and matches indicators off the main thread. Analyst input never leaves the browser.

**Tech Stack:** TypeScript, Vite, Vitest, `fake-indexeddb` (tests only). No runtime dependencies, no framework, no backend.

**Spec:** `docs/superpowers/specs/2026-08-08-warning-lists-checker-design.md`

## Global Constraints

- **Zero runtime dependencies.** `dependencies` in `package.json` stays empty. Everything ships as hand-written TypeScript.
- **No network calls except to `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/<name>/list.json`.** Never call `api.github.com` at runtime (60 req/hour unauthenticated, against 125 lists).
- **Analyst indicators never leave the browser.** No telemetry, no analytics, no error reporting service, no indicator ever placed in a URL, query string, or outbound request.
- **All matching runs inside the Web Worker.** Modules under `src/core/` must not reference `window`, `document`, or any DOM API, so they stay unit-testable under Node.
- **`version` from upstream is a `number`, not a string** (observed values: `5`, `27`, `20250115`, `20260709`). The spec's `Result` sketch says string; number is correct.
- **The word "clean" is reserved for full coverage.** When any in-scope list failed to load, zero-hit indicators must be labeled `no hits (N/M lists)` instead.
- **Node 20.19+ or 22.12+** for the toolchain (Node 20 reached EOL in April 2026; CI runs 24 LTS).
- **Vite `base` must be `'./'`** so the build works from a GitHub Pages project subpath.
- **CI supply-chain hardening.** Every GitHub Action is pinned to a full commit
  SHA with a trailing **exact-version** comment (`# v2.20.1`, not `# v2`), never
  a moving tag. The comment is the only human-readable signal of what a pin
  actually is, and Dependabot writes exact versions when it bumps one, so a
  bare major like `# v2` makes drift invisible. Every workflow job
  begins with a `step-security/harden-runner` step. Workflow-level `permissions`
  is `{}` and each job declares its own minimum. Dependabot keeps both the
  action SHAs and the npm devDependencies current.

## Terminology

Two independent axes, deliberately not conflated:

- **`tier`** — *presentation* category, controls how a hit is rendered: `infrastructure`, `known-fp`, `popularity`, `context`, `neutral`.
- **`loadTier`** — *download* grouping: `core` (121 lists, ~1.4 MB gzipped, loaded at startup) or `heavy` (`tranco` + `google-chrome-crux-1million`, ~7 MB gzipped, opt-in).

`alexa`, `majestic_million`, `tranco10k`, `cisco_top1000`/`5k`/`10k`/`20k`, and `moz-top500` are `tier: 'popularity'` but `loadTier: 'core'` — they are small.

## File Structure

| file | responsibility |
|---|---|
| `package.json`, `tsconfig.json`, `vite.config.ts` | toolchain |
| `.github/workflows/deploy.yml` | build + publish to GitHub Pages |
| `.github/workflows/catalog-drift.yml` | nightly upstream-vs-catalog diff, opens an issue |
| `scripts/build-catalog.ts` | dev-time generator: fetch upstream metadata → `src/catalog.json` |
| `src/catalog.json` | generated, committed. List names, types, attributes, tiers |
| `src/core/types.ts` | shared types, no logic |
| `src/core/parse.ts` | raw text → `Indicator[]` (refang, classify, dedupe) |
| `src/core/ip.ts` | IPv4/IPv6 address and CIDR parsing primitives |
| `src/core/matchers/cidr.ts` | CIDR range matcher (74 lists, the hot path) |
| `src/core/matchers/simple.ts` | `string`, `hostname`, `substring`, `regex` matchers |
| `src/core/matchers/index.ts` | `buildMatcher(type, entries)` factory |
| `src/core/applicability.ts` | which lists apply to which indicator type |
| `src/core/listStore.ts` | IndexedDB cache, decay policy, fetch, coverage |
| `src/core/engine.ts` | orchestrates store + matchers → `MatchReport` |
| `src/worker.ts` | Worker entry + message protocol |
| `src/ui/app.ts` | wiring, state, worker client |
| `src/ui/render.ts` | coverage header, tiered results, unparseable section |
| `src/ui/export.ts` | TSV / CSV / JSON / clean-only output |
| `src/main.ts`, `index.html`, `src/style.css` | shell |

---

### Task 1: Project scaffold and toolchain

**Files:**
- Create: `package.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `src/main.ts`, `.gitignore`
- Create: `src/core/types.ts`
- Test: `src/core/types.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: the type vocabulary every later task imports —
  `IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'unparseable'`;
  `Tier = 'infrastructure' | 'known-fp' | 'popularity' | 'context' | 'neutral'`;
  `LoadTier = 'core' | 'heavy'`;
  `ListType = 'cidr' | 'string' | 'hostname' | 'substring' | 'regex'`;
  interfaces `CatalogEntry`, `Indicator`, `Hit`, `IndicatorResult`, `MatchReport`, `Matcher`.

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "warning-lists-checker",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest",
    "build:catalog": "tsx scripts/build-catalog.ts"
  },
  "dependencies": {},
  "devDependencies": {
    "typescript": "^5.6.0",
    "vite": "^5.4.0",
    "vitest": "^2.1.0",
    "fake-indexeddb": "^6.0.0",
    "tsx": "^4.19.0"
  }
}
```

- [ ] **Step 2: Create `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable", "WebWorker"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noEmit": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "types": ["vitest/globals"]
  },
  "include": ["src", "scripts"]
}
```

- [ ] **Step 3: Create `vite.config.ts`**

`base: './'` is required for GitHub Pages project sites, which serve from `/<repo>/`.

```ts
// Imported from 'vitest/config', not 'vite' — the base defineConfig type does
// not accept the `test` key and would fail `tsc --noEmit`.
import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: './',
  build: { target: 'es2022' },
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
```

- [ ] **Step 4: Create `.gitignore`**

```
node_modules
dist
.DS_Store
```

- [ ] **Step 5: Create `index.html`**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>MISP Warninglists Checker</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 6: Create `src/main.ts` placeholder**

```ts
document.querySelector<HTMLDivElement>('#app')!.textContent = 'warning-lists-checker'
```

- [ ] **Step 7: Create `src/core/types.ts`**

```ts
export type IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'unparseable'
export type Tier = 'infrastructure' | 'known-fp' | 'popularity' | 'context' | 'neutral'
export type LoadTier = 'core' | 'heavy'
export type ListType = 'cidr' | 'string' | 'hostname' | 'substring' | 'regex'

/** One entry in the shipped catalog.json. Mirrors upstream metadata plus our tiers. */
export interface CatalogEntry {
  /** Upstream directory name, e.g. "public-dns-v4". Used to build the fetch URL. */
  name: string
  /** Upstream "name" field, a human sentence, e.g. "List of RFC 1918 CIDR blocks". */
  title: string
  description: string
  type: ListType
  matchingAttributes: string[]
  tier: Tier
  loadTier: LoadTier
  /** Raw byte size upstream, used to show download size on the opt-in button. */
  bytes: number
}

/** A single parsed input line. */
export interface Indicator {
  /** Exactly what the analyst pasted, before refanging. */
  original: string
  /** Refanged, lowercased value used for matching. For URLs this is the hostname. */
  normalized: string
  type: IndicatorType
  /** How many times this normalized value appeared in the input. */
  count: number
}

export interface Hit {
  list: string
  title: string
  description: string
  tier: Tier
  version: number
}

export interface IndicatorResult {
  original: string
  normalized: string
  type: IndicatorType
  hits: Hit[]
}

export interface Coverage {
  loaded: number
  total: number
  failed: string[]
  heavyLoaded: boolean
  /** Oldest fetchedAt across loaded lists, epoch ms. Drives the staleness banner. */
  oldestFetchedAt: number | null
}

export interface MatchReport {
  results: IndicatorResult[]
  unparseable: string[]
  coverage: Coverage
}

/** Built once per list per session, then queried per indicator. */
export interface Matcher {
  match(normalized: string, type: IndicatorType): boolean
}
```

- [ ] **Step 8: Write the failing test**

This test exists to prove the toolchain runs and the type module imports cleanly.

```ts
// src/core/types.test.ts
import { describe, it, expect } from 'vitest'
import { TIERS, LOAD_TIERS } from './types'

describe('type vocabulary', () => {
  it('exposes the five presentation tiers', () => {
    expect(TIERS).toEqual(['infrastructure', 'known-fp', 'popularity', 'context', 'neutral'])
  })

  it('exposes the two load tiers', () => {
    expect(LOAD_TIERS).toEqual(['core', 'heavy'])
  })
})
```

- [ ] **Step 9: Run test to verify it fails**

Run: `npm install && npx vitest run src/core/types.test.ts`
Expected: FAIL — `TIERS` and `LOAD_TIERS` are not exported from `./types`.

- [ ] **Step 10: Add the runtime constants to `src/core/types.ts`**

Append to the file. These are runtime values (the type aliases above are erased at compile time, so tests cannot assert on them).

```ts
export const TIERS: readonly Tier[] = [
  'infrastructure', 'known-fp', 'popularity', 'context', 'neutral',
] as const

export const LOAD_TIERS: readonly LoadTier[] = ['core', 'heavy'] as const
```

- [ ] **Step 11: Run test to verify it passes**

Run: `npx vitest run src/core/types.test.ts`
Expected: PASS, 2 tests.

- [ ] **Step 12: Verify the build works**

Run: `npm run build`
Expected: `tsc --noEmit` reports no errors, Vite writes `dist/`.

- [ ] **Step 13: Commit**

```bash
git add package.json package-lock.json tsconfig.json vite.config.ts index.html .gitignore src/main.ts src/core/types.ts src/core/types.test.ts
git commit -m "chore: scaffold vite + typescript + vitest, add core type vocabulary"
```

---

### Task 2: Catalog generator and generated catalog

**Files:**
- Create: `scripts/build-catalog.ts`
- Create: `src/catalog.json` (generated output, committed)
- Test: `src/core/catalog.test.ts`

**Interfaces:**
- Consumes: `CatalogEntry`, `Tier`, `LoadTier`, `ListType` from `src/core/types.ts`.
- Produces: `src/catalog.json` — a JSON array of `CatalogEntry`, importable as `import catalog from '../catalog.json'`. Also exports `assignTier(name: string, upstreamType: ListType, attrs: string[]): Tier` and `assignLoadTier(name: string): LoadTier` from `scripts/build-catalog.ts` for testing.

Background: upstream publishes no machine-readable index, so this script walks the GitHub tree API **once at dev time**, fetches each `list.json`, and writes a catalog we ship. It is never run in the browser. This is a deliberate freshness-for-determinism tradeoff, backstopped by the drift job in Task 12.

- [ ] **Step 1: Write the failing test for tier assignment**

```ts
// src/core/catalog.test.ts
import { describe, it, expect } from 'vitest'
import { assignTier, assignLoadTier } from '../../scripts/build-catalog'

describe('assignTier', () => {
  it('classifies cloud and CDN ranges as infrastructure', () => {
    expect(assignTier('cloudflare', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('amazon-aws', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('microsoft-azure', 'cidr', ['ip-src'])).toBe('infrastructure')
    expect(assignTier('public-dns-v4', 'cidr', ['ip-src'])).toBe('infrastructure')
  })

  it('classifies curated false-positive lists as known-fp', () => {
    expect(assignTier('ti-falsepositives', 'hostname', ['domain'])).toBe('known-fp')
    expect(assignTier('common-ioc-false-positive', 'string', ['domain'])).toBe('known-fp')
    expect(assignTier('rfc1918', 'cidr', ['ip-src'])).toBe('known-fp')
  })

  it('classifies popularity rankings as popularity', () => {
    expect(assignTier('tranco', 'hostname', ['domain'])).toBe('popularity')
    expect(assignTier('alexa', 'string', ['domain'])).toBe('popularity')
    expect(assignTier('cisco_top10k', 'string', ['domain'])).toBe('popularity')
  })

  it('auto-classifies any scanner list as context via name suffix', () => {
    expect(assignTier('shodan-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('censys-scanning', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('rapid7-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
    // A scanner list added upstream tomorrow must self-classify.
    expect(assignTier('brandnew-nt-scanning', 'cidr', ['ip-src'])).toBe('context')
  })

  it('classifies investigative-lead lists as context', () => {
    expect(assignTier('dynamic-dns', 'hostname', ['domain'])).toBe('context')
    expect(assignTier('vpn-ipv4', 'cidr', ['ip-src'])).toBe('context')
    expect(assignTier('url-shortener', 'hostname', ['domain'])).toBe('context')
  })

  it('falls through to neutral for unrecognised lists', () => {
    expect(assignTier('some-future-list', 'string', ['domain'])).toBe('neutral')
  })
})

describe('assignLoadTier', () => {
  it('marks only the two multi-megabyte popularity lists as heavy', () => {
    expect(assignLoadTier('tranco')).toBe('heavy')
    expect(assignLoadTier('google-chrome-crux-1million')).toBe('heavy')
  })

  it('keeps small popularity lists in core', () => {
    expect(assignLoadTier('alexa')).toBe('core')
    expect(assignLoadTier('majestic_million')).toBe('core')
    expect(assignLoadTier('tranco10k')).toBe('core')
    expect(assignLoadTier('cloudflare')).toBe('core')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/catalog.test.ts`
Expected: FAIL — cannot resolve `../../scripts/build-catalog`.

- [ ] **Step 3: Write `scripts/build-catalog.ts`**

```ts
import { writeFileSync } from 'node:fs'
import type { CatalogEntry, ListType, LoadTier, Tier } from '../src/core/types'

const TREE_URL =
  'https://api.github.com/repos/MISP/misp-warninglists/git/trees/main?recursive=1'
const RAW = 'https://raw.githubusercontent.com/MISP/misp-warninglists/main'

/** Lists excluded entirely: file-hash lists, out of scope for v1. */
const EXCLUDED = new Set(['windows-binary-hashes', 'nioc-filehash'])

/** Only these two are large enough to defer behind an opt-in. */
const HEAVY = new Set(['tranco', 'google-chrome-crux-1million'])

const INFRASTRUCTURE = new Set([
  'akamai', 'amazon-aws', 'apple', 'cloudflare', 'fastly', 'github', 'google',
  'google-gcp', 'google-gmail-sending-ips', 'googlebot', 'microsoft',
  'microsoft-azure', 'microsoft-azure-appid', 'microsoft-azure-china',
  'microsoft-azure-germany', 'microsoft-azure-us-gov', 'microsoft-office365',
  'microsoft-office365-cn', 'microsoft-office365-ip',
  'microsoft-win10-connection-endpoints', 'mozilla-CA', 'mozilla-IntermediateCA',
  'ovh-cluster', 'public-dns-hostname', 'public-dns-v4', 'public-dns-v6',
  'smtp-receiving-ips', 'smtp-sending-ips', 'stackpath', 'telegram-ips',
  'tenable-cloud-ipv4', 'tenable-cloud-ipv6', 'wikimedia', 'zscaler',
  'crl-hostname', 'crl-ip', 'captive-portals', 'openai-gptbot',
])

const KNOWN_FP = new Set([
  'ti-falsepositives', 'common-ioc-false-positive', 'rfc1918', 'rfc3849',
  'rfc5735', 'rfc6598', 'rfc6761', 'ipv6-linklocal', 'multicast',
  'covid-19-cyber-threat-coalition-whitelist', 'covid-19-krassi-whitelist',
  'eicar.com', 'empty-hashes', 'second-level-tlds', 'tlds',
  'microsoft-attack-simulator', 'whats-my-ip', 'university_domains',
  'bank-website', 'dax30', 'sinkholes',
])

const POPULARITY = new Set([
  'alexa', 'cisco_top1000', 'cisco_top5k', 'cisco_top10k', 'cisco_top20k',
  'google-chrome-crux-1million', 'majestic_million', 'moz-top500', 'tranco',
  'tranco10k',
])

const CONTEXT = new Set([
  'dynamic-dns', 'vpn-ipv4', 'vpn-ipv6', 'url-shortener', 'link-in-bio',
  'parking-domain', 'parking-domain-ns', 'disposable-email', 'covid',
  'automated-malware-analysis', 'security-provider-blogpost', 'digitalside',
  'lots-project', 'public-ipfs-gateways', 'findip-host', 'check-host-net',
  'shadowserver', 'modat-scanner', 'onyphe-scanner', 'internetcleanup-scanner',
  'umbrella-blockpage-hostname', 'umbrella-blockpage-v4', 'umbrella-blockpage-v6',
  'umich-cse-connection-attempts', 'palo-alto-networks-cortex-xpanse',
  'common-contact-emails', 'phone_numbers',
])

/**
 * Presentation tier. Name-suffix rule for scanners comes first so that
 * scanner lists added upstream self-classify without a catalog edit.
 */
export function assignTier(name: string, _type: ListType, _attrs: string[]): Tier {
  if (name.endsWith('-scanning') || name.endsWith('-nt-scanning')) return 'context'
  if (INFRASTRUCTURE.has(name)) return 'infrastructure'
  if (KNOWN_FP.has(name)) return 'known-fp'
  if (POPULARITY.has(name)) return 'popularity'
  if (CONTEXT.has(name)) return 'context'
  return 'neutral'
}

export function assignLoadTier(name: string): LoadTier {
  return HEAVY.has(name) ? 'heavy' : 'core'
}

interface UpstreamList {
  description: string
  list: string[]
  matching_attributes: string[]
  name: string
  type: ListType
  version: number
}

async function main(): Promise<void> {
  const tree = (await (await fetch(TREE_URL)).json()) as {
    tree: Array<{ path: string; type: string; size?: number }>
  }

  const files = tree.tree.filter(
    (e) => e.type === 'blob' && e.path.endsWith('/list.json'),
  )

  const entries: CatalogEntry[] = []
  for (const f of files) {
    const name = f.path.split('/')[1]!
    if (EXCLUDED.has(name)) continue

    const res = await fetch(`${RAW}/${f.path}`)
    if (!res.ok) throw new Error(`fetch failed for ${name}: ${res.status}`)
    const body = (await res.json()) as UpstreamList

    entries.push({
      name,
      title: body.name,
      description: body.description,
      type: body.type,
      matchingAttributes: body.matching_attributes,
      tier: assignTier(name, body.type, body.matching_attributes),
      loadTier: assignLoadTier(name),
      bytes: f.size ?? 0,
    })
    console.log(`${name} ${body.type} ${assignTier(name, body.type, body.matching_attributes)}`)
  }

  entries.sort((a, b) => a.name.localeCompare(b.name))
  writeFileSync('src/catalog.json', JSON.stringify(entries, null, 2) + '\n')
  console.log(`\nwrote ${entries.length} entries`)
}

// Only run when invoked directly, so importing for tests does not hit the network.
if (import.meta.url === `file://${process.argv[1]}`) {
  await main()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/catalog.test.ts`
Expected: PASS, 8 tests.

- [ ] **Step 5: Generate the catalog**

Run: `npm run build:catalog`
Expected: prints one line per list, ends with `wrote 123 entries` (125 lists minus the 2 excluded hash lists). Writes `src/catalog.json`.

- [ ] **Step 6: Write the failing test for catalog integrity**

Add to `src/core/catalog.test.ts`:

```ts
import catalog from '../catalog.json'
import type { CatalogEntry } from './types'

describe('generated catalog.json', () => {
  const entries = catalog as CatalogEntry[]

  it('contains every non-hash upstream list', () => {
    expect(entries.length).toBe(123)
  })

  it('excludes the out-of-scope hash lists', () => {
    const names = entries.map((e) => e.name)
    expect(names).not.toContain('windows-binary-hashes')
    expect(names).not.toContain('nioc-filehash')
  })

  it('has exactly 121 core lists and 2 heavy lists', () => {
    expect(entries.filter((e) => e.loadTier === 'core').length).toBe(121)
    expect(entries.filter((e) => e.loadTier === 'heavy').length).toBe(2)
  })

  it('assigns every entry a known list type', () => {
    for (const e of entries) {
      expect(['cidr', 'string', 'hostname', 'substring', 'regex']).toContain(e.type)
    }
  })

  it('gives every entry a non-empty name, title and matchingAttributes', () => {
    for (const e of entries) {
      expect(e.name.length).toBeGreaterThan(0)
      expect(e.title.length).toBeGreaterThan(0)
      expect(e.matchingAttributes.length).toBeGreaterThan(0)
    }
  })
})
```

- [ ] **Step 7: Run the test**

Run: `npx vitest run src/core/catalog.test.ts`
Expected: PASS, 13 tests. If the count assertions fail because upstream changed, update the expected numbers and note the change in the commit message — do not loosen the assertion, it is the drift tripwire.

- [ ] **Step 8: Commit**

```bash
git add scripts/build-catalog.ts src/catalog.json src/core/catalog.test.ts package.json
git commit -m "feat: add catalog generator and generated list catalog"
```

---

### Task 3: Input parsing — refang, classify, dedupe

**Files:**
- Create: `src/core/parse.ts`
- Test: `src/core/parse.test.ts`

**Interfaces:**
- Consumes: `Indicator`, `IndicatorType` from `./types`.
- Produces: `parseInput(raw: string): { indicators: Indicator[]; unparseable: string[] }`, `refang(s: string): string`, `classify(s: string): IndicatorType`.

- [ ] **Step 1: Write the failing test**

```ts
// src/core/parse.test.ts
import { describe, it, expect } from 'vitest'
import { parseInput, refang, classify } from './parse'

describe('refang', () => {
  it('restores bracketed and braced dots', () => {
    expect(refang('evil[.]com')).toBe('evil.com')
    expect(refang('evil(.)com')).toBe('evil.com')
    expect(refang('evil{.}com')).toBe('evil.com')
    expect(refang('evil\\.com')).toBe('evil.com')
  })

  it('restores defanged schemes case-insensitively', () => {
    expect(refang('hxxp://evil.com')).toBe('http://evil.com')
    expect(refang('hXXps://evil.com')).toBe('https://evil.com')
    expect(refang('hxxps://evil.com')).toBe('https://evil.com')
  })

  it('restores bracketed colons and slashes', () => {
    expect(refang('http[:]//evil.com')).toBe('http://evil.com')
    expect(refang('http:[//]evil.com')).toBe('http://evil.com')
  })

  it('restores defanged at-signs', () => {
    expect(refang('user[at]evil.com')).toBe('user@evil.com')
    expect(refang('user(at)evil.com')).toBe('user@evil.com')
  })

  it('leaves clean input untouched', () => {
    expect(refang('https://example.com/a')).toBe('https://example.com/a')
    expect(refang('8.8.8.8')).toBe('8.8.8.8')
  })
})

describe('classify', () => {
  it('identifies IPv4', () => {
    expect(classify('8.8.8.8')).toBe('ipv4')
    expect(classify('192.168.0.1')).toBe('ipv4')
  })

  it('rejects malformed IPv4 as domain or unparseable', () => {
    expect(classify('999.1.1.1')).not.toBe('ipv4')
    expect(classify('1.2.3')).not.toBe('ipv4')
  })

  it('identifies IPv6 in compressed, full and bracketed forms', () => {
    expect(classify('::1')).toBe('ipv6')
    expect(classify('2001:db8::1')).toBe('ipv6')
    expect(classify('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('ipv6')
    expect(classify('[2001:db8::1]:443')).toBe('ipv6')
  })

  it('identifies URLs', () => {
    expect(classify('https://example.com/path')).toBe('url')
    expect(classify('example.com/path')).toBe('url')
  })

  it('identifies bare domains', () => {
    expect(classify('example.com')).toBe('domain')
    expect(classify('a.b.example.co.uk')).toBe('domain')
  })

  it('rejects junk', () => {
    expect(classify('not a domain!')).toBe('unparseable')
    expect(classify('')).toBe('unparseable')
  })
})

describe('parseInput', () => {
  it('splits on newlines, commas, semicolons and whitespace', () => {
    const { indicators } = parseInput('8.8.8.8\n1.1.1.1, 9.9.9.9; 8.8.4.4 4.4.4.4')
    expect(indicators.map((i) => i.normalized)).toEqual([
      '8.8.8.8', '1.1.1.1', '9.9.9.9', '8.8.4.4', '4.4.4.4',
    ])
  })

  it('refangs before classifying', () => {
    const { indicators } = parseInput('hxxps://evil[.]com/payload')
    expect(indicators[0]!.type).toBe('url')
    expect(indicators[0]!.normalized).toBe('evil.com')
  })

  it('preserves the original text exactly as pasted', () => {
    const { indicators } = parseInput('hxxps://evil[.]com/payload')
    expect(indicators[0]!.original).toBe('hxxps://evil[.]com/payload')
  })

  it('reduces URLs to their hostname for matching', () => {
    const { indicators } = parseInput('https://sub.example.com:8443/a/b?c=d')
    expect(indicators[0]!.normalized).toBe('sub.example.com')
  })

  it('strips a port from a bare IPv4', () => {
    const { indicators } = parseInput('8.8.8.8:53')
    expect(indicators[0]!.normalized).toBe('8.8.8.8')
    expect(indicators[0]!.type).toBe('ipv4')
  })

  it('strips brackets and port from IPv6', () => {
    const { indicators } = parseInput('[2001:db8::1]:443')
    expect(indicators[0]!.normalized).toBe('2001:db8::1')
    expect(indicators[0]!.type).toBe('ipv6')
  })

  it('lowercases the normalized value but not the original', () => {
    const { indicators } = parseInput('EXAMPLE.COM')
    expect(indicators[0]!.normalized).toBe('example.com')
    expect(indicators[0]!.original).toBe('EXAMPLE.COM')
  })

  it('dedupes on normalized value, keeping first-seen order and a count', () => {
    const { indicators } = parseInput('example.com\nEXAMPLE.com\n8.8.8.8\nexample.com')
    expect(indicators.map((i) => i.normalized)).toEqual(['example.com', '8.8.8.8'])
    expect(indicators[0]!.count).toBe(3)
    expect(indicators[1]!.count).toBe(1)
  })

  it('collects unparseable lines separately rather than dropping them', () => {
    const { indicators, unparseable } = parseInput('8.8.8.8\nd41d8cd98f00b204e9800998ecf8427e\n???')
    expect(indicators.map((i) => i.normalized)).toEqual(['8.8.8.8'])
    expect(unparseable).toEqual(['d41d8cd98f00b204e9800998ecf8427e', '???'])
  })

  it('strips surrounding quotes and trailing punctuation', () => {
    const { indicators } = parseInput('"example.com", \'8.8.8.8\'')
    expect(indicators.map((i) => i.normalized)).toEqual(['example.com', '8.8.8.8'])
  })

  it('returns empty results for empty input', () => {
    expect(parseInput('')).toEqual({ indicators: [], unparseable: [] })
    expect(parseInput('   \n  \n')).toEqual({ indicators: [], unparseable: [] })
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/parse.test.ts`
Expected: FAIL — cannot resolve `./parse`.

- [ ] **Step 3: Write `src/core/parse.ts`**

```ts
import type { Indicator, IndicatorType } from './types'

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/

/** Undo the common defanging conventions found in threat reports. */
export function refang(s: string): string {
  return s
    .replace(/h(?:xx|XX|Xx|xX)(p|P)(s|S)?:/g, (_m, p: string, sec?: string) =>
      `htt${p.toLowerCase()}${sec ? 's' : ''}:`)
    .replace(/[[({]\s*\.\s*[\])}]/g, '.')
    .replace(/\\\./g, '.')
    .replace(/[[({]\s*:\s*[\])}]/g, ':')
    .replace(/[[({]\s*\/\/\s*[\])}]/g, '//')
    .replace(/[[({]\s*at\s*[\])}]/gi, '@')
}

function isIpv4(s: string): boolean {
  const m = IPV4_RE.exec(s)
  if (!m) return false
  return m.slice(1).every((o) => Number(o) <= 255 && !(o.length > 1 && o.startsWith('0')))
}

/**
 * Structural IPv6 check. Full numeric validation lives in ip.ts; here we only
 * need enough to route the value to the right matcher.
 */
function isIpv6(s: string): boolean {
  if (!s.includes(':')) return false
  if (!/^[0-9a-f:.]+$/i.test(s)) return false
  const doubles = s.match(/::/g)
  if (doubles && doubles.length > 1) return false
  const groups = s.split(':').filter((g) => g.length > 0)
  if (groups.length > 8) return false
  return groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g) || isIpv4(g))
}

export function classify(s: string): IndicatorType {
  if (!s) return 'unparseable'
  if (isIpv4(s)) return 'ipv4'
  if (isIpv6(s)) return 'ipv6'
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return 'url'
  if (s.includes('/')) return 'url'
  if (DOMAIN_RE.test(s.toLowerCase())) return 'domain'
  return 'unparseable'
}

/** Reduce a URL to the hostname the warninglists actually match against. */
function hostnameOf(s: string): string | null {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `http://${s}`
  try {
    const u = new URL(withScheme)
    // URL keeps IPv6 hosts bracketed; strip for matching.
    return u.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  } catch {
    return null
  }
}

/** Strip a trailing :port from a bare host, leaving IPv6 alone. */
function stripPort(s: string): string {
  if (s.startsWith('[')) {
    const close = s.indexOf(']')
    if (close !== -1) return s.slice(1, close)
  }
  const colons = (s.match(/:/g) ?? []).length
  if (colons === 1) {
    const [host, port] = s.split(':')
    if (host && port && /^\d{1,5}$/.test(port)) return host
  }
  return s
}

function tidy(token: string): string {
  return token
    .replace(/^["'`<(\[]+/, '')
    .replace(/["'`>)\]]+$/, '')
    .replace(/[.,;]+$/, '')
    .trim()
}

export function parseInput(raw: string): {
  indicators: Indicator[]
  unparseable: string[]
} {
  const tokens = raw
    .split(/[\s,;]+/)
    .map(tidy)
    .filter((t) => t.length > 0)

  const byNormalized = new Map<string, Indicator>()
  const unparseable: string[] = []

  for (const token of tokens) {
    const refanged = refang(token)
    const type = classify(refanged)

    if (type === 'unparseable') {
      unparseable.push(token)
      continue
    }

    let normalized: string
    if (type === 'url') {
      const host = hostnameOf(refanged)
      if (!host) {
        unparseable.push(token)
        continue
      }
      normalized = host
    } else {
      normalized = stripPort(refanged).toLowerCase()
    }

    const existing = byNormalized.get(normalized)
    if (existing) {
      existing.count += 1
    } else {
      byNormalized.set(normalized, { original: token, normalized, type, count: 1 })
    }
  }

  return { indicators: [...byNormalized.values()], unparseable }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/parse.test.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add src/core/parse.ts src/core/parse.test.ts
git commit -m "feat: parse pasted input with refanging, classification and dedupe"
```

---

### Task 4: IP primitives and the CIDR matcher

**Files:**
- Create: `src/core/ip.ts`
- Create: `src/core/matchers/cidr.ts`
- Test: `src/core/ip.test.ts`, `src/core/matchers/cidr.test.ts`

**Interfaces:**
- Consumes: `Matcher`, `IndicatorType` from `../types`.
- Produces: from `ip.ts` — `ipv4ToInt(s: string): number | null`, `ipv6ToBigInt(s: string): bigint | null`. From `matchers/cidr.ts` — `buildCidrMatcher(entries: string[]): Matcher`.

This is the hot path: 74 of 123 lists are CIDR, and IPv6 ranges are common (`amazon-aws` has 2,066, `microsoft-azure` 1,017), so IPv6 is required, not optional.

- [ ] **Step 1: Write the failing test for IP primitives**

```ts
// src/core/ip.test.ts
import { describe, it, expect } from 'vitest'
import { ipv4ToInt, ipv6ToBigInt } from './ip'

describe('ipv4ToInt', () => {
  it('converts boundary addresses', () => {
    expect(ipv4ToInt('0.0.0.0')).toBe(0)
    expect(ipv4ToInt('255.255.255.255')).toBe(4294967295)
  })

  it('converts a normal address without sign overflow', () => {
    expect(ipv4ToInt('192.168.1.1')).toBe(3232235777)
    expect(ipv4ToInt('8.8.8.8')).toBe(134744072)
    // Above 2^31 — must not come back negative.
    expect(ipv4ToInt('200.0.0.1')).toBe(3355443201)
  })

  it('rejects malformed input', () => {
    expect(ipv4ToInt('256.0.0.1')).toBeNull()
    expect(ipv4ToInt('1.2.3')).toBeNull()
    expect(ipv4ToInt('1.2.3.4.5')).toBeNull()
    expect(ipv4ToInt('a.b.c.d')).toBeNull()
    expect(ipv4ToInt('')).toBeNull()
  })
})

describe('ipv6ToBigInt', () => {
  it('converts loopback and unspecified', () => {
    expect(ipv6ToBigInt('::1')).toBe(1n)
    expect(ipv6ToBigInt('::')).toBe(0n)
  })

  it('converts a full uncompressed address', () => {
    expect(ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(
      0x20010db8000000000000000000000001n,
    )
  })

  it('treats compressed and uncompressed forms as equal', () => {
    expect(ipv6ToBigInt('2001:db8::1')).toBe(
      ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'),
    )
  })

  it('is case insensitive', () => {
    expect(ipv6ToBigInt('2001:DB8::1')).toBe(ipv6ToBigInt('2001:db8::1'))
  })

  it('handles an embedded IPv4 tail', () => {
    expect(ipv6ToBigInt('::ffff:192.168.1.1')).toBe(0xffffc0a80101n)
  })

  it('strips brackets and zone identifiers', () => {
    expect(ipv6ToBigInt('[2001:db8::1]')).toBe(ipv6ToBigInt('2001:db8::1'))
    expect(ipv6ToBigInt('fe80::1%eth0')).toBe(ipv6ToBigInt('fe80::1'))
  })

  it('rejects malformed input', () => {
    expect(ipv6ToBigInt('2001:db8::1::2')).toBeNull()
    expect(ipv6ToBigInt('gggg::1')).toBeNull()
    expect(ipv6ToBigInt('1:2:3:4:5:6:7')).toBeNull()
    expect(ipv6ToBigInt('1:2:3:4:5:6:7:8:9')).toBeNull()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/ip.test.ts`
Expected: FAIL — cannot resolve `./ip`.

- [ ] **Step 3: Write `src/core/ip.ts`**

```ts
/** Dotted-quad to unsigned 32-bit. Returns null on anything malformed. */
export function ipv4ToInt(addr: string): number | null {
  const parts = addr.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null
    const n = Number(p)
    if (n > 255) return null
    out = out * 256 + n
  }
  return out >>> 0
}

/**
 * IPv6 text to a 128-bit BigInt. Handles :: compression, embedded IPv4 tails,
 * surrounding brackets and %zone suffixes. Returns null on anything malformed.
 */
export function ipv6ToBigInt(addr: string): bigint | null {
  let s = addr.trim().toLowerCase()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)

  const pct = s.indexOf('%')
  if (pct !== -1) s = s.slice(0, pct)

  if (!s.includes(':')) return null

  // Fold an embedded IPv4 tail into two hex groups.
  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':')
    const v4 = s.slice(lastColon + 1)
    const n = ipv4ToInt(v4)
    if (n === null) return null
    const hi = ((n >>> 16) & 0xffff).toString(16)
    const lo = (n & 0xffff).toString(16)
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`
  }

  const doubles = s.match(/::/g)
  if (doubles && doubles.length > 1) return null

  const dbl = s.indexOf('::')
  let head: string[]
  let tail: string[]
  if (dbl === -1) {
    head = s.split(':')
    tail = []
    if (head.length !== 8) return null
  } else {
    const left = s.slice(0, dbl)
    const right = s.slice(dbl + 2)
    head = left ? left.split(':') : []
    tail = right ? right.split(':') : []
    if (head.length + tail.length > 7) return null
  }

  const fill = 8 - head.length - tail.length
  if (fill < 0) return null
  const groups = [...head, ...Array<string>(fill).fill('0'), ...tail]

  let out = 0n
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    out = (out << 16n) | BigInt(parseInt(g, 16))
  }
  return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/ip.test.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Write the failing test for the CIDR matcher**

```ts
// src/core/matchers/cidr.test.ts
import { describe, it, expect } from 'vitest'
import { buildCidrMatcher } from './cidr'

describe('buildCidrMatcher — IPv4', () => {
  const m = buildCidrMatcher(['10.0.0.0/8', '192.168.0.0/16', '8.8.8.8'])

  it('matches an address inside a range', () => {
    expect(m.match('10.1.2.3', 'ipv4')).toBe(true)
    expect(m.match('192.168.50.1', 'ipv4')).toBe(true)
  })

  it('matches the network and broadcast addresses', () => {
    expect(m.match('10.0.0.0', 'ipv4')).toBe(true)
    expect(m.match('10.255.255.255', 'ipv4')).toBe(true)
  })

  it('rejects addresses just outside a range', () => {
    expect(m.match('9.255.255.255', 'ipv4')).toBe(false)
    expect(m.match('11.0.0.0', 'ipv4')).toBe(false)
    expect(m.match('192.167.255.255', 'ipv4')).toBe(false)
    expect(m.match('192.169.0.0', 'ipv4')).toBe(false)
  })

  it('treats a bare IP entry as /32', () => {
    expect(m.match('8.8.8.8', 'ipv4')).toBe(true)
    expect(m.match('8.8.8.9', 'ipv4')).toBe(false)
    expect(m.match('8.8.8.7', 'ipv4')).toBe(false)
  })

  it('handles /32 and /0 explicitly', () => {
    expect(buildCidrMatcher(['1.2.3.4/32']).match('1.2.3.4', 'ipv4')).toBe(true)
    expect(buildCidrMatcher(['1.2.3.4/32']).match('1.2.3.5', 'ipv4')).toBe(false)
    const all = buildCidrMatcher(['0.0.0.0/0'])
    expect(all.match('0.0.0.0', 'ipv4')).toBe(true)
    expect(all.match('255.255.255.255', 'ipv4')).toBe(true)
  })

  it('handles addresses above 2^31 without sign errors', () => {
    const high = buildCidrMatcher(['200.0.0.0/8'])
    expect(high.match('200.1.2.3', 'ipv4')).toBe(true)
    expect(high.match('199.255.255.255', 'ipv4')).toBe(false)
  })

  it('merges adjacent and overlapping ranges without losing coverage', () => {
    const merged = buildCidrMatcher(['10.0.0.0/9', '10.128.0.0/9', '10.0.0.0/8'])
    expect(merged.match('10.0.0.0', 'ipv4')).toBe(true)
    expect(merged.match('10.127.255.255', 'ipv4')).toBe(true)
    expect(merged.match('10.128.0.0', 'ipv4')).toBe(true)
    expect(merged.match('10.255.255.255', 'ipv4')).toBe(true)
    expect(merged.match('11.0.0.0', 'ipv4')).toBe(false)
  })

  it('ignores unparseable entries instead of throwing', () => {
    const m2 = buildCidrMatcher(['garbage', '10.0.0.0/8', '999.0.0.0/8'])
    expect(m2.match('10.0.0.1', 'ipv4')).toBe(true)
    expect(m2.match('1.1.1.1', 'ipv4')).toBe(false)
  })

  it('returns false for an empty list', () => {
    expect(buildCidrMatcher([]).match('8.8.8.8', 'ipv4')).toBe(false)
  })
})

describe('buildCidrMatcher — IPv6', () => {
  const m = buildCidrMatcher(['2001:db8::/32', '::1/128', '2600:1f00::/24'])

  it('matches inside an IPv6 range', () => {
    expect(m.match('2001:db8::1', 'ipv6')).toBe(true)
    expect(m.match('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')).toBe(true)
  })

  it('rejects just outside an IPv6 range', () => {
    expect(m.match('2001:db9::1', 'ipv6')).toBe(false)
    expect(m.match('2001:db7:ffff::1', 'ipv6')).toBe(false)
  })

  it('handles /128 host routes', () => {
    expect(m.match('::1', 'ipv6')).toBe(true)
    expect(m.match('::2', 'ipv6')).toBe(false)
  })

  it('matches regardless of compressed or expanded input form', () => {
    expect(m.match('2001:0db8:0000:0000:0000:0000:0000:0001', 'ipv6')).toBe(true)
  })
})

describe('buildCidrMatcher — type routing', () => {
  const m = buildCidrMatcher(['10.0.0.0/8', '2001:db8::/32'])

  it('never matches domain or url indicators', () => {
    expect(m.match('example.com', 'domain')).toBe(false)
    expect(m.match('example.com', 'url')).toBe(false)
  })

  it('does not cross v4 and v6 families', () => {
    expect(m.match('2001:db8::1', 'ipv4')).toBe(false)
    expect(m.match('10.0.0.1', 'ipv6')).toBe(false)
  })
})
```

- [ ] **Step 6: Run test to verify it fails**

Run: `npx vitest run src/core/matchers/cidr.test.ts`
Expected: FAIL — cannot resolve `./cidr`.

- [ ] **Step 7: Write `src/core/matchers/cidr.ts`**

```ts
import { ipv4ToInt, ipv6ToBigInt } from '../ip'
import type { IndicatorType, Matcher } from '../types'

interface V6Range {
  start: bigint
  end: bigint
}

function parseV4Cidr(entry: string): [number, number] | null {
  const slash = entry.indexOf('/')
  const addr = slash === -1 ? entry : entry.slice(0, slash)
  const base = ipv4ToInt(addr)
  if (base === null) return null

  const prefix = slash === -1 ? 32 : Number(entry.slice(slash + 1))
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null

  // Avoid the undefined behaviour of << 32 in JS by special-casing /0.
  const size = prefix === 0 ? 4294967296 : 2 ** (32 - prefix)
  const start = Math.floor(base / size) * size
  return [start, start + size - 1]
}

function parseV6Cidr(entry: string): V6Range | null {
  const slash = entry.indexOf('/')
  const addr = slash === -1 ? entry : entry.slice(0, slash)
  const base = ipv6ToBigInt(addr)
  if (base === null) return null

  const prefix = slash === -1 ? 128 : Number(entry.slice(slash + 1))
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null

  const hostBits = BigInt(128 - prefix)
  const size = 1n << hostBits
  const start = (base >> hostBits) << hostBits
  return { start, end: start + size - 1n }
}

/** Sort by start, then merge overlapping or adjacent ranges. */
function mergeV4(ranges: Array<[number, number]>): Array<[number, number]> {
  ranges.sort((a, b) => a[0] - b[0])
  const out: Array<[number, number]> = []
  for (const r of ranges) {
    const last = out[out.length - 1]
    if (last && r[0] <= last[1] + 1) {
      if (r[1] > last[1]) last[1] = r[1]
    } else {
      out.push([r[0], r[1]])
    }
  }
  return out
}

function mergeV6(ranges: V6Range[]): V6Range[] {
  ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0))
  const out: V6Range[] = []
  for (const r of ranges) {
    const last = out[out.length - 1]
    if (last && r.start <= last.end + 1n) {
      if (r.end > last.end) last.end = r.end
    } else {
      out.push({ start: r.start, end: r.end })
    }
  }
  return out
}

export function buildCidrMatcher(entries: string[]): Matcher {
  const v4raw: Array<[number, number]> = []
  const v6raw: V6Range[] = []

  for (const entry of entries) {
    const e = entry.trim()
    if (!e) continue
    if (e.includes(':')) {
      const r = parseV6Cidr(e)
      if (r) v6raw.push(r)
    } else {
      const r = parseV4Cidr(e)
      if (r) v4raw.push(r)
    }
  }

  const v4 = mergeV4(v4raw)
  const v6 = mergeV6(v6raw)

  // Flatten IPv4 into a typed array: [start0, end0, start1, end1, ...].
  const v4flat = new Uint32Array(v4.length * 2)
  for (let i = 0; i < v4.length; i++) {
    v4flat[i * 2] = v4[i]![0]
    v4flat[i * 2 + 1] = v4[i]![1]
  }

  function containsV4(n: number): boolean {
    let lo = 0
    let hi = v4.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const start = v4flat[mid * 2]!
      const end = v4flat[mid * 2 + 1]!
      if (n < start) hi = mid - 1
      else if (n > end) lo = mid + 1
      else return true
    }
    return false
  }

  function containsV6(n: bigint): boolean {
    let lo = 0
    let hi = v6.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const r = v6[mid]!
      if (n < r.start) hi = mid - 1
      else if (n > r.end) lo = mid + 1
      else return true
    }
    return false
  }

  return {
    match(normalized: string, type: IndicatorType): boolean {
      if (type === 'ipv4') {
        if (v4.length === 0) return false
        const n = ipv4ToInt(normalized)
        return n === null ? false : containsV4(n)
      }
      if (type === 'ipv6') {
        if (v6.length === 0) return false
        const n = ipv6ToBigInt(normalized)
        return n === null ? false : containsV6(n)
      }
      return false
    },
  }
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `npx vitest run src/core/matchers/cidr.test.ts`
Expected: PASS, all tests.

- [ ] **Step 9: Commit**

```bash
git add src/core/ip.ts src/core/ip.test.ts src/core/matchers/cidr.ts src/core/matchers/cidr.test.ts
git commit -m "feat: add IPv4/IPv6 primitives and binary-search CIDR matcher"
```

---

### Task 5: String, hostname, substring and regex matchers

**Files:**
- Create: `src/core/matchers/simple.ts`
- Create: `src/core/matchers/index.ts`
- Test: `src/core/matchers/simple.test.ts`

**Interfaces:**
- Consumes: `Matcher`, `IndicatorType`, `ListType` from `../types`; `buildCidrMatcher` from `./cidr`.
- Produces: `buildStringMatcher`, `buildHostnameMatcher`, `buildSubstringMatcher`, `buildRegexMatcher` from `simple.ts`; `buildMatcher(type: ListType, entries: string[]): Matcher` from `index.ts`.

- [ ] **Step 1: Write the failing test**

The hostname suffix cases are the important ones — `endsWith(entry)` without the dot guard is the classic bug that would let `evilexample.com` match `example.com`.

```ts
// src/core/matchers/simple.test.ts
import { describe, it, expect } from 'vitest'
import {
  buildStringMatcher,
  buildHostnameMatcher,
  buildSubstringMatcher,
  buildRegexMatcher,
} from './simple'
import { buildMatcher } from './index'

describe('buildStringMatcher', () => {
  const m = buildStringMatcher(['example.com', 'Test.COM'])

  it('matches exactly, case-insensitively', () => {
    expect(m.match('example.com', 'domain')).toBe(true)
    expect(m.match('test.com', 'domain')).toBe(true)
  })

  it('does not match subdomains', () => {
    expect(m.match('a.example.com', 'domain')).toBe(false)
  })

  it('does not match superstrings', () => {
    expect(m.match('notexample.com', 'domain')).toBe(false)
  })
})

describe('buildHostnameMatcher', () => {
  const m = buildHostnameMatcher(['example.com', 'co.uk'])

  it('matches the exact entry', () => {
    expect(m.match('example.com', 'domain')).toBe(true)
  })

  it('matches subdomains at any depth', () => {
    expect(m.match('a.example.com', 'domain')).toBe(true)
    expect(m.match('a.b.c.example.com', 'domain')).toBe(true)
  })

  it('does NOT match a domain that merely ends with the entry text', () => {
    expect(m.match('evilexample.com', 'domain')).toBe(false)
    expect(m.match('notexample.com', 'domain')).toBe(false)
    expect(m.match('xco.uk', 'domain')).toBe(false)
  })

  it('does not match a parent of the entry', () => {
    expect(m.match('com', 'domain')).toBe(false)
  })

  // Entries come from upstream and are not guaranteed lowercase, so the
  // matcher lowercases them at build time. The indicator is NOT lowercased
  // here: parse.ts guarantees `normalized` is already lowercase, and
  // re-normalizing on every call would be waste on a hot path.
  it('lowercases its entries at build time', () => {
    const u = buildHostnameMatcher(['EXAMPLE.com'])
    expect(u.match('a.example.com', 'domain')).toBe(true)
  })

  it('never matches IP indicators', () => {
    expect(m.match('8.8.8.8', 'ipv4')).toBe(false)
  })
})

describe('buildSubstringMatcher', () => {
  const m = buildSubstringMatcher(['sandbox', 'malware-analysis'])

  it('matches when the entry appears anywhere', () => {
    expect(m.match('my-sandbox.example.com', 'domain')).toBe(true)
    expect(m.match('a.malware-analysis.net', 'domain')).toBe(true)
  })

  it('does not match when absent', () => {
    expect(m.match('example.com', 'domain')).toBe(false)
  })

  it('lowercases its entries at build time', () => {
    const s = buildSubstringMatcher(['SANDBOX'])
    expect(s.match('my-sandbox.example.com', 'domain')).toBe(true)
  })
})

describe('buildRegexMatcher', () => {
  const m = buildRegexMatcher(['^abuse@', '^postmaster@'])

  it('matches a compiled pattern', () => {
    expect(m.match('abuse@example.com', 'domain')).toBe(true)
  })

  it('does not match a non-matching value', () => {
    expect(m.match('sales@example.com', 'domain')).toBe(false)
  })

  it('ignores invalid patterns instead of throwing', () => {
    const bad = buildRegexMatcher(['([unclosed', 'ok'])
    expect(bad.match('ok', 'domain')).toBe(true)
    expect(bad.match('nope', 'domain')).toBe(false)
  })
})

describe('buildMatcher factory', () => {
  it('routes each list type to the right implementation', () => {
    expect(buildMatcher('cidr', ['10.0.0.0/8']).match('10.0.0.1', 'ipv4')).toBe(true)
    expect(buildMatcher('string', ['a.com']).match('a.com', 'domain')).toBe(true)
    expect(buildMatcher('hostname', ['a.com']).match('x.a.com', 'domain')).toBe(true)
    expect(buildMatcher('substring', ['abc']).match('xabcx.com', 'domain')).toBe(true)
    expect(buildMatcher('regex', ['^z']).match('z.com', 'domain')).toBe(true)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/matchers/simple.test.ts`
Expected: FAIL — cannot resolve `./simple`.

- [ ] **Step 3: Write `src/core/matchers/simple.ts`**

```ts
import type { IndicatorType, Matcher } from '../types'

function isHostLike(type: IndicatorType): boolean {
  return type === 'domain' || type === 'url'
}

export function buildStringMatcher(entries: string[]): Matcher {
  const set = new Set(entries.map((e) => e.trim().toLowerCase()).filter(Boolean))
  return {
    match(normalized: string): boolean {
      return set.has(normalized)
    },
  }
}

/**
 * Matches the entry itself or any subdomain of it. Probes each parent suffix
 * rather than using endsWith, so "evilexample.com" cannot match "example.com".
 */
export function buildHostnameMatcher(entries: string[]): Matcher {
  const set = new Set(entries.map((e) => e.trim().toLowerCase()).filter(Boolean))
  return {
    match(normalized: string, type: IndicatorType): boolean {
      if (!isHostLike(type)) return false
      if (set.has(normalized)) return true
      let idx = normalized.indexOf('.')
      while (idx !== -1) {
        if (set.has(normalized.slice(idx + 1))) return true
        idx = normalized.indexOf('.', idx + 1)
      }
      return false
    },
  }
}

export function buildSubstringMatcher(entries: string[]): Matcher {
  const list = entries.map((e) => e.trim().toLowerCase()).filter(Boolean)
  return {
    match(normalized: string): boolean {
      for (const e of list) {
        if (normalized.includes(e)) return true
      }
      return false
    },
  }
}

export function buildRegexMatcher(entries: string[]): Matcher {
  const patterns: RegExp[] = []
  for (const e of entries) {
    const src = e.trim()
    if (!src) continue
    try {
      patterns.push(new RegExp(src, 'i'))
    } catch {
      // Upstream pattern does not compile in JS — skip it rather than fail the list.
    }
  }
  return {
    match(normalized: string): boolean {
      for (const p of patterns) {
        if (p.test(normalized)) return true
      }
      return false
    },
  }
}
```

- [ ] **Step 4: Write `src/core/matchers/index.ts`**

```ts
import type { ListType, Matcher } from '../types'
import { buildCidrMatcher } from './cidr'
import {
  buildHostnameMatcher,
  buildRegexMatcher,
  buildStringMatcher,
  buildSubstringMatcher,
} from './simple'

export function buildMatcher(type: ListType, entries: string[]): Matcher {
  switch (type) {
    case 'cidr':
      return buildCidrMatcher(entries)
    case 'string':
      return buildStringMatcher(entries)
    case 'hostname':
      return buildHostnameMatcher(entries)
    case 'substring':
      return buildSubstringMatcher(entries)
    case 'regex':
      return buildRegexMatcher(entries)
  }
}

export { buildCidrMatcher } from './cidr'
export * from './simple'
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/core/matchers/`
Expected: PASS, all cidr and simple tests.

- [ ] **Step 6: Commit**

```bash
git add src/core/matchers/simple.ts src/core/matchers/simple.test.ts src/core/matchers/index.ts
git commit -m "feat: add string, hostname, substring and regex matchers plus factory"
```

---

### Task 6: Applicability filter

**Files:**
- Create: `src/core/applicability.ts`
- Test: `src/core/applicability.test.ts`

**Interfaces:**
- Consumes: `CatalogEntry`, `IndicatorType` from `./types`.
- Produces: `appliesTo(entry: CatalogEntry, type: IndicatorType): boolean`, `IP_ATTRS: Set<string>`, `HOST_ATTRS: Set<string>`.

Rationale: consulting all 123 lists for every indicator is both slower and wrong. Upstream `matching_attributes` says which MISP attribute types a list is for. The observed vocabulary across all lists is: `domain|ip` (105), `ip-src` (74), `ip-dst` (74), `ip-src|port` (70), `ip-dst|port` (70), `hostname` (38), `domain` (38), `url` (27), `uri` (6), plus hash, email, phone and `azure-application-id` attributes.

`domain|ip` is ambiguous on its own — it appears on 105 of the 123 lists, on both CIDR and hostname lists, because it is a composite attribute whose two halves belong to different indicator families. It must therefore be disambiguated by the list's `type` in **both** directions: it counts toward IP applicability only when the list is `cidr`, and toward host applicability only when it is not. Counting it unconditionally on the IP side would route all 105 lists to every IPv4 indicator instead of the correct 74.

- [ ] **Step 1: Write the failing test**

```ts
// src/core/applicability.test.ts
import { describe, it, expect } from 'vitest'
import { appliesTo } from './applicability'
import type { CatalogEntry } from './types'

function entry(over: Partial<CatalogEntry>): CatalogEntry {
  return {
    name: 'x', title: 'X', description: '', type: 'string',
    matchingAttributes: [], tier: 'neutral', loadTier: 'core', bytes: 0,
    ...over,
  }
}

describe('appliesTo', () => {
  const cidrList = entry({
    name: 'rfc1918', type: 'cidr',
    matchingAttributes: ['ip-src', 'ip-dst', 'domain|ip', 'ip-dst|port', 'ip-src|port'],
  })
  const hostnameList = entry({
    name: 'url-shortener', type: 'hostname',
    matchingAttributes: ['domain', 'hostname', 'domain|ip', 'url', 'uri'],
  })
  const hashList = entry({
    name: 'empty-hashes', type: 'string',
    matchingAttributes: ['md5', 'sha1', 'sha256', 'filename|md5'],
  })
  const emailRegexList = entry({
    name: 'common-contact-emails', type: 'regex',
    matchingAttributes: ['email-src', 'email-dst', 'target-email'],
  })
  const phoneRegexList = entry({
    name: 'phone_numbers', type: 'regex',
    matchingAttributes: ['phone-number', 'whois-registrant-phone'],
  })

  it('sends IP indicators to CIDR lists only', () => {
    expect(appliesTo(cidrList, 'ipv4')).toBe(true)
    expect(appliesTo(cidrList, 'ipv6')).toBe(true)
    expect(appliesTo(hostnameList, 'ipv4')).toBe(false)
    expect(appliesTo(hostnameList, 'ipv6')).toBe(false)
  })

  it('sends domain and url indicators to host lists only', () => {
    expect(appliesTo(hostnameList, 'domain')).toBe(true)
    expect(appliesTo(hostnameList, 'url')).toBe(true)
    expect(appliesTo(cidrList, 'domain')).toBe(false)
    expect(appliesTo(cidrList, 'url')).toBe(false)
  })

  it('excludes hash lists from every in-scope indicator type', () => {
    for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
      expect(appliesTo(hashList, t)).toBe(false)
    }
  })

  it('excludes email and phone regex lists from every in-scope type', () => {
    for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
      expect(appliesTo(emailRegexList, t)).toBe(false)
      expect(appliesTo(phoneRegexList, t)).toBe(false)
    }
  })

  it('applies a non-cidr list of IPs to IP indicators', () => {
    const stringIps = entry({
      name: 'some-ip-strings', type: 'string',
      matchingAttributes: ['ip-src', 'ip-dst'],
    })
    expect(appliesTo(stringIps, 'ipv4')).toBe(true)
    expect(appliesTo(stringIps, 'domain')).toBe(false)
  })

  it('never applies anything to unparseable indicators', () => {
    expect(appliesTo(cidrList, 'unparseable')).toBe(false)
    expect(appliesTo(hostnameList, 'unparseable')).toBe(false)
  })

  it('disambiguates the domain|ip composite attribute by list type', () => {
    // domain|ip appears on 105 of 123 lists and covers both families at once,
    // so on its own it must never pull a list into the wrong family.
    const cidrComposite = entry({ type: 'cidr', matchingAttributes: ['domain|ip'] })
    const hostComposite = entry({ type: 'hostname', matchingAttributes: ['domain|ip'] })

    expect(appliesTo(cidrComposite, 'ipv4')).toBe(true)
    expect(appliesTo(cidrComposite, 'domain')).toBe(false)

    expect(appliesTo(hostComposite, 'domain')).toBe(true)
    expect(appliesTo(hostComposite, 'ipv4')).toBe(false)
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/applicability.test.ts`
Expected: FAIL — cannot resolve `./applicability`.

- [ ] **Step 3: Write `src/core/applicability.ts`**

```ts
import type { CatalogEntry, IndicatorType } from './types'

/**
 * Attributes that unambiguously mean "this list is about IP addresses".
 * `domain|ip` is deliberately absent — see COMPOSITE below.
 */
export const IP_ATTRS = new Set([
  'ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port',
])

/** Attributes that unambiguously mean "this list is about hostnames". */
export const HOST_ATTRS = new Set([
  'hostname', 'domain', 'hostname|port', 'url', 'uri',
])

/**
 * A composite attribute covering both families at once. It appears on 105 of
 * 123 lists, so it carries almost no signal on its own and must be
 * disambiguated by the list's own type in both directions.
 */
const COMPOSITE = 'domain|ip'

function intersects(attrs: string[], set: Set<string>): boolean {
  for (const a of attrs) {
    if (set.has(a)) return true
  }
  return false
}

export function appliesTo(entry: CatalogEntry, type: IndicatorType): boolean {
  if (type === 'unparseable') return false

  const composite = entry.matchingAttributes.includes(COMPOSITE)

  if (type === 'ipv4' || type === 'ipv6') {
    if (intersects(entry.matchingAttributes, IP_ATTRS)) return true
    return composite && entry.type === 'cidr'
  }

  // domain | url
  if (entry.type === 'cidr') return false
  if (intersects(entry.matchingAttributes, HOST_ATTRS)) return true
  return composite
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/applicability.test.ts`
Expected: PASS, 6 tests.

- [ ] **Step 5: Add a test that pins the filter against the real catalog**

Append to `src/core/applicability.test.ts`:

```ts
import catalog from '../catalog.json'

describe('appliesTo against the real catalog', () => {
  const entries = catalog as CatalogEntry[]

  it('routes IPv4 to roughly the CIDR list population', () => {
    const n = entries.filter((e) => appliesTo(e, 'ipv4')).length
    expect(n).toBeGreaterThanOrEqual(70)
    expect(n).toBeLessThanOrEqual(80)
  })

  it('never routes an IP indicator to a hostname-typed list', () => {
    for (const e of entries) {
      if (e.type === 'hostname' && appliesTo(e, 'ipv4')) {
        throw new Error(`hostname list ${e.name} incorrectly applies to ipv4`)
      }
    }
  })

  it('never routes a domain indicator to a cidr-typed list', () => {
    for (const e of entries) {
      if (e.type === 'cidr' && appliesTo(e, 'domain')) {
        throw new Error(`cidr list ${e.name} incorrectly applies to domain`)
      }
    }
  })

  it('excludes both regex lists from all in-scope types', () => {
    for (const e of entries.filter((x) => x.type === 'regex')) {
      for (const t of ['ipv4', 'ipv6', 'domain', 'url'] as const) {
        expect(appliesTo(e, t)).toBe(false)
      }
    }
  })
})
```

Note: the `hostname` list type never carries IP attributes upstream, but the second test guards the invariant in case that changes.

- [ ] **Step 6: Run the test**

Run: `npx vitest run src/core/applicability.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 7: Commit**

```bash
git add src/core/applicability.ts src/core/applicability.test.ts
git commit -m "feat: route indicators to applicable lists via upstream matching_attributes"
```

---

### Task 7: List store — IndexedDB cache with decay

**Files:**
- Create: `src/core/listStore.ts`
- Test: `src/core/listStore.test.ts`

**Interfaces:**
- Consumes: `CatalogEntry`, `LoadTier` from `./types`.
- Produces:
  `interface CachedList { name: string; entries: string[]; version: number; fetchedAt: number }`,
  `interface StoreDeps { fetch: typeof fetch; idb: IDBFactory; now: () => number }`,
  `createListStore(deps: StoreDeps): ListStore`, where
  `ListStore = { load(entries: CatalogEntry[], onProgress?: (done: number, total: number) => void): Promise<LoadResult> }`,
  `interface LoadResult { lists: Map<string, CachedList>; failed: string[]; oldestFetchedAt: number | null }`,
  and the exported constants `FRESH_MS` (24h) and `STALE_MS` (7d).

- [ ] **Step 1: Write the failing test**

```ts
// src/core/listStore.test.ts
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
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/listStore.test.ts`
Expected: FAIL — cannot resolve `./listStore`.

- [ ] **Step 3: Write `src/core/listStore.ts`**

```ts
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

async function readCached(db: IDBDatabase | null, name: string): Promise<CachedList | null> {
  if (!db) return null
  try {
    const tx = db.transaction(STORE, 'readonly')
    const got = await promisify(tx.objectStore(STORE).get(name) as IDBRequest<CachedList>)
    return got ?? null
  } catch {
    return null
  }
}

async function writeCached(db: IDBDatabase | null, value: CachedList): Promise<void> {
  if (!db) return
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
    const cached = await readCached(db, entry.name)
    const age = cached ? now() - cached.fetchedAt : Infinity

    if (cached && age < FRESH_MS) return cached

    if (cached && age < STALE_MS) {
      // Stale-while-revalidate: return now, refresh in the background.
      void fetchList(entry.name)
        .then((fresh) => writeCached(db, fresh))
        .catch(() => undefined)
      return cached
    }

    try {
      const fresh = await fetchList(entry.name)
      await writeCached(db, fresh)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/listStore.test.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add src/core/listStore.ts src/core/listStore.test.ts
git commit -m "feat: add IndexedDB list cache with age-based decay and stale fallback"
```

---

### Task 8: Match engine and coverage accounting

**Files:**
- Create: `src/core/engine.ts`
- Test: `src/core/engine.test.ts`

**Interfaces:**
- Consumes: `parseInput` from `./parse`, `buildMatcher` from `./matchers`, `appliesTo` from `./applicability`, `CachedList` from `./listStore`, and the types from `./types`.
- Produces: `createEngine(catalog: CatalogEntry[]): Engine`, where
  `Engine = { ingest(lists: Map<string, CachedList>): void; run(raw: string, coverage: Coverage): MatchReport }`.
  Also `coverageLabel(c: Coverage): string` — the single place the "clean" vs "no hits (N/M)" rule lives.

- [ ] **Step 1: Write the failing test**

```ts
// src/core/engine.test.ts
import { describe, it, expect } from 'vitest'
import { createEngine, coverageLabel } from './engine'
import type { CachedList } from './listStore'
import type { CatalogEntry, Coverage } from './types'

function cat(over: Partial<CatalogEntry>): CatalogEntry {
  return {
    name: 'x', title: 'X', description: 'desc', type: 'cidr',
    matchingAttributes: ['ip-src'], tier: 'neutral', loadTier: 'core', bytes: 0,
    ...over,
  }
}

function cached(name: string, entries: string[]): CachedList {
  return { name, entries, version: 7, fetchedAt: 1000 }
}

const CATALOG: CatalogEntry[] = [
  cat({ name: 'cloudflare', title: 'Cloudflare ranges', type: 'cidr',
        matchingAttributes: ['ip-src', 'ip-dst'], tier: 'infrastructure' }),
  cat({ name: 'rfc1918', title: 'RFC1918', type: 'cidr',
        matchingAttributes: ['ip-src', 'ip-dst'], tier: 'known-fp' }),
  cat({ name: 'tranco', title: 'Tranco 1M', type: 'hostname',
        matchingAttributes: ['domain', 'hostname'], tier: 'popularity', loadTier: 'heavy' }),
  cat({ name: 'dynamic-dns', title: 'Dynamic DNS', type: 'hostname',
        matchingAttributes: ['domain', 'hostname'], tier: 'context' }),
]

const FULL: Coverage = {
  loaded: 4, total: 4, failed: [], heavyLoaded: true, oldestFetchedAt: 1000,
}

function engineWith(lists: Array<[string, string[]]>) {
  const e = createEngine(CATALOG)
  e.ingest(new Map(lists.map(([n, v]) => [n, cached(n, v)])))
  return e
}

describe('engine.run', () => {
  it('reports hits with tier, title, description and version', () => {
    const e = engineWith([['rfc1918', ['10.0.0.0/8']]])
    const rep = e.run('10.1.2.3', FULL)

    expect(rep.results).toHaveLength(1)
    const hits = rep.results[0]!.hits
    expect(hits).toHaveLength(1)
    expect(hits[0]).toEqual({
      list: 'rfc1918', title: 'RFC1918', description: 'desc',
      tier: 'known-fp', version: 7,
    })
  })

  it('records every matching list, not just the strongest', () => {
    const e = engineWith([
      ['cloudflare', ['1.1.1.0/24']],
      ['rfc1918', ['1.1.1.0/24']],
    ])
    const rep = e.run('1.1.1.1', FULL)
    expect(rep.results[0]!.hits.map((h) => h.list).sort()).toEqual(['cloudflare', 'rfc1918'])
  })

  it('returns an empty hits array for an indicator that matches nothing', () => {
    const e = engineWith([['rfc1918', ['10.0.0.0/8']]])
    const rep = e.run('8.8.8.8', FULL)
    expect(rep.results[0]!.hits).toEqual([])
  })

  it('does not consult lists that failed to load', () => {
    const e = engineWith([])
    const rep = e.run('10.1.2.3', FULL)
    expect(rep.results[0]!.hits).toEqual([])
  })

  it('applies the applicability filter — a domain never hits a cidr list', () => {
    const e = engineWith([
      ['rfc1918', ['10.0.0.0/8']],
      ['dynamic-dns', ['no-ip.com']],
    ])
    const rep = e.run('sub.no-ip.com', FULL)
    expect(rep.results[0]!.hits.map((h) => h.list)).toEqual(['dynamic-dns'])
  })

  it('passes unparseable lines through to the report', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8\nd41d8cd98f00b204e9800998ecf8427e', FULL)
    expect(rep.unparseable).toEqual(['d41d8cd98f00b204e9800998ecf8427e'])
  })

  it('preserves input order and dedupe', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8\n1.1.1.1\n8.8.8.8', FULL)
    expect(rep.results.map((r) => r.normalized)).toEqual(['8.8.8.8', '1.1.1.1'])
  })

  it('carries coverage through to the report', () => {
    const e = engineWith([])
    const rep = e.run('8.8.8.8', FULL)
    expect(rep.coverage).toEqual(FULL)
  })
})

describe('coverageLabel', () => {
  it('says clean only when every in-scope list loaded', () => {
    expect(coverageLabel({ loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: 1 }))
      .toBe('clean')
  })

  it('refuses to say clean when any list failed', () => {
    expect(coverageLabel({ loaded: 120, total: 121, failed: ['rfc1918'], heavyLoaded: false, oldestFetchedAt: 1 }))
      .toBe('no hits (120/121 lists)')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/core/engine.test.ts`
Expected: FAIL — cannot resolve `./engine`.

- [ ] **Step 3: Write `src/core/engine.ts`**

```ts
import { appliesTo } from './applicability'
import type { CachedList } from './listStore'
import { buildMatcher } from './matchers'
import { parseInput } from './parse'
import type {
  CatalogEntry, Coverage, Hit, IndicatorResult, MatchReport, Matcher,
} from './types'

interface Compiled {
  entry: CatalogEntry
  matcher: Matcher
  version: number
}

export interface Engine {
  /** Compile the loaded list bodies into matchers. Call once per load. */
  ingest(lists: Map<string, CachedList>): void
  run(raw: string, coverage: Coverage): MatchReport
}

/**
 * The single place the "clean" rule lives: the word is reserved for full
 * coverage, because a false clean verdict is the worst output this tool can
 * produce.
 */
export function coverageLabel(c: Coverage): string {
  if (c.failed.length === 0 && c.loaded === c.total) return 'clean'
  return `no hits (${c.loaded}/${c.total} lists)`
}

export function createEngine(catalog: CatalogEntry[]): Engine {
  const byName = new Map(catalog.map((e) => [e.name, e]))
  let compiled: Compiled[] = []

  return {
    ingest(lists) {
      const next: Compiled[] = []
      for (const [name, cached] of lists) {
        const entry = byName.get(name)
        if (!entry) continue
        next.push({
          entry,
          matcher: buildMatcher(entry.type, cached.entries),
          version: cached.version,
        })
      }
      compiled = next
    },

    run(raw, coverage) {
      const { indicators, unparseable } = parseInput(raw)

      const results: IndicatorResult[] = indicators.map((ind) => {
        const hits: Hit[] = []
        for (const c of compiled) {
          if (!appliesTo(c.entry, ind.type)) continue
          if (!c.matcher.match(ind.normalized, ind.type)) continue
          hits.push({
            list: c.entry.name,
            title: c.entry.title,
            description: c.entry.description,
            tier: c.entry.tier,
            version: c.version,
          })
        }
        return {
          original: ind.original,
          normalized: ind.normalized,
          type: ind.type,
          hits,
        }
      })

      return { results, unparseable, coverage }
    },
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/core/engine.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 5: Add a performance guard test**

Append to `src/core/engine.test.ts`. This pins the spec's 10,000-indicator target so a future change to the matchers cannot silently regress it.

```ts
describe('engine performance', () => {
  it('matches 10,000 IPs against 74 CIDR lists in under 2 seconds', () => {
    const bigCatalog: CatalogEntry[] = Array.from({ length: 74 }, (_, i) =>
      cat({ name: `list${i}`, type: 'cidr', matchingAttributes: ['ip-src'] }),
    )
    const engine = createEngine(bigCatalog)

    // 1,000 ranges per list, non-overlapping.
    const lists = new Map<string, CachedList>()
    for (let i = 0; i < 74; i++) {
      const entries = Array.from({ length: 1000 }, (_, j) => `${(j % 200) + 10}.${i}.${j % 256}.0/24`)
      lists.set(`list${i}`, cached(`list${i}`, entries))
    }
    engine.ingest(lists)

    const input = Array.from({ length: 10_000 }, (_, i) =>
      `${(i % 200) + 10}.${i % 74}.${i % 256}.${i % 254}`,
    ).join('\n')

    const cov: Coverage = { loaded: 74, total: 74, failed: [], heavyLoaded: false, oldestFetchedAt: 1 }
    const t0 = performance.now()
    const rep = engine.run(input, cov)
    const elapsed = performance.now() - t0

    expect(rep.results.length).toBeGreaterThan(0)
    expect(elapsed).toBeLessThan(2000)
  })
})
```

- [ ] **Step 6: Run the test**

Run: `npx vitest run src/core/engine.test.ts`
Expected: PASS, 11 tests. If the performance test fails, do not raise the threshold — investigate the matcher.

- [ ] **Step 7: Commit**

```bash
git add src/core/engine.ts src/core/engine.test.ts
git commit -m "feat: add match engine with coverage-aware clean labeling"
```

---

### Task 9: Web Worker and message protocol

**Files:**
- Create: `src/worker.ts`
- Create: `src/workerProtocol.ts`
- Create: `src/ui/workerClient.ts`
- Test: `src/workerProtocol.test.ts`

**Interfaces:**
- Consumes: everything from `src/core/`.
- Produces:
  `type WorkerRequest = { id: number; kind: 'load'; heavy: boolean } | { id: number; kind: 'match'; raw: string }`;
  `type WorkerResponse = { id: number; kind: 'progress'; done: number; total: number } | { id: number; kind: 'loaded'; coverage: Coverage } | { id: number; kind: 'report'; report: MatchReport } | { id: number; kind: 'error'; message: string }`;
  `createWorkerClient(worker: Worker): WorkerClient` with
  `WorkerClient = { load(heavy: boolean, onProgress: (d: number, t: number) => void): Promise<Coverage>; match(raw: string): Promise<MatchReport> }`.

- [ ] **Step 1: Write the failing test**

The protocol module is pure, so it is testable without spinning up a real Worker. `createWorkerClient` is tested against a fake that implements the two methods it uses.

```ts
// src/workerProtocol.test.ts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/workerProtocol.test.ts`
Expected: FAIL — cannot resolve `./ui/workerClient`.

- [ ] **Step 3: Write `src/workerProtocol.ts`**

```ts
import type { Coverage, MatchReport } from './core/types'

export type WorkerRequest =
  | { id: number; kind: 'load'; heavy: boolean }
  | { id: number; kind: 'match'; raw: string }

export type WorkerResponse =
  | { id: number; kind: 'progress'; done: number; total: number }
  | { id: number; kind: 'loaded'; coverage: Coverage }
  | { id: number; kind: 'report'; report: MatchReport }
  | { id: number; kind: 'error'; message: string }
```

- [ ] **Step 4: Write `src/ui/workerClient.ts`**

```ts
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

  function send<T>(req: Omit<WorkerRequest, 'id'>, onProgress?: Pending['onProgress']): Promise<T> {
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/workerProtocol.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 6: Write `src/worker.ts`**

```ts
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
```

- [ ] **Step 7: Verify it type-checks**

Run: `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
git add src/worker.ts src/workerProtocol.ts src/ui/workerClient.ts src/workerProtocol.test.ts
git commit -m "feat: add web worker and typed request/response protocol"
```

---

### Task 10: Result rendering and coverage header

**Files:**
- Create: `src/ui/render.ts`
- Create: `src/style.css`
- Modify: `index.html`
- Test: `src/ui/render.test.ts`

**Interfaces:**
- Consumes: `MatchReport`, `IndicatorResult`, `Tier`, `Coverage` from `../core/types`; `coverageLabel` from `../core/engine`.
- Produces: `renderCoverage(c: Coverage): string`, `renderResults(report: MatchReport): string`, `TIER_META: Record<Tier, { label: string; caption: string; order: number }>`. All return HTML strings; the caller assigns to `innerHTML`.

Tier captions carry the spec's two warnings — popular does not mean safe, and context means look closer rather than dismiss.

- [ ] **Step 1: Write the failing test**

```ts
// src/ui/render.test.ts
import { describe, it, expect } from 'vitest'
import { renderCoverage, renderResults, TIER_META } from './render'
import type { Coverage, MatchReport } from '../core/types'

const FULL: Coverage = {
  loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: Date.now(),
}
const DEGRADED: Coverage = {
  loaded: 119, total: 121, failed: ['rfc1918', 'cloudflare'],
  heavyLoaded: false, oldestFetchedAt: Date.now(),
}

function report(over: Partial<MatchReport> = {}): MatchReport {
  return { results: [], unparseable: [], coverage: FULL, ...over }
}

describe('TIER_META', () => {
  it('warns that popular does not mean safe', () => {
    expect(TIER_META.popularity.caption.toLowerCase()).toContain('does not mean safe')
  })

  it('frames context hits as a reason to look closer', () => {
    expect(TIER_META.context.caption.toLowerCase()).toContain('look closer')
  })

  it('orders strong false-positive signals before informational ones', () => {
    expect(TIER_META['known-fp'].order).toBeLessThan(TIER_META.popularity.order)
    expect(TIER_META.infrastructure.order).toBeLessThan(TIER_META.popularity.order)
  })
})

describe('renderCoverage', () => {
  it('shows the loaded fraction', () => {
    expect(renderCoverage(FULL)).toContain('121/121')
  })

  it('names the failed lists when coverage is degraded', () => {
    const html = renderCoverage(DEGRADED)
    expect(html).toContain('119/121')
    expect(html).toContain('rfc1918')
    expect(html).toContain('cloudflare')
  })

  it('warns when the cache is stale', () => {
    const old = { ...FULL, oldestFetchedAt: Date.now() - 40 * 24 * 60 * 60 * 1000 }
    expect(renderCoverage(old)).toMatch(/40 days old|stale/i)
  })
})

describe('renderResults', () => {
  it('labels a zero-hit indicator clean at full coverage', () => {
    const html = renderResults(report({
      results: [{ original: '8.8.8.8', normalized: '8.8.8.8', type: 'ipv4', hits: [] }],
    }))
    expect(html).toContain('clean')
    expect(html).not.toContain('no hits (')
  })

  it('refuses to say clean when coverage is degraded', () => {
    const html = renderResults(report({
      coverage: DEGRADED,
      results: [{ original: '8.8.8.8', normalized: '8.8.8.8', type: 'ipv4', hits: [] }],
    }))
    expect(html).toContain('no hits (119/121 lists)')
    expect(html).not.toMatch(/>\s*clean\s*</)
  })

  it('renders every hit, grouped by tier', () => {
    const html = renderResults(report({
      results: [{
        original: '1.1.1.1', normalized: '1.1.1.1', type: 'ipv4',
        hits: [
          { list: 'cloudflare', title: 'CF', description: 'd', tier: 'infrastructure', version: 1 },
          { list: 'tranco', title: 'Tranco', description: 'd', tier: 'popularity', version: 2 },
        ],
      }],
    }))
    expect(html).toContain('cloudflare')
    expect(html).toContain('tranco')
    expect(html).toContain(TIER_META.infrastructure.label)
    expect(html).toContain(TIER_META.popularity.label)
  })

  it('escapes HTML in indicator text', () => {
    const html = renderResults(report({
      results: [{
        original: '<img src=x onerror=alert(1)>', normalized: 'x.com',
        type: 'domain', hits: [],
      }],
    }))
    expect(html).not.toContain('<img')
    expect(html).toContain('&lt;img')
  })

  it('lists unparseable input in its own section', () => {
    const html = renderResults(report({ unparseable: ['d41d8cd98f00b204e9800998ecf8427e'] }))
    expect(html).toMatch(/unparseable|not recognised/i)
    expect(html).toContain('d41d8cd98f00b204e9800998ecf8427e')
  })

  it('handles an empty report without crashing', () => {
    expect(() => renderResults(report())).not.toThrow()
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/ui/render.test.ts`
Expected: FAIL — cannot resolve `./render`.

- [ ] **Step 3: Write `src/ui/render.ts`**

```ts
import { coverageLabel } from '../core/engine'
import type { Coverage, IndicatorResult, MatchReport, Tier } from '../core/types'

export const TIER_META: Record<Tier, { label: string; caption: string; order: number }> = {
  'known-fp': {
    label: 'Known false positive',
    caption: 'Curated as a common false positive. Strong reason to deprioritise.',
    order: 0,
  },
  infrastructure: {
    label: 'Known infrastructure',
    caption: 'Belongs to a major cloud, CDN, or public resolver. Strong reason to deprioritise.',
    order: 1,
  },
  context: {
    label: 'Context — look closer',
    caption: 'Not a false-positive signal. This is a reason to look closer, not to dismiss.',
    order: 2,
  },
  popularity: {
    label: 'High-traffic site (informational)',
    caption: 'Ranked by traffic alone — popular does not mean safe. These lists can contain malicious infrastructure.',
    order: 3,
  },
  neutral: {
    label: 'Other',
    caption: 'Matched a list with no assigned category.',
    order: 4,
  },
}

const DAY_MS = 24 * 60 * 60 * 1000

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function renderCoverage(c: Coverage): string {
  const parts: string[] = [
    `<span class="cov-count">${c.loaded}/${c.total} lists loaded</span>`,
  ]

  if (c.failed.length > 0) {
    parts.push(
      `<span class="cov-warn">${c.failed.length} failed: ${esc(c.failed.join(', '))}</span>`,
    )
  }

  if (c.oldestFetchedAt !== null) {
    const days = Math.floor((Date.now() - c.oldestFetchedAt) / DAY_MS)
    if (days >= 7) {
      parts.push(`<span class="cov-warn">lists up to ${days} days old — refresh failed</span>`)
    }
  }

  if (!c.heavyLoaded) {
    parts.push('<span class="cov-note">popularity tier not loaded</span>')
  }

  return `<div class="coverage">${parts.join(' · ')}</div>`
}

function renderHits(r: IndicatorResult, coverage: Coverage): string {
  if (r.hits.length === 0) {
    const label = coverageLabel(coverage)
    const cls = label === 'clean' ? 'clean' : 'nohits'
    return `<span class="verdict ${cls}">${esc(label)}</span>`
  }

  const byTier = new Map<Tier, typeof r.hits>()
  for (const h of r.hits) {
    const bucket = byTier.get(h.tier) ?? []
    bucket.push(h)
    byTier.set(h.tier, bucket)
  }

  const groups = [...byTier.entries()].sort(
    (a, b) => TIER_META[a[0]].order - TIER_META[b[0]].order,
  )

  return groups
    .map(([tier, hits]) => {
      const meta = TIER_META[tier]
      const badges = hits
        .map(
          (h) =>
            `<li class="hit" title="${esc(h.description)}">` +
            `<code>${esc(h.list)}</code> <span class="hit-title">${esc(h.title)}</span></li>`,
        )
        .join('')
      return (
        `<div class="tier tier-${tier}">` +
        `<div class="tier-label">${esc(meta.label)}</div>` +
        `<div class="tier-caption">${esc(meta.caption)}</div>` +
        `<ul class="hits">${badges}</ul></div>`
      )
    })
    .join('')
}

export function renderResults(report: MatchReport): string {
  const rows = report.results
    .map(
      (r) =>
        `<tr><td class="ind"><code>${esc(r.original)}</code>` +
        `<span class="ind-type">${esc(r.type)}</span></td>` +
        `<td class="res">${renderHits(r, report.coverage)}</td></tr>`,
    )
    .join('')

  const table = report.results.length
    ? `<table class="results"><tbody>${rows}</tbody></table>`
    : '<p class="empty">No indicators parsed yet.</p>'

  const unparseable = report.unparseable.length
    ? `<section class="unparseable"><h3>Not recognised as an IP, domain or URL ` +
      `(${report.unparseable.length})</h3><ul>` +
      report.unparseable.map((u) => `<li><code>${esc(u)}</code></li>`).join('') +
      '</ul></section>'
    : ''

  return table + unparseable
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/ui/render.test.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Write `src/style.css`**

```css
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #5c6270; --line: #e3e6ec;
  --fp: #0a7c42; --fp-bg: #e8f6ee;
  --infra: #10559a; --infra-bg: #e8f0fa;
  --ctx: #a8590a; --ctx-bg: #fdf1e3;
  --pop: #5c6270; --pop-bg: #f1f2f5;
  --warn: #b3261e;
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e6e8ec; --muted: #9aa1b1; --line: #2a2f38;
    --fp-bg: #10291c; --infra-bg: #121f31; --ctx-bg: #2a1f10; --pop-bg: #1d2027;
  }
}

body { margin: 0; background: var(--bg); color: var(--fg); }
#app { max-width: 60rem; margin: 0 auto; padding: 1.5rem 1rem 4rem; }
h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
.sub { color: var(--muted); margin: 0 0 1rem; font-size: .875rem; }

textarea {
  width: 100%; min-height: 9rem; padding: .75rem; box-sizing: border-box;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8125rem;
  background: var(--bg); color: var(--fg);
  border: 1px solid var(--line); border-radius: .5rem; resize: vertical;
}

.toolbar { display: flex; flex-wrap: wrap; gap: .5rem; margin: .75rem 0; }
button {
  font: inherit; font-size: .8125rem; padding: .4rem .8rem; cursor: pointer;
  background: var(--bg); color: var(--fg);
  border: 1px solid var(--line); border-radius: .375rem;
}
button.primary { background: var(--fg); color: var(--bg); border-color: var(--fg); }
button:disabled { opacity: .5; cursor: default; }

.coverage { font-size: .75rem; color: var(--muted); margin: .5rem 0 1rem; }
.cov-warn { color: var(--warn); font-weight: 600; }

.results { width: 100%; border-collapse: collapse; }
.results td { border-top: 1px solid var(--line); padding: .6rem .4rem; vertical-align: top; }
.ind { width: 34%; }
.ind code { font-size: .8125rem; word-break: break-all; }
.ind-type { display: block; font-size: .6875rem; color: var(--muted); margin-top: .15rem; }

.verdict { font-size: .8125rem; font-weight: 600; }
.verdict.clean { color: var(--fp); }
.verdict.nohits { color: var(--muted); }

.tier { border-left: 3px solid; padding: .4rem .6rem; margin-bottom: .4rem; border-radius: .25rem; }
.tier-known-fp { border-color: var(--fp); background: var(--fp-bg); }
.tier-infrastructure { border-color: var(--infra); background: var(--infra-bg); }
.tier-context { border-color: var(--ctx); background: var(--ctx-bg); }
.tier-popularity { border-color: var(--pop); background: var(--pop-bg); }
.tier-neutral { border-color: var(--line); background: var(--pop-bg); }

.tier-label { font-size: .75rem; font-weight: 700; }
.tier-caption { font-size: .6875rem; color: var(--muted); margin: .1rem 0 .3rem; }
.hits { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: .3rem; }
.hit { font-size: .75rem; }
.hit code { background: var(--bg); padding: .05rem .3rem; border-radius: .2rem; }
.hit-title { color: var(--muted); }

.unparseable { margin-top: 1.5rem; }
.unparseable h3 { font-size: .8125rem; margin: 0 0 .4rem; }
.unparseable ul { margin: 0; padding-left: 1.1rem; font-size: .75rem; color: var(--muted); }
.empty { color: var(--muted); font-size: .875rem; }
```

- [ ] **Step 6: Update `index.html` to include the stylesheet**

Replace the `<head>` contents:

```html
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>MISP Warninglists Checker</title>
    <link rel="stylesheet" href="/src/style.css" />
  </head>
```

- [ ] **Step 7: Commit**

```bash
git add src/ui/render.ts src/ui/render.test.ts src/style.css index.html
git commit -m "feat: render tiered results with coverage-aware verdict labels"
```

---

### Task 11: Export

**Files:**
- Create: `src/ui/export.ts`
- Test: `src/ui/export.test.ts`

**Interfaces:**
- Consumes: `MatchReport`, `Coverage` from `../core/types`.
- Produces: `toTsv(r: MatchReport): string`, `toCsv(r: MatchReport): string`, `toJson(r: MatchReport): string`, `cleanOnly(r: MatchReport): string`, `download(filename: string, mime: string, content: string): void`.

Every export carries a header line with coverage and the oldest list age, for the same reason the UI does: an export that omits it can be read later as a full-coverage result.

- [ ] **Step 1: Write the failing test**

```ts
// src/ui/export.test.ts
import { describe, it, expect } from 'vitest'
import { toTsv, toCsv, toJson, cleanOnly } from './export'
import type { Coverage, MatchReport } from '../core/types'

const FULL: Coverage = {
  loaded: 121, total: 121, failed: [], heavyLoaded: false, oldestFetchedAt: 1000,
}
const DEGRADED: Coverage = {
  loaded: 119, total: 121, failed: ['rfc1918'], heavyLoaded: false, oldestFetchedAt: 1000,
}

const REPORT: MatchReport = {
  coverage: FULL,
  unparseable: ['junk'],
  results: [
    {
      original: '1.1.1.1', normalized: '1.1.1.1', type: 'ipv4',
      hits: [
        { list: 'cloudflare', title: 'CF', description: 'd', tier: 'infrastructure', version: 1 },
        { list: 'public-dns-v4', title: 'DNS', description: 'd', tier: 'infrastructure', version: 2 },
      ],
    },
    { original: '9.9.9.9', normalized: '9.9.9.9', type: 'ipv4', hits: [] },
    { original: 'evil.test', normalized: 'evil.test', type: 'domain', hits: [] },
  ],
}

describe('toTsv', () => {
  it('emits a coverage header comment', () => {
    expect(toTsv(REPORT).split('\n')[0]).toContain('121/121')
  })

  it('emits a tab-separated column header', () => {
    const header = toTsv(REPORT).split('\n')[1]!
    expect(header.split('\t')).toEqual(['indicator', 'type', 'verdict', 'lists', 'tiers'])
  })

  it('joins multiple list hits in one cell', () => {
    const row = toTsv(REPORT).split('\n').find((l) => l.startsWith('1.1.1.1'))!
    expect(row).toContain('cloudflare,public-dns-v4')
  })

  it('writes clean for zero hits at full coverage', () => {
    const row = toTsv(REPORT).split('\n').find((l) => l.startsWith('9.9.9.9'))!
    expect(row.split('\t')[2]).toBe('clean')
  })

  it('writes the degraded verdict when coverage is incomplete', () => {
    const row = toTsv({ ...REPORT, coverage: DEGRADED })
      .split('\n').find((l) => l.startsWith('9.9.9.9'))!
    expect(row.split('\t')[2]).toBe('no hits (119/121 lists)')
  })
})

describe('toCsv', () => {
  it('quotes fields containing commas', () => {
    const row = toCsv(REPORT).split('\n').find((l) => l.startsWith('1.1.1.1'))!
    expect(row).toContain('"cloudflare,public-dns-v4"')
  })

  it('escapes embedded double quotes by doubling them', () => {
    const r: MatchReport = {
      ...REPORT,
      results: [{ original: 'a"b.com', normalized: 'a"b.com', type: 'domain', hits: [] }],
    }
    expect(toCsv(r)).toContain('"a""b.com"')
  })
})

describe('toJson', () => {
  it('round-trips to an object carrying coverage and results', () => {
    const parsed = JSON.parse(toJson(REPORT))
    expect(parsed.coverage.loaded).toBe(121)
    expect(parsed.results).toHaveLength(3)
    expect(parsed.results[0].hits[0].list).toBe('cloudflare')
  })

  it('includes unparseable input', () => {
    expect(JSON.parse(toJson(REPORT)).unparseable).toEqual(['junk'])
  })
})

describe('cleanOnly', () => {
  it('returns only the indicators that hit nothing, one per line', () => {
    expect(cleanOnly(REPORT)).toBe('9.9.9.9\nevil.test')
  })

  it('returns an empty string when everything hit something', () => {
    expect(cleanOnly({ ...REPORT, results: [REPORT.results[0]!] })).toBe('')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/ui/export.test.ts`
Expected: FAIL — cannot resolve `./export`.

- [ ] **Step 3: Write `src/ui/export.ts`**

```ts
import { coverageLabel } from '../core/engine'
import type { Coverage, MatchReport } from '../core/types'

function header(c: Coverage): string {
  const age = c.oldestFetchedAt === null
    ? 'unknown'
    : new Date(c.oldestFetchedAt).toISOString()
  const failed = c.failed.length ? ` failed=${c.failed.join(',')}` : ''
  const heavy = c.heavyLoaded ? ' popularity-tier=loaded' : ' popularity-tier=not-loaded'
  return `# misp-warninglists-checker coverage=${c.loaded}/${c.total}${failed}${heavy} oldest-list=${age}`
}

function verdict(r: MatchReport['results'][number], c: Coverage): string {
  return r.hits.length === 0 ? coverageLabel(c) : `${r.hits.length} hit(s)`
}

export function toTsv(report: MatchReport): string {
  const lines = [header(report.coverage), ['indicator', 'type', 'verdict', 'lists', 'tiers'].join('\t')]
  for (const r of report.results) {
    lines.push([
      r.original,
      r.type,
      verdict(r, report.coverage),
      r.hits.map((h) => h.list).join(','),
      [...new Set(r.hits.map((h) => h.tier))].join(','),
    ].join('\t'))
  }
  return lines.join('\n')
}

function csvCell(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

export function toCsv(report: MatchReport): string {
  const lines = [header(report.coverage), ['indicator', 'type', 'verdict', 'lists', 'tiers'].join(',')]
  for (const r of report.results) {
    lines.push([
      r.original,
      r.type,
      verdict(r, report.coverage),
      r.hits.map((h) => h.list).join(','),
      [...new Set(r.hits.map((h) => h.tier))].join(','),
    ].map(csvCell).join(','))
  }
  return lines.join('\n')
}

export function toJson(report: MatchReport): string {
  return JSON.stringify(report, null, 2)
}

export function cleanOnly(report: MatchReport): string {
  return report.results
    .filter((r) => r.hits.length === 0)
    .map((r) => r.original)
    .join('\n')
}

export function download(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/ui/export.test.ts`
Expected: PASS, all tests.

- [ ] **Step 5: Commit**

```bash
git add src/ui/export.ts src/ui/export.test.ts
git commit -m "feat: add TSV, CSV, JSON and clean-only export"
```

---

### Task 12: App wiring, popularity opt-in, and deployment

**Files:**
- Create: `src/ui/app.ts`
- Modify: `src/main.ts`
- Create: `.github/workflows/deploy.yml`
- Create: `.github/workflows/catalog-drift.yml`
- Create: `README.md`

**Interfaces:**
- Consumes: `createWorkerClient` from `./workerClient`, `renderCoverage`/`renderResults` from `./render`, the export functions from `./export`, `CatalogEntry` from `../core/types`.
- Produces: `mountApp(root: HTMLElement, worker: Worker): void`.

- [ ] **Step 1: Write `src/ui/app.ts`**

```ts
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
    <button id="load-heavy">Load popularity lists (${Math.round(heavyBytes / 1e6)} MB)</button>
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
  let heavyLoaded = false

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
      coverageEl.innerHTML =
        `<div class="coverage"><span class="cov-warn">Could not load any lists: ` +
        `${(err as Error).message}. Checking is disabled until lists load.</span></div>`
      checkBtn.textContent = 'Lists unavailable'
      return
    }

    heavyLoaded = heavy
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
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') void runCheck()
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

  void loadLists(heavyLoaded)
}
```

- [ ] **Step 2: Replace `src/main.ts`**

```ts
import { mountApp } from './ui/app'

const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
mountApp(document.querySelector<HTMLDivElement>('#app')!, worker)
```

- [ ] **Step 3: Verify the whole suite and the build**

Run: `npm test && npm run build`
Expected: all tests pass, `tsc --noEmit` clean, `dist/` written.

- [ ] **Step 4: Manually verify in the browser**

Run: `npm run dev`

Check, in order:
1. The button shows loading progress, then reads "Check indicators".
2. Coverage reads `121/121 lists loaded · popularity tier not loaded`.
3. Paste `8.8.8.8`, `1.1.1.1`, `10.0.0.1`, `hxxps://evil[.]com/x`, `d41d8cd98f00b204e9800998ecf8427e` and press Check.
   - `8.8.8.8` and `1.1.1.1` hit infrastructure lists including `public-dns-v4`.
   - `10.0.0.1` hits `rfc1918` under "Known false positive".
   - `evil.test`-style domains with no hits read `clean`.
   - The hash appears under "Not recognised as an IP, domain or URL".
4. Click "Load popularity lists" — it loads, coverage becomes `123/123`, and the note disappears.
5. Reload the page: lists come from IndexedDB, so loading completes without network requests (confirm in DevTools Network).
6. Click each export button and confirm the coverage header line is present.

- [ ] **Step 5: Create `.github/workflows/deploy.yml`**

Every action is pinned to a full commit SHA rather than a moving tag, every
job starts with `harden-runner`, and permissions are granted per job rather
than globally — the build job never needs `pages: write`.

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main, master]
  workflow_dispatch:

# No workflow-level permissions block: each job declares its own minimum.
permissions: {}

concurrency:
  group: pages
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Harden the runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          # Start in audit so the first runs record real egress. Once the
          # Insights page shows a stable endpoint set, switch to `block` and
          # add an allowed-endpoints list.
          egress-policy: audit

      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0

      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '24'
          cache: npm

      - run: npm ci
      - run: npm test
      - run: npm run build

      - uses: actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b # v5.0.0
      - uses: actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa # v3.0.1
        with:
          path: dist

  deploy:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Harden the runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - id: deployment
        uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e # v4.0.5
```

- [ ] **Step 6: Create `.github/workflows/catalog-drift.yml`**

The catalog is app-owned, so something has to notice when upstream adds a list.

```yaml
name: Catalog drift check

on:
  schedule:
    - cron: '0 6 1 * *'
  workflow_dispatch:

permissions: {}

jobs:
  drift:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - name: Harden the runner
        uses: step-security/harden-runner@b09bb98e06d4d774595224525879c09bc6e98c40 # v2.20.1
        with:
          egress-policy: audit

      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: '24'
          cache: npm
      - run: npm ci

      - name: Compare upstream lists against catalog.json
        id: diff
        run: |
          curl -s "https://api.github.com/repos/MISP/misp-warninglists/git/trees/main?recursive=1" \
            | jq -r '.tree[] | select(.path | endswith("/list.json")) | .path | split("/")[1]' \
            | sort > /tmp/upstream.txt
          jq -r '.[].name' src/catalog.json | sort > /tmp/ours.txt
          # Hash lists are deliberately excluded from the catalog.
          printf 'windows-binary-hashes\nnioc-filehash\n' | sort > /tmp/excluded.txt
          comm -23 /tmp/upstream.txt /tmp/ours.txt | comm -23 - /tmp/excluded.txt > /tmp/missing.txt
          if [ -s /tmp/missing.txt ]; then
            echo "drift=true" >> "$GITHUB_OUTPUT"
            { echo 'body<<EOF'; \
              echo 'Upstream MISP has lists absent from `src/catalog.json`:'; echo; \
              sed 's/^/- /' /tmp/missing.txt; echo; \
              echo 'Run `npm run build:catalog`, review the assigned tiers, and commit.'; \
              echo EOF; } >> "$GITHUB_OUTPUT"
          else
            echo "drift=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Open an issue
        if: steps.diff.outputs.drift == 'true'
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7.1.0
        with:
          script: |
            const body = process.env.BODY
            const title = 'Catalog drift: upstream MISP added warninglists'
            const existing = await github.rest.issues.listForRepo({
              owner: context.repo.owner, repo: context.repo.repo,
              state: 'open', labels: 'catalog-drift',
            })
            if (existing.data.length > 0) {
              await github.rest.issues.createComment({
                owner: context.repo.owner, repo: context.repo.repo,
                issue_number: existing.data[0].number, body,
              })
            } else {
              await github.rest.issues.create({
                owner: context.repo.owner, repo: context.repo.repo,
                title, body, labels: ['catalog-drift'],
              })
            }
        env:
          BODY: ${{ steps.diff.outputs.body }}
```

- [ ] **Step 6b: Create `.github/dependabot.yml`**

Because every action is pinned to a SHA, Dependabot is what keeps those pins
moving — it bumps the SHA and rewrites the trailing `# v4` comment. Without it,
SHA pinning silently freezes the actions at today's versions forever.

```yaml
version: 2
updates:
  # Keeps the SHA-pinned actions above current. Dependabot rewrites both the
  # SHA and its trailing version comment.
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: monthly
    commit-message:
      prefix: 'chore(actions)'
    groups:
      actions:
        patterns: ['*']

  - package-ecosystem: npm
    directory: /
    schedule:
      interval: monthly
    commit-message:
      prefix: 'chore(deps)'
    groups:
      # This project has zero runtime dependencies, so every update is a
      # devDependency; one grouped PR per week rather than five.
      dev-dependencies:
        patterns: ['*']
```

- [ ] **Step 7: Create `README.md`**

```markdown
# MISP Warninglists Checker

Paste IPs, domains, or URLs and see which [MISP warninglists](https://github.com/MISP/misp-warninglists)
they hit — so likely false positives get filtered out before investigation starts.

Everything runs in the browser. Indicators you paste are never sent anywhere.

## How it works

- A shipped `src/catalog.json` describes the 123 in-scope upstream lists.
- List bodies are fetched directly from `raw.githubusercontent.com` and cached in
  IndexedDB with age-based decay (fresh under 24h, stale-while-revalidate to 7 days,
  blocking refetch beyond that, always falling back to stale data rather than failing).
- Matching runs in a Web Worker: binary-search CIDR ranges for IPs, set and
  suffix lookups for hostnames.

## Reading the results

Hits are grouped into tiers, and two of them are easy to misread:

- **High-traffic site** is informational only. These lists rank by traffic, not safety,
  and contain plenty of malicious infrastructure. Popular does not mean safe.
- **Context — look closer** (dynamic DNS, VPN ranges, Tor exits, scanners) is a reason
  to investigate further, not to dismiss.

An indicator is only labelled **clean** when every in-scope list loaded successfully.
If any list failed, it reads `no hits (N/M lists)` instead.

## Development

```bash
npm install
npm run dev            # local dev server
npm test               # vitest
npm run build          # typecheck + production build
npm run build:catalog  # regenerate src/catalog.json from upstream
```
```

- [ ] **Step 8: Commit**

```bash
git add src/ui/app.ts src/main.ts .github/workflows/deploy.yml .github/workflows/catalog-drift.yml .github/dependabot.yml README.md
git commit -m "feat: wire up app shell, popularity opt-in, Pages deploy and drift check"
```

- [ ] **Step 9: Enable GitHub Pages**

In the repository settings, set **Pages → Build and deployment → Source** to **GitHub Actions**. Push to `main` and confirm the deployed URL loads and completes a check.

---

## Self-Review

**1. Spec coverage**

| spec section | task |
|---|---|
| Goals / non-goals | Task 1 (scope), Task 12 (README states them) |
| Upstream data measurements | Task 2 (catalog + integrity assertions pin the counts) |
| Architecture, Web Worker | Tasks 9, 12 |
| `catalog.json` app-owned + CI drift job | Tasks 2, 12 |
| Two tiers, lazily loaded | Tasks 2 (`loadTier`), 12 (opt-in button) |
| Parsing: refang, classify, dedupe, unparseable surfaced | Task 3 |
| Matchers: cidr, string, hostname, substring, regex | Tasks 4, 5 |
| Applicability filter from `matching_attributes` | Task 6 |
| Result record shape | Task 1 (types), Task 8 (populated) |
| Presentation tiers + popularity/context wording | Tasks 2 (assignment), 10 (`TIER_META`) |
| Caching + decay tiers + no-ETag note | Task 7 |
| Error handling + coverage + "clean" reserved | Tasks 7, 8 (`coverageLabel`), 10, 12 |
| Export TSV/CSV/JSON/clean-only with coverage header | Task 11 |
| Testing plan (all listed cases) | Tasks 3–8, 10, 11 |
| Module layout | matches the File Structure table |

No gaps found.

**2. Placeholder scan**

No `TBD`, `TODO`, "similar to Task N", or bare "add error handling" instructions. Every code step carries complete code; every test step carries complete assertions.

**3. Type consistency**

Checked across tasks:
- `Matcher.match(normalized, type)` — two arguments everywhere (Tasks 1, 4, 5, 8).
- `CatalogEntry.matchingAttributes` — camelCase in our types, mapped from upstream `matching_attributes` in Task 2's generator and Task 7's `isUpstreamList`.
- `Coverage` has five fields (`loaded`, `total`, `failed`, `heavyLoaded`, `oldestFetchedAt`) — constructed in Task 9's worker, consumed in Tasks 8, 10, 11.
- `coverageLabel` is defined once in Task 8 and imported by Tasks 10 and 11 rather than reimplemented.
- `version` is `number` throughout, matching upstream and the Global Constraints note.
- `CachedList` is defined in Task 7 and imported by Task 8.
- `buildMatcher(type, entries)` — Task 5's signature matches Task 8's call.

Two corrections applied while reviewing:
- The engine's `run` signature in the Task 8 interface block originally described `coverage` with a redundant intersection type; simplified to `Coverage`.
- Task 10's degraded-coverage test originally asserted `not.toContain('clean')`, which would fail because the degraded string does not contain the word — but a future refactor could make it pass vacuously. Changed to a regex asserting the standalone verdict is absent.
