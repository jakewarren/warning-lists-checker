# MISP Warninglists Checker — Design

**Date:** 2026-08-08
**Status:** Approved

## Problem

A SOC analyst triaging indicators has no fast way to tell which of them are likely
false positives. Pasting a list of IPs and domains into a browser and getting back
"these 12 belong to Cloudflare, AWS, and public DNS resolvers" removes most of the
noise before investigation starts.

[MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) already curates
this data. This tool is a front-end for it. Nothing more.

## Goals

- Paste IPs, domains, and URLs; get back which MISP warninglists each one hits and why.
- Run entirely in the browser. Analyst indicators never leave the machine.
- Static hosting on GitHub Pages. No backend, no build-time list bundling, no
  server-side state.
- Handle ~10,000 indicators comfortably.

## Non-goals

No reputation lookups, no VirusTotal or passive DNS enrichment, no scoring or verdicts,
no file hash support in v1. This tool answers one question — "which of these indicators
are likely false positives, and why" — and stays a pure warninglists front-end.

## Upstream data, measured

Measured against `MISP/misp-warninglists@main` on 2026-08-08.

| | |
|---|---|
| Total lists | 125 (`lists/*/list.json`; 128 blobs under `lists/`, 3 are READMEs) |
| Total size | 124 MB |
| Hash lists (out of scope) | 2 lists, 67 MB — `windows-binary-hashes` 57 MB, `nioc-filehash` 10.5 MB |
| Popularity tier | 2 lists, 47 MB — `google-chrome-crux-1million` 25.5 MB, `tranco` 21.8 MB |
| **Core tier (in scope)** | **121 lists, 9.05 MB raw, ~1.4 MB gzipped** |

`raw.githubusercontent.com` serves `access-control-allow-origin: *` and
`content-encoding: gzip` (measured: `vpn-ipv4` 955 KB → 147 KB, ~6.5x), so the browser
can fetch lists directly with no proxy.

### List type distribution (125 lists carrying a `type`)

| type | count | matching semantics |
|---|---|---|
| `cidr` | 74 | IP falls inside a network range |
| `string` | 26 | exact equality |
| `hostname` | 19 | exact, or indicator is a subdomain of the entry |
| `substring` | 3 | entry appears anywhere in the indicator |
| `regex` | 2 | compiled pattern test |

CIDR dominates. The two `regex` lists match email addresses and phone numbers, so they
are out of scope for every indicator type this tool handles. All three `substring`
lists are under 17 KB.

## Architecture

Single-page static app, vanilla TypeScript + Vite, deployed to GitHub Pages.

```
┌─ index.html (GitHub Pages) ─────────────────────────┐
│                                                     │
│  UI layer (vanilla TS)                              │
│   textarea ──▶ parser ──▶ [Indicator]               │
│                             │                       │
│  Web Worker ◀───────────────┘                       │
│   ├─ ListStore  ──▶ IndexedDB (cache + timestamps)  │
│   │                  └─ miss/stale ─▶ raw.github…   │
│   ├─ MatcherIndex (built once per list, per session)│
│   └─ match(indicators) ──▶ [Result]                 │
│                             │                       │
│  Results view ◀─────────────┘                       │
│   grouped by tier ──▶ export (TSV/CSV/JSON/clean)   │
└─────────────────────────────────────────────────────┘
```

### Flow

1. On load, the app reads a static `catalog.json` shipped with the app: list names,
   their MISP `type`, their `matching_attributes`, and the tier mapping. It does not
   hit the network to discover lists.
2. `ListStore` resolves each core-tier list — IndexedDB hit if fresh, otherwise
   `fetch` from
   `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/<name>/list.json`,
   stored with `fetchedAt` and the upstream `version`.
3. Each list compiles once into a matcher structure appropriate to its type, held in
   the Worker for the session.
4. Analyst pastes → parser refangs, classifies, dedupes → Worker matches → results
   render grouped by tier.

### Key decisions

**Everything matching-related runs in a Web Worker.** Parsing ~1.4 MB of gzipped JSON
into 74 CIDR indexes would jank the main thread. It also keeps the matching engine a
pure module with no DOM access, so it is directly unit-testable.

**`catalog.json` is app-owned, not fetched from upstream.** MISP publishes no
machine-readable index of list types, and deriving one at runtime would mean 125
requests before the first match. Shipping the catalog trades freshness for determinism:
lists added upstream are not loaded until the catalog is updated. A CI job diffs
upstream against the catalog and opens an issue when MISP adds a list
(`.github/workflows/catalog-drift.yml`).

**Two tiers, lazily loaded.** Core tier (121 lists, ~1.4 MB gzipped) loads on startup.
Popularity tier (`tranco`, `google-chrome-crux-1million`; ~7 MB gzipped) loads only on
explicit opt-in, with its size shown on the button. `alexa` and `majestic_million` are
small enough to stay in core.

**No access control.** Nothing sensitive is stored or transmitted. Public URL.

## Parsing

`parse.ts` — pure functions, no DOM.

1. Split on newlines, commas, semicolons, and whitespace. Strip surrounding quotes and
   brackets.
2. **Refang:** `[.]` `(.)` `{.}` `\.` → `.` · `[:]` → `:` · `hxxp`/`hXXp`/`hxxps` →
   `http`/`https` · `[//]` → `//` · `[at]`/`(at)` → `@`. The original string stays on
   the record so results display exactly what was pasted.
3. **Classify**, in order: URL (has a scheme or `/`) → parse and extract the hostname,
   keeping the full URL as the display value · IPv4 · IPv6 · domain · otherwise
   `unparseable`. The extracted host is re-classified, so an IP-literal URL carries
   type `ipv4`/`ipv6` and reaches the CIDR lists — a URL is a carrier, and the type
   must describe the value the matchers actually see.
4. Dedupe on the normalized value, preserving first-seen order and an occurrence count.

Unparseable lines appear in their own section rather than being silently dropped. An
analyst who pastes a column of hashes is told, not left staring at zero results.

## Matching

One implementation per MISP type behind a common interface:

```ts
interface Matcher {
  build(entries: string[]): void
  match(indicator: Indicator): boolean
}
```

- **`cidr` (74 lists)** — the hot path. IPv4 entries convert to `uint32` `[start, end]`
  pairs, sorted and merged into a `Uint32Array`, queried by binary search. IPv6 uses a
  parallel `BigInt` range array. Entries with no prefix are treated as `/32` (`/128`).
  10k IPs across 74 lists is roughly 12M comparisons — sub-second.
- **`string` (26)** — lowercased `Set`, exact lookup.
- **`hostname` (19)** — `Set` of entries. For `a.b.example.com`, probe
  `a.b.example.com`, `b.example.com`, `example.com`, `com`. Bounded at ~5 lookups. No
  Public Suffix List required.
- **`substring` (3)** — linear scan over entries. All three lists are under 17 KB.
  Start naive; swap in Aho-Corasick only if measurement justifies it.
- **`regex` (2)** — compiled once. Both target email and phone attributes only.

### Applicability filter

Every list declares `matching_attributes` (`ip-src`, `ip-dst`, `hostname`, `domain`,
`url`, `md5`, `email-src`, …). A list is consulted only for indicator types its
attributes cover. An IPv4 address never touches the 19 hostname lists; a domain never
touches the 74 CIDR lists; the two regex lists are excluded from every in-scope type
without hardcoding their names. This derives from upstream metadata, so it stays
correct as MISP evolves.

### Result record

```ts
{
  original: string
  normalized: string
  type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'unparseable'
  hits: Array<{ list: string, tier: Tier, description: string, version: number }>
}
```

No severity collapsing. Tier comes from the catalog. Zero-hit indicators are marked
explicitly (see coverage rules below).

## Presentation tiers

An indicator can hit several lists that mean different things — `1.1.1.1` hits
`cloudflare`, `public-dns-v4`, and `common-ioc-false-positive` at once. Hits are
grouped into four tiers, rendered differently:

| tier | example lists | meaning |
|---|---|---|
| **Infrastructure / known-good** | `cloudflare`, `microsoft-azure`, `google-gcp`, `akamai`, `public-dns-v4` | strong false-positive signal |
| **Known-FP curated** | `ti-falsepositives`, `common-ioc-false-positive`, `rfc1918`, `bogon` | strong false-positive signal — the lists' core purpose |
| **Popularity** | `tranco`, `google-chrome-crux-1million`, `majestic_million`, `alexa` | **informational only** |
| **Context / caution** | `dynamic-dns`, `vpn-ipv4`, `tor-exit-nodes`, `url-shortener` | a reason to look *closer*, not to dismiss |

Two tiers carry deliberate wording:

**Popular does not mean safe.** These lists rank by traffic, not safety, and the raw
data contains abundant malicious infrastructure — `1337x.to`, `9anime.to`, dozens of
gambling domains, `*.x.yupoo.com` counterfeit storefronts, `0000000000.download`. The
UI labels these "high-traffic site — popular does not mean safe" and never styles
them like an allowlist. `tranco`'s snapshot is also stale (`version: 20250115`, ~19
months old at time of writing) versus `crux` (`20260709`).

**Context / caution means the opposite of safe.** A hit on `tor-exit-nodes` or
`dynamic-dns` is an investigative lead. Rendering it as "known good" would actively
mislead.

Lists absent from the catalog's tier mapping fall through to a neutral default, so
coverage degrades gracefully.

## Caching

IndexedDB, one object store keyed by list name:

```ts
{ name, entries: string[], version, matchingAttributes, fetchedAt, ok }
```

Decay tiers, evaluated per list on load:

| age | behavior |
|---|---|
| < 24h | serve from cache, no network |
| 24h – 7d | serve from cache immediately, revalidate in background, swap in silently on change |
| > 7d | block on refetch with progress; on failure fall back to stale plus a persistent banner |

The rule underneath: **the tool never refuses to run because a refresh failed.** Stale
lists beat no lists.

`raw.githubusercontent.com` sends no `access-control-expose-headers`, so JavaScript
cannot read the `ETag` cross-origin. Revalidation still happens transparently via the
browser's HTTP cache, but the decay logic is driven by the `fetchedAt` timestamp
recorded in IndexedDB, not by ETag comparison.

`api.github.com` is not used for per-list requests: unauthenticated rate limit is 60
requests per hour per IP, against 125 lists.

## Error handling

The most dangerous output this tool can produce is a false "clean" verdict. Error
handling is built around that.

- **Per-list failures are isolated.** A 404 or malformed JSON marks that list
  unavailable; the other 120 still match.
- **Coverage is always visible.** The header shows `120/121 lists loaded` (denominator
  is in-scope lists for the tiers currently loaded, so it becomes `/123` once the
  popularity tier is opted into). When coverage is degraded, zero-hit indicators are
  labeled **"no hits (120/121 lists)"** —
  the word "clean" is reserved for full coverage. Exports carry the coverage figure and
  list versions in a header row.
- **Popularity tier not loaded** is shown as an explicit state, not silence.
- **IndexedDB unavailable or over quota** (private browsing) → fall back to in-memory
  for the session, with a notice that lists will re-download next visit.
- **Cold start, no network, no cache** → say so plainly and disable the check button,
  rather than reporting everything as clean.

## Export

- Copy to clipboard as TSV (primary — pastes into tickets and spreadsheets)
- Download CSV
- Download JSON (full structured detail: every hit with tier and description)
- Copy only the clean indicators — one click to get "the ones that hit nothing", so the
  analyst can move straight to what's worth investigating

All exports include a header carrying coverage and list versions.

## Testing

Every module is a pure function or a class with an injected `fetch` / `IDBFactory`, so
the suite runs under Vitest with no browser automation.

- **Parser table tests:** each refang form; `hxxps://evil[.]com/path` → hostname
  extraction; IPv6 compressed, expanded, and bracketed-with-port; junk → `unparseable`;
  dedupe with counts.
- **CIDR boundaries:** network and broadcast addresses, `/32`, `/0`, off-by-one just
  outside a range, adjacent-range merging, bare-IP entries, IPv6 via BigInt.
- **Hostname suffix correctness:** `evilexample.com` must **not** match entry
  `example.com`, while `a.b.example.com` must. Tested in both directions — this is the
  classic `endsWith` bug.
- **Applicability filter:** an IPv4 input consults zero hostname lists; a domain
  consults zero CIDR lists; regex email/phone lists are consulted by nothing in scope.
- **Cache decay:** fake timers across all three tiers, plus stale-fallback-on-failure
  and degraded-coverage labeling.
- **Fixtures:** small trimmed excerpts of real `list.json` files checked into the repo —
  real structure, not 9 MB.

## Module layout

| module | responsibility | depends on |
|---|---|---|
| `catalog.json` | list names, types, matching attributes, tier mapping | — |
| `parse.ts` | text → `Indicator[]` (refang, classify, dedupe) | — |
| `matchers/*.ts` | one `Matcher` per MISP type | — |
| `applicability.ts` | which lists apply to which indicator type | catalog |
| `listStore.ts` | IndexedDB cache, decay, fetch, coverage tracking | catalog |
| `engine.ts` | orchestrates store + matchers → `Result[]` | above |
| `worker.ts` | Worker entry, message protocol | engine |
| `ui/*.ts` | textarea, tiered results, coverage header, export | worker |
