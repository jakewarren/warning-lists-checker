# MISP Warninglists Checker

Paste a pile of IPs, domains and URLs; get back which
[MISP warninglists](https://github.com/MISP/misp-warninglists) each one hits, so the
likely false positives are out of the way before investigation starts.

**Everything runs in your browser.** Indicators you paste are never sent anywhere —
there is no backend, no telemetry, and no analytics. The only network requests the app
makes are for the warninglists themselves.

## The problem it solves

An analyst triaging a batch of indicators has no fast way to tell which ones are noise.
`8.8.8.8` is a public resolver, `13.107.42.14` is Microsoft, half the domains in a report
are CDN infrastructure. MISP already curates exactly this data across 123 lists. This is
a front-end for it — paste, scan, move on to what actually matters.

## Features

- **IPs, domains and URLs**, IPv4 and IPv6. URLs are reduced to the host that gets matched.
- **Defanged input works.** `hxxps://evil[.]com/x`, `1.1.1[.]1`, `(at)`, `[:]` — all
  refanged automatically, because that is how indicators commonly arrive from reports and PDFs.
- **Results grouped by what a hit actually means**, not one flat list (see below).
- **Export** to clipboard as TSV, or download CSV/JSON — plus a one-click
  **"copy clean only"** for the shortlist worth investigating.
- **Works offline after first load.** Lists are cached in IndexedDB; a failed refresh
  degrades to stale data with a visible warning rather than a dead app.
- **~10,000 indicators** checked in well under a second.

## Reading the results

Hits are grouped into tiers, because a single indicator can hit several lists that mean
very different things. Two are easy to misread, so the UI labels them explicitly:

| Tier | Meaning |
|---|---|
| **Known false positive** | Curated as a common FP. Strong reason to deprioritise. |
| **Known infrastructure** | Major cloud, CDN or public resolver. Strong reason to deprioritise. |
| **Context — look closer** | Dynamic DNS, VPN ranges, Tor exits, internet scanners. **Not** a safety signal — a reason to investigate further. |
| **High-traffic site** | Informational only. **Popular does not mean safe.** |

That last one matters. The popularity lists rank by traffic, not safety, and the raw data
contains piracy sites, gambling domains, counterfeit storefronts and plenty of malware
infrastructure hosted on high-traffic services. A hit there means "this is a busy site",
never "this is safe".

Similarly, an indicator is only labelled **clean** when every in-scope list loaded
successfully. If any list failed, it reads `no hits (N/M lists)` instead — a false clean
verdict is the worst thing a tool like this can produce, so the word is reserved.

## How it works

- A generated `src/catalog.json` describes the 123 in-scope lists — their name, MISP
  type, matching attributes and tier. It ships with the app, so no discovery requests are
  needed before the first match.
- List bodies are fetched directly from `raw.githubusercontent.com` (which serves
  gzip and permissive CORS) and cached in IndexedDB with age-based decay: fresh under
  24h, stale-while-revalidate to 7 days, blocking refetch beyond that — always falling
  back to stale data rather than failing.
- Matching runs in a Web Worker so the UI never blocks: binary-searched CIDR ranges for
  IPs, suffix-probing set lookups for hostnames, chosen per list from its MISP type.
- Which lists a given indicator is even tested against is derived from upstream's own
  `matching_attributes` metadata, so an IP never touches a hostname list and the routing
  stays correct as MISP evolves.

Zero runtime dependencies — the whole thing is hand-written TypeScript, about 10 kB
gzipped plus the worker.

## Development

```bash
npm install
npm run dev            # local dev server
npm test               # vitest
npm run build          # typecheck + production build
npm run build:catalog  # regenerate src/catalog.json from upstream
```

`npm run build:catalog` walks the upstream repository and rewrites the catalog. A monthly
CI job diffs upstream against it and opens an issue when MISP adds a list, so the shipped
catalog does not quietly fall behind.

## Credits

This tool is a front-end. **All of the actual intelligence comes from the
[MISP project](https://www.misp-project.org/)** and the contributors who maintain
[MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) — curating 123 lists
of known-good infrastructure, common false positives, scanners and popularity rankings is
the hard part, and they have been doing it for years.

If you find this useful, the credit belongs upstream. Consider
[contributing a list or a correction](https://github.com/MISP/misp-warninglists) to MISP
rather than here.

## License

The code in this repository is [MIT licensed](LICENSE).

**That covers this application only, not the warninglist data.** The lists are fetched
live from [MISP/misp-warninglists](https://github.com/MISP/misp-warninglists) at runtime
and no copy of them is bundled or redistributed here — `src/catalog.json` holds only list
names and metadata, not list contents.
