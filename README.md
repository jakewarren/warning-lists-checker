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
  and contain plenty of malicious infrastructure. Popularity is not benignness.
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
