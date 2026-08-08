# TODO

## Keep `catalog.json` in sync with upstream MISP warninglists

`catalog.json` is app-owned, not fetched from upstream. MISP has no machine-readable
index of list types, and deriving one at runtime means 125 requests before you can
match anything. Shipping it means a known list set, and unknown-to-me lists simply
don't get loaded until I update the catalog — a deliberate tradeoff of freshness for
determinism. I'd add a CI job that diffs upstream against the catalog and opens an
issue when MISP adds a list.
