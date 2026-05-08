# AUDIT.md

Audit notes for `subharvest`. Updated per release.

## Code Quality

- **Language / runtime.** Python 3.11+. Uses `tomllib` from stdlib (3.11+), `httpx` async client, `dnspython.asyncresolver`.
- **Async throughout.** All sources implement `async def fetch(domain)`. Orchestrator dispatches them in parallel via `asyncio.gather` with per-source timeout (`asyncio.wait_for`).
- **Source isolation.** A source raising an exception or timing out does not abort the run. Errors are captured per source in `SourceResult.error` and surfaced in JSON/Markdown output and stderr telemetry.
- **No mutable global state.** Each source instance carries its own config dict.
- **Tests.** `pytest` + `respx` for HTTP mocking. Fixtures in `tests/fixtures/` are canned API responses captured by hand. No live calls in tests.
- **Lint debt.** No linter wired up in v0.1. v0.2 will add `ruff` to CI.

## Security

- **Passive by default.** No source generates traffic to the target's infrastructure unless `--active` is set (active sources are not yet implemented in v0.1).
- **API keys.** Read from `~/.subharvest/config.toml` or `SUBHARVEST_<SOURCE>_API_KEY` env vars. Never logged. `--list-sources` only shows whether a key is required, not whether one is loaded.
- **DNS resolution.** Uses the system resolver by default. `--resolver` lets you pin a specific resolver IP. `--doh` is recognized but not yet wired in v0.1.
- **No user-supplied code execution.** Wordlists and permutation files (v0.3) are read line-by-line as plain strings.
- **Output safety.** Markdown output wraps subdomain values in backticks; CSV uses `csv.writer` (handles quoting). No raw HTML emitted.
- **Operational note.** Passive sources log requester IPs at the provider side. Run from a jumpbox in the engagement environment.

## GitHub Repo

- License: MIT.
- No CI in v0.1 — `pytest -q` locally.
- No release artifacts. Install via `pipx install -e .` from a clone, or `pipx install subharvest` once published.
- Repo banner: `assets/banner.svg`. SVG, 760x180, dark gradient, blue accent. No emoji in headings.
- README structure: banner → one-liner → Author → What It Does → Quick Start → tables → Usage → Notes → Authorized Use → Changelog → Roadmap → Credits → Project Hygiene → AUDIT.md → License.

## Feature Backlog

### Near-term (v0.2)
- API-key sources: SecurityTrails, VirusTotal, Censys CT, Google CT.
- Local cache (`~/.subharvest/cache/`) with TTL — re-runs against the same domain within `cache.ttl_seconds` skip API calls.
- Per-source rate limit (token bucket) configured via TOML.
- Common Crawl source.

### v0.3 — active mode
- DNS brute force using shipped 5k-entry wordlist (`subharvest/data/default_wordlist.txt`). Rate-limited, concurrency-bounded.
- Permutation engine (`subharvest/data/permutations.txt`) — generate variants of already-discovered subdomains.
- AXFR attempt against each NS.
- Wildcard fingerprint must apply to active findings, not just passive — already structurally supported by `WildcardFingerprint.matches`.
- DNS-over-HTTPS resolver (`--doh` actually wired).

### v0.4
- `-f domains.txt` batch mode.
- Takeover candidate detection: live HTTP probe against SaaS-CNAME findings, look for known fingerprint strings ("There isn't a GitHub Pages site here", "NoSuchBucket", etc.).
- Diff mode: persist a fingerprint of the last run per domain, surface new subdomains since last sweep.

### v0.5 — stretch
- ASN-adjacent domain discovery (off by default — noisy).
- phishprint integration: pipe `subharvest` JSON → phishprint score for each subdomain that has its own MX.
- Output adapter for `httpx`/`nuclei` input format.
- Subdomain takeover provider DB pulled from upstream (e.g., projectdiscovery's templates).

### Bugs / known limitations (v0.1)
- `--doh` flag is parsed but uses the system resolver. Tracked for v0.3.
- `--threads` flag is parsed but unused (active mode not implemented).
- SPF include chain only follows one hop — circular includes won't loop, but deeper chains are missed.
- `crt.sh` returns large responses for popular domains; no streaming JSON parse yet — peak memory on huge zones could be a problem.
- No retry/backoff on transient 5xx from sources. Single attempt per source per run.
