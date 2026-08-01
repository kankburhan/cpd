# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Host-blind cache key detection (`cpd/logic/host_key.py`). A cache key built from the URI alone, omitting the Host/authority, lets one virtual host poison another — this is CVE-2026-2836 in Cloudflare Pingora (all versions < 0.8.0), whose default cache key used only the URI. The probe tests for the behaviour rather than fingerprinting a product, since the same shape occurs in any hand-rolled proxy cache. A spoofed Host returning different content is not treated as a finding on its own (that is just virtual hosting working); the clean request must come back carrying the spoofed host's response. Guarded by two agreeing control probes, a stability recheck, and a fresh-key drift check.
- Next.js internal cache poisoning detection (CVE-2024-46982), ranked #7 in PortSwigger's Top 10 Web Hacking Techniques of 2025. On the pages router (13.5.1 – 14.2.9) the internal `x-now-route-matches` header makes a server-rendered request be classified as static, flipping `Cache-Control` from `private, no-cache, no-store` to `s-maxage=1, stale-while-revalidate` — a per-user response becomes shared-cacheable. Causes DoS when JSON replaces HTML, and stored XSS when `getServerSideProps` reflects request data. The `__nextDataReq` parameter reaches the same code path, was explicitly not covered by the CVE, and is reported as unpatched even on fixed builds.

### Changed
- Only shared-cache directives (`s-maxage`, `stale-while-revalidate`) count as a cacheability flip; a plain `max-age` is browser caching and is ignored. A flip alone is reported MEDIUM as a confirmed misclassification — HIGH/CRITICAL requires the clean request to re-serve the entry, matching the cache-hit gating used by the other techniques.

## [0.10.3] - 2026-08-01

### Added
- `cpd/logic/control.py`: `stable_hash()` (hashes with our own cache-buster token neutralised), `control_probe()` (fetches a second cache-busted copy with clean headers as the correct "did this change anything?" reference), and `new_cb()` (fixed-width buster so a reflection cannot shift response length).

### Fixed
- Probes are now compared against a cache-busted control instead of the clean-URL baseline. Every technique appends its own `?cb=...`, so on any target that reflects the query string back into the page (Drupal `drupal-settings-json.currentQuery`, Next.js `__NEXT_DATA__`, Rails, most analytics bootstraps) the probe body differed from the baseline on every request and every signature fired. Observed on a Drupal 11 site as five false-positive HIGH `AcceptHeaderPoisoning` findings.
- The same wrong reference ran in the other direction in `cache_deception_v2.py`, where `resp_hash == baseline.body_hash` could never be true on such a target, silently dropping every deception finding. `poison.py`'s drift guard discarded real findings as "chaotic" for the same reason.
- Accept / h2c / no-middleware checks now require the clean request to actually receive the poisoned body *and* a cache hit. Content change alone is origin behaviour, not poisoning.
- Accept polymorphism suppresses itself when nearly all variants fire, since five unrelated values "working" at once means the methodology broke.
- Hop-by-hop sub-tests get their own cache entry and marker. Sharing one URL let the first poison sit in the cache and be re-read by the rest, turning one bug into five.
- `CacheKeyNormalization` ignores variants the client was redirected away from; an uppercase URL that 301s to canonical is the redirect working.
- `CACHE_HIT_HEADERS` was missing `X-Drupal-Cache`, `X-Varnish`, Akamai and the nginx/proxy variants that `CacheValidator` already recognised, so the new cache-hit gates would have gone blind on exactly those targets.
- `control_probe()` swallows transport errors: losing the control is a skip, not a scan-aborting exception.
- `scripts/release.py` no longer drops the new release entry from the changelog. `update_changelog()` inserted the entry and then removed it again with a regex that matched what it had just written, which is why v0.10.2 has no changelog section.

### Changed
- Repaired 16 long-standing test failures in the poisoning suite. Tests that drove `Poisoner.run()` are retargeted at `_attempt_poison`, the unit they describe, since `run()` now executes ~10 sub-detectors first and exhausted their scripted mocks. Assertions on the old `"POTENTIAL VULNERABILITY: X"` detail string moved to the `vulnerability` key. Five tests in `test_poison_enhanced.py` describe features that were never implemented (they failed on the commit that introduced them) and are now `xfail(strict=True)` so the gaps stay documented.

## [0.10.1] - 2026-05-09

### Fixed
- `X-Cache: CONFIG_NOCACHE` and similar no-cache values no longer treated as cache HIT evidence.
- `validator.py` skips headers whose value explicitly signals CDN bypass/no-cache.
- `nextjs_poisoning.py`: `_i18n_data_route_bypass` now requires three conditions before flagging — i18n configured, route gated (4xx/3xx without header), and sensitive fields in response. Eliminates false positives on public Next.js data endpoints.

## [0.10.0] - 2026-05-09

### Added
- Next.js cache poisoning detection module (`nextjs_poisoning.py`) covering 9 CVEs from the v16.2.4 security release.
- CVE-2026-44572: `x-nextjs-data` redirect cache poisoning detection.
- CVE-2026-44576: RSC/HTML cache confusion detection.
- CVE-2026-44582: Weak `_rsc` hash collision probe.
- CVE-2026-44575: `.rsc` suffix middleware bypass detection.
- CVE-2026-44573: i18n data-route bypass detection.
- CVE-2026-44574: `nxtP`/`nxtI` parameter injection detection.
- CVE-2026-44579: `next-resume` header injection (cache poisoning + CPDoS).
- CVE-2026-44581: CSP nonce reflection via cache.
- CVE-2026-23870: Server-action stream DoS signature.
- 18 new signatures in `signatures.py` for Next.js CVE-2026 vectors.
- 12 new unit tests for Next.js poisoning techniques.

## [0.7.1] - 2026-01-20

### Added
- Severity filtering in HTML reports.

### Removed
- Debug scripts (`debug_stability.py`, `verify_bypass.py`).

## [0.7.0] - 2026-01-20

### Added
- Enhanced HTML reports with evidence URLs and PoC details.
- Query parameter case normalization detection.
- Auto-open HTML reports in browser (`--open` flag).
- Donation section in reports and GitHub funding.

## [0.4.1] - 2026-01-12

### Fixed
- Relaxed false positive reduction logic: detections with small byte differences (< 50 bytes) are now only discarded if the percentage difference is also < 1% (previously was discarding any < 50 bytes difference).
- Fixed regression with indentation in verification logic.

## [0.4.0] - 2026-01-12

### Added
- Status code validation to skip unsuitable endpoints (401, 429, 500, etc.)
- Payload prioritization based on response status codes
- Statistics tracking for scanned/skipped/found URLs
- Redirect Location header poisoning detection
- Enhanced cache detection with Azure, Nginx, and Akamai headers
- Content-Type field in Baseline for future validations
- Percentage-based false positive reduction (5% threshold)
- HTML Report Generation via `scan --output report.html`
- Rate Limiting via `--rate-limit` CLI option
- Configuration file support via `--config cpd.yaml`

### Changed
- Improved false positive reduction using percentage diff instead of absolute bytes
- 404 endpoints now skip method override tests (optimization)
- Cookie-Vary header now properly quoted

### Fixed
- Removed duplicate Accept-Language signature
- Fixed Cookie header quoting in Vary exploitation tests

## [0.3.2] - 2025-01-XX

### Added
- Initial public release
- Core cache poisoning detection
- Support for 100+ poisoning signatures
- Pipeline mode for mass scanning
- Burp Suite raw request support

[Unreleased]: https://github.com/kankburhan/cpd/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/kankburhan/cpd/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/kankburhan/cpd/releases/tag/v0.3.2
