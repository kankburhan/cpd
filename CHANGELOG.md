# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
