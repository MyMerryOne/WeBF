# Changelog

All notable changes to WeBF are recorded here. Entries describe behavior, security or integrity impact, compatibility, and validation.

## Unreleased

### Documentation and SSDLC baseline

- Established the SSDLC quality, review, sensitive-output, release-evidence, and historical-package controls.
- Defined neutral product terminology: Web Capture and Verification Tool, Capture Package, and Technical Capture Report.
- Added repository protection for generated captures, reports, timestamp material, secrets, and case data.
- Added an SSDLC review procedure covering integrity, provenance, packaging, timestamps, reports, network capture, and sensitive evidence.

### Capture and reporting

- Added ISO 28500:2017 WARC output as the primary captured artifact.
- Improved browser capture handling for cookie banners, overlays, and logged-out prompts, including embedded legal-content modal capture.
- Added automatic legal-page discovery with `--no-legal` and `--max-legal-pages` controls.
- Hardened report layout for print output and added TLS certificate-chain status reporting.
- Renamed the tool and generated metadata to WeBF and adopted neutral technical-report terminology.

### Timestamp and trust verification

- Added independent RFC 3161 timestamp response verification, including manifest imprint and nonce checks.
- Added explicit TSA trust-anchor and intermediate-certificate material for OpenSSL chain verification.
- Kept timestamp token validity, certificate-chain validation, and qualified-service status as separate claims; an endpoint name or signer certificate alone does not establish qualification.
- Added Italian operator fields and fail-closed requirements for the configured TSA trust material.

### Package integrity

- Introduced manifest schema `1.1` with a complete package-member inventory.
- Added duplicate-name, unsafe-path, malformed-manifest, missing-member, and missing-hash validation.
- Added `package_hashes.json` and detached `package_hashes.sha256` values covering every other ZIP member with SHA-256 and SHA-512 checksums.
- Made package verification fail closed for invalid JSON, missing manifest hashes, incomplete inventories, and hash mismatches.

### Compatibility and remaining work

- Existing generated packages with schema `1.0` or pre-migration terminology are historical outputs and must not be rewritten. New packages use schema `1.1` and current WeBF terminology.
- Structured stage status, redirect chronology, browser diagnostics timing, a trusted binding for the complete package hash index, current Italian Trusted List/revocation validation, and structured custody records remain implementation gaps. See [IMPLEMENTATION_GAPS.md](IMPLEMENTATION_GAPS.md).
