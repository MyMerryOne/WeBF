# Security Policy

## Authorized use

Use WeBF only for public web content and related network metadata covered by documented authorization or another lawful basis. Do not use it to bypass access controls, impersonate users, or collect content outside the approved scope.

## Sensitive material

Treat captures, raw HTTP responses, reports, manifests, logs, certificates, timestamp trust material, operator identifiers, credentials, and local configuration as sensitive. Restrict access, use controlled storage, and never include them in issues, pull requests, screenshots, or public archives.

Tests must use synthetic content. Live sites, network lookups, browser sessions, and timestamp authorities are not deterministic test fixtures.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainer with the affected version, a synthetic reproduction, impact, and proposed mitigation. Do not disclose case material or secrets while reporting.

Security-sensitive areas include URL handling, browser rendering, archive creation and extraction, path handling, timestamp verification, generated scripts, logging, and report generation.

Capture targets and every HTTP redirect must use HTTP(S), contain no credentials,
and resolve only to public addresses. TLS certificate verification failures stop
the capture; unverifiable responses must not be packaged as normal evidence.

Generated verification scripts must treat recorded TSA URLs as data rather than
executable shell or PowerShell source.

## Package and trust-material handling

Treat `timestamp/tsa_trust.pem` and `timestamp/tsa_untrusted.pem` as case-sensitive trust configuration. Record their source, retrieval time, version or list reference, hashes, and validation scope with the case record. A token signer certificate, provider name, endpoint URL, or successful OpenSSL chain check does not by itself establish current qualified-service status.

Package verification must reject unsafe archive member paths, duplicate names, missing declared members, malformed manifests, invalid hash lengths, missing primary WARC evidence, and digest mismatches. Do not extract an untrusted package without applying equivalent path-safety controls.

The generated verification scripts are convenience tooling. Their output is technical verification evidence, not a determination of legal admissibility. Report timestamp imprint validity, certificate-chain validity, revocation/status checks, and Trusted List/service status separately.

Historical packages and reports must remain unchanged. Preserve the original package and create a corrected or superseding package/report with provenance when interpretation or software behavior changes.

## Response and correction

The maintainer should assess exploitability and impact on package integrity or interpretation, preserve the report, test the correction, and document affected versions. Existing capture packages must not be rewritten to apply a software correction.
