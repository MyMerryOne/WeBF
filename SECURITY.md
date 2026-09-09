# Security Policy

## Authorized use

Use WeBF only for public web content and related network metadata covered by documented authorization or another lawful basis. Do not use it to bypass access controls, impersonate users, or collect content outside the approved scope.

## Sensitive material

Treat captures, raw HTTP responses, reports, manifests, logs, certificates, timestamp trust material, operator identifiers, credentials, and local configuration as sensitive. Restrict access, use controlled storage, and never include them in issues, pull requests, screenshots, or public archives.

Tests must use synthetic content. Live sites, network lookups, browser sessions, and timestamp authorities are not deterministic test fixtures.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainer with the affected version, a synthetic reproduction, impact, and proposed mitigation. Do not disclose case material or secrets while reporting.

Security-sensitive areas include URL handling, browser rendering, archive creation and extraction, path handling, timestamp verification, generated scripts, logging, and report generation.

## Response and correction

The maintainer should assess exploitability and impact on package integrity or interpretation, preserve the report, test the correction, and document affected versions. Existing capture packages must not be rewritten to apply a software correction.
