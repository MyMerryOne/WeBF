# Next-Phase Remediation Plan

This plan addresses the technical and Italian-proceeding gaps identified after the SDLC baseline checkpoint `83f77a6`. It strengthens verifiability and provenance without asserting legal admissibility. Each phase requires focused tests before the next phase begins.

## Phase 1: Package contract and strict verification

**Goal:** Make every generated package member covered by one explicit, independently checkable integrity contract.

- Define manifest schema version `1.1` and required fields.
- Decide whether every package member, including reports, network files, timestamp files, verification scripts, and `VERIFICATION.md`, is hashed in the manifest. Recommended: hash every member except the detached `manifest.sha256` file itself.
- Add package member inventory and duplicate-name checks before reading package content.
- Reject missing or malformed `manifest.json`, `manifest.sha256`, required hashes, invalid hash lengths, missing primary captured artifact, unsafe paths, empty timestamp material, and incomplete required artifacts.
- Make verification fail closed for missing manifest hashes and invalid JSON instead of warning and continuing.
- Add tests for valid packages, malformed manifests, missing hashes, unexpected members, duplicate members, incomplete packages, and hash mismatches.

**Acceptance:** A package verifies only when its manifest schema, member inventory, artifact hashes, timestamp status, and required files all satisfy the documented contract. Every failure returns a non-zero result with a specific message.

## Phase 2: Explicit capture status and provenance

**Goal:** Ensure partial collection cannot appear complete.

- Add `scope`, `stages`, `warnings`, and `omitted_artifacts` to the manifest.
- Record separate status for HTTP, DNS, TLS, WHOIS, browser rendering, legal-page discovery, legal-modal capture, WARC creation, report generation, and timestamping.
- Record tool version, Python version, browser version, operating system, URL, redirect chronology, capture timestamps, and configured options.
- Register browser console and page-error listeners before navigation.
- Preserve redirect request/response details in the raw capture and WARC where available.
- Mark reports as `complete`, `partial`, or `failed` and surface the status prominently.

**Acceptance:** A simulated browser, network, legal-page, report, or timestamp failure produces a package whose manifest and report visibly identify the affected stage and resulting limitations.

## Phase 3: Italian trust and timestamp validation

**Goal:** Separate cryptographic token validation from current qualified-service assessment.

- Replace static provider assumptions with a configurable TSA service record.
- Record TSA URL, provider name, certificate fingerprint, response status, token policy, generation time, trust-anchor source, trust-material hash, retrieval time, and validation scope.
- Preserve the applicable AgID Trusted List reference or snapshot hash outside or inside the package according to the case policy.
- Add explicit results for certificate-chain validation, revocation/status validation, and Trusted List/service-status validation.
- Avoid treating an endpoint URL, provider name, or successful OpenSSL chain check as proof of qualification.
- Prefer HTTPS endpoints where supported and document any required transport exception.
- Add Italian-specific tests for trust status wording, missing trust material, stale trust material, and unverified qualification.

**Acceptance:** Italian output distinguishes `token imprint valid`, `certificate chain valid`, and `qualified service status independently. No report claims a qualified timestamp unless the separate validation record supports it.

## Phase 4: Operator authorization and custody

**Goal:** Make the operator and handling history explicit without storing private signing keys.

- Add structured authorization fields: operator identity, role, organization, tax code where appropriate, mandate/reference, scope, purpose, and acquisition location.
- Add a custody event model with event type, UTC time, actor, action, package hash, storage reference, and notes.
- Record clock source and any synchronization check used by the operator.
- Support external CMS/CAdES or PAdES signatures over the manifest or report, including certificate-chain references and verification status.
- Keep private-key operations outside WeBF.
- Update the Italian report to display recorded facts and clearly mark unavailable fields.

**Acceptance:** The package can be accompanied by an independently verifiable authorization and custody record, while unsigned or incomplete records are visibly marked as such.

## Phase 5: Italian operational validation

**Goal:** Prove the workflow under controlled conditions.

- Obtain current legal and trust-service review from an appropriately qualified Italian professional.
- Run an authorized sample capture using a current AgID-listed service and documented trust materials.
- Independently verify package inventory, hashes, RFC 3161 imprint/nonce, certificate chain, revocation/status evidence, and Trusted List reference.
- Inspect Italian HTML and PDF reports for neutral wording and accurate status labels.
- Record source revision, environment, tool versions, package hash, reviewer, validation results, and residual risks outside Git.
- Do not rewrite historical packages; label them as pre-remediation outputs.

**Acceptance:** A signed-off validation record exists for the supported Italian workflow, with all unavailable checks and residual risks explicitly recorded.

## Verification sequence

1. Run focused unit tests for the changed phase.
2. Run `./.venv/bin/python -m unittest discover tests -v`.
3. Run `make PYTHON=./.venv/bin/python quality` in a clean development environment.
4. Run dependency audit, SBOM generation, secret scan, and distribution inspection in CI or a release environment.
5. Perform the authorized Italian operational validation only after deterministic checks pass.

## Non-goals

- WeBF will not determine legal admissibility.
- WeBF will not claim current qualification solely from a configured endpoint or embedded signer certificate.
- WeBF will not store private signing keys.
- Historical capture packages and captured third-party content will not be rewritten.