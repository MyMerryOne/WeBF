---
name: ssdlc-code-review
description: 'Review code changes using a secure software development lifecycle workflow. Use for SSDLC reviews, security reviews, pull-request reviews, release gates, threat-oriented regression analysis, and changes involving integrity, provenance, packaging, timestamps, reports, network capture, or sensitive evidence.'
argument-hint: '[diff, files, PR, or risk area to review]'
user-invocable: true
---

# SSDLC Code Review

Review changes for correctness, security, privacy, maintainability, and release risk. Findings are the primary output; a summary is secondary.

## Review Procedure

1. Establish scope and intent.
   - Inspect the diff and the changed files before exploring unrelated code.
   - Identify the requirement, affected user workflow, trust boundaries, data handled, and expected behavior.
   - Note whether the change affects capture scope, browser or network handling, URL or path handling, hashing, timestamps, WARC output, packaging or extraction, provenance, reports, jurisdiction wording, logging, or generated scripts.
   - Check repository instructions, `SECURITY.md`, `SDLC.md`, `CONTRIBUTING.md`, and the nearest tests before judging behavior.

2. Trace the controlling behavior.
   - Follow inputs from public interfaces to validation, state changes, external calls, file writes, and emitted artifacts.
   - Check both success and failure paths, including partial output, retries, cleanup, exceptions, and user-visible errors.
   - Treat archive extraction, path construction, template rendering, subprocess execution, browser content, network metadata, and timestamp verification as security-sensitive boundaries.

3. Assess security and privacy.
   - Look for URL validation gaps, SSRF, unsafe redirects, browser escape or script injection, path traversal, archive extraction hazards, unsafe template or shell interpolation, insecure deserialization, credential leakage, and log or report disclosure.
   - Verify that trust decisions are based on authenticated and verified data, not filenames, endpoint names, user-supplied metadata, or unchecked status fields.
   - Confirm that sensitive captures, raw responses, reports, manifests, certificates, timestamp material, operator identifiers, credentials, and local configuration are not added to source control, logs, screenshots, issues, or public output.
   - Confirm tests use synthetic fixtures and do not perform live browser, network, TSA, or trust-list calls.

4. Check integrity and provenance.
   - Confirm hashes cover the intended bytes and are checked at the right boundary.
   - Check that manifest, package, WARC, timestamp, verification, and report relationships remain internally consistent.
   - Ensure verification failures fail closed and cannot be converted into apparent success by fallback behavior.
   - Preserve historical packages; corrections should produce a superseding report or package with clear provenance rather than rewriting evidence.
   - Check that legal or jurisdictional text describes technical behavior accurately and does not imply legal admissibility or qualification without separate validation.

5. Evaluate tests and documentation.
   - Require focused regression tests for changed behavior, especially for packaging, integrity, timestamping, provenance, reports, jurisdiction language, and failure handling.
   - Prefer deterministic unit tests with synthetic inputs. Add boundary, malformed-input, negative, and permission/error cases where risk warrants them.
   - Check that public behavior, security impact, residual risk, and unavailable live validation are documented.
   - Treat missing tests as a finding when the changed risk cannot be established from existing coverage.

6. Run proportionate validation.
   - Run the narrowest relevant test first, then the repository gate when practical.
   - For this repository, use `python -m unittest discover tests -v` for deterministic tests and `make quality` for the standard gate.
   - Inspect build artifacts and tracked paths when packaging or release files change.
   - Treat live browser, network, TSA, and jurisdiction trust-list checks as separate controlled validation. Do not claim they passed when they were not run.
   - If tools or dependencies are unavailable, record the exact skipped check and its residual risk.

7. Report findings before summary.
   - For every finding, include severity, file and location, concrete failure mode, impact, and a minimal remediation direction.
   - Order findings by severity: blocking, high, medium, low, then informational.
   - Report only actionable issues grounded in the code or validation evidence. Do not speculate about hypothetical risks without a plausible trigger path.
   - State explicitly when no findings were found, followed by remaining test gaps or residual risk.

## Severity Guidance

- **Blocking**: evidence can be falsified, verification can report success for invalid data, secrets or real case material are exposed, or a release-critical control is bypassed.
- **High**: a realistic attacker can cross a trust boundary, access protected data, execute unintended code, corrupt packages, or materially misrepresent provenance.
- **Medium**: meaningful security, privacy, integrity, or reliability weakness requiring specific conditions or causing limited impact.
- **Low**: defense-in-depth gap, misleading error or terminology, maintainability issue with plausible operational impact, or missing narrow coverage.
- **Informational**: useful observation with no required corrective action.

## Completion Checklist

- [ ] Scope, affected workflow, and trust boundaries are identified.
- [ ] Changed behavior and failure paths were traced to their controlling implementation.
- [ ] Security, privacy, integrity, provenance, and terminology implications were assessed.
- [ ] Sensitive data and real case material remain out of tests, logs, issues, and tracked output.
- [ ] Focused tests were run or their absence is recorded.
- [ ] `make quality` was run when the environment supports it, or the skipped controls are named.
- [ ] Findings are severity-ordered and include locations, impact, and remediation direction.
- [ ] Residual risk and unavailable validation are stated.

## Review Output Format

Use this shape unless the user requests another format:

```text
Findings
- [severity] path:location - issue, impact, and remediation direction

Open questions or assumptions
- ...

Validation
- Commands/checks run: ...
- Checks unavailable or intentionally skipped: ...

Summary
- Change intent and overall disposition
- Residual risk
```