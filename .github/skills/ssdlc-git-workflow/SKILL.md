---
name: ssdlc-git-workflow
description: "Use for Git and GitHub work that needs SSDLC controls: reviewing diffs, preparing commits, opening or reviewing pull requests, release gates, provenance, sensitive evidence, or security and privacy risk."
argument-hint: "[task, diff, branch, commit, or pull request]"
user-invocable: true
---

# SSDLC Git Workflow

Use this workflow for repository changes and GitHub collaboration in WeBF. Keep findings and validation evidence separate from the change summary, and never represent an unavailable check as passed.

## 1. Establish the change

1. Read repository instructions and relevant `SECURITY.md`, `SDLC.md`, `CONTRIBUTING.md`, package-contract documentation, and nearby tests.
2. Inspect `git status --short --untracked-files=all`, the branch, and the complete diff before editing or committing.
3. State the requirement, affected workflow, trust boundaries, data handled, security and privacy impact, validation plan, and residual risk.
4. Keep unrelated user changes. Do not reset, checkout, clean, amend, rebase, force-push, or delete branches unless the user explicitly requests that exact operation.

## 2. Review the implementation

Trace changed inputs through validation, state changes, external calls, file writes, and emitted artifacts. Check success, failure, partial-output, retry, cleanup, and exception paths.

For WeBF, pay particular attention to:

- URL, redirect, DNS, TLS, browser, and network capture boundaries
- path construction, archive creation and extraction, subprocesses, and generated shell or PowerShell scripts
- hashing, manifests, WARC output, timestamp requests and responses, verification, packaging, and provenance
- report templates, jurisdiction wording, logs, operator metadata, and disclosure of case material

Assess URL validation, SSRF, path traversal, archive hazards, injection, credential leakage, unsafe deserialization, integrity bypasses, and misleading verification or legal claims. Trust decisions must use verified data rather than filenames, endpoint names, unchecked metadata, or status strings.

## 3. Protect repository contents

- Never commit captures, raw responses, reports, manifests, logs, certificates, timestamp material, credentials, private keys, local configuration, generated packages, or real case data.
- Use synthetic fixtures. Do not perform live browser, network, TSA, or trust-list calls in deterministic tests.
- Preserve historical packages and reports. Corrections require a new superseding artifact with clear provenance.
- Before staging, inspect the exact paths with `git diff --stat`, `git diff --cached --stat`, and `git diff --cached --name-status`; use `git diff --cached` for sensitive or release-related changes.
- If a secret or case artifact was staged, stop, unstage it, and report the exposure. Do not assume deletion from the working tree removes it from history.

## 4. Validate proportionately

Run the narrowest relevant deterministic test first, then the repository gate when practical:

```sh
python -m unittest discover tests -v
make quality
```

Use focused tests for changed modules. Packaging, integrity, timestamping, provenance, reports, jurisdiction wording, CLI behavior, schema, package members, and verification rules require focused regression coverage and documentation updates. Inspect built artifacts and tracked paths when packaging or release files change.

Record exact commands and results. Record unavailable checks separately, including dependency audit, secret scan, SBOM, live browser/network/TSA validation, and jurisdiction Trusted List validation. Do not claim `make quality` covers those controls.

## 5. Make commits safely

1. Stage only files belonging to one logical change; prefer `git add <paths>` over broad staging.
2. Review the staged patch, staged names, and staged status before committing.
3. Use an imperative, specific commit subject that explains the change. Keep commits atomic and avoid generated or unrelated files.
4. Put test commands and relevant risk or documentation notes in the commit body when they will help a reviewer.
5. After committing, verify `git status`, `git show --stat --oneline HEAD`, and the commit contents.

Do not rewrite shared history, sign commits on behalf of the user, or push without explicit authorization. If a commit is wrong, prefer a corrective commit unless the user explicitly asks for history rewriting and understands its scope.

## 6. Prepare or review GitHub changes

For a pull request, include the intent, affected workflow, security and privacy impact, tests and commands run, unavailable validation, documentation updates, residual risk, and reviewer questions. Keep real case material and secrets out of commits, issues, PR descriptions, comments, screenshots, and public artifacts.

For review, inspect the full diff and relevant history, then report actionable findings first in severity order. Each finding needs a severity, file and location, concrete failure mode, impact, and minimal remediation direction. State assumptions and open questions separately, followed by validation and a short disposition.

Use this output shape:

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

## Completion checklist

- [ ] Scope, intent, affected workflow, and trust boundaries are recorded.
- [ ] The complete diff and staged paths were inspected.
- [ ] Security, privacy, integrity, provenance, and terminology implications were assessed.
- [ ] Sensitive evidence, secrets, and real case material remain untracked and out of GitHub output.
- [ ] Focused tests were run, or the exact gap and residual risk were recorded.
- [ ] `make quality` was run when supported, or the skipped gate is named.
- [ ] Documentation and package-contract updates were made when required.
- [ ] Commit or PR content is atomic, reviewable, and free of unrelated changes.
- [ ] Findings, validation evidence, unavailable checks, and disposition are explicit.