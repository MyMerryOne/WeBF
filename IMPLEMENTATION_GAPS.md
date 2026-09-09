# Implementation Gaps

This file tracks known limitations that affect technical interpretation, operational readiness, or release confidence.

| Area | Gap | Risk | Planned treatment |
| --- | --- | --- | --- |
| Package integrity | Not every generated package member is currently represented in the manifest hash set. | A package can be incomplete without a single manifest contract detecting it. | Define and test complete package inventory coverage. |
| Capture status | Stage failures are not yet represented as a structured manifest status. | Partial collection can appear complete. | Add stage status, warnings, and omitted-artifact fields. |
| Verification | Malformed manifests and some missing verification material need clearer non-zero outcomes. | Independent reviewers may receive ambiguous results. | Harden schema and failure validation. |
| Browser diagnostics | Console listeners are registered after navigation. | Page-load errors can be missed. | Register diagnostics before navigation. |
| Redirect provenance | The archive currently emphasizes the terminal response. | Redirect context may be incomplete. | Preserve and test redirect chronology. |
| Terminology | Existing generated packages contain pre-migration labels. | Historical output may not match current product language. | Do not rewrite historical packages; regenerate new outputs and document the boundary. |
| Release automation | CI, dependency audit, SBOM, and secret scanning are not yet configured. | Release evidence is inconsistent. | Add the documented quality and release controls. |
