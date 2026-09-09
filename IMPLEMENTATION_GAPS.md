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
| Release automation | CI, dependency audit, SBOM, and secret scanning are configured, but the first CI run and release evidence are still outstanding. | Release evidence is not yet operationally proven. | Execute CI and retain the release record, audit result, SBOM, and distribution hashes. |
| Italian trust validation | Certificate-chain validation does not validate current AgID Trusted List status, revocation, service identity, or trust-material provenance. | A valid chain could be mistaken for proof of qualified-service status. | Add an explicit trust-validation record and require independent current-list validation. |
| Operator and custody record | The Italian report contains a declaration and signature line but no structured authorization or custody event history. | Identity, scope, storage, and transfer chronology are not independently represented. | Add manifest authorization, environment, and custody-event structures; support external signing. |
