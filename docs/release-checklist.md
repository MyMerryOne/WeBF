# Release Checklist

Record the release version, source revision, reviewer, and residual-risk decision with the release record.

- [ ] Requirement, affected workflows, security impact, and residual risk documented.
- [ ] Focused regression tests added and passing.
- [ ] `make quality` passes in a clean development environment.
- [ ] Supported Python version and dependency inventory reviewed.
- [ ] Dependency audit completed or findings explicitly accepted.
- [ ] Secret scan completed.
- [ ] SBOM generated and retained with the release record.
- [ ] Source and wheel distributions built and inspected.
- [ ] Distribution SHA-256 values recorded outside the repository.
- [ ] CLI version and entry point checks pass.
- [ ] Package inventory and independent verification tested.
- [ ] Documentation, report language, and terminology reviewed.
- [ ] Live browser/network/TSA validation documented separately when required.
- [ ] Reviewer approval recorded.
- [ ] Correction, rollback, and disclosure decisions recorded where applicable.
