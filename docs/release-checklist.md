# Release Checklist

Record the release version, source revision, reviewer, validation environment, and residual-risk decision with the release record.

## Local deterministic gate

- [ ] Requirement, affected workflows, security impact, and residual risk documented.
- [ ] Focused regression tests added and passing.
- [ ] `make quality` passes in a clean development environment.
- [ ] The quality gate used the intended Python environment and did not skip missing `ruff`, `mypy`, or `build` tools.
- [ ] Supported Python version and dependency inventory reviewed.
- [ ] Source and wheel distributions built and inspected.
- [ ] CLI version and entry point checks pass.
- [ ] Package inventory and independent verification tested.

## CI security and release evidence

- [ ] Dependency audit completed or findings explicitly accepted.
- [ ] Secret scan completed.
- [ ] SBOM generated and retained with the release record.
- [ ] Distribution SHA-256 values recorded outside the repository.

## Live and jurisdiction validation

- [ ] Live browser/network/TSA validation documented separately when required.
- [ ] Browser isolated-egress proxy configuration and private-peer rejection validated when required.
- [ ] TSA certificate-chain, revocation, and current Trusted List/service-status checks recorded separately where claimed.

## Documentation and approval

- [ ] Manifest schema and package-contract compatibility reviewed.
- [ ] Documentation, report language, and terminology reviewed.
- [ ] Historical capture packages and generated reports were not rewritten.
- [ ] Reviewer approval recorded.
- [ ] Correction, rollback, and disclosure decisions recorded where applicable.
