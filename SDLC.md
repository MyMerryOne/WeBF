# Software Development Lifecycle Controls

## Purpose

WeBF is a Web Capture and Verification Tool. It records public web content and technical metadata for authorized, documented review. These controls govern software changes; they do not determine legal admissibility or certify any capture.

## Change baseline

Every change should record its purpose, affected workflow, security and privacy impact, validation performed, and residual risk. Changes affecting capture scope, hashing, timestamping, packaging, provenance, reports, or jurisdiction language require focused regression tests and explicit review.

## Quality gate

Run the local gate from an activated development environment:

```sh
make quality
```

The gate runs deterministic tests, static checks, package building, and a repository package audit. The CI workflow runs it in a clean environment with the development extra installed. Live browser, network, TSA, and jurisdiction trust-list checks are separate controlled validation activities.

## Evidence and output handling

Treat captures, raw responses, reports, manifests, logs, timestamp material, certificates, and operator metadata as sensitive case material. Do not commit generated packages, credentials, private keys, or real case data. Use synthetic fixtures for tests.

Historical capture packages are immutable. If a defect affects interpretation or verification, preserve the original package and issue a corrected or superseding report with provenance.

## Release controls

A release requires a clean-environment install, test and static-check results, package inspection, dependency review, secret scan, SBOM, documentation review, version verification, reviewer approval, and an explicit disposition for unresolved risks. Record distribution hashes outside the repository. The dependency audit and SBOM jobs in CI are release evidence; a local run must not be represented as complete when those tools were unavailable.
