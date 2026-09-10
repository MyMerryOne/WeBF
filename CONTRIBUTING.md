# Contributing

## Before changing code

Describe the requirement or issue, affected capture or reporting workflow, security and privacy impact, and residual risk. Do not use real captures, credentials, private keys, or generated case packages in changes.

For user-visible changes, update the relevant Markdown documentation, report template, or package contract in the same change. Do not add generated capture packages or real case data to the repository. Historical packages are immutable; test corrections should use synthetic fixtures or produce a new superseding artifact.

## Validation

Run focused tests for the changed module, then run:

```sh
make quality
```

Changes to packaging, integrity, timestamping, provenance, reports, or jurisdiction language require regression coverage and a note explaining any unavailable live validation.

Useful focused commands include:

```sh
python -m unittest tests.test_manifest -v
python -m unittest tests.test_bundler -v
python -m unittest tests.test_timestamper -v
python -m unittest tests.test_terminology -v
```

`make quality` covers the deterministic local gate. Dependency auditing, SBOM generation, secret scanning, live browser/network/TSA checks, and current jurisdiction trust-list validation are separate controls and must be recorded separately when run.

## Review

Reviewers check behavior, failure handling, package and provenance implications, sensitive-data exposure, terminology, documentation, and test results. Changes that affect legal or jurisdictional wording require explicit review and must not imply legal admissibility without separate validation.
