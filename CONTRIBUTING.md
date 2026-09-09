# Contributing

## Before changing code

Describe the requirement or issue, affected capture or reporting workflow, security and privacy impact, and residual risk. Do not use real captures, credentials, private keys, or generated case packages in changes.

## Validation

Run focused tests for the changed module, then run:

```sh
make quality
```

Changes to packaging, integrity, timestamping, provenance, reports, or jurisdiction language require regression coverage and a note explaining any unavailable live validation.

## Review

Reviewers check behavior, failure handling, package and provenance implications, sensitive-data exposure, terminology, documentation, and test results. Changes that affect legal or jurisdictional wording require explicit review and must not imply legal admissibility without separate validation.
