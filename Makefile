.PHONY: quality test lint typecheck build package-audit secret-scan dependency-audit sbom

PYTHON ?= python3

quality: test lint typecheck build package-audit
	@echo "Quality gate passed"

test:
	$(PYTHON) -m unittest discover tests -v

lint:
	@$(PYTHON) -m ruff --version >/dev/null 2>&1 || { echo "ruff is not installed; install the dev extra before release." >&2; exit 1; }
	$(PYTHON) -m ruff check capture evidence jurisdiction packaging tests webf.py

typecheck:
	@$(PYTHON) -m mypy --version >/dev/null 2>&1 || { echo "mypy is not installed; install the dev extra before release." >&2; exit 1; }
	$(PYTHON) -m mypy capture evidence jurisdiction packaging webf.py

build:
	@$(PYTHON) -c 'import build' >/dev/null 2>&1 || { echo "build is not installed; install the dev extra before release." >&2; exit 1; }
	$(PYTHON) -m build

package-audit:
	@set -eu; \
	bad="$$(git ls-files | awk 'tolower($$0) ~ /(^|\/)(captures|output|secrets|credentials)(\/|$$)/ || tolower($$0) ~ /(^|\/)(\.env|.*\.(crypt|db|sqlite|sqlite3|ab|pem|key|p12|pfx|tsq|tsr|warc|warc\.gz|zip))$$/')"; \
	if [ -n "$$bad" ]; then echo "Forbidden generated or sensitive paths tracked:"; printf '%s\n' "$$bad"; exit 1; fi

secret-scan:
	@if command -v gitleaks >/dev/null 2>&1; then gitleaks detect --source . --no-banner; else echo "gitleaks is not installed; run it before release sign-off."; fi

dependency-audit:
	@$(PYTHON) -m pip_audit

sbom:
	@$(PYTHON) -m cyclonedx_py environment $(PYTHON) -o /tmp/webf-sbom.json
	@echo "SBOM written to /tmp/webf-sbom.json"
