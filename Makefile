.PHONY: quality test lint typecheck build package-audit secret-scan dependency-audit sbom

PYTHON ?= python3

quality: test lint typecheck build package-audit
	@echo "Quality gate passed"

test:
	$(PYTHON) -m unittest discover tests -v

lint:
	@if command -v ruff >/dev/null 2>&1; then ruff check capture evidence jurisdiction packaging tests webf.py; else echo "ruff is not installed; install the dev extra before release."; fi

typecheck:
	@if command -v mypy >/dev/null 2>&1; then mypy capture evidence jurisdiction packaging webf.py; else echo "mypy is not installed; install the dev extra before release."; fi

build:
	@if $(PYTHON) -c 'import build' >/dev/null 2>&1; then $(PYTHON) -m build; else echo "build is not installed; install the dev extra before release."; fi

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
