"""Assemble the final ZIP evidence package."""
import io
import json
import zipfile
import datetime
from typing import Any


def assemble_package(
    manifest_bytes: bytes,
    manifest_hashes: dict[str, str],
    report_html: bytes,
    report_pdf: bytes,
    warc_bytes: bytes,
    screenshot_full: bytes,
    screenshot_vp: bytes,
    rendered_html: bytes,
    page_pdf: bytes,
    http_raw_bytes: bytes,
    network_result: dict[str, Any],
    timestamp_result: dict[str, Any],
    artifact_hashes: dict[str, dict[str, str]],
    legal_captures: list[dict] = (),
) -> bytes:
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("manifest.sha256", manifest_hashes["sha256"].encode())

        zf.writestr("report/forensic_report.html", report_html)
        zf.writestr("report/forensic_report.pdf", report_pdf)

        zf.writestr("capture/page.warc.gz", warc_bytes)
        if screenshot_full:
            zf.writestr("capture/screenshot_full.png", screenshot_full)
        if screenshot_vp:
            zf.writestr("capture/screenshot_viewport.png", screenshot_vp)
        if rendered_html:
            zf.writestr("capture/page.html", rendered_html)
        if page_pdf:
            zf.writestr("capture/page.pdf", page_pdf)
        zf.writestr("capture/http_response_raw.bin", http_raw_bytes)

        if legal_captures:
            legal_index = []
            for lc in legal_captures:
                entry: dict[str, Any] = {
                    "label": lc["label"],
                    "slug": lc["slug"],
                    "url": lc["url"],
                    "embedded": lc.get("embedded", False),
                }
                if not lc.get("embedded"):
                    entry["status_code"] = lc["http_result"].get("status_code")
                else:
                    entry["note"] = (
                        "Content is embedded in the main page. "
                        "See capture/page.warc.gz and capture/http_response_raw.bin."
                    )
                legal_index.append(entry)
            zf.writestr(
                "capture/legal/legal_index.json",
                json.dumps(legal_index, indent=2, ensure_ascii=False).encode(),
            )
            for lc in legal_captures:
                slug = lc["slug"]
                if lc.get("embedded"):
                    if lc.get("raw_html"):
                        zf.writestr(f"capture/legal/{slug}/embedded_extract.html", lc["raw_html"])
                    if lc.get("plain_text"):
                        zf.writestr(f"capture/legal/{slug}/embedded_extract.txt", lc["plain_text"])
                    if lc.get("modal_screenshot_png"):
                        zf.writestr(f"capture/legal/{slug}/modal_screenshot.png", lc["modal_screenshot_png"])
                    if lc.get("modal_rendered_html"):
                        zf.writestr(f"capture/legal/{slug}/modal_rendered.html", lc["modal_rendered_html"])
                    if lc.get("modal_pdf_bytes"):
                        zf.writestr(f"capture/legal/{slug}/modal_page.pdf", lc["modal_pdf_bytes"])
                else:
                    if lc.get("raw_html"):
                        zf.writestr(f"capture/legal/{slug}/page.html", lc["raw_html"])
                    if lc.get("raw_bytes"):
                        zf.writestr(
                            f"capture/legal/{slug}/http_response_raw.bin", lc["raw_bytes"]
                        )

        dns_json = json.dumps(
            network_result.get("dns", {}), indent=2, ensure_ascii=False
        ).encode()
        zf.writestr("network/dns.json", dns_json)

        whois_raw = network_result.get("whois", {}).get("raw", "") or ""
        zf.writestr("network/whois.txt", whois_raw.encode("utf-8", errors="replace"))

        tls_data = network_result.get("tls") or {}
        zf.writestr(
            "network/tls_certificate.json",
            json.dumps(tls_data, indent=2).encode(),
        )

        zf.writestr("timestamp/request.tsq", timestamp_result.get("tsq_bytes", b""))
        zf.writestr("timestamp/response.tsr", timestamp_result.get("tsr_bytes", b""))

        ts_info = {
            "tsa_url": timestamp_result.get("tsa_url", ""),
            "data_hash_sha256": timestamp_result.get("data_hash_hex", ""),
            **timestamp_result.get("parsed", {}),
        }
        zf.writestr(
            "timestamp/timestamp_info.json",
            json.dumps(ts_info, indent=2).encode(),
        )

        verify_sh = _build_verify_script(timestamp_result)
        zf.writestr("timestamp/verify.sh", verify_sh.encode())

        verify_ps1 = _build_verify_script_windows(timestamp_result)
        zf.writestr("timestamp/verify.ps1", verify_ps1.encode())

        zf.writestr(
            "VERIFICATION.md",
            _build_verification_readme(manifest_hashes, artifact_hashes).encode(),
        )

    buf.seek(0)
    return buf.read()


def _build_verify_script(ts_result: dict[str, Any]) -> str:
    tsa_url = ts_result.get("tsa_url", "")
    return f"""#!/usr/bin/env bash
# RFC 3161 timestamp verification
# Requires: OpenSSL >= 1.1.0
# Usage: bash verify.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

echo "=== Verifying RFC 3161 timestamp token ==="
echo "TSA: {tsa_url}"
echo ""

# Download the TSA CA certificate bundle if not present
if [ ! -f "$SCRIPT_DIR/tsa_ca.pem" ]; then
  echo "Fetching TSA certificate chain from response..."
  openssl ts -reply -in "$SCRIPT_DIR/response.tsr" -text 2>/dev/null | \\
    grep -A 100 "TSA Certificate:" | \\
    openssl x509 -inform PEM > "$SCRIPT_DIR/tsa_ca.pem" 2>/dev/null || true
fi

openssl ts -verify \\
  -queryfile "$SCRIPT_DIR/request.tsq" \\
  -in "$SCRIPT_DIR/response.tsr" \\
  -CAfile "$SCRIPT_DIR/tsa_ca.pem" \\
  && echo "RESULT: Timestamp VERIFIED — token is authentic and has not been tampered with." \\
  || echo "RESULT: Timestamp VERIFICATION FAILED."

echo ""
echo "=== Timestamp details ==="
openssl ts -reply -in "$SCRIPT_DIR/response.tsr" -text 2>/dev/null | \\
  grep -E "(Status|Time stamp|TSA:|Serial Number)"
"""


def _build_verify_script_windows(ts_result: dict[str, Any]) -> str:
    tsa_url = ts_result.get("tsa_url", "")
    return f"""# RFC 3161 timestamp verification (PowerShell / Windows)
# Requires: OpenSSL available in PATH (e.g. from Git for Windows)
# Usage: pwsh verify.ps1

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "=== Verifying RFC 3161 timestamp token ==="
Write-Host "TSA: {tsa_url}"
Write-Host ""

$tsqPath = Join-Path $ScriptDir "request.tsq"
$tsrPath = Join-Path $ScriptDir "response.tsr"
$caPath  = Join-Path $ScriptDir "tsa_ca.pem"

if (-not (Test-Path $caPath)) {{
    Write-Host "Extracting TSA certificate from response..."
    & openssl ts -reply -in $tsrPath -text 2>$null |
        Select-String -Pattern "Certificate:" -Context 0,100 |
        Out-String |
        & openssl x509 -inform PEM -out $caPath 2>$null
}}

& openssl ts -verify -queryfile $tsqPath -in $tsrPath -CAfile $caPath
if ($LASTEXITCODE -eq 0) {{
    Write-Host "RESULT: Timestamp VERIFIED" -ForegroundColor Green
}} else {{
    Write-Host "RESULT: Timestamp VERIFICATION FAILED" -ForegroundColor Red
}}

Write-Host ""
Write-Host "=== Timestamp details ==="
& openssl ts -reply -in $tsrPath -text 2>$null |
    Select-String -Pattern "Status|Time stamp|TSA:|Serial Number"
"""


def _build_verification_readme(
    manifest_hashes: dict[str, str],
    artifact_hashes: dict[str, dict[str, str]],
) -> str:
    lines = [
        "# Evidence Package Verification",
        "",
        "## Manifest Integrity",
        "",
        f"SHA-256: `{manifest_hashes.get('sha256', '')}`",
        f"SHA-512: `{manifest_hashes.get('sha512', '')}`",
        "",
        "Recompute with:",
        "```",
        "# Linux/macOS",
        "sha256sum manifest.json",
        "# Windows PowerShell",
        "Get-FileHash manifest.json -Algorithm SHA256",
        "```",
        "",
        "## RFC 3161 Timestamp Verification",
        "",
        "Run `timestamp/verify.sh` (Linux/macOS) or `timestamp/verify.ps1` (Windows).",
        "OpenSSL >= 1.1.0 must be available in PATH.",
        "",
        "## Individual Artifact Hashes",
        "",
        "| File | SHA-256 |",
        "|------|---------|",
    ]
    for name, hashes in sorted(artifact_hashes.items()):
        lines.append(f"| `{name}` | `{hashes.get('sha256', '')}` |")
    lines.append("")
    lines.append(
        "These hashes can be independently verified against the files "
        "inside this ZIP to confirm no tampering has occurred."
    )
    return "\n".join(lines)
