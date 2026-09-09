"""Assemble the final ZIP capture package."""
import io
import hashlib
import json
import zipfile
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
    timestamp_trust_pem: bytes = b"",
    timestamp_untrusted_pem: bytes = b"",
) -> bytes:
    buf = io.BytesIO()
    members: dict[str, bytes] = {}

    members["manifest.json"] = manifest_bytes
    members["manifest.sha256"] = manifest_hashes["sha256"].encode()

    members["report/capture_report.html"] = report_html
    members["report/capture_report.pdf"] = report_pdf

    members["capture/page.warc.gz"] = warc_bytes
    if screenshot_full:
        members["capture/screenshot_full.png"] = screenshot_full
    if screenshot_vp:
        members["capture/screenshot_viewport.png"] = screenshot_vp
    if rendered_html:
        members["capture/page.html"] = rendered_html
    if page_pdf:
        members["capture/page.pdf"] = page_pdf
    members["capture/http_response_raw.bin"] = http_raw_bytes

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
        members["capture/legal/legal_index.json"] = json.dumps(
            legal_index, indent=2, ensure_ascii=False
        ).encode()
        for lc in legal_captures:
            slug = lc["slug"]
            if lc.get("embedded"):
                if lc.get("raw_html"):
                    members[f"capture/legal/{slug}/embedded_extract.html"] = lc["raw_html"]
                if lc.get("plain_text"):
                    members[f"capture/legal/{slug}/embedded_extract.txt"] = lc["plain_text"]
                if lc.get("modal_screenshot_png"):
                    members[f"capture/legal/{slug}/modal_screenshot.png"] = lc["modal_screenshot_png"]
                if lc.get("modal_rendered_html"):
                    members[f"capture/legal/{slug}/modal_rendered.html"] = lc["modal_rendered_html"]
                if lc.get("modal_pdf_bytes"):
                    members[f"capture/legal/{slug}/modal_page.pdf"] = lc["modal_pdf_bytes"]
            else:
                if lc.get("raw_html"):
                    members[f"capture/legal/{slug}/page.html"] = lc["raw_html"]
                if lc.get("raw_bytes"):
                    members[f"capture/legal/{slug}/http_response_raw.bin"] = lc["raw_bytes"]

    dns_json = json.dumps(network_result.get("dns", {}), indent=2, ensure_ascii=False).encode()
    members["network/dns.json"] = dns_json

    whois_raw = network_result.get("whois", {}).get("raw", "") or ""
    members["network/whois.txt"] = whois_raw.encode("utf-8", errors="replace")

    tls_data = network_result.get("tls") or {}
    members["network/tls_certificate.json"] = json.dumps(tls_data, indent=2).encode()

    members["timestamp/request.tsq"] = timestamp_result.get("tsq_bytes", b"")
    members["timestamp/response.tsr"] = timestamp_result.get("tsr_bytes", b"")

    ts_info = {
        "tsa_url": timestamp_result.get("tsa_url", ""),
        "data_hash_sha256": timestamp_result.get("data_hash_hex", ""),
        **timestamp_result.get("parsed", {}),
    }
    members["timestamp/timestamp_info.json"] = json.dumps(ts_info, indent=2).encode()

    verify_sh = _build_verify_script(timestamp_result)
    members["timestamp/verify.sh"] = verify_sh.encode()

    verify_ps1 = _build_verify_script_windows(timestamp_result)
    members["timestamp/verify.ps1"] = verify_ps1.encode()
    if timestamp_trust_pem:
        members["timestamp/tsa_trust.pem"] = timestamp_trust_pem
    if timestamp_untrusted_pem:
        members["timestamp/tsa_untrusted.pem"] = timestamp_untrusted_pem

    members["VERIFICATION.md"] = _build_verification_readme(
        manifest_hashes, artifact_hashes
    ).encode()

    package_hashes = {
        name: {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }
        for name, data in sorted(members.items())
    }
    package_hashes_bytes = json.dumps(
        package_hashes, indent=2, ensure_ascii=False
    ).encode()
    members["package_hashes.json"] = package_hashes_bytes
    members["package_hashes.sha256"] = hashlib.sha256(package_hashes_bytes).hexdigest().encode()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)

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

if [ -f "$SCRIPT_DIR/tsa_trust.pem" ]; then
    untrusted_args=()
    if [ -f "$SCRIPT_DIR/tsa_untrusted.pem" ]; then
        untrusted_args=(-untrusted "$SCRIPT_DIR/tsa_untrusted.pem")
    fi
    openssl ts -verify \\
        -queryfile "$SCRIPT_DIR/request.tsq" \\
        -in "$SCRIPT_DIR/response.tsr" \\
        -CAfile "$SCRIPT_DIR/tsa_trust.pem" \\
        "${{untrusted_args[@]}}" \\
        && echo "RESULT: TSA trust-chain verification PASSED." \\
        || {{ echo "RESULT: TSA trust-chain verification FAILED."; exit 1; }}
else
    echo "RESULT: TSA trust-chain NOT VERIFIED (provide tsa_trust.pem)."
    echo "The signer certificate embedded in the token is not a trust anchor."
fi

echo ""
echo "=== Timestamp details ==="
openssl ts -reply -in "$SCRIPT_DIR/response.tsr" -text 2>/dev/null | \\
  grep -E "(Status|Time stamp|TSA:|Serial Number)"
"""


def _build_verify_script_windows(ts_result: dict[str, Any]) -> str:
    tsa_url = ts_result.get("tsa_url", "")
    return f"""# RFC 3161 timestamp verification (PowerShell / Windows)
# Equivalent command: openssl ts -verify -queryfile request.tsq -in response.tsr
# Requires: OpenSSL available in PATH (e.g. from Git for Windows)
# Usage: pwsh verify.ps1

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "=== Verifying RFC 3161 timestamp token ==="
Write-Host "TSA: {tsa_url}"
Write-Host ""

$tsqPath = Join-Path $ScriptDir "request.tsq"
$tsrPath = Join-Path $ScriptDir "response.tsr"
$caPath  = Join-Path $ScriptDir "tsa_trust.pem"
$untrustedPath = Join-Path $ScriptDir "tsa_untrusted.pem"

if (-not (Test-Path $caPath)) {{
    Write-Host "RESULT: TSA trust-chain NOT VERIFIED (provide tsa_trust.pem)." -ForegroundColor Yellow
    Write-Host "The signer certificate embedded in the token is not a trust anchor."
}} else {{
    $verifyArgs = @("ts", "-verify", "-queryfile", $tsqPath, "-in", $tsrPath, "-CAfile", $caPath)
    if (Test-Path $untrustedPath) {{
        $verifyArgs += @("-untrusted", $untrustedPath)
    }}
    & openssl @verifyArgs
    if ($LASTEXITCODE -eq 0) {{
        Write-Host "RESULT: TSA trust-chain verification PASSED" -ForegroundColor Green
    }} else {{
        Write-Host "RESULT: TSA trust-chain verification FAILED" -ForegroundColor Red
        exit 1
    }}
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
        "# Capture Package Integrity Verification",
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
    lines.extend([
        "",
        "## Complete Package Member Checksums",
        "",
        "`package_hashes.json` contains SHA-256 and SHA-512 values for every other ZIP member.",
        "Verify its detached SHA-256 before comparing the individual member values:",
        "```",
        "sha256sum package_hashes.json",
        "```",
    ])
    return "\n".join(lines)
