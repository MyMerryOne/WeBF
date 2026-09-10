"""Build the JSON manifest for an integrity-verifiable capture package."""
import json
import datetime
import platform
import re
from typing import Any

TOOL_VERSION = "1.0.0"
TOOL_NAME = "WeBF-CaptureVerification"
MANIFEST_SCHEMA_VERSION = "1.1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")


def expected_package_members(
    artifact_hashes: dict[str, dict[str, str]],
    timestamp_trust_material: bool,
) -> list[str]:
    """Return the complete member contract for a generated package."""
    members = {
        "manifest.json",
        "manifest.sha256",
        "package_hashes.json",
        "package_hashes.sha256",
        "report/capture_report.html",
        "report/capture_report.pdf",
        "network/dns.json",
        "network/whois.txt",
        "network/tls_certificate.json",
        "timestamp/request.tsq",
        "timestamp/response.tsr",
        "timestamp/timestamp_info.json",
        "timestamp/verify.sh",
        "timestamp/verify.ps1",
        "VERIFICATION.md",
        *artifact_hashes,
    }
    if any(name.startswith("capture/legal/") for name in artifact_hashes):
        members.add("capture/legal/legal_index.json")
    if timestamp_trust_material:
        members.update({"timestamp/tsa_trust.pem", "timestamp/tsa_untrusted.pem"})
    members.update({
        "timestamp/package-index-request.tsq",
        "timestamp/package-index-response.tsr",
        "timestamp/package-index-info.json",
    })
    return sorted(members)
def build_manifest(
    url: str,
    operator: str,
    case_ref: str,
    notes: str,
    jurisdiction_id: str,
    start_time_utc: datetime.datetime,
    end_time_utc: datetime.datetime,
    http_result: dict[str, Any],
    network_result: dict[str, Any],
    browser_result: dict[str, Any] | None,
    artifact_hashes: dict[str, dict[str, str]],
    tsa_url: str,
    extra_operator_fields: dict[str, str] | None = None,
    timestamp_trust_material: bool = False,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
        },
        "capture": {
            "target_url": url,
            "final_url": http_result.get("final_url", url),
            "page_title": (browser_result or {}).get("page_title", ""),
            "http_status": http_result.get("status_code"),
            "http_reason": http_result.get("reason", ""),
            "content_type": http_result.get("content_type", ""),
            "redirect_chain": http_result.get("redirect_chain", []),
            "elapsed_ms": http_result.get("elapsed_ms"),
            "ssl_verified": http_result.get("ssl_verified", True),
            "ssl_error": http_result.get("ssl_error"),
        },
        "timing": {
            "capture_start_utc": start_time_utc.isoformat(),
            "capture_end_utc": end_time_utc.isoformat(),
            "timezone": "UTC",
        },
        "operator": {
            "name": operator,
            "case_reference": case_ref,
            "notes": notes,
            **(extra_operator_fields or {}),
        },
        "jurisdiction": jurisdiction_id,
        "tsa_url": tsa_url,
        "network": {
            "hostname": network_result.get("hostname", ""),
            "dns": network_result.get("dns", {}),
            "tls": network_result.get("tls"),
            "whois_parsed": network_result.get("whois", {}).get("parsed", {}),
            "whois_raw": (network_result.get("whois", {}).get("raw", "") or "")[:1500],
        },
        "response_headers": http_result.get("response_headers", {}),
        "artifacts": artifact_hashes,
        "package_members": expected_package_members(artifact_hashes, timestamp_trust_material),
        "primary_evidence": "capture/page.warc.gz",
        "hash_algorithms": ["sha256", "sha512"],
        "signature": {
            "status": "not_applied",
            "scope": "manifest.json canonical bytes",
            "external_signer_required": True,
        },
        "timestamp_trust_material": timestamp_trust_material,
        "provenance": {
            "host_os": platform.platform(),
            "python_version": platform.python_version(),
            "clock": "System clock; timestamps recorded in UTC",
            "capture_method": "HTTP response capture with optional Playwright rendering",
        },
        "limitations": [
            "Browser screenshots, PDFs, and rendered HTML are derived renderings, not wire bytes.",
            "Network metadata and WHOIS results are observations at capture time and may be incomplete.",
            "A hash or timestamp does not establish authorship, truth of content, or legal admissibility.",
            "Operator signature, lawful authority, and chain-of-custody handling require separate evidence.",
        ],
    }
    return manifest


def serialize_manifest(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")


def validate_manifest(manifest: object) -> list[str]:
    """Return contract violations for a package manifest.

    Validation is deliberately structural and deterministic. It does not make
    legal conclusions or validate external timestamp-service status.
    """
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    required = (
        "schema_version", "tool", "capture", "timing", "operator",
        "jurisdiction", "artifacts", "primary_evidence", "hash_algorithms",
    )
    for field in required:
        if field not in manifest:
            errors.append(f"missing required field: {field}")

    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        errors.append(f"unsupported schema_version: {manifest.get('schema_version')!r}")

    tool = manifest.get("tool")
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not isinstance(tool.get("version"), str):
        errors.append("tool.name and tool.version must be strings")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        errors.append("artifacts must be a non-empty object")
        return errors

    algorithms = manifest.get("hash_algorithms")
    if not isinstance(algorithms, list) or not {"sha256", "sha512"}.issubset(algorithms):
        errors.append("hash_algorithms must include sha256 and sha512")

    package_members = manifest.get("package_members")
    if not isinstance(package_members, list) or not package_members:
        errors.append("package_members must be a non-empty list")
    elif len(package_members) != len(set(package_members)):
        errors.append("package_members must not contain duplicates")
    elif any(
        not isinstance(name, str)
        or not name
        or name.startswith("/")
        or ".." in name.split("/")
        for name in package_members
    ):
        errors.append("package_members contains an unsafe path")
    primary = manifest.get("primary_evidence")
    if not isinstance(primary, str) or primary not in artifacts:
        errors.append("primary_evidence must name an artifact")

    for name, hashes in artifacts.items():
        if not isinstance(name, str) or not name or name.startswith("/") or ".." in name.split("/"):
            errors.append(f"unsafe artifact path: {name!r}")
        if not isinstance(hashes, dict):
            errors.append(f"artifact hashes must be an object: {name}")
            continue
        sha256 = hashes.get("sha256")
        sha512 = hashes.get("sha512")
        if not isinstance(sha256, str) or not _SHA256_RE.fullmatch(sha256):
            errors.append(f"invalid SHA-256 hash: {name}")
        if not isinstance(sha512, str) or not _SHA512_RE.fullmatch(sha512):
            errors.append(f"invalid SHA-512 hash: {name}")

    return errors
