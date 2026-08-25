"""Build the JSON manifest — the root-of-trust for the evidence package."""
import json
import datetime
import platform
from typing import Any

TOOL_VERSION = "1.0.0"
TOOL_NAME = "WeBF-ForensicCapture"


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
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
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
        "primary_evidence": "capture/page.warc.gz",
        "hash_algorithms": ["sha256", "sha512"],
        "signature": {
            "status": "not_applied",
            "scope": "manifest.json canonical bytes",
            "external_signer_required": True,
        },
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
