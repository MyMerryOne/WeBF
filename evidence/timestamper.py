"""RFC 3161 trusted timestamping client.

Builds a TimeStampReq (DER), POSTs it to a TSA, and returns the raw .tsr bytes
together with a human-readable summary of the token.  The page content is never
sent — only a SHA-256 hash of the manifest leaves the machine.
"""
import hashlib
from typing import Any

import requests
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1_modules import rfc3161, rfc5652

from evidence.der_helpers import build_timestamp_request


def send_timestamp_request(tsq_bytes: bytes, tsa_url: str, timeout: int = 30) -> bytes:
    resp = requests.post(
        tsa_url,
        data=tsq_bytes,
        headers={"Content-Type": "application/timestamp-query"},
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(
            f"TSA returned HTTP {resp.status_code}: {resp.text[:200]}"
        )
    content_type = resp.headers.get("Content-Type", "")
    if "timestamp-reply" not in content_type and "octet-stream" not in content_type:
        raise RuntimeError(
            f"Unexpected Content-Type from TSA: {content_type!r}"
        )
    return resp.content


def parse_timestamp_response(tsr_bytes: bytes) -> dict[str, Any]:
    """Parse the .tsr and extract human-readable fields."""
    try:
        ts_resp, _ = der_decoder.decode(tsr_bytes, asn1Spec=rfc3161.TimeStampResp())

        status = int(ts_resp["status"]["status"])
        status_label = {
            0: "granted",
            1: "grantedWithMods",
            2: "rejection",
            3: "waiting",
            4: "revocationWarning",
            5: "revocationNotification",
        }.get(status, str(status))

        result: dict[str, Any] = {"status": status_label}

        if status not in (0, 1):
            result["failure_info"] = str(ts_resp["status"]["failInfo"])
            return result

        # Extract TSTInfo from ContentInfo → [0] EXPLICIT SignedData → encapContentInfo
        try:
            token = ts_resp["timeStampToken"]
            # token["content"] is Any with a [0] EXPLICIT tag wrapping the SignedData SEQUENCE.
            # Strip the [0] EXPLICIT tag+length bytes to reach the inner SEQUENCE.
            content_der = der_encoder.encode(token["content"])
            len_byte = content_der[1]
            offset = 2 if len_byte < 0x80 else (3 if len_byte == 0x81 else 4)
            signed_data, _ = der_decoder.decode(
                content_der[offset:], asn1Spec=rfc5652.SignedData()
            )
            e_content = bytes(signed_data["encapContentInfo"]["eContent"])
            tst_info, _ = der_decoder.decode(e_content, asn1Spec=rfc3161.TSTInfo())

            result.update({
                "gen_time": str(tst_info["genTime"]),
                "serial_number": str(int(tst_info["serialNumber"])),
                "tsa_policy": str(tst_info["policy"]),
            })
        except Exception as inner_exc:
            result["tst_info_note"] = f"TSTInfo not parseable: {inner_exc}"

        return result

    except Exception as exc:
        return {"status": "parse_error", "error": str(exc)}


def validate_timestamp_response(
    tsq_bytes: bytes,
    tsr_bytes: bytes,
    expected_data: bytes,
) -> dict[str, Any]:
    """Validate the RFC 3161 imprint and nonce against the original request."""
    try:
        ts_req, _ = der_decoder.decode(tsq_bytes, asn1Spec=rfc3161.TimeStampReq())
        ts_resp, _ = der_decoder.decode(tsr_bytes, asn1Spec=rfc3161.TimeStampResp())
        status = int(ts_resp["status"]["status"])
        if status not in (0, 1):
            return {"imprint_valid": False, "nonce_valid": False, "error": "timestamp was not granted"}

        token = ts_resp["timeStampToken"]
        content_der = der_encoder.encode(token["content"])
        len_byte = content_der[1]
        offset = 2 if len_byte < 0x80 else (3 if len_byte == 0x81 else 4)
        signed_data, _ = der_decoder.decode(
            content_der[offset:], asn1Spec=rfc5652.SignedData()
        )
        e_content = bytes(signed_data["encapContentInfo"]["eContent"])
        tst_info, _ = der_decoder.decode(e_content, asn1Spec=rfc3161.TSTInfo())

        request_digest = bytes(ts_req["messageImprint"]["hashedMessage"])
        expected_digest = hashlib.sha256(expected_data).digest()
        token_digest = bytes(tst_info["messageImprint"]["hashedMessage"])
        request_nonce = int(ts_req["nonce"])
        token_nonce = int(tst_info["nonce"]) if tst_info["nonce"] is not None else None
        return {
            "imprint_valid": (
                request_digest == expected_digest
                and token_digest == request_digest
            ),
            "nonce_valid": token_nonce == request_nonce,
            "hash_algorithm": str(ts_req["messageImprint"]["hashAlgorithm"]["algorithm"]),
        }
    except Exception as exc:
        return {
            "imprint_valid": False,
            "nonce_valid": False,
            "error": f"timestamp validation failed: {exc}",
        }


def request_timestamp(
    manifest_bytes: bytes,
    tsa_url: str,
) -> dict[str, Any]:
    """Full RFC 3161 flow. Returns dict with tsq, tsr, and parsed info."""
    tsq_bytes, data_hash = build_timestamp_request(manifest_bytes)
    tsr_bytes = send_timestamp_request(tsq_bytes, tsa_url)
    parsed = parse_timestamp_response(tsr_bytes)
    validation = validate_timestamp_response(tsq_bytes, tsr_bytes, manifest_bytes)
    parsed["validation"] = validation
    parsed["trust"] = {
        "status": "external_validation_required",
        "qualification": "not_established_by_webf",
        "network_policy": "configurable",
    }
    return {
        "tsq_bytes": tsq_bytes,
        "tsr_bytes": tsr_bytes,
        "data_hash_hex": data_hash.hex(),
        "tsa_url": tsa_url,
        "parsed": parsed,
    }
