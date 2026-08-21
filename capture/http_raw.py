"""Raw HTTP capture: status, headers, body, redirect chain."""
import time
from typing import Any
import requests


TOOL_UA = (
    "Mozilla/5.0 (compatible; WeBF-ForensicCapture/1.0; "
    "+https://github.com/webf-forensic)"
)


def capture_http(url: str, timeout: int = 30) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update({"User-Agent": TOOL_UA})

    redirect_chain: list[dict] = []

    start_ts = time.time()
    response = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
    elapsed_ms = int((time.time() - start_ts) * 1000)

    for r in response.history:
        redirect_chain.append({
            "url": r.url,
            "status_code": r.status_code,
            "reason": r.reason,
            "headers": dict(r.headers),
        })

    raw_body: bytes = response.content

    request_headers = dict(response.request.headers)

    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "reason": response.reason,
        "http_version": "HTTP/1.1",
        "elapsed_ms": elapsed_ms,
        "redirect_chain": redirect_chain,
        "request_headers": request_headers,
        "response_headers": dict(response.headers),
        "content_type": response.headers.get("Content-Type", ""),
        "content_length_header": response.headers.get("Content-Length"),
        "actual_body_bytes": len(raw_body),
        "raw_body": raw_body,
    }


def build_raw_http_bytes(result: dict[str, Any]) -> bytes:
    """Reconstruct a raw HTTP/1.1 response bytes for archival."""
    status_line = (
        f"HTTP/1.1 {result['status_code']} {result['reason']}\r\n"
    ).encode()
    headers_block = b"".join(
        f"{k}: {v}\r\n".encode()
        for k, v in result["response_headers"].items()
    )
    return status_line + headers_block + b"\r\n" + result["raw_body"]
