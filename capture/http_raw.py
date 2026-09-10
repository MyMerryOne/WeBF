"""Raw HTTP capture: status, headers, body, redirect chain."""
import time
from typing import Any
from urllib.parse import urljoin

import requests

from capture.url_policy import validate_public_url


TOOL_UA = (
    "Mozilla/5.0 (compatible; WeBF/1.0; "
    "+https://github.com/webf-capture)"
)


def capture_http(url: str, timeout: int = 30) -> dict[str, Any]:
    validate_public_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": TOOL_UA})

    redirect_chain: list[dict] = []
    current_url = url

    start_ts = time.time()
    # Disable automatic redirects: each Location target must pass the public
    # address policy before it is allowed to receive a request.
    for _ in range(10):
        try:
            response = session.get(
                current_url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                verify=True,
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                f"TLS certificate verification failed for capture target: {exc}"
            ) from exc

        location = response.headers.get("Location")
        if response.is_redirect and location:
            redirect_chain.append({
                "url": response.url,
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
            })
            current_url = urljoin(current_url, location)
            validate_public_url(current_url)
            continue
        break
    else:
        raise RuntimeError("redirect limit exceeded for capture target")

    elapsed_ms = int((time.time() - start_ts) * 1000)

    raw_body: bytes = response.content

    request_headers = dict(response.request.headers)

    result = {
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
        "ssl_verified": True,
    }
    return result


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
