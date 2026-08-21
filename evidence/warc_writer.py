"""Build an ISO 28500 WARC archive containing all capture artifacts."""
import io
import datetime
from typing import Any

from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

TOOL_VERSION = "WeBF-ForensicCapture/1.0"


def _utc_now_str() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_warc(
    url: str,
    http_result: dict[str, Any],
    browser_result: dict[str, Any],
    operator: str,
    case_ref: str,
) -> bytes:
    buf = io.BytesIO()
    writer = WARCWriter(buf, gzip=True)

    # warcinfo record — info must be a dict (warcio calls info.items() internally)
    warc_date = _utc_now_str()
    writer.write_record(
        writer.create_warcinfo_record(
            filename="page.warc.gz",
            info={
                "software": TOOL_VERSION,
                "operator": operator,
                "case-reference": case_ref,
                "format": "WARC File Format 1.1 (ISO 28500:2017)",
                "target-url": url,
            },
        )
    )

    # request record — build complete HTTP/1.1 request bytes; warcio auto-detects headers
    req_headers_text = "".join(
        f"{k}: {v}\r\n" for k, v in http_result.get("request_headers", {}).items()
    )
    req_payload = f"GET / HTTP/1.1\r\n{req_headers_text}\r\n".encode()
    writer.write_record(
        writer.create_warc_record(
            uri=url,
            record_type="request",
            payload=io.BytesIO(req_payload),
            length=len(req_payload),
            warc_headers_dict={"WARC-Date": warc_date},
        )
    )

    # response record — pass complete raw HTTP response (status + headers + body);
    # warcio auto-detects the StatusAndHeaders from the payload stream.
    raw_response = (
        f"HTTP/1.1 {http_result['status_code']} {http_result['reason']}\r\n"
    ).encode()
    for k, v in http_result.get("response_headers", {}).items():
        raw_response += f"{k}: {v}\r\n".encode()
    raw_response += b"\r\n" + http_result.get("raw_body", b"")

    writer.write_record(
        writer.create_warc_record(
            uri=http_result.get("final_url", url),
            record_type="response",
            payload=io.BytesIO(raw_response),
            length=len(raw_response),
            warc_headers_dict={"WARC-Date": warc_date},
        )
    )

    # rendered HTML resource record
    rendered_html = browser_result.get("rendered_html", b"")
    if rendered_html:
        writer.write_record(
            writer.create_warc_record(
                uri=url + "#rendered-html",
                record_type="resource",
                payload=io.BytesIO(rendered_html),
                length=len(rendered_html),
                warc_date=warc_date,
                warc_headers_dict={
                    "Content-Type": "text/html; charset=utf-8",
                    "WARC-Date": warc_date,
                    "WARC-Description": "Post-JavaScript rendered HTML",
                },
            )
        )

    # full-page screenshot resource record
    screenshot = browser_result.get("screenshot_full_png", b"")
    if screenshot:
        writer.write_record(
            writer.create_warc_record(
                uri=url + "#screenshot-full",
                record_type="resource",
                payload=io.BytesIO(screenshot),
                length=len(screenshot),
                warc_date=warc_date,
                warc_headers_dict={
                    "Content-Type": "image/png",
                    "WARC-Date": warc_date,
                    "WARC-Description": "Full-page screenshot",
                },
            )
        )

    # PDF resource record
    pdf_bytes = browser_result.get("pdf_bytes", b"")
    if pdf_bytes:
        writer.write_record(
            writer.create_warc_record(
                uri=url + "#pdf-rendering",
                record_type="resource",
                payload=io.BytesIO(pdf_bytes),
                length=len(pdf_bytes),
                warc_date=warc_date,
                warc_headers_dict={
                    "Content-Type": "application/pdf",
                    "WARC-Date": warc_date,
                    "WARC-Description": "PDF rendering (A4 print media)",
                },
            )
        )

    buf.seek(0)
    return buf.read()
