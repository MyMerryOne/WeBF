"""WeBF — Web Forensic Capture Tool.

Usage:
  webf capture <URL> --operator NAME [--case-ref REF] [--notes TEXT]
               [--jurisdiction eu|it|cz] [--tsa-url URL] [--output-dir DIR]
               [--no-browser]
  webf verify  <package.zip>
  webf info    <package.zip>
"""
import datetime
import hashlib
import json
import pathlib
import re
import sys
import zipfile

import click

TOOL_VERSION = "1.0.0"


# ── helpers ──────────────────────────────────────────────────────────────────


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _sanitise_domain(url: str) -> str:
    domain = re.sub(r"https?://", "", url).split("/")[0].split("?")[0]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain)[:40]


def _package_name(url: str, ts: datetime.datetime) -> str:
    stamp = ts.strftime("%Y%m%d_%H%M%S")
    return f"webf_{stamp}_{_sanitise_domain(url)}.zip"


def _echo_step(msg: str) -> None:
    click.echo(f"  {msg}")


def _echo_ok(msg: str) -> None:
    click.echo(click.style(f"  ✓ {msg}", fg="green"))


def _echo_warn(msg: str) -> None:
    click.echo(click.style(f"  ⚠ {msg}", fg="yellow"), err=True)


def _echo_err(msg: str) -> None:
    click.echo(click.style(f"  ✗ {msg}", fg="red"), err=True)


# ── CLI definition ────────────────────────────────────────────────────────────


@click.group()
@click.version_option(TOOL_VERSION, prog_name="webf")
def cli() -> None:
    """WeBF — Web Forensic Capture Tool for EU court proceedings."""


# ── capture command ───────────────────────────────────────────────────────────


@cli.command("capture")
@click.argument("url")
@click.option("--operator", required=True, help="Full name of the person performing the capture.")
@click.option("--case-ref", default="", help="Case reference number.")
@click.option("--notes", default="", help="Free-text contextual notes.")
@click.option(
    "--jurisdiction",
    default="eu",
    type=click.Choice(["eu", "it", "cz"], case_sensitive=False),
    show_default=True,
    help="Jurisdiction profile: eu (eIDAS), it (Italy CAD), cz (Czech Republic).",
)
@click.option("--tsa-url", default=None, help="Override TSA endpoint URL.")
@click.option(
    "--output-dir",
    default="./captures",
    show_default=True,
    help="Directory where the ZIP package will be written.",
)
@click.option("--no-browser", is_flag=True, help="Skip Playwright rendering (HTTP + WARC only).")
@click.option(
    "--operator-role",
    default="",
    help="[Italy only] Professional role of the operator (e.g. Consulente Tecnico d'Ufficio).",
)
@click.option(
    "--operator-cf",
    default="",
    help="[Italy only] Codice Fiscale of the operator.",
)
def capture_cmd(
    url: str,
    operator: str,
    case_ref: str,
    notes: str,
    jurisdiction: str,
    tsa_url: str | None,
    output_dir: str,
    no_browser: bool,
    operator_role: str,
    operator_cf: str,
) -> None:
    """Capture a public web page and produce a court-ready evidence package."""
    from jurisdiction import get_profile
    from capture.http_raw import capture_http, build_raw_http_bytes
    from capture.network import capture_network
    from capture.browser import capture_browser
    from evidence.hasher import hash_bytes, hash_artifacts
    from evidence.timestamper import request_timestamp
    from evidence.warc_writer import build_warc
    from packaging.manifest import build_manifest, serialize_manifest
    from packaging.report import render_html_report, render_pdf_report
    from packaging.bundler import assemble_package

    profile = get_profile(jurisdiction)
    effective_tsa = tsa_url or profile["tsa_url"]

    extra_op: dict[str, str] = {}
    if jurisdiction == "it":
        if operator_role:
            extra_op["operator_role"] = operator_role
        if operator_cf:
            extra_op["operator_cf"] = operator_cf

    click.echo("")
    click.echo(click.style("WeBF — Web Forensic Capture", bold=True))
    click.echo(f"  Target   : {url}")
    click.echo(f"  Operator : {operator}")
    click.echo(f"  Jurisdiction: {profile['name']}")
    click.echo(f"  TSA      : {effective_tsa}")
    click.echo("")

    start_time = _utc_now()

    # 1. Network info
    _echo_step("Resolving DNS, WHOIS, TLS certificate...")
    try:
        network_result = capture_network(url)
        _echo_ok("Network information captured.")
    except Exception as exc:
        _echo_warn(f"Network capture partial: {exc}")
        network_result = {"hostname": "", "scheme": "", "dns": {}, "tls": None, "whois": {}}

    # 2. Raw HTTP
    _echo_step("Fetching raw HTTP response...")
    try:
        http_result = capture_http(url)
        _echo_ok(f"HTTP {http_result['status_code']} received ({http_result['actual_body_bytes']:,} bytes).")
    except Exception as exc:
        _echo_err(f"HTTP capture failed: {exc}")
        sys.exit(1)

    # 3. Browser
    browser_result: dict = {}
    if not no_browser:
        _echo_step("Launching headless browser (screenshot, PDF, rendered HTML)...")
        try:
            browser_result = capture_browser(url)
            _echo_ok(f"Browser capture complete. Title: {browser_result.get('page_title', '')!r}")
        except Exception as exc:
            _echo_warn(f"Browser capture failed: {exc}. Continuing without browser artifacts.")

    # 4. WARC
    _echo_step("Building ISO 28500 WARC archive...")
    try:
        warc_bytes = build_warc(url, http_result, browser_result, operator, case_ref)
        _echo_ok(f"WARC archive built ({len(warc_bytes):,} bytes).")
    except Exception as exc:
        _echo_warn(f"WARC build failed: {exc}")
        warc_bytes = b""

    # 5. Collect artifacts for hashing
    raw_http_bytes = build_raw_http_bytes(http_result)
    artifacts: dict[str, bytes] = {
        "capture/page.warc.gz": warc_bytes,
        "capture/http_response_raw.bin": raw_http_bytes,
    }
    if browser_result.get("screenshot_full_png"):
        artifacts["capture/screenshot_full.png"] = browser_result["screenshot_full_png"]
    if browser_result.get("screenshot_viewport_png"):
        artifacts["capture/screenshot_viewport.png"] = browser_result["screenshot_viewport_png"]
    if browser_result.get("rendered_html"):
        artifacts["capture/page.html"] = browser_result["rendered_html"]
    if browser_result.get("pdf_bytes"):
        artifacts["capture/page.pdf"] = browser_result["pdf_bytes"]

    # 6. Hash artifacts
    _echo_step("Computing SHA-256 / SHA-512 hashes...")
    artifact_hashes = hash_artifacts(artifacts)
    _echo_ok(f"Hashed {len(artifact_hashes)} artifacts.")

    # 7. Build manifest
    end_time = _utc_now()
    manifest = build_manifest(
        url=url,
        operator=operator,
        case_ref=case_ref,
        notes=notes,
        jurisdiction_id=jurisdiction,
        start_time_utc=start_time,
        end_time_utc=end_time,
        http_result=http_result,
        network_result=network_result,
        browser_result=browser_result or None,
        artifact_hashes=artifact_hashes,
        tsa_url=effective_tsa,
        extra_operator_fields=extra_op or None,
    )
    manifest_bytes = serialize_manifest(manifest)
    manifest_hashes = hash_bytes(manifest_bytes)
    _echo_ok("Manifest built.")

    # 8. RFC 3161 timestamp
    _echo_step(f"Requesting RFC 3161 timestamp from {effective_tsa} ...")
    try:
        timestamp_result = request_timestamp(manifest_bytes, effective_tsa)
        ts_status = timestamp_result["parsed"].get("status", "unknown")
        if ts_status in ("granted", "grantedWithMods"):
            _echo_ok(f"Timestamp received: {timestamp_result['parsed'].get('gen_time', '')}")
        else:
            _echo_warn(f"TSA status: {ts_status}")
    except Exception as exc:
        _echo_warn(f"Timestamping failed ({exc}). Package will be created without timestamp token.")
        timestamp_result = {
            "tsq_bytes": b"",
            "tsr_bytes": b"",
            "data_hash_hex": manifest_hashes["sha256"],
            "tsa_url": effective_tsa,
            "parsed": {"status": "error", "error": str(exc)},
        }

    # 9. Generate reports
    _echo_step("Generating forensic report (HTML + PDF)...")
    ts_info_for_report = {
        "tsa_url": effective_tsa,
        "data_hash_sha256": manifest_hashes["sha256"],
        **timestamp_result.get("parsed", {}),
    }
    try:
        report_html = render_html_report(manifest, ts_info_for_report, profile, extra_op)
        _echo_ok("HTML report rendered.")
    except Exception as exc:
        _echo_warn(f"HTML report rendering failed: {exc}.")
        report_html = b"<html><body>Report generation failed.</body></html>"

    report_pdf = b""
    try:
        report_pdf = render_pdf_report(report_html)
        _echo_ok("PDF report rendered.")
    except Exception as exc:
        _echo_warn(f"PDF report skipped (requires playwright): {exc}")

    # 10. Assemble ZIP
    _echo_step("Assembling evidence package...")
    zip_bytes = assemble_package(
        manifest_bytes=manifest_bytes,
        manifest_hashes=manifest_hashes,
        report_html=report_html,
        report_pdf=report_pdf,
        warc_bytes=warc_bytes,
        screenshot_full=browser_result.get("screenshot_full_png", b""),
        screenshot_vp=browser_result.get("screenshot_viewport_png", b""),
        rendered_html=browser_result.get("rendered_html", b""),
        page_pdf=browser_result.get("pdf_bytes", b""),
        http_raw_bytes=raw_http_bytes,
        network_result=network_result,
        timestamp_result=timestamp_result,
        artifact_hashes=artifact_hashes,
    )

    out_dir = pathlib.Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pkg_name = _package_name(url, start_time)
    pkg_path = out_dir / pkg_name
    pkg_path.write_bytes(zip_bytes)
    _echo_ok(f"Package written: {pkg_path} ({len(zip_bytes):,} bytes)")

    # Summary
    click.echo("")
    click.echo(click.style("── Evidence Package Summary ─────────────────────────", bold=True))
    click.echo(f"  Package   : {pkg_path}")
    click.echo(f"  Manifest  : SHA-256 = {manifest_hashes['sha256']}")
    click.echo(f"  Timestamp : {ts_info_for_report.get('gen_time') or 'not available'}")
    click.echo(f"  TSA       : {effective_tsa}")
    click.echo(f"  Primary   : capture/page.warc.gz (ISO 28500:2017)")
    click.echo("")
    click.echo("  To verify: python webf.py verify " + str(pkg_path))
    click.echo("")


# ── verify command ────────────────────────────────────────────────────────────


@cli.command("verify")
@click.argument("package_path", type=click.Path(exists=True))
def verify_cmd(package_path: str) -> None:
    """Verify the integrity of an evidence package (hashes + timestamp token)."""
    path = pathlib.Path(package_path)
    click.echo(f"\nVerifying: {path}\n")

    all_ok = True

    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()

        # Load manifest
        if "manifest.json" not in names:
            _echo_err("manifest.json not found in package.")
            sys.exit(1)

        manifest_bytes = zf.read("manifest.json")
        manifest = json.loads(manifest_bytes)

        # Verify manifest hash
        stored_sha256 = (zf.read("manifest.sha256").decode().strip()
                         if "manifest.sha256" in names else "")
        computed_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        if stored_sha256 and computed_sha256 == stored_sha256:
            _echo_ok("manifest.json SHA-256 matches.")
        elif stored_sha256:
            _echo_err(f"manifest.json SHA-256 MISMATCH!\n"
                      f"    stored  : {stored_sha256}\n"
                      f"    computed: {computed_sha256}")
            all_ok = False
        else:
            _echo_warn("manifest.sha256 not found; skipping manifest hash check.")

        # Verify artifact hashes
        artifact_hashes: dict = manifest.get("artifacts", {})
        click.echo(f"\n  Checking {len(artifact_hashes)} artifact hashes:")
        for name, expected in sorted(artifact_hashes.items()):
            if name not in names:
                _echo_warn(f"  {name}: NOT FOUND in package")
                all_ok = False
                continue
            data = zf.read(name)
            actual_sha256 = hashlib.sha256(data).hexdigest()
            if actual_sha256 == expected.get("sha256", ""):
                _echo_ok(f"  {name}")
            else:
                _echo_err(f"  {name}: SHA-256 MISMATCH")
                all_ok = False

        # Timestamp token check
        click.echo("\n  RFC 3161 timestamp:")
        if "timestamp/response.tsr" in names and "timestamp/request.tsq" in names:
            tsr = zf.read("timestamp/response.tsr")
            tsq = zf.read("timestamp/request.tsq")
            if tsr and tsq:
                from evidence.timestamper import parse_timestamp_response
                parsed = parse_timestamp_response(tsr)
                status = parsed.get("status", "unknown")
                if status in ("granted", "grantedWithMods"):
                    _echo_ok(f"  Token status: {status}  |  Time: {parsed.get('gen_time', '—')}")
                    _echo_warn("  Full cryptographic signature verification requires OpenSSL.")
                    _echo_warn("  Run timestamp/verify.sh (Linux/macOS) or timestamp/verify.ps1 (Windows).")
                else:
                    _echo_err(f"  Token status: {status}")
                    all_ok = False
            else:
                _echo_warn("  Timestamp files are empty.")
        else:
            _echo_warn("  No timestamp token found in package.")

    click.echo("")
    if all_ok:
        click.echo(click.style("RESULT: Package integrity VERIFIED.", bold=True, fg="green"))
    else:
        click.echo(click.style("RESULT: Package integrity FAILED — see errors above.", bold=True, fg="red"))
        sys.exit(1)
    click.echo("")


# ── info command ──────────────────────────────────────────────────────────────


@cli.command("info")
@click.argument("package_path", type=click.Path(exists=True))
def info_cmd(package_path: str) -> None:
    """Print metadata summary of an evidence package."""
    path = pathlib.Path(package_path)

    with zipfile.ZipFile(path, "r") as zf:
        if "manifest.json" not in zf.namelist():
            _echo_err("Not a valid WeBF package (manifest.json missing).")
            sys.exit(1)
        manifest = json.loads(zf.read("manifest.json"))

    c = manifest.get("capture", {})
    t = manifest.get("timing", {})
    o = manifest.get("operator", {})

    click.echo(f"\n{'─'*55}")
    click.echo(f"  WeBF Evidence Package — {path.name}")
    click.echo(f"{'─'*55}")
    click.echo(f"  URL        : {c.get('target_url', '—')}")
    click.echo(f"  HTTP status: {c.get('http_status', '—')} {c.get('http_reason', '')}")
    click.echo(f"  Title      : {c.get('page_title', '—')}")
    click.echo(f"  Captured   : {t.get('capture_start_utc', '—')} UTC")
    click.echo(f"  Operator   : {o.get('name', '—')}")
    click.echo(f"  Case ref   : {o.get('case_reference', '—')}")
    click.echo(f"  Jurisdiction: {manifest.get('jurisdiction', '—')}")
    click.echo(f"  TSA        : {manifest.get('tsa_url', '—')}")
    click.echo(f"  Tool       : {manifest.get('tool', {}).get('name', '—')} "
               f"v{manifest.get('tool', {}).get('version', '—')}")
    click.echo(f"  Artifacts  : {len(manifest.get('artifacts', {}))} files hashed")
    click.echo(f"{'─'*55}\n")


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
