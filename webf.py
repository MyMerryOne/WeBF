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


def _package_inventory(manifest: dict, names: list[str]) -> tuple[set[str], set[str]]:
    """Return manifest entries missing from, and unexpected in, the package."""
    expected = {"manifest.json", "manifest.sha256", *manifest.get("artifacts", {})}
    expected.update({
        "report/forensic_report.html",
        "report/forensic_report.pdf",
        "network/dns.json",
        "network/whois.txt",
        "network/tls_certificate.json",
        "timestamp/request.tsq",
        "timestamp/response.tsr",
        "timestamp/timestamp_info.json",
        "timestamp/verify.sh",
        "timestamp/verify.ps1",
        "VERIFICATION.md",
    })
    package_names = set(names)
    return expected - package_names, package_names - expected


def _unsafe_package_members(names: list[str]) -> set[str]:
    """Return ZIP members that could escape the package extraction directory."""
    return {
        name for name in names
        if not name or name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts
    }


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
@click.option("--no-legal", is_flag=True, help="Skip automatic legal sub-page capture.")
@click.option(
    "--max-legal-pages",
    default=10,
    show_default=True,
    help="Maximum number of legal sub-pages to capture.",
)
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
    no_legal: bool,
    max_legal_pages: int,
    operator_role: str,
    operator_cf: str,
) -> None:
    """Capture a public web page and produce a court-ready evidence package."""
    from jurisdiction import get_profile
    from capture.http_raw import capture_http, build_raw_http_bytes
    from capture.network import capture_network
    from capture.browser import capture_browser
    from capture.legal_links import find_legal_links, extract_embedded_section
    from capture.browser import capture_legal_modals
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

    # 3b. Legal sub-pages
    legal_captures: list[dict] = []
    if not no_legal:
        _echo_step("Scanning for legal sub-pages (Privacy Policy, Cookie Policy, T&C)...")
        html_source = browser_result.get("rendered_html") or http_result.get("raw_body", b"")
        links = find_legal_links(html_source, url, max_links=max_legal_pages)
        embedded_count = 0
        fetched_count = 0
        for link in links:
            if link.get("embedded"):
                plain_text, html_fragment = extract_embedded_section(html_source, link)
                legal_captures.append({
                    **link,
                    "http_result": http_result,
                    "raw_html": html_fragment.encode("utf-8") if html_fragment else b"",
                    "plain_text": plain_text.encode("utf-8") if plain_text else b"",
                    "raw_bytes": b"",
                })
                if html_fragment:
                    _echo_ok(f"  {link['label']} — extracted from main page ({len(html_fragment):,} chars)")
                else:
                    _echo_ok(f"  {link['label']} — embedded in main page (content not separately extractable)")
                embedded_count += 1
            else:
                try:
                    lhttpres = capture_http(link["url"])
                    legal_captures.append({
                        **link,
                        "http_result": lhttpres,
                        "raw_html": lhttpres.get("raw_body", b""),
                        "raw_bytes": build_raw_http_bytes(lhttpres),
                    })
                    _echo_ok(f"  {link['label']} — {link['url']}")
                    fetched_count += 1
                except Exception as exc:
                    _echo_warn(f"  {link['label']} failed: {exc}")
        if legal_captures:
            parts = []
            if fetched_count:
                parts.append(f"{fetched_count} fetched")
            if embedded_count:
                parts.append(f"{embedded_count} embedded in main page")
            _echo_ok(f"Legal content: {', '.join(parts)}.")
        else:
            _echo_warn("No legal sub-pages detected on this page.")

    # 3c. Browser modal capture for embedded legal sections
    if not no_browser and any(lc.get("embedded") for lc in legal_captures):
        _echo_step("Capturing legal modal screenshots with browser...")
        try:
            modal_results = capture_legal_modals(url, legal_captures)
            captured_count = 0
            for lc in legal_captures:
                slug = lc["slug"]
                mr = modal_results.get(slug, {})
                if "error" in mr:
                    _echo_warn(f"  {lc['label']} modal: {mr['error']}")
                elif mr:
                    lc["modal_screenshot_png"] = mr.get("screenshot_png", b"")
                    lc["modal_rendered_html"] = mr.get("rendered_html", b"")
                    lc["modal_pdf_bytes"] = mr.get("pdf_bytes", b"")
                    _echo_ok(f"  {lc['label']} — modal screenshot captured")
                    captured_count += 1
            if captured_count:
                _echo_ok(f"Browser modal capture: {captured_count} modal(s) screenshotted.")
        except Exception as exc:
            _echo_warn(f"Browser modal capture skipped: {exc}")

    # 4. WARC
    _echo_step("Building ISO 28500 WARC archive...")
    try:
        warc_bytes = build_warc(url, http_result, browser_result, operator, case_ref, legal_captures)
        _echo_ok(f"WARC archive built ({len(warc_bytes):,} bytes).")
    except Exception as exc:
        _echo_err(f"WARC build failed; capture aborted: {exc}")
        raise click.ClickException("Primary WARC evidence could not be created.") from exc

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
    for lc in legal_captures:
        slug = lc["slug"]
        if lc.get("embedded"):
            if lc.get("raw_html"):
                artifacts[f"capture/legal/{slug}/embedded_extract.html"] = lc["raw_html"]
            if lc.get("plain_text"):
                artifacts[f"capture/legal/{slug}/embedded_extract.txt"] = lc["plain_text"]
            if lc.get("modal_screenshot_png"):
                artifacts[f"capture/legal/{slug}/modal_screenshot.png"] = lc["modal_screenshot_png"]
            if lc.get("modal_rendered_html"):
                artifacts[f"capture/legal/{slug}/modal_rendered.html"] = lc["modal_rendered_html"]
            if lc.get("modal_pdf_bytes"):
                artifacts[f"capture/legal/{slug}/modal_page.pdf"] = lc["modal_pdf_bytes"]
        else:
            if lc.get("raw_html"):
                artifacts[f"capture/legal/{slug}/page.html"] = lc["raw_html"]
            if lc.get("raw_bytes"):
                artifacts[f"capture/legal/{slug}/http_response_raw.bin"] = lc["raw_bytes"]

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
    # For Italian jurisdiction (without a manual --tsa-url override) we must
    # use an AgID-accredited Qualified TSP.  Iterate the full fallback list
    # before giving up.  FreeTSA and other non-qualified TSAs are NOT
    # compliant with D.Lgs. 82/2005 / DPCM 22/02/2013.
    qualified_endpoints: list[tuple[str, str]] = profile.get("tsa_qualified_endpoints", [])
    # Build the candidate list: explicit override goes first (single entry);
    # otherwise use the profile's qualified list or the single profile URL.
    if tsa_url:
        tsa_candidates = [("TSA (manual override)", tsa_url)]
    elif qualified_endpoints:
        tsa_candidates = [(label, url) for label, url in qualified_endpoints]
    else:
        tsa_candidates = [(effective_tsa, effective_tsa)]

    timestamp_result: dict = {}
    ts_used_tsa: str = effective_tsa
    for tsa_label, tsa_candidate_url in tsa_candidates:
        _echo_step(f"Requesting RFC 3161 timestamp from {tsa_label} ({tsa_candidate_url}) ...")
        try:
            timestamp_result = request_timestamp(manifest_bytes, tsa_candidate_url)
            ts_status = timestamp_result["parsed"].get("status", "unknown")
            if ts_status in ("granted", "grantedWithMods"):
                ts_used_tsa = tsa_candidate_url
                _echo_ok(
                    f"Timestamp received from {tsa_label}: "
                    f"{timestamp_result['parsed'].get('gen_time', '')}"
                )
                break
            else:
                _echo_warn(f"  {tsa_label} returned status: {ts_status}. Trying next TSA...")
                timestamp_result = {}
        except Exception as exc:
            _echo_warn(f"  {tsa_label} unreachable: {exc}. Trying next TSA...")
            timestamp_result = {}

    if not timestamp_result:
        # All candidates exhausted
        if qualified_endpoints and not tsa_url:
            # Italian jurisdiction — no qualified TSA was reachable
            click.echo("")
            click.echo(click.style(
                "  ✗ ATTENZIONE — MARCA TEMPORALE NON DISPONIBILE",
                fg="red", bold=True,
            ), err=True)
            click.echo(click.style(
                "    Nessun TSP qualificato AgID raggiungibile. "
                "Il pacchetto verrà creato SENZA marca temporale qualificata.\n"
                "    Ai sensi del DPCM 22/02/2013 e dell'art. 41 eIDAS, "
                "la prova elettronica priva di marca temporale qualificata\n"
                "    ha minor efficacia probatoria in giudizio. "
                "Accertarsi di avere connettività ai TSP AgID prima di\n"
                "    produrre un pacchetto destinato a uso legale.",
                fg="red",
            ), err=True)
            click.echo("")
        else:
            _echo_warn("Timestamping failed. Package will be created without a timestamp token.")
        timestamp_result = {
            "tsq_bytes": b"",
            "tsr_bytes": b"",
            "data_hash_hex": manifest_hashes["sha256"],
            "tsa_url": effective_tsa,
            "parsed": {"status": "error", "error": "No TSA reachable"},
        }
    else:
        timestamp_result["tsa_url"] = ts_used_tsa
        effective_tsa = ts_used_tsa

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
        legal_captures=legal_captures,
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

        missing_members, unexpected_members = _package_inventory(manifest, names)
        duplicate_members = {name for name in names if names.count(name) > 1}
        unsafe_members = _unsafe_package_members(names)
        for name in sorted(missing_members):
            _echo_err(f"Package member missing: {name}")
        for name in sorted(unexpected_members):
            _echo_err(f"Unexpected package member: {name}")
        for name in sorted(duplicate_members):
            _echo_err(f"Duplicate package member: {name}")
        for name in sorted(unsafe_members):
            _echo_err(f"Unsafe package member path: {name}")
        if missing_members or unexpected_members or duplicate_members or unsafe_members:
            all_ok = False

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
            actual_sha512 = hashlib.sha512(data).hexdigest()
            sha256_ok = actual_sha256 == expected.get("sha256", "")
            sha512_ok = actual_sha512 == expected.get("sha512", "")
            if sha256_ok and sha512_ok:
                _echo_ok(f"  {name}")
            else:
                algorithms = []
                if not sha256_ok:
                    algorithms.append("SHA-256")
                if not sha512_ok:
                    algorithms.append("SHA-512")
                _echo_err(f"  {name}: {', '.join(algorithms)} MISMATCH")
                all_ok = False

        # Timestamp token check
        click.echo("\n  RFC 3161 timestamp:")
        if "timestamp/response.tsr" in names and "timestamp/request.tsq" in names:
            tsr = zf.read("timestamp/response.tsr")
            tsq = zf.read("timestamp/request.tsq")
            if tsr and tsq:
                from evidence.timestamper import (
                    parse_timestamp_response,
                    validate_timestamp_response,
                )
                parsed = parse_timestamp_response(tsr)
                status = parsed.get("status", "unknown")
                if status in ("granted", "grantedWithMods"):
                    validation = validate_timestamp_response(tsq, tsr, manifest_bytes)
                    if validation.get("imprint_valid") and validation.get("nonce_valid"):
                        _echo_ok(f"  Token status: {status}  |  Time: {parsed.get('gen_time', '—')}")
                        _echo_ok("  Message imprint and nonce match manifest.json.")
                        _echo_warn("  Signer signature and trust-chain verification require OpenSSL.")
                        _echo_warn("  Run timestamp/verify.sh (Linux/macOS) or timestamp/verify.ps1 (Windows).")
                    else:
                        _echo_err(
                            "  Timestamp token does not match the manifest: "
                            f"{validation.get('error', 'imprint or nonce mismatch')}"
                        )
                        all_ok = False
                else:
                    _echo_err(f"  Token status: {status}")
                    all_ok = False
            else:
                _echo_err("  Timestamp files are empty.")
                all_ok = False
        else:
            _echo_err("  No timestamp token found in package.")
            all_ok = False

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
