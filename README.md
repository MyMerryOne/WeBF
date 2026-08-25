# WeBF — Web Forensic Capture Tool

A Python CLI tool that captures public websites and produces tamper-evident, independently verifiable technical evidence packages for review in EU and Italian proceedings.

## Legal Standards

| Jurisdiction | Legal framework | TSA |
|---|---|---|
| `eu` | eIDAS Regulation 910/2014, Art. 41–42; ETSI EN 319 422 | Configured TSA; qualification must be validated |
| `it` | D.Lgs. 82/2005 (CAD), DPCM 22/02/2013; AgID Trusted List | Configured TSA; AgID status must be validated |
| `cz` | Zákon č. 297/2016 Sb.; Občanský soudní řád §79, §125 | FreeTSA.org (any EU-TSL TSA) |

**Key properties:**
- The page content never leaves your machine — only a SHA-256 hash of the manifest is sent to the TSA
- Primary evidence format is **WARC (ISO 28500:2017)** — the only ISO-standardised web archive, used by national libraries
- All artifacts are double-hashed (SHA-256 + SHA-512) to future-proof against hash deprecation
- RFC 3161 timestamp token records a third-party time/hash relationship; qualification is not inferred from the endpoint URL

---

## Requirements

- Python ≥ 3.10
- For full capture: Playwright Chromium, and all packages in `requirements.txt`
- For core tests only: Python stdlib + `click` + `requests`

---

## Setup

### 1 — Install Python dependencies

```powershell
pip install -r requirements.txt
```

### 2 — Install Playwright browser (required for screenshot, PDF, and rendered HTML capture)

```powershell
playwright install chromium
```

### 3 — (Optional) Verify the installation

```powershell
python webf.py --version
```

---

## Usage

### Capture a web page

```powershell
# General EU capture (eIDAS profile, FreeTSA)
python webf.py capture https://example.com `
  --operator "Paolo Romagnoli" `
  --case-ref "CASE-2026-001" `
  --notes "Homepage as of August 2026" `
  --jurisdiction eu

# Italian capture (CAD profile, Aruba AgID-accredited TSA)
python webf.py capture https://www.governo.it `
  --operator "Paolo Romagnoli" `
  --jurisdiction it `
  --operator-role "Consulente Tecnico d'Ufficio" `
  --operator-cf "RMGPLA80A01H501Z"

# Czech capture (Act 297/2016 profile)
python webf.py capture https://www.mvcr.cz `
  --operator "Paolo Romagnoli" `
  --jurisdiction cz `
  --case-ref "CZ-2026-042"

# Skip browser rendering (faster; HTTP + WARC only, no screenshot or PDF)
python webf.py capture https://example.com `
  --operator "Paolo Romagnoli" `
  --no-browser

# Use a custom TSA (e.g. a paid InfoCert qualified TSA for Italy)
python webf.py capture https://example.com `
  --operator "Paolo Romagnoli" `
  --jurisdiction it `
  --tsa-url "https://sello.infocert.it/tsa/tsa.shtml"

# Write output to a specific directory
python webf.py capture https://example.com `
  --operator "Paolo Romagnoli" `
  --output-dir "C:\Evidence\2026\Case001"
```

### Verify an evidence package

```powershell
python webf.py verify .\captures\webf_20260821_100130_example.com.zip
```

This re-hashes every file and compares against the manifest. For cryptographic signature verification of the RFC 3161 token, also run the script inside the package:

```powershell
# Linux / macOS
bash timestamp/verify.sh

# Windows (requires OpenSSL in PATH, e.g. from Git for Windows)
pwsh timestamp/verify.ps1
```

### Inspect a package without extracting

```powershell
python webf.py info .\captures\webf_20260821_100130_example.com.zip
```

---

## Output Package Structure

Each capture produces a single `.zip` file:

```
webf_YYYYMMDD_HHMMSS_<domain>.zip
├── manifest.json               ← Central inventory: all file hashes + metadata
├── manifest.sha256             ← Detached SHA-256 of manifest (quick integrity check)
├── VERIFICATION.md             ← Instructions for independent verification
├── report/
│   ├── forensic_report.html    ← Human-readable report (opens in any browser)
│   └── forensic_report.pdf    ← PDF version for court submission
├── capture/
│   ├── page.warc.gz           ← PRIMARY EVIDENCE (ISO 28500:2017 WARC archive)
│   ├── screenshot_full.png    ← Full-page rendering
│   ├── screenshot_viewport.png
│   ├── page.html              ← Rendered HTML (post-JavaScript execution)
│   ├── page.pdf               ← PDF rendering (A4, print media)
│   └── http_response_raw.bin  ← Raw HTTP response bytes (headers + body)
├── network/
│   ├── dns.json               ← A, AAAA, MX, NS, TXT records at capture time
│   ├── whois.txt              ← WHOIS data
│   └── tls_certificate.json   ← TLS cert: issuer, validity, SHA-256 fingerprint
└── timestamp/
    ├── request.tsq            ← RFC 3161 TimeStampRequest (DER)
    ├── response.tsr           ← RFC 3161 TimeStampResponse — signed token
    ├── timestamp_info.json    ← Human-readable: TSA, time, serial number
    ├── verify.sh              ← OpenSSL verification script (Linux/macOS)
    └── verify.ps1             ← OpenSSL verification script (Windows/PowerShell)
```

---

## Running Tests

The test suite uses only Python's built-in `unittest` framework. No additional test dependencies are required.

### Run all tests

```powershell
cd c:\Users\paolo.romagnoli\Claude_Folder\WeBF
python -m unittest discover tests -v
```

### Run a specific test module

```powershell
python -m unittest tests.test_hasher -v
python -m unittest tests.test_der_helpers -v
python -m unittest tests.test_manifest -v
python -m unittest tests.test_jurisdiction -v
python -m unittest tests.test_timestamper -v
python -m unittest tests.test_bundler -v
```

### What is tested

| Module | Test file | Requires |
|---|---|---|
| `evidence/hasher.py` | `tests/test_hasher.py` | stdlib only |
| `evidence/der_helpers.py` | `tests/test_der_helpers.py` | stdlib only |
| `packaging/manifest.py` | `tests/test_manifest.py` | stdlib only |
| `jurisdiction/` | `tests/test_jurisdiction.py` | stdlib only |
| `evidence/timestamper.py` | `tests/test_timestamper.py` | `requests` (installed) |
| `packaging/bundler.py` | `tests/test_bundler.py` | stdlib only |

Tests that require `pyasn1` (TSR parsing) are skipped automatically if the library is not installed. All other tests run without any pip installations beyond `requests`.

---

## Full Dependency List

| Package | Purpose | Required for |
|---|---|---|
| `playwright` | Headless Chromium: screenshot, PDF, rendered HTML | Browser capture |
| `requests` | HTTP capture + TSA communication | All captures |
| `dnspython` | DNS resolution (A, AAAA, MX, NS, TXT) | Network info |
| `python-whois` | WHOIS lookup | Network info |
| `cryptography` | TLS certificate parsing | Network info |
| `warcio` | ISO 28500 WARC archive creation | WARC (primary evidence) |
| `jinja2` | Report HTML templating | Report generation |
| `click` | CLI interface | CLI |
| `pyasn1` + `pyasn1-modules` | RFC 3161 TSR response parsing | Timestamp verification |

---

## Frequently Asked Questions

**Why is the WARC the primary evidence and not the PDF/screenshot?**
WARC (ISO 28500:2017) is a structured archive format suitable for preserving HTTP capture records. PDFs, screenshots, and rendered HTML are derived representations and should be assessed together with the underlying HTTP/WARC evidence.

**Why is only a hash sent to the TSA?**
RFC 3161 only requires the hash of the data to be timestamped. The page content never leaves your machine. The resulting token records a third-party time/hash relationship; its signature, trust chain, and qualification must still be validated.

**What TSA should I use for Italian courts?**
Use a provider and service appearing on the current AgID/EU Trusted List for the relevant qualified service, and preserve the list/version and validation time with the case record. An endpoint configured in `jurisdiction/it.py` is not proof of qualification.

**Can I verify the package without installing WeBF?**
Yes. Run `timestamp/verify.sh` (Linux/macOS) or `timestamp/verify.ps1` (Windows/PowerShell) — both require only OpenSSL, which is available on all modern systems. Hash verification only requires `sha256sum` or PowerShell's `Get-FileHash`.

**How should external signatures be handled?**
WeBF does not generate or store private signing keys. The first supported evidence contracts are a detached CMS/PKCS#7 signature over `manifest.json`, or a PAdES signature over the PDF report with an explicit hash link to the manifest. Store the signature and certificate chain as separate verification material, and verify them independently with the provider's tools or OpenSSL. Until this step is performed, `manifest.json` records `signature.status` as `not_applied` and the report must be treated as unsigned.
