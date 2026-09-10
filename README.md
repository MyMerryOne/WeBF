# WeBF — Web Capture and Verification Tool

A Python CLI tool that captures public websites and produces integrity-verifiable technical capture packages for documented review in EU and Italian proceedings.

Current packages use manifest schema `1.1`. The package and verification contract is documented in [docs/package-contract.md](docs/package-contract.md); known limitations are tracked in [IMPLEMENTATION_GAPS.md](IMPLEMENTATION_GAPS.md).

## Legal Standards

| Jurisdiction | Legal framework | TSA |
| --- | --- | --- |
| `eu` | eIDAS Regulation 910/2014, Art. 41–42; ETSI EN 319 422 | Configured TSA; qualification must be validated |
| `it` | D.Lgs. 82/2005 (CAD), DPCM 22/02/2013; AgID Trusted List | Configured TSA; AgID status must be validated |
| `cz` | Zákon č. 297/2016 Sb.; Občanský soudní řád §79, §125 | FreeTSA.org (any EU-TSL TSA) |

**Key properties:**

- The page content never leaves your machine — only a SHA-256 hash of the manifest is sent to the TSA
- Primary captured artifact is **WARC (ISO 28500:2017)** — the only ISO-standardised web archive, used by national libraries
- All artifacts are double-hashed (SHA-256 + SHA-512) to future-proof against hash deprecation
- RFC 3161 timestamp token records a third-party time/hash relationship; qualification is not inferred from the endpoint URL

---

## Requirements

- Python ≥ 3.10
- For full capture: Playwright Chromium, and all packages in `requirements.txt`
- For the complete test suite: install the dependencies from `requirements.txt`; timestamp tests require `pyasn1` and `pyasn1-modules`.

---

## Setup

### 1 — Install Python dependencies

```sh
pip install -r requirements.txt
```text

### 2 — Install Playwright browser (required for screenshot, PDF, and rendered HTML capture)

```sh
playwright install chromium
```

### 3 — (Optional) Verify the installation

```sh
python webf.py --version
```

---

## Usage

### Capture a web page

```sh
# General EU capture (eIDAS profile, configured TSA)
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --case-ref "CASE-2026-001" \
  --notes "Homepage as of August 2026" \
  --jurisdiction eu

# Italian capture (CAD profile)
python webf.py capture https://www.governo.it \
  --operator "Paolo Romagnoli" \
  --jurisdiction it \
  --operator-role "Consulente Tecnico d'Ufficio" \
  --operator-cf "RMGPLA80A01H501Z"

# Czech capture (Act 297/2016 profile)
python webf.py capture https://www.mvcr.cz \
  --operator "Paolo Romagnoli" \
  --jurisdiction cz \
  --case-ref "CZ-2026-042"

# Skip browser rendering (HTTP + WARC only, no screenshot or PDF)
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --no-browser

# Skip automatic legal sub-page discovery
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --no-legal

# Limit automatic legal-page discovery
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --max-legal-pages 5

# Use a custom TSA endpoint
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --jurisdiction it \
  --tsa-url "https://sello.infocert.it/tsa/tsa.shtml"

# Write output to a specific directory
python webf.py capture https://example.com \
  --operator "Paolo Romagnoli" \
  --output-dir "./captures/Case001"
```

PowerShell uses the same options with the backtick continuation character:

```powershell
python webf.py capture https://example.com `
  --operator "Paolo Romagnoli" `
  --jurisdiction eu `
  --no-browser
```

For the `it` profile, the capture requires the explicit TSA trust materials
`timestamp/tsa_trust.pem` and `timestamp/tsa_untrusted.pem`. The capture verifies
the RFC 3161 chain before creating the package and includes both certificates in
the package inventory. Their presence and cryptographic validity do not, by
themselves, establish current AgID qualification; that status must be documented
against the applicable Trusted List at review time.

The capture command requires a successful raw HTTP capture and WARC build. DNS,
WHOIS, TLS, browser rendering, legal-page discovery, modal capture, report
generation, and timestamping have separate failure behavior. Network or browser
failures may produce a partial package; HTTP or primary-WARC failure aborts the
capture. The current manifest does not yet expose structured status for every
stage, so review the console output, report, and package contents together.

### Verify a capture package

```sh
python webf.py verify ./captures/webf_20260821_100130_example.com.zip
```

This re-hashes every file and compares against the manifest. For cryptographic signature verification of the RFC 3161 token, also run the script inside the package:

```sh
# Linux / macOS
bash timestamp/verify.sh

# Windows (requires OpenSSL in PATH, e.g. from Git for Windows)
pwsh timestamp/verify.ps1
```

The verifier also checks `package_hashes.json` and its detached SHA-256 value.
That index contains SHA-256 and SHA-512 checksums for every other ZIP member,
including reports, network metadata, timestamp files, verification scripts, and
captured content. This is an additional package-integrity check; it does not
replace an external signature or establish legal admissibility.

### Inspect a package without extracting

```sh
python webf.py info ./captures/webf_20260821_100130_example.com.zip
```

---

## Output Package Structure

Each capture produces a single `.zip` file:

```text
webf_YYYYMMDD_HHMMSS_<domain>.zip
├── manifest.json               ← Central inventory: all file hashes + metadata
├── manifest.sha256             ← Detached SHA-256 of manifest (quick integrity check)
├── package_hashes.json         ← SHA-256/SHA-512 checksums for every other ZIP member
├── package_hashes.sha256       ← Detached SHA-256 of package_hashes.json
├── VERIFICATION.md             ← Instructions for independent verification
├── report/
│   ├── capture_report.html     ← Technical capture report (opens in any browser)
│   └── capture_report.pdf      ← PDF version for documented review
├── capture/
│   ├── page.warc.gz           ← Primary captured artifact (ISO 28500:2017 WARC archive)
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
    ├── tsa_trust.pem          ← Explicit trusted root used for OpenSSL validation
    ├── tsa_untrusted.pem      ← Explicit intermediate chain certificate
    ├── verify.sh              ← OpenSSL verification script (Linux/macOS)
    └── verify.ps1             ← OpenSSL verification script (Windows/PowerShell)
```

Browser-rendered files, legal-page files, and TSA trust files are conditional;
they are not present in every package. See [docs/package-contract.md](docs/package-contract.md)
for the complete required and conditional member contract.

`timestamp/tsa_trust.pem` is intentionally not generated or included automatically.
It must be obtained from the TSA's official certificate documentation or the
applicable AgID/EU Trusted List, with its source, version, retrieval time, and
validation scope recorded in the case file. The signer certificate embedded in a
timestamp token is evidence about the signer, but is not by itself a trust anchor.
If the trust anchor does not directly chain to the signer, place the official
intermediate certificate in `timestamp/tsa_untrusted.pem`; it is supplied to
OpenSSL with `-untrusted` and is not treated as a root of trust.

### Independent timestamp verification

The package contains two separate timestamp checks:

1. `python webf.py verify package.zip` validates the RFC 3161 response status and
   checks that the token imprint and nonce correspond to the exact `manifest.json`
   bytes in the package.
2. `timestamp/verify.sh` or `timestamp/verify.ps1` validates the TSA certificate
   chain with OpenSSL when `timestamp/tsa_trust.pem` is supplied.

Without `tsa_trust.pem`, the scripts deliberately report `TSA trust-chain NOT
VERIFIED`; they do not download certificates, parse human-readable OpenSSL output,
or promote a token signer certificate to a root of trust. A successful local
imprint check therefore means that the token binds the manifest hash to a claimed
time, while a qualified-timestamp conclusion additionally requires independent
certificate-chain, revocation, service-status, and Trusted List validation.

---

## Running Tests

The test suite uses Python's built-in `unittest` framework. Install the dependencies from `requirements.txt` before running the complete suite.

### Run all tests

```sh
cd /path/to/WeBF
python -m unittest discover tests -v
```

### Run a specific test module

```sh
python -m unittest tests.test_hasher -v
python -m unittest tests.test_der_helpers -v
python -m unittest tests.test_manifest -v
python -m unittest tests.test_jurisdiction -v
python -m unittest tests.test_timestamper -v
python -m unittest tests.test_bundler -v
```

### What is tested

| Module | Test file | Requires |
| --- | --- | --- |
| `evidence/hasher.py` | `tests/test_hasher.py` | stdlib only |
| `evidence/der_helpers.py` | `tests/test_der_helpers.py` | stdlib only |
| `packaging/manifest.py` | `tests/test_manifest.py` | stdlib only |
| `jurisdiction/` | `tests/test_jurisdiction.py` | stdlib only |
| `evidence/timestamper.py` | `tests/test_timestamper.py` | `requests`, `pyasn1`, `pyasn1-modules` |
| `packaging/bundler.py` | `tests/test_bundler.py` | stdlib only |

The deterministic test suite does not perform live browser, network, WHOIS, or
TSA calls. Browser and full-capture validation require the optional runtime
dependencies and controlled test targets. The timestamp test module imports its
ASN.1 dependencies at module load time, so it is not safely skippable when those
packages are absent.

---

## Full Dependency List

| Package | Purpose | Required for |
| --- | --- | --- |
| `playwright` | Headless Chromium: screenshot, PDF, rendered HTML | Browser capture |
| `requests` | HTTP capture + TSA communication | All captures |
| `dnspython` | DNS resolution (A, AAAA, MX, NS, TXT) | Network info |
| `python-whois` | WHOIS lookup | Network info |
| `cryptography` | TLS certificate parsing | Network info |
| `warcio` | ISO 28500 WARC archive creation | WARC (primary captured artifact) |
| `jinja2` | Report HTML templating | Report generation |
| `click` | CLI interface | CLI |
| `pyasn1` + `pyasn1-modules` | RFC 3161 TSR response parsing | Timestamp verification |


## Limitations and interpretation

WeBF records technical observations and integrity relationships. A successful
hash check does not establish that captured content is true, complete, authored
by the operator, lawfully collected, or legally admissible. A valid RFC 3161
imprint is distinct from certificate-chain validation, revocation checking,
current Trusted List status, and qualified-service conclusions.

The current manifest records provenance and limitations but does not yet provide
structured status for every capture stage, a complete redirect chronology,
early browser diagnostics, a trusted binding for the package-hash index, or a
structured authorization and custody history. These gaps are tracked in
[IMPLEMENTATION_GAPS.md](IMPLEMENTATION_GAPS.md).

Packages generated before the schema and terminology migration may contain
schema `1.0` and the former tool name. They are historical outputs and must not
be rewritten. New packages use schema `1.1` and current WeBF terminology.
---

## Frequently Asked Questions

**Why is the WARC the primary captured artifact and not the PDF/screenshot?**
WARC (ISO 28500:2017) is a structured archive format suitable for preserving HTTP capture records. PDFs, screenshots, and rendered HTML are derived representations and should be assessed together with the underlying HTTP/WARC evidence.

**Why is only a hash sent to the TSA?**
RFC 3161 only requires the hash of the data to be timestamped. The page content never leaves your machine. The resulting token records a third-party time/hash relationship; its signature, trust chain, and qualification must still be validated.

**What TSA should I use for an Italian jurisdiction profile?**
Use a provider and service appearing on the current AgID/EU Trusted List for the relevant qualified service, and preserve the list/version and validation time with the case record. An endpoint configured in `jurisdiction/it.py` is not proof of qualification.

**Can I verify the package without installing WeBF?**
Yes. Run `timestamp/verify.sh` (Linux/macOS) or `timestamp/verify.ps1` (Windows/PowerShell) — both require only OpenSSL, which is available on all modern systems. Hash verification only requires `sha256sum` or PowerShell's `Get-FileHash`.

**How should external signatures be handled?**
WeBF does not generate or store private signing keys. The first supported evidence contracts are a detached CMS/PKCS#7 signature over `manifest.json`, or a PAdES signature over the PDF report with an explicit hash link to the manifest. Store the signature and certificate chain as separate verification material, and verify them independently with the provider's tools or OpenSSL. For timestamp chain verification, place a separately obtained and documented trust bundle at `timestamp/tsa_trust.pem` before running the script. Until this step is performed, `manifest.json` records `signature.status` as `not_applied` and the report must be treated as unsigned.
