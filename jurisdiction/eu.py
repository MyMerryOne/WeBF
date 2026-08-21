"""General EU / eIDAS jurisdiction profile."""

PROFILE = {
    "id": "eu",
    "name": "European Union (eIDAS)",
    "tsa_url": "https://freetsa.org/tsr",
    "tsa_fallback_url": "https://timestamp.digicert.com",
    "tsa_name": "FreeTSA.org",
    "hash_algorithms": ["sha256", "sha512"],
    "legal_references": [
        "Regulation (EU) No 910/2014 (eIDAS), Art. 41 — Admissibility of electronic documents",
        "Regulation (EU) No 910/2014 (eIDAS), Art. 42 — Legal effects of qualified electronic time stamps",
        "ETSI EN 319 422 — Time-stamping protocol and time-stamp token profiles",
        "ISO 28500:2017 — WARC file format",
    ],
    "report_template": "report_eu.html.j2",
    "extra_operator_fields": [],
    "notes": (
        "Under eIDAS Art. 41, electronic documents shall not be denied admissibility "
        "solely because they are in electronic form. A qualified electronic time stamp "
        "(Art. 42) carries a presumption of accuracy of the date and time it indicates "
        "and of the integrity of the data to which it is bound."
    ),
}
