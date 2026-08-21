"""Italian jurisdiction profile.

Based on D.Lgs. 82/2005 (Codice dell'Amministrazione Digitale - CAD)
as amended by D.Lgs. 179/2016 and D.Lgs. 217/2017 to implement eIDAS.
Hash requirements per DPCM 22/02/2013 (Regole tecniche in materia di
generazione, apposizione e verifica delle firme elettroniche avanzate,
qualificate e digitali): SHA-256 minimum.

AgID-accredited Qualified Trust Service Providers (TSPs) for timestamps:
  - Aruba PEC S.p.A.       https://ca.aruba.it/
  - InfoCert S.p.A.        https://www.infocert.it/
  - Namirial S.p.A.        https://www.namirial.com/
  - Actalis S.p.A.         https://www.actalis.it/
  - Poste Italiane S.p.A.  https://postecert.poste.it/

For maximum evidential weight in Italian courts use a TSP on the AgID
Trusted List (https://eidas.agid.gov.it/TL/TSL-IT.xml).
"""

PROFILE = {
    "id": "it",
    "name": "Italia (CAD / D.Lgs. 82/2005)",
    # Actalis is listed first because it is the only AgID-qualified TSP with a
    # publicly accessible endpoint (no subscription credentials required).
    # Aruba, InfoCert, and Namirial require a paid subscription and HTTP Basic
    # Auth credentials; add them here once credentials are available.
    "tsa_url": "http://timestamp.actalis.com",
    "tsa_name": "Actalis S.p.A. (AgID-accredited TSP)",
    # Ordered fallback list; all are AgID/eIDAS-qualified TSPs.
    # webf tries each in order and stops at the first success.
    # Endpoints verified 2026-08-21. Credentials marked where required.
    "tsa_qualified_endpoints": [
        # Public endpoint — no credentials required
        ("Actalis S.p.A.", "http://timestamp.actalis.com"),
        # Requires paid subscription + HTTP Basic Auth (username:password)
        ("Aruba PEC S.p.A.", "https://servizi.arubapec.it/tsa/ngrequest.php"),
        ("InfoCert S.p.A.", "https://digitaltimestamp.infocert.it/idts-rest/dts/timestamp"),
        ("Namirial S.p.A.", "https://timestamp.namirialtsp.com"),
    ],
    "hash_algorithms": ["sha256", "sha512"],
    "legal_references": [
        "D.Lgs. 82/2005 — Codice dell'Amministrazione Digitale (CAD), art. 20–23-ter",
        "DPCM 22/02/2013 — Regole tecniche firme elettroniche (SHA-256 minimo)",
        "Regulation (EU) No 910/2014 (eIDAS), Art. 41–42",
        "AgID — Trusted List dei prestatori di servizi fiduciari qualificati",
        "ISO 28500:2017 — Formato WARC",
    ],
    "report_template": "report_it.html.j2",
    "extra_operator_fields": [
        {
            "key": "operator_role",
            "label": "Qualifica/Ruolo dell'operatore",
            "required": False,
        },
        {
            "key": "operator_cf",
            "label": "Codice Fiscale dell'operatore",
            "required": False,
        },
    ],
    "notes": (
        "Ai sensi dell'art. 20 CAD il documento informatico soddisfa il requisito "
        "della forma scritta e ha l'efficacia probatoria di cui all'art. 2702 c.c. "
        "quando è sottoscritto con firma digitale o firma elettronica qualificata. "
        "La marca temporale qualificata apposta da un TSP accreditato AgID produce "
        "gli effetti giuridici di cui all'art. 41 eIDAS."
    ),
    "verbale_section": True,
}

# Ordered list of AgID-accredited TSA endpoints to try.
# Verified 2026-08-21. Actalis is the only publicly accessible endpoint;
# the others require a paid subscription with HTTP Basic Auth credentials.
AGID_TSA_ENDPOINTS = [
    ("Actalis S.p.A.", "http://timestamp.actalis.com"),
    ("Aruba PEC S.p.A.", "https://servizi.arubapec.it/tsa/ngrequest.php"),
    ("InfoCert S.p.A.", "https://digitaltimestamp.infocert.it/idts-rest/dts/timestamp"),
    ("Namirial S.p.A.", "https://timestamp.namirialtsp.com"),
]
