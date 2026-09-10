"""Italian jurisdiction profile.

Based on D.Lgs. 82/2005 (Codice dell'Amministrazione Digitale - CAD)
as amended by D.Lgs. 179/2016 and D.Lgs. 217/2017 to implement eIDAS.
Hash requirements per DPCM 22/02/2013 (Regole tecniche in materia di
generazione, apposizione e verifica delle firme elettroniche avanzate,
qualificate e digitali): SHA-256 minimum.

Examples of providers that may appear in the applicable AgID/EU Trusted List
for timestamp services (current status must be checked at review time):
  - Aruba PEC S.p.A.       https://ca.aruba.it/
  - InfoCert S.p.A.        https://www.infocert.it/
  - Namirial S.p.A.        https://www.namirial.com/
  - Actalis S.p.A.         https://www.actalis.it/
  - Poste Italiane S.p.A.  https://postecert.poste.it/

Any qualification or current service status must be established against the
applicable AgID/EU Trusted List and validation record; this configuration does
not establish it (https://eidas.agid.gov.it/TL/TSL-IT.xml).
"""

PROFILE = {
    "id": "it",
    "name": "Italia (CAD / D.Lgs. 82/2005)",
    # Actalis is listed first because it is the only AgID-qualified TSP with a
    # publicly accessible endpoint (no subscription credentials required).
    # Aruba, InfoCert, and Namirial require a paid subscription and HTTP Basic
    # Auth credentials; add them here once credentials are available.
    "tsa_url": "http://timestamp.actalis.com",
    "tsa_name": "Actalis S.p.A. (configured endpoint; status requires validation)",
    # Ordered fallback list; current qualification is not inferred here.
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
        "Il profilo richiama CAD ed eIDAS come riferimenti normativi da verificare "
        "nel caso concreto. La configurazione di una TSA o la presenza di un token "
        "non dimostra da sola la qualificazione del servizio, l'identità dell'operatore, "
        "la provenienza del contenuto o la sua ammissibilità in giudizio."
    ),
    "verbale_section": True,
}

# Ordered list of configured TSA endpoints to try.
# Endpoint reachability was checked 2026-08-21. Actalis is the only publicly accessible endpoint;
# the others require a paid subscription with HTTP Basic Auth credentials.
AGID_TSA_ENDPOINTS = [
    ("Actalis S.p.A.", "http://timestamp.actalis.com"),
    ("Aruba PEC S.p.A.", "https://servizi.arubapec.it/tsa/ngrequest.php"),
    ("InfoCert S.p.A.", "https://digitaltimestamp.infocert.it/idts-rest/dts/timestamp"),
    ("Namirial S.p.A.", "https://timestamp.namirialtsp.com"),
]
