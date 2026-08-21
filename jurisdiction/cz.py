"""Czech Republic jurisdiction profile.

Based on:
  - Act No. 297/2016 Coll. on trust services for electronic transactions
    (implementing eIDAS into Czech law, replacing Act 227/2000 Coll.)
  - Act No. 99/1963 Coll. — Civil Procedure Code (§79, §125)
  - Act No. 300/2008 Coll. — Electronic actions and authorised conversion

Czech courts accept qualified electronic timestamps from any TSP on the
EU Trusted List. Any EU-TSL-listed TSA is valid.
"""

PROFILE = {
    "id": "cz",
    "name": "Česká republika (Zákon č. 297/2016 Sb.)",
    "tsa_url": "https://freetsa.org/tsr",
    "tsa_fallback_url": "https://timestamp.digicert.com",
    "tsa_name": "FreeTSA.org (EU Trusted List)",
    "hash_algorithms": ["sha256", "sha512"],
    "legal_references": [
        "Zákon č. 297/2016 Sb. — o službách vytvářejících důvěru pro elektronické transakce",
        "Zákon č. 99/1963 Sb. — Občanský soudní řád, §79, §125 (elektronické důkazy)",
        "Zákon č. 300/2008 Sb. — o elektronických úkonech a autorizované konverzi dokumentů",
        "Nařízení (EU) č. 910/2014 (eIDAS), čl. 41–42",
        "ISO 28500:2017 — formát WARC",
    ],
    "report_template": "report_cz.html.j2",
    "extra_operator_fields": [],
    "notes": (
        "Podle čl. 41 nařízení eIDAS nelze elektronickému dokumentu upřít "
        "právní účinky a přípustnost jako důkazu v soudním nebo správním řízení "
        "pouze proto, že je v elektronické podobě. Kvalifikované elektronické "
        "časové razítko (čl. 42 eIDAS) zakládá právní domněnku přesnosti data "
        "a času a integrity dat."
    ),
}
