"""DNS, WHOIS, and TLS certificate capture."""
import socket
import ssl
import datetime
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import whois
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def resolve_dns(hostname: str) -> dict[str, Any]:
    result: dict[str, list] = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
    }
    for rtype in result:
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            for rdata in answers:
                result[rtype].append(str(rdata))
        except Exception:
            pass
    return result


def fetch_tls_cert(hostname: str, port: int = 443) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=10),
            server_hostname=hostname,
        ) as sock:
            der_cert = sock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        sha256_fp = cert.fingerprint(hashes.SHA256()).hex(":")
        sha1_fp = cert.fingerprint(hashes.SHA1()).hex(":")

        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = [str(n.value) for n in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": not_before.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "sha256_fingerprint": sha256_fp,
            "sha1_fingerprint": sha1_fp,
            "subject_alternative_names": san_list,
            "version": cert.version.name,
        }
    except Exception as exc:
        return {"error": str(exc)}


def fetch_whois(hostname: str) -> dict[str, Any]:
    try:
        w = whois.whois(hostname)
        raw = w.text if hasattr(w, "text") else str(w)

        def _serialize(v: Any) -> Any:
            if isinstance(v, (list, tuple)):
                return [_serialize(i) for i in v]
            if isinstance(v, datetime.datetime):
                return v.isoformat()
            return str(v) if v is not None else None

        parsed: dict[str, Any] = {}
        for key in ("registrar", "creation_date", "expiration_date",
                    "updated_date", "name_servers", "status", "emails",
                    "registrant_country", "org"):
            val = getattr(w, key, None)
            if val is not None:
                parsed[key] = _serialize(val)

        return {"raw": raw, "parsed": parsed}
    except Exception as exc:
        return {"error": str(exc), "raw": "", "parsed": {}}


def capture_network(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    return {
        "hostname": hostname,
        "scheme": parsed.scheme,
        "dns": resolve_dns(hostname),
        "tls": fetch_tls_cert(hostname, port) if parsed.scheme == "https" else None,
        "whois": fetch_whois(hostname),
    }
