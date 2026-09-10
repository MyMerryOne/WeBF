"""URL policy for public-web capture targets and redirect destinations."""
import ipaddress
import socket
from urllib.parse import urlparse


def validate_public_url(url: str) -> None:
    """Reject capture destinations outside the authorized public-web scope."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported capture URL scheme: {parsed.scheme or '<none>'}")
    if not parsed.hostname:
        raise ValueError("capture URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("capture URL must not contain credentials")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost") or hostname.endswith(".local"):
        raise ValueError(f"private capture hostname is not allowed: {hostname}")

    # Resolve every address before the request so a hostname cannot hide a
    # loopback, link-local, private, or otherwise non-public destination.
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(hostname, parsed.port, type=socket.SOCK_STREAM)
        }
    except OSError as exc:
        raise ValueError(f"could not resolve capture hostname: {hostname}") from exc

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError(f"non-public capture address is not allowed: {address}")