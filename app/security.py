"""Reusable security controls, each tied to a remediated finding (see findings/)."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import bcrypt

# ---- F05 Cryptographic Failures: password storage -------------------------------------------
def hash_password(plaintext: str) -> str:
    """bcrypt with a per-password salt and a work factor. Never store plaintext or a bare hash."""
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plaintext: str, stored: str) -> bool:
    try:
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    except (ValueError, TypeError):
        return False


# ---- F04 SSRF: URL allowlist + private-range block ------------------------------------------
_ALLOWED_SCHEMES = {"https"}


def _is_disallowed_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def validate_outbound_url(url: str, allowed_hosts: set[str]) -> str:
    """Return the URL only if it is https, its host is on the allowlist, and every resolved
    address is public. Blocks cloud-metadata (169.254.169.254), localhost and internal ranges.
    Raises ValueError otherwise. (CWE-918)"""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError("scheme not allowed")
    host = parsed.hostname or ""
    if host.lower() not in {h.lower() for h in allowed_hosts}:
        raise ValueError("host not on allowlist")
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("host does not resolve") from exc
    for info in infos:
        if _is_disallowed_ip(info[4][0]):
            raise ValueError("host resolves to a non-public address")
    return url
