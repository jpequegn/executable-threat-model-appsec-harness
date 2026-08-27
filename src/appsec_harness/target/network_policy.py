"""Local-only network policy for synthetic dependencies."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class NetworkPolicyError(ValueError):
    """Raised when a target attempts to leave the loopback boundary."""


def require_loopback_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise NetworkPolicyError("only explicit HTTP(S) loopback URLs are permitted")
    if parsed.hostname == "localhost":
        return url
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise NetworkPolicyError("DNS hostnames are denied; use a loopback IP") from exc
    if not address.is_loopback:
        raise NetworkPolicyError("non-loopback network access is denied")
    return url
