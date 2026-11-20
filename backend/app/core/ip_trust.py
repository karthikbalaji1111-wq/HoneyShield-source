"""Secure client IP extraction, validation, and trusted-proxy handling."""
from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Mapping, Optional

if TYPE_CHECKING:
    from fastapi import Request
    from app.core.config import Settings

logger = logging.getLogger(__name__)


def is_valid_ip(value: str) -> bool:
    """Check if a string represents a valid IPv4 or IPv6 address.

    Handles test environment loopbacks ('testclient' or 'localhost') appropriately.
    """
    if not value or not isinstance(value, str):
        return False
    val = value.strip()
    if val in ("testclient", "localhost"):
        return True
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    """Parse and normalize an IP address to standard string form.

    Raises:
        ValueError: If value is not a valid IP address.
    """
    if not value or not isinstance(value, str):
        raise ValueError("IP address must be a non-empty string")
    val = value.strip()
    if val in ("testclient", "localhost"):
        return "127.0.0.1"
    try:
        obj = ipaddress.ip_address(val)
        return str(obj)
    except ValueError as e:
        raise ValueError(f"Invalid IP address format: '{val}'") from e


def is_ip_in_trusted_proxies(peer_ip: str, trusted_proxies: list[str]) -> bool:
    """Determine whether the peer IP address matches the trusted proxy configuration."""
    if not peer_ip:
        return False
    if "*" in trusted_proxies:
        return True

    # Normalize testclient / localhost
    if peer_ip in ("testclient", "localhost"):
        peer_ip = "127.0.0.1"

    try:
        peer_addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False

    for proxy_pattern in trusted_proxies:
        proxy_pattern = proxy_pattern.strip()
        if not proxy_pattern:
            continue
        try:
            if "/" in proxy_pattern:
                # CIDR network notation
                network = ipaddress.ip_network(proxy_pattern, strict=False)
                if peer_addr in network:
                    return True
            else:
                # Exact IP match
                target_addr = ipaddress.ip_address(proxy_pattern)
                if peer_addr == target_addr:
                    return True
        except ValueError:
            logger.warning("Invalid trusted proxy pattern configured: %s", proxy_pattern)
            continue

    return False


def client_from_forwarded_for(x_forwarded_for: str, trusted_proxies: list[str]) -> Optional[str]:
    """Return the original client from an X-Forwarded-For chain, or None.

    Each proxy *appends* the address it received the request from, so only the
    right-hand end of the chain was written by infrastructure we trust; everything
    to the left may have been supplied by the client. Walk from the right, skip our
    own trusted proxies, and return the first address that is not one of them
    (HONEY-005). Taking the leftmost entry would let any client choose its
    recorded IP by sending its own X-Forwarded-For header.

    A malformed hop stops the walk (None): addresses left of it cannot be trusted.
    If every hop is a trusted proxy, the leftmost one is the best available answer.
    """
    parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
    if not parts:
        return None
    normalized: list[str] = []
    for candidate in reversed(parts):
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            return None
        if not is_ip_in_trusted_proxies(ip, trusted_proxies):
            return ip
        normalized.append(ip)
    return normalized[-1]


def resolve_client_ip(peer_host: Optional[str], headers: "Mapping[str, str]", trusted_proxies: list[str]) -> str:
    """Resolve the client IP from the direct peer and, if it is trusted, forwarding headers.

    Security Rules:
    1. If the direct peer is NOT in ``trusted_proxies``, X-Forwarded-For and X-Real-IP
       are ignored, so clients cannot spoof their address.
    2. If the peer IS trusted, X-Forwarded-For is walked right-to-left skipping trusted
       proxies (see ``client_from_forwarded_for``), then X-Real-IP is consulted.
    3. Malformed values fall back safely to the direct peer IP.
    4. Test environment 'testclient' / 'localhost' is normalized to '127.0.0.1'.
    """
    if not peer_host:
        return "127.0.0.1"

    if peer_host in ("testclient", "localhost"):
        peer_ip = "127.0.0.1"
    else:
        try:
            peer_ip = str(ipaddress.ip_address(peer_host.strip()))
        except ValueError:
            return "127.0.0.1"

    if not is_ip_in_trusted_proxies(peer_ip, trusted_proxies):
        return peer_ip

    x_forwarded_for = headers.get("x-forwarded-for")
    if x_forwarded_for:
        client = client_from_forwarded_for(x_forwarded_for, trusted_proxies)
        if client is not None:
            return client

    x_real_ip = headers.get("x-real-ip")
    if x_real_ip:
        try:
            return str(ipaddress.ip_address(x_real_ip.strip()))
        except ValueError:
            pass

    return peer_ip


def extract_client_ip(request: "Request", settings: "Settings") -> str:
    """Extract the client IP for a request according to the trusted proxy model."""
    peer_host = request.client.host if request.client else None
    return resolve_client_ip(peer_host, request.headers, settings.trusted_proxies)
