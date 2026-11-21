"""SSRF-resistant webhook delivery (stdlib only).

Defences
* Only https (http only when ALERT_ALLOW_HTTP_WEBHOOKS, development). No userinfo, no
  fragments, ports limited to 443/8443 (or 80/8080 for allowed http).
* The host is resolved and EVERY address must be public unicast: loopback, private (RFC1918,
  ULA), link-local (incl. cloud metadata 169.254.169.254), CGNAT, multicast, reserved,
  unspecified and IPv4-mapped forms are refused.
* Resolution happens again at delivery time and the TCP connection is made to the address
  that was validated, so DNS rebinding cannot redirect it. TLS still verifies the certificate
  against the hostname (SNI + check_hostname).
* Redirects are never followed; response bodies are read up to 4 KiB and discarded.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from app.core import tls

ALLOWED_HTTPS_PORTS = {443, 8443}
ALLOWED_HTTP_PORTS = {80, 8080}
_BLOCKED_V4 = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "0.0.0.0/8")]

Resolver = Callable[[str, int], list[str]]


class UnsafeWebhookURL(ValueError):
    pass


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def is_public_address(addr: str, allowed_private: tuple = ()) -> bool:
    """True for public unicast, or for an address inside an operator-allowed private network.

    Loopback, link-local (cloud metadata), multicast and unspecified addresses are refused even
    when an allowed network covers them.
    """
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if any(ip.version == n.version and ip in n for n in allowed_private):
        return True
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and any(ip in n for n in _BLOCKED_V4):
        return False
    return True


@dataclass(frozen=True)
class ValidatedTarget:
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...]


def validate_url(url: str, allow_http: bool = False, resolver: Resolver | None = None,
                 resolve: bool = True, allowed_private: tuple = ()) -> ValidatedTarget:
    resolver = resolver or default_resolver
    if len(url) > 2048:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http") or (scheme == "http" and not allow_http):
        raise UnsafeWebhookURL("Webhook URL must use https")
    if parts.username or parts.password:
        raise UnsafeWebhookURL("Webhook URL must not contain credentials")
    if parts.fragment:
        raise UnsafeWebhookURL("Webhook URL must not contain a fragment")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeWebhookURL("Webhook URL must have a host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeWebhookURL("Invalid port") from exc
    if port not in (ALLOWED_HTTPS_PORTS if scheme == "https" else ALLOWED_HTTP_PORTS):
        raise UnsafeWebhookURL("Webhook port is not allowed")
    if host in ("localhost",) or host.endswith((".localhost", ".local", ".internal", ".home.arpa")):
        raise UnsafeWebhookURL("Webhook host is not public")
    literal = None
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    if literal is not None and not is_public_address(str(literal), allowed_private):
        raise UnsafeWebhookURL("Webhook host is not public")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    addresses: tuple[str, ...] = ()
    if resolve:
        try:
            resolved = [str(literal)] if literal is not None else resolver(host, port)
        except OSError as exc:
            raise UnsafeWebhookURL("Webhook host does not resolve") from exc
        if not resolved or not all(is_public_address(a, allowed_private) for a in resolved):
            raise UnsafeWebhookURL("Webhook host resolves to a non-public address")
        addresses = tuple(resolved)
    return ValidatedTarget(scheme, host, port, path, addresses)


def signing_secret(master_key: str, public_id: str, key_salt: str) -> str:
    msg = f"honeyshield-webhook-v1|{public_id}|{key_salt}".encode()
    return hmac.new(master_key.encode(), msg, hashlib.sha256).hexdigest()


def signature(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "v1=" + mac.hexdigest()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


Sender = Callable[[ValidatedTarget, dict[str, str], bytes, float], int]


def http_sender(target: ValidatedTarget, headers: dict[str, str], body: bytes, timeout: float) -> int:
    """POST to the first validated address. Returns the status code; raises OSError on failure."""
    address = target.addresses[0]
    if target.scheme == "https":
        conn = _PinnedHTTPSConnection(target.host, address, target.port, timeout, tls.client_context())
    else:
        conn = _PinnedHTTPConnection(target.host, address, target.port, timeout)
    try:
        conn.request("POST", target.path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read(4096)
        return resp.status
    finally:
        conn.close()
