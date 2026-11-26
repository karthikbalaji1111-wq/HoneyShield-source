"""DNS decoy names: <token>.<zone>, optionally with anything in front (<data>.<token>.<zone>).

Shared by the generator, the DNS listener and the backend so the three always agree on what a
token label looks like. No settings or database imports: the listener runs without them.
"""
from __future__ import annotations

import re
import secrets

# 26 characters of lower-case base32: 130 bits, and DNS-safe because resolvers may change the case
# of a name in flight (0x20 randomisation), so only lower-case letters and digits are used.
TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
TOKEN_LENGTH = 26
TOKEN_LABEL = re.compile(rf"^[a-z2-7]{{{TOKEN_LENGTH}}}$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")


def new_token_label() -> str:
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(TOKEN_LENGTH))


def normalise_zone(zone: str | None) -> str | None:
    """The zone in canonical form, or None when unset. Raises ValueError for a malformed zone."""
    if not zone or not zone.strip():
        return None
    value = zone.strip().lower().rstrip(".")
    if not HOSTNAME.match(value):
        raise ValueError("DNS_TOKEN_ZONE must be a host name such as dns.example.com")
    return value


def in_zone(qname: str, zone: str) -> bool:
    return qname == zone or qname.endswith("." + zone)


def token_label(qname: str, zone: str) -> str | None:
    """The token label of a query name inside ``zone``, or None. ``qname`` is lower case."""
    if not qname.endswith("." + zone):
        return None
    label = qname[: -len(zone) - 1].rsplit(".", 1)[-1]
    return label if TOKEN_LABEL.match(label) else None
