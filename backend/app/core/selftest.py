"""The watchdog's self-test decoy.

Every few minutes the watchdog requests ``/<link path>/<probe token>?n=<nonce>`` through the same
public entry point attackers use. The ingest route recognises the probe token and writes the nonce
to ``system_status`` (key ``selftest_probe``); the watchdog then waits for that nonce. Seeing it
proves the whole path a real hit takes: DNS or the edge address, TLS, nginx, the backend and a
database write.

The probe is not a honey token. It is never stored as a detection event, never alerts a customer
and never touches the append-only evidence tables, so running it every few minutes leaves no
permanent trace. The HTTP response is the normal one for an unknown token, so a probe request
looks like any other request to the ingest host.

The token is derived from INTEGRATION_SIGNING_KEY, so only the server knows it.
"""
from __future__ import annotations

import hashlib
import hmac
import re

PROBE_KEY = "selftest_probe"
_NONCE = re.compile(r"^[0-9a-f]{32}$")


def probe_token(settings) -> str:
    key = (settings.integration_signing_key or "").encode()
    if not key:
        # Development without an integration key: derive from the JWT key, domain-separated.
        key = hashlib.sha256(b"honeyshield-selftest-dev|" + settings.jwt_secret_key.encode()).digest()
    return hmac.new(key, b"honeyshield-selftest-v1", hashlib.sha256).hexdigest()[:32]


def is_probe(token_value: str, settings) -> bool:
    return len(token_value) == 32 and hmac.compare_digest(token_value.encode(), probe_token(settings).encode())


def valid_nonce(value: str | None) -> bool:
    return bool(value) and bool(_NONCE.match(value))
