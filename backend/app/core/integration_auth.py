"""Request signing for customer integrations (CUSTOMER_HOOK).

Wire format (all hex lowercase):

    X-HS-Integration: <public_id>
    X-HS-Timestamp:   <unix seconds>
    X-HS-Signature:   v1=<HMAC-SHA256(secret, canonical)>

    canonical = "v1\\n" + METHOD + "\\n" + PATH + "\\n" + TIMESTAMP + "\\n" + SHA256(body)

PATH is the request path without query string. The secret is never stored server-side;
it is re-derived from INTEGRATION_SIGNING_KEY, the credential's public id and its salt.
"""
from __future__ import annotations

import hashlib
import hmac

SIGNATURE_VERSION = "v1"
HEADER_INTEGRATION = "x-hs-integration"
HEADER_TIMESTAMP = "x-hs-timestamp"
HEADER_SIGNATURE = "x-hs-signature"


def derive_secret(master_key: str, public_id: str, key_salt: str) -> str:
    msg = f"honeyshield-integration-{SIGNATURE_VERSION}|{public_id}|{key_salt}".encode()
    return hmac.new(master_key.encode(), msg, hashlib.sha256).hexdigest()


def canonical_string(method: str, path: str, timestamp: str, body: bytes) -> str:
    return "\n".join((SIGNATURE_VERSION, method.upper(), path, timestamp, hashlib.sha256(body).hexdigest()))


def sign(secret: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), canonical_string(method, path, timestamp, body).encode(), hashlib.sha256)
    return f"{SIGNATURE_VERSION}={mac.hexdigest()}"


def verify(secret: str, method: str, path: str, timestamp: str, body: bytes, presented: str) -> bool:
    expected = sign(secret, method, path, timestamp, body)
    return hmac.compare_digest(expected.encode(), (presented or "").encode())


def parse_timestamp(raw: str | None) -> int | None:
    if not raw or not raw.isdigit() or len(raw) > 12:
        return None
    return int(raw)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
