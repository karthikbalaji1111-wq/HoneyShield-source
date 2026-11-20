"""Signatures for edge-replay batches (worker -> backend). No database or settings imports, so the
replay worker can run next to the edge with nothing but INTEGRATION_SIGNING_KEY."""
from __future__ import annotations

import hashlib
import hmac


def replay_key(integration_signing_key: str) -> bytes:
    """Key for replay signatures, derived so it is never the integration signing key itself."""
    return hmac.new(integration_signing_key.encode(), b"honeyshield-ingest-replay-v1", hashlib.sha256).digest()


def sign(key: bytes, timestamp: str, body: bytes) -> str:
    return "v1=" + hmac.new(key, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
