"""TOTP (RFC 6238 / RFC 4226) and recovery-code primitives for operator MFA (HONEY-029).

Secrets are derived, never stored: secret = HMAC-SHA256(MFA_SECRET_KEY, "honeyshield-totp-v1|id|nonce")
truncated to 160 bits (the RFC 4226 recommended length). Re-enrolment changes the nonce and
therefore the secret. Recovery codes are stored only as keyed hashes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
import urllib.parse

from app.core.config import get_settings

PERIOD_SECONDS = 30
DIGITS = 6
# Accept the previous and next 30 s step to absorb clock drift between phone and server.
DRIFT_STEPS = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
_TOTP_RE = re.compile(r"^[0-9]{6}$")
_RECOVERY_RE = re.compile(r"^[a-z0-9]{10}$")


def new_nonce() -> str:
    return secrets.token_hex(16)


def derive_secret(user_id: int, nonce: str) -> bytes:
    key = get_settings().mfa_key_bytes
    return hmac.new(key, f"honeyshield-totp-v1|{user_id}|{nonce}".encode(), hashlib.sha256).digest()[:20]


def secret_base32(secret: bytes) -> str:
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def hotp(secret: bytes, counter: int) -> str:
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD_SECONDS)


def totp(secret: bytes, now: float | None = None) -> str:
    return hotp(secret, current_step(now))


def looks_like_totp(code: str) -> bool:
    return bool(_TOTP_RE.match(code))


def verify_totp(secret: bytes, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. A step at or before ``last_step`` is a replay."""
    if not looks_like_totp(code):
        return None
    step = current_step(now)
    matched: int | None = None
    for candidate in range(step - DRIFT_STEPS, step + DRIFT_STEPS + 1):
        # Compare every candidate (no early exit) so timing does not reveal which step matched.
        if hmac.compare_digest(hotp(secret, candidate), code) and matched is None:
            matched = candidate
    if matched is None or (last_step is not None and matched <= last_step):
        return None
    return matched


def provisioning_uri(secret: bytes, account: str, issuer: str) -> str:
    label = urllib.parse.quote(f"{issuer}:{account}", safe="@:")
    query = urllib.parse.urlencode({"secret": secret_base32(secret), "issuer": issuer, "algorithm": "SHA1",
                                    "digits": DIGITS, "period": PERIOD_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code).lower()


def generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_code(user_id: int, code: str) -> str:
    key = get_settings().mfa_key_bytes
    message = f"honeyshield-recovery-v1|{user_id}|{normalize_recovery_code(code)}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def looks_like_recovery_code(code: str) -> bool:
    return bool(_RECOVERY_RE.match(normalize_recovery_code(code)))
