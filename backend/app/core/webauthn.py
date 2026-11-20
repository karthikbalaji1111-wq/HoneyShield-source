"""WebAuthn (passkey) verification for the relying-party side, W3C Web Authentication Level 2.

Only what HoneyShield needs: registration with ``attestation: "none"`` and assertions, for ES256
(-7), EdDSA/Ed25519 (-8) and RS256 (-257) keys. The attestation statement is not verified: the
user registering a passkey is already signed in with their password, so the authenticator's make
is not a trust decision here (the same reason "none" is requested from the browser).

What is verified (registration, section 7.1 / assertion, section 7.2):
* clientDataJSON ``type``, ``challenge`` (single-use, issued by the server) and ``origin``;
* the RP ID hash in authenticatorData, the user-present flag, and the attested credential data;
* for assertions, the signature over ``authenticatorData || SHA-256(clientDataJSON)`` with the stored
  public key, and the signature counter (a counter that goes backwards means a cloned key).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALG_ES256 = -7
ALG_EDDSA = -8
ALG_RS256 = -257
SUPPORTED_ALGS = (ALG_ES256, ALG_EDDSA, ALG_RS256)

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40
FLAG_ED = 0x80


class WebAuthnError(ValueError):
    """The browser's response failed verification. The message is safe to log, not to show."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or len(value) > 16384:
        raise WebAuthnError("invalid base64url value")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise WebAuthnError("invalid base64url value") from exc


# ------------------------------------------------------------------------------------- CBOR
# Minimal RFC 8949 decoder for authenticator data: definite lengths only (authenticators emit
# canonical CBOR), depth- and size-bounded.

def cbor_decode(data: bytes, offset: int = 0, depth: int = 0) -> tuple[Any, int]:
    """Decode one item at ``offset``; returns (value, offset after the item)."""
    if depth > 16:
        raise WebAuthnError("CBOR nesting too deep")
    if offset >= len(data):
        raise WebAuthnError("truncated CBOR")
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if offset + size > len(data):
            raise WebAuthnError("truncated CBOR")
        arg = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    else:
        raise WebAuthnError("unsupported CBOR encoding")
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major in (2, 3):
        if offset + arg > len(data):
            raise WebAuthnError("truncated CBOR")
        raw = data[offset:offset + arg]
        offset += arg
        if major == 2:
            return bytes(raw), offset
        try:
            return raw.decode("utf-8"), offset
        except UnicodeDecodeError as exc:
            raise WebAuthnError("invalid CBOR text") from exc
    if major == 4:
        if arg > 1024:
            raise WebAuthnError("CBOR array too large")
        items = []
        for _ in range(arg):
            item, offset = cbor_decode(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        if arg > 256:
            raise WebAuthnError("CBOR map too large")
        out: dict[Any, Any] = {}
        for _ in range(arg):
            key, offset = cbor_decode(data, offset, depth + 1)
            if isinstance(key, (list, dict)):
                raise WebAuthnError("unsupported CBOR map key")
            value, offset = cbor_decode(data, offset, depth + 1)
            out[key] = value
        return out, offset
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        raise WebAuthnError("unsupported CBOR simple value")
    raise WebAuthnError("unsupported CBOR type (tags)")


# ------------------------------------------------------------------------------------- COSE keys

def cose_public_key(cose: bytes):
    """(cryptography public key, COSE algorithm) for a COSE_Key."""
    key, end = cbor_decode(cose)
    if end != len(cose) or not isinstance(key, dict):
        raise WebAuthnError("invalid COSE key")
    kty, alg = key.get(1), key.get(3)
    if alg not in SUPPORTED_ALGS:
        raise WebAuthnError(f"unsupported key algorithm {alg}")
    try:
        if alg == ALG_ES256:
            if kty != 2 or key.get(-1) != 1:
                raise WebAuthnError("ES256 key must be EC2 on P-256")
            x, y = key.get(-2), key.get(-3)
            if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
                raise WebAuthnError("invalid EC2 coordinates")
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                ec.SECP256R1()).public_key()
            return pub, alg
        if alg == ALG_EDDSA:
            if kty != 1 or key.get(-1) != 6:
                raise WebAuthnError("EdDSA key must be OKP Ed25519")
            x = key.get(-2)
            if not isinstance(x, bytes) or len(x) != 32:
                raise WebAuthnError("invalid Ed25519 key")
            return ed25519.Ed25519PublicKey.from_public_bytes(x), alg
        if kty != 3:
            raise WebAuthnError("RS256 key must be RSA")
        n, e = key.get(-1), key.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) < 256:
            raise WebAuthnError("invalid RSA key (at least 2048 bits)")
        return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key(), alg
    except WebAuthnError:
        raise
    except Exception as exc:  # invalid point, etc.
        raise WebAuthnError("invalid public key") from exc


def verify_signature(cose: bytes, signature: bytes, signed: bytes) -> None:
    pub, alg = cose_public_key(cose)
    try:
        if alg == ALG_ES256:
            pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_EDDSA:
            pub.verify(signature, signed)
        else:
            pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise WebAuthnError("signature does not verify") from exc


# ------------------------------------------------------------------------------------- parsing

@dataclass
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None = None
    public_key: bytes | None = None  # COSE_Key bytes

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)


def parse_authenticator_data(data: bytes) -> AuthenticatorData:
    if len(data) < 37:
        raise WebAuthnError("authenticator data too short")
    rp_id_hash, flags = data[:32], data[32]
    (sign_count,) = struct.unpack(">I", data[33:37])
    out = AuthenticatorData(rp_id_hash, flags, sign_count)
    offset = 37
    if flags & FLAG_AT:
        if len(data) < offset + 18:
            raise WebAuthnError("attested credential data too short")
        (cred_len,) = struct.unpack(">H", data[offset + 16:offset + 18])
        offset += 18
        if cred_len < 16 or cred_len > 1023 or len(data) < offset + cred_len:
            raise WebAuthnError("invalid credential id length")
        out.credential_id = data[offset:offset + cred_len]
        offset += cred_len
        _, end = cbor_decode(data, offset)
        out.public_key = data[offset:end]
        offset = end
    if flags & FLAG_ED:
        _, offset = cbor_decode(data, offset)
    if offset != len(data):
        raise WebAuthnError("trailing bytes in authenticator data")
    return out


def _client_data(raw: bytes, expected_type: str, challenge: bytes, origin_ok: Callable[[str], bool]) -> None:
    try:
        cd = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WebAuthnError("clientDataJSON is not JSON") from exc
    if not isinstance(cd, dict) or cd.get("type") != expected_type:
        raise WebAuthnError(f"clientData type is not {expected_type}")
    got = cd.get("challenge")
    if not isinstance(got, str) or b64url_decode(got) != challenge:
        raise WebAuthnError("challenge mismatch")
    origin = cd.get("origin")
    if not isinstance(origin, str) or not origin_ok(origin):
        raise WebAuthnError(f"unexpected origin {str(cd.get('origin'))[:100]!r}")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin ceremony")


def _check_rp(auth: AuthenticatorData, rp_id: str, require_uv: bool) -> None:
    if auth.rp_id_hash != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("RP ID hash mismatch")
    if not auth.user_present:
        raise WebAuthnError("user presence flag not set")
    if require_uv and not auth.user_verified:
        raise WebAuthnError("user verification required")


@dataclass
class NewCredential:
    credential_id: bytes
    public_key: bytes
    alg: int
    sign_count: int
    user_verified: bool


def verify_registration(response: dict[str, Any], *, challenge: bytes, rp_id: str, origin_ok: Callable[[str], bool],
                        require_uv: bool = False) -> NewCredential:
    """Verify a PublicKeyCredential from navigator.credentials.create() (JSON-encoded by the client)."""
    if not isinstance(response, dict) or response.get("type") != "public-key":
        raise WebAuthnError("not a public-key credential")
    inner = response.get("response")
    if not isinstance(inner, dict):
        raise WebAuthnError("missing response")
    client_data = b64url_decode(inner.get("clientDataJSON", ""))
    _client_data(client_data, "webauthn.create", challenge, origin_ok)
    att, end = cbor_decode(b64url_decode(inner.get("attestationObject", "")))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise WebAuthnError("invalid attestation object")
    auth = parse_authenticator_data(att["authData"])
    _check_rp(auth, rp_id, require_uv)
    if not auth.credential_id or not auth.public_key:
        raise WebAuthnError("no attested credential")
    raw_id = b64url_decode(response.get("rawId") or response.get("id") or "")
    if raw_id != auth.credential_id:
        raise WebAuthnError("credential id mismatch")
    _, alg = cose_public_key(auth.public_key)
    return NewCredential(auth.credential_id, auth.public_key, alg, auth.sign_count, auth.user_verified)


@dataclass
class Assertion:
    credential_id: bytes
    sign_count: int
    user_verified: bool
    user_handle: bytes | None


def assertion_credential_id(response: dict[str, Any]) -> bytes:
    if not isinstance(response, dict) or response.get("type") != "public-key":
        raise WebAuthnError("not a public-key credential")
    return b64url_decode(response.get("rawId") or response.get("id") or "")


def verify_assertion(response: dict[str, Any], *, challenge: bytes, rp_id: str, origin_ok: Callable[[str], bool],
                     public_key: bytes, stored_sign_count: int, require_uv: bool = False) -> Assertion:
    """Verify a PublicKeyCredential from navigator.credentials.get() against the stored key."""
    cred_id = assertion_credential_id(response)
    inner = response.get("response")
    if not isinstance(inner, dict):
        raise WebAuthnError("missing response")
    client_data = b64url_decode(inner.get("clientDataJSON", ""))
    auth_raw = b64url_decode(inner.get("authenticatorData", ""))
    signature = b64url_decode(inner.get("signature", ""))
    _client_data(client_data, "webauthn.get", challenge, origin_ok)
    auth = parse_authenticator_data(auth_raw)
    _check_rp(auth, rp_id, require_uv)
    verify_signature(public_key, signature, auth_raw + hashlib.sha256(client_data).digest())
    if (auth.sign_count or stored_sign_count) and auth.sign_count <= stored_sign_count:
        raise WebAuthnError("signature counter did not increase (possible cloned authenticator)")
    handle = inner.get("userHandle")
    return Assertion(cred_id, auth.sign_count, auth.user_verified, b64url_decode(handle) if handle else None)
