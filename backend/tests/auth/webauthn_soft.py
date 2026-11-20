"""A software authenticator for tests: produces real WebAuthn responses (ES256, EdDSA or RS256)."""
from __future__ import annotations

import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.core.webauthn import b64url_decode, b64url_encode


def cbor(value) -> bytes:
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)

    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


class SoftAuthenticator:
    def __init__(self, alg: int = -7, rp_id: str = "localhost", origin: str = "http://localhost") -> None:
        self.alg, self.rp_id, self.origin = alg, rp_id, origin
        self.credential_id = os.urandom(32)
        self.counter = 0
        if alg == -7:
            self.key = ec.generate_private_key(ec.SECP256R1())
            nums = self.key.public_key().public_numbers()
            self.cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        elif alg == -8:
            self.key = ed25519.Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.cose = cbor({1: 1, 3: -8, -1: 6, -2: raw})
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            nums = self.key.public_key().public_numbers()
            self.cose = cbor({1: 3, 3: -257, -1: nums.n.to_bytes(256, "big"), -2: nums.e.to_bytes(3, "big")})

    def _client_data(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def _auth_data(self, flags: int, attested: bool, rp_id: str | None = None) -> bytes:
        out = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        if attested:
            out += b"\x00" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose
        return out

    def create(self, options: dict, *, origin: str | None = None, rp_id: str | None = None,
               flags: int = 0x45) -> dict:
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": self._auth_data(flags, True, rp_id)})
        cid = b64url_encode(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key",
                "response": {"clientDataJSON": b64url_encode(client_data), "attestationObject": b64url_encode(att),
                             "transports": ["internal"]}}

    def get(self, options: dict, *, origin: str | None = None, rp_id: str | None = None, flags: int = 0x05,
            bump: int = 1, user_handle: bytes | None = None) -> dict:
        self.counter += bump
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth = self._auth_data(flags, False, rp_id)
        signed = auth + hashlib.sha256(client_data).digest()
        if self.alg == -7:
            sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        elif self.alg == -8:
            sig = self.key.sign(signed)
        else:
            sig = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        cid = b64url_encode(self.credential_id)
        resp = {"clientDataJSON": b64url_encode(client_data), "authenticatorData": b64url_encode(auth),
                "signature": b64url_encode(sig)}
        if user_handle is not None:
            resp["userHandle"] = b64url_encode(user_handle)
        return {"id": cid, "rawId": cid, "type": "public-key", "response": resp}


__all__ = ["SoftAuthenticator", "cbor", "b64url_decode", "b64url_encode"]
