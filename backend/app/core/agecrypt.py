"""Backup encryption in the age v1 file format (https://age-encryption.org/v1), X25519 recipients.

Why age: the operator can decrypt a backup with the standard ``age`` tool on any machine, without
HoneyShield, and the format is small, modern and well reviewed. Backups are encrypted to a public
key ("age1..."); only the matching identity ("AGE-SECRET-KEY-1..."), kept off the server, can read
them, so a leaked bucket or a stolen storage account reveals nothing.

Implemented with ``cryptography`` only (X25519, HKDF-SHA-256, HMAC-SHA-256, ChaCha20-Poly1305) and
streamed in 64 KiB chunks, so memory use does not grow with the database. Interoperability with
the reference ``age`` binary is tested both ways (tests/ops/test_backup.py).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import BinaryIO, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

INTRO = b"age-encryption.org/v1\n"
X25519_LABEL = b"age-encryption.org/v1/X25519"
CHUNK = 64 * 1024
TAG = 16


class AgeError(ValueError):
    pass


# ------------------------------------------------------------------------------------ bech32 (BIP 173)
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: Iterable[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc, bits, out, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise AgeError("invalid bech32 data")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise AgeError("invalid bech32 padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    five = _convertbits(data, 8, 5, True)
    values = _hrp_expand(hrp) + five
    pm = _polymod(values + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in five + checksum)


def bech32_decode(text: str) -> tuple[str, bytes]:
    if text.lower() != text and text.upper() != text:
        raise AgeError("mixed-case bech32")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise AgeError("invalid bech32 string")
    hrp, data = text[:pos], text[pos + 1:]
    try:
        values = [_CHARSET.index(c) for c in data]
    except ValueError as exc:
        raise AgeError("invalid bech32 character") from exc
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise AgeError("bech32 checksum mismatch")
    return hrp, bytes(_convertbits(values[:-6], 5, 8, False))


# ------------------------------------------------------------------------------------ keys
def generate_identity() -> tuple[str, str]:
    """A new (identity, recipient) pair: ("AGE-SECRET-KEY-1...", "age1...")."""
    key = X25519PrivateKey.generate()
    secret = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return bech32_encode("age-secret-key-", secret).upper(), recipient_of(key)


def recipient_of(key: X25519PrivateKey) -> str:
    return bech32_encode("age", key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def parse_recipient(text: str) -> X25519PublicKey:
    hrp, data = bech32_decode(text.strip())
    if hrp != "age" or len(data) != 32:
        raise AgeError("not an age X25519 recipient (age1...)")
    return X25519PublicKey.from_public_bytes(data)


def parse_identity(text: str) -> X25519PrivateKey:
    hrp, data = bech32_decode(text.strip())
    if hrp != "age-secret-key-" or len(data) != 32:
        raise AgeError("not an age X25519 identity (AGE-SECRET-KEY-1...)")
    return X25519PrivateKey.from_private_bytes(data)


def identities_from_text(text: str) -> list[X25519PrivateKey]:
    """Identities from an age identity file (comments and blank lines ignored)."""
    out = [parse_identity(line) for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not out:
        raise AgeError("no identity found")
    return out


# ------------------------------------------------------------------------------------ primitives
def _b64(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


def _unb64(data: bytes) -> bytes:
    if b"=" in data or b"\r" in data:
        raise AgeError("non-canonical base64")
    try:
        out = base64.b64decode(data + b"=" * (-len(data) % 4), validate=True)
    except ValueError as exc:
        raise AgeError("invalid base64") from exc
    if _b64(out) != data:
        raise AgeError("non-canonical base64")
    return out


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _chunk_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


# ------------------------------------------------------------------------------------ encrypt
def encrypt_stream(src: BinaryIO, dst: BinaryIO, recipients: list[str]) -> int:
    """Encrypt ``src`` to every recipient; returns the number of plaintext bytes."""
    if not recipients:
        raise AgeError("at least one recipient is required")
    file_key = os.urandom(16)
    header = bytearray(INTRO)
    for text in recipients:
        rcpt = parse_recipient(text)
        eph = X25519PrivateKey.generate()
        share = _raw_public(eph.public_key())
        shared = eph.exchange(rcpt)
        if shared == b"\x00" * 32:
            raise AgeError("invalid recipient")
        wrap = _hkdf(shared, share + _raw_public(rcpt), X25519_LABEL)
        body = ChaCha20Poly1305(wrap).encrypt(b"\x00" * 12, file_key, None)
        header += b"-> X25519 " + _b64(share) + b"\n"
        encoded = _b64(body)
        for i in range(0, len(encoded), 64):
            header += encoded[i:i + 64] + b"\n"
        if len(encoded) % 64 == 0:
            header += b"\n"
    header += b"---"
    mac = hmac.new(_hkdf(file_key, b"", b"header"), bytes(header), hashlib.sha256).digest()
    dst.write(bytes(header) + b" " + _b64(mac) + b"\n")
    nonce = os.urandom(16)
    dst.write(nonce)
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    total, counter = 0, 0
    current = src.read(CHUNK)
    while True:
        following = src.read(CHUNK) if len(current) == CHUNK else b""
        last = not following
        dst.write(aead.encrypt(_chunk_nonce(counter, last), current, None))
        total += len(current)
        if last:
            return total
        counter += 1
        current = following


# ------------------------------------------------------------------------------------ decrypt
def _read_line(src: BinaryIO, limit: int = 4096) -> bytes:
    line = src.readline(limit)
    if not line.endswith(b"\n"):
        raise AgeError("truncated or oversized header")
    return line[:-1]


def decrypt_stream(src: BinaryIO, dst: BinaryIO, identities: list[X25519PrivateKey]) -> int:
    if src.read(len(INTRO)) != INTRO:
        raise AgeError("not an age v1 file")
    header = bytearray(INTRO)
    stanzas: list[tuple[list[bytes], bytes]] = []
    while True:
        line = _read_line(src)
        if line.startswith(b"---"):
            if not line.startswith(b"--- "):
                raise AgeError("malformed header MAC line")
            header += b"---"
            mac = _unb64(line[4:])
            break
        if not line.startswith(b"-> "):
            raise AgeError("malformed stanza")
        header += line + b"\n"
        args = line[3:].split(b" ")
        body = bytearray()
        while True:
            chunk = _read_line(src)
            header += chunk + b"\n"
            if len(chunk) > 64:
                raise AgeError("stanza line too long")
            body += chunk
            if len(chunk) < 64:
                break
        stanzas.append((args, _unb64(bytes(body))))
        if len(stanzas) > 64:
            raise AgeError("too many stanzas")
    file_key = None
    for args, body in stanzas:
        if len(args) != 2 or args[0] != b"X25519" or len(body) != 32:
            continue
        share = _unb64(args[1])
        if len(share) != 32:
            raise AgeError("invalid X25519 share")
        for ident in identities:
            shared = ident.exchange(X25519PublicKey.from_public_bytes(share))
            if shared == b"\x00" * 32:
                raise AgeError("invalid X25519 share")
            wrap = _hkdf(shared, share + _raw_public(ident.public_key()), X25519_LABEL)
            try:
                file_key = ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, body, None)
                break
            except Exception:
                continue
        if file_key:
            break
    if file_key is None:
        raise AgeError("no identity matches this file")
    expected = hmac.new(_hkdf(file_key, b"", b"header"), bytes(header), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise AgeError("header MAC mismatch (file modified?)")
    nonce = src.read(16)
    if len(nonce) != 16:
        raise AgeError("truncated payload")
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    total, counter = 0, 0
    current = src.read(CHUNK + TAG)
    if not current:
        raise AgeError("truncated payload")
    while True:
        following = src.read(CHUNK + TAG) if len(current) == CHUNK + TAG else b""
        last = not following
        try:
            plain = aead.decrypt(_chunk_nonce(counter, last), current, None)
        except Exception as exc:
            raise AgeError("payload authentication failed (file modified or truncated)") from exc
        if last and not plain and counter > 0:
            raise AgeError("empty final chunk")
        dst.write(plain)
        total += len(plain)
        if last:
            return total
        counter += 1
        current = following
