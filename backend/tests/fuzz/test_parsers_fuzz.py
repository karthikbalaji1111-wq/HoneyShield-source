"""Property-based fuzzing of the code that reads attacker- or network-controlled bytes.

Each test feeds generated input (thousands of cases across the suite) to one parser and asserts the
only failure is that parser's own "invalid input" error: never another exception, never a hang.
The public decoy endpoints get the same treatment over HTTP and must never answer with a 5xx.

Raise the effort locally with HYPOTHESIS_PROFILE=deep (10x the examples).
"""
from __future__ import annotations

import io
import os
import string
from types import SimpleNamespace

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from app.core import agecrypt, decoy_paths, safexml, webauthn
from tests.auth.webauthn_soft import cbor

settings.register_profile("ci", max_examples=300, deadline=None)
settings.register_profile("deep", max_examples=3000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))

RAW = st.binary(max_size=2048)


# --------------------------------------------------------------------------------------- WebAuthn
@given(RAW)
def test_cbor_decode_rejects_garbage_cleanly(data):
    try:
        webauthn.cbor_decode(data)
    except webauthn.WebAuthnError:
        pass


CBOR_VALUES = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**63), max_value=2**64 - 1)
    | st.binary(max_size=64) | st.text(max_size=32),
    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=8) | st.integers(-50, 50), inner,
                                                                 max_size=5),
    max_leaves=25,
)


@given(CBOR_VALUES)
def test_cbor_round_trip(value):
    decoded, end = webauthn.cbor_decode(cbor(value))
    assert decoded == value
    assert end == len(cbor(value))


@given(RAW)
def test_authenticator_data_rejects_garbage_cleanly(data):
    try:
        webauthn.parse_authenticator_data(data)
    except webauthn.WebAuthnError:
        pass


@given(RAW)
def test_cose_key_rejects_garbage_cleanly(data):
    try:
        webauthn.cose_public_key(data)
    except webauthn.WebAuthnError:
        pass


B64URL = st.text(alphabet=string.ascii_letters + string.digits + "-_=+/ .", max_size=200)


@given(st.fixed_dictionaries({}, optional={
    "clientDataJSON": B64URL, "authenticatorData": B64URL, "signature": B64URL, "userHandle": B64URL,
    "attestationObject": B64URL}))
def test_assertion_and_registration_reject_garbage_cleanly(response):
    for call in (
        lambda: webauthn.verify_assertion(response, challenge=b"c" * 32, rp_id="app.example.test",
                                          origin_ok=lambda o: True, public_key=b"\xa0", stored_sign_count=0),
        lambda: webauthn.verify_registration(response, challenge=b"c" * 32, rp_id="app.example.test",
                                             origin_ok=lambda o: True),
        lambda: webauthn.assertion_credential_id(response),
    ):
        try:
            call()
        except webauthn.WebAuthnError:
            pass


# ----------------------------------------------------------------------------------- age backups
IDENTITY = agecrypt.identities_from_text(agecrypt.generate_identity()[0])


@given(RAW)
def test_age_decrypt_rejects_garbage_cleanly(data):
    out = io.BytesIO()
    try:
        agecrypt.decrypt_stream(io.BytesIO(data), out, IDENTITY)
    except agecrypt.AgeError:
        pass


@given(st.binary(max_size=1024))
def test_age_decrypt_rejects_tampered_files(payload):
    secret, _ = agecrypt.generate_identity()
    ids = agecrypt.identities_from_text(secret)
    sealed = io.BytesIO()
    agecrypt.encrypt_stream(io.BytesIO(payload), sealed, [agecrypt.recipient_of(ids[0])])
    blob = bytearray(sealed.getvalue())
    blob[len(blob) // 2] ^= 0x01  # one flipped bit anywhere must be detected, never decrypted
    with pytest.raises(agecrypt.AgeError):
        agecrypt.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), ids)


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 3 * 65536])  # chunk boundaries
def test_age_round_trip_at_chunk_boundaries(size):
    secret, _ = agecrypt.generate_identity()
    ids = agecrypt.identities_from_text(secret)
    payload = os.urandom(size)
    sealed, opened = io.BytesIO(), io.BytesIO()
    agecrypt.encrypt_stream(io.BytesIO(payload), sealed, [agecrypt.recipient_of(ids[0])])
    agecrypt.decrypt_stream(io.BytesIO(sealed.getvalue()), opened, ids)
    assert opened.getvalue() == payload


@given(st.text(max_size=200))
def test_age_key_parsing_rejects_garbage_cleanly(text):
    for call in (agecrypt.bech32_decode, agecrypt.parse_recipient, agecrypt.parse_identity,
                 agecrypt.identities_from_text):
        try:
            call(text)
        except agecrypt.AgeError:
            pass


# --------------------------------------------------------------------------------- S3 responses
@given(RAW)
def test_s3_xml_rejects_garbage_cleanly(data):
    try:
        safexml.fromstring(data)
    except safexml.ParseError:
        pass


def test_s3_xml_refuses_entity_expansion():
    bomb = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><l>&b;</l>')
    with pytest.raises(safexml.ParseError):
        safexml.fromstring(bomb)
    external = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    with pytest.raises(safexml.ParseError):
        safexml.fromstring(external)


# ------------------------------------------------------------------------------- decoy URL paths
SEGMENT = st.text(alphabet=string.ascii_letters + string.digits + "-_./%~ ", max_size=40)


@given(SEGMENT, SEGMENT, SEGMENT, st.booleans())
def test_path_validation_only_raises_value_error(link, pixel, collect, legacy):
    try:
        decoy_paths.validate(link, pixel, collect, legacy)
    except ValueError:
        return
    for value in (link, pixel, collect):  # anything accepted is safe inside nginx regexes and paths
        assert decoy_paths.PATH_RE.match(value)
        assert ".." not in value and "%" not in value


PATH_CHARS = string.ascii_letters + string.digits + "-_./%~:@!$&'()*+,;=" + "äé漢"
CONF = SimpleNamespace(decoy_link_path="static/v2", decoy_pixel_path="assets/img",
                       decoy_collect_path="telemetry/v1", decoy_legacy_paths=True)


@given(st.text(alphabet=PATH_CHARS, max_size=120))
def test_token_from_path_never_raises(path):
    token = decoy_paths.token_from_path(CONF, "/" + path)
    assert token is None or (token and "/" not in token)


# --------------------------------------------------------------------- public endpoints over HTTP
URL_CHARS = string.ascii_letters + string.digits + "-_.~%!$&'()*+,;=:@/"
INGEST = {"Host": "cdn.example.test"}


@pytest.fixture()
def ingest_settings(monkeypatch):
    from app.core.config import get_settings
    s = get_settings()
    monkeypatch.setattr(s, "public_ingest_base_url", "https://cdn.example.test")
    monkeypatch.setattr(s, "control_plane_hostnames", ["app.example.test"])
    return s


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=150)
@given(prefix=st.sampled_from(["t", "px", "collect", "integrations/v1", "api/v1", "", "console"]),
       rest=st.text(alphabet=URL_CHARS, max_size=80),
       method=st.sampled_from(["GET", "POST", "HEAD", "PUT", "OPTIONS"]),
       body=st.binary(max_size=512),
       agent=st.text(alphabet=string.printable.strip("\r\n\x0b\x0c"), max_size=120))
def test_public_endpoints_never_fail_with_5xx(client, ingest_settings, prefix, rest, method, body, agent):
    from app.core.rate_limit import reset_all_limiters
    reset_all_limiters()  # measure the handlers, not the rate limiter
    path = f"/{prefix}/{rest}" if prefix else f"/{rest}"
    response = client.request(method, path, content=body if method in ("POST", "PUT") else None,
                              headers={**INGEST, "User-Agent": agent, "Content-Type": "application/json"})
    assert response.status_code < 500, (method, path, response.status_code, response.text[:200])
