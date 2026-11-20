"""Passkeys (WebAuthn) as a phishing-resistant second factor: registration, sign-in, misuse."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.core import webauthn
from app.core.config import get_settings
from app.core.security import AMR_MFA, create_access_token, decode_access_token
from app.models.audit_log import AuditLog
from app.models.passkey import PasskeyChallenge, PasskeyCredential
from app.models.user import User
from tests.auth.webauthn_soft import SoftAuthenticator, cbor
from tests.conftest import auth_headers


def _audit(db_session, event_type: str) -> list[AuditLog]:
    return list(db_session.execute(select(AuditLog).where(AuditLog.event_type == event_type)).scalars())


def _register(client, user: User, auth: SoftAuthenticator, headers=None, name="Laptop", **kw):
    headers = headers or auth_headers(user)
    r = client.post("/auth/passkeys/register/options", json={"current_password": "password"}, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    cred = auth.create(body["options"], **kw)
    return client.post("/auth/passkeys/register", json={"challenge_id": body["challenge_id"], "name": name,
                                                       "credential": cred}, headers=headers)


def _login_options(client, user: User, password="password"):
    return client.post("/auth/passkey/login/options", json={"email": user.email, "password": password})


def _login(client, user: User, auth: SoftAuthenticator, **kw):
    r = _login_options(client, user)
    assert r.status_code == 200, r.text
    body = r.json()
    return body, client.post("/auth/passkey/login", json={"challenge_id": body["challenge_id"],
                                                         "credential": auth.get(body["options"], **kw)})


@pytest.mark.parametrize("alg", [-7, -8, -257])
def test_register_then_sign_in_with_password_and_passkey(client, db_session, admin_a, alg):
    db_session.commit()
    auth = SoftAuthenticator(alg)
    r = _register(client, admin_a, auth)
    assert r.status_code == 200, r.text
    assert decode_access_token(r.json()["access_token"])["amr"] == AMR_MFA
    assert r.json()["passkey"]["algorithm"] == {-7: "ES256", -8: "EdDSA", -257: "RS256"}[alg]
    db_session.refresh(admin_a)
    assert admin_a.passkey_enabled is True and admin_a.has_second_factor

    # The password alone no longer signs in, and old password-only tokens stop working.
    r = client.post("/auth/login", json={"email": admin_a.email, "password": "password"})
    assert r.status_code == 401 and r.json()["detail"] == "Passkey required"
    assert client.get("/api/v1/projects", headers=auth_headers(admin_a)).status_code == 401
    # A code cannot stand in for the passkey (no authenticator app is enrolled).
    r = client.post("/auth/login", json={"email": admin_a.email, "password": "password", "otp": "123456"})
    assert r.status_code == 401

    _, r = _login(client, admin_a, auth)
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    assert decode_access_token(token)["amr"] == AMR_MFA
    assert client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["passkey_enabled"] is True and me["passkeys"] == 1 and me["mfa_enabled"] is False
    events = _audit(db_session, "AUTH_LOGIN_SUCCESS")
    assert any((e.event_metadata or {}).get("method") == "passkey" for e in events)
    assert _audit(db_session, "PASSKEY_REGISTERED")


def test_a_response_cannot_be_replayed(client, db_session, admin_a):
    db_session.commit()
    auth = SoftAuthenticator()
    assert _register(client, admin_a, auth).status_code == 200
    body, r = _login(client, admin_a, auth)
    assert r.status_code == 200
    again = auth.get(body["options"])
    r = client.post("/auth/passkey/login", json={"challenge_id": body["challenge_id"], "credential": again})
    assert r.status_code == 401


def test_expired_challenge_is_refused(client, db_session, admin_a):
    db_session.commit()
    auth = SoftAuthenticator()
    assert _register(client, admin_a, auth).status_code == 200
    body = _login_options(client, admin_a).json()
    db_session.execute(update(PasskeyChallenge).where(PasskeyChallenge.public_id == body["challenge_id"])
                       .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    db_session.commit()
    r = client.post("/auth/passkey/login", json={"challenge_id": body["challenge_id"],
                                                 "credential": auth.get(body["options"])})
    assert r.status_code == 401


@pytest.mark.parametrize("tamper", ["origin", "rp", "no_user_presence", "signature", "counter", "user_handle"])
def test_tampered_assertions_are_refused_and_audited(client, db_session, admin_a, tamper):
    db_session.commit()
    auth = SoftAuthenticator()
    assert _register(client, admin_a, auth).status_code == 200
    body = _login_options(client, admin_a).json()
    kw = {"origin": {"origin": "https://honeyshield-login.example"}, "rp": {"rp_id": "evil.example"},
          "no_user_presence": {"flags": 0x04}, "counter": {"bump": 0},
          "user_handle": {"user_handle": b"someone-else-0000"}}.get(tamper, {})
    if tamper == "counter":
        auth.counter = 0  # an authenticator whose counter went backwards (or a clone)
        stored = db_session.scalars(select(PasskeyCredential)).one()
        stored.sign_count = 5
        db_session.commit()
    cred = auth.get(body["options"], **kw)
    if tamper == "signature":
        sig = bytearray(webauthn.b64url_decode(cred["response"]["signature"]))
        sig[-1] ^= 1
        cred["response"]["signature"] = webauthn.b64url_encode(bytes(sig))
    r = client.post("/auth/passkey/login", json={"challenge_id": body["challenge_id"], "credential": cred})
    assert r.status_code == 401
    expected = "PASSKEY_CLONE_SUSPECTED" if tamper == "counter" else "AUTH_PASSKEY_FAILURE"
    reason = {"origin": "unexpected origin", "rp": "RP ID hash", "no_user_presence": "user presence",
              "signature": "signature does not verify", "counter": "counter", "user_handle": "user handle"}[tamper]
    assert any(reason in e.event_metadata["reason"] for e in _audit(db_session, expected))


def test_another_users_passkey_cannot_complete_a_sign_in(client, db_session, admin_a, admin_b):
    db_session.commit()
    auth_a, auth_b = SoftAuthenticator(), SoftAuthenticator()
    assert _register(client, admin_a, auth_a).status_code == 200
    assert _register(client, admin_b, auth_b).status_code == 200
    body = _login_options(client, admin_a).json()  # admin_a's password, then admin_b's passkey
    r = client.post("/auth/passkey/login", json={"challenge_id": body["challenge_id"],
                                                 "credential": auth_b.get(body["options"])})
    assert r.status_code == 401


def test_registration_checks_origin_rp_and_challenge(client, db_session, admin_a):
    db_session.commit()
    for kw in ({"origin": "https://phish.example"}, {"rp_id": "phish.example"}, {"flags": 0x44}):
        assert _register(client, admin_a, SoftAuthenticator(), **kw).status_code == 401
    reasons = " | ".join(e.event_metadata["reason"] for e in _audit(db_session, "AUTH_PASSKEY_FAILURE"))
    assert "unexpected origin" in reasons and "RP ID hash" in reasons and "user presence" in reasons
    # A challenge is single-use and bound to the user who asked for it.
    r = client.post("/auth/passkeys/register/options", json={"current_password": "password"},
                    headers=auth_headers(admin_a)).json()
    auth = SoftAuthenticator()
    payload = {"challenge_id": r["challenge_id"], "name": "Key", "credential": auth.create(r["options"])}
    assert client.post("/auth/passkeys/register", json=payload, headers=auth_headers(admin_a)).status_code == 200
    assert client.post("/auth/passkeys/register", json=payload, headers=auth_headers(admin_a)).status_code == 401
    db_session.refresh(admin_a)
    assert db_session.scalar(select(PasskeyCredential).where(PasskeyCredential.user_id == admin_a.id)) is not None


def test_options_require_the_password(client, db_session, admin_a, user_a):
    db_session.commit()
    assert client.post("/auth/passkeys/register/options", json={"current_password": "wrong"},
                       headers=auth_headers(admin_a)).status_code == 401
    assert _login_options(client, admin_a, password="wrong").status_code == 401
    # Correct password but no passkey registered.
    assert _login_options(client, user_a).status_code == 409


def test_required_role_can_enrol_with_a_passkey_and_drop_the_app(client, db_session, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    db_session.commit()
    pending = auth_headers(admin_a)
    assert client.get("/api/v1/projects", headers=pending).status_code == 403
    r = _register(client, admin_a, SoftAuthenticator(), headers=pending)
    assert r.status_code == 200, r.text
    full = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/api/v1/projects", headers=full).status_code == 200
    assert client.get("/auth/me", headers=full).json()["mfa_enrollment_required"] is False
    # The last passkey of a role that requires MFA cannot be removed without another factor.
    pk = client.get("/auth/passkeys", headers=full).json()[0]
    r = client.post(f"/auth/passkeys/{pk['id']}/remove", json={"current_password": "password"}, headers=full)
    assert r.status_code == 403


def test_removing_the_last_factor_ends_sessions(client, db_session, admin_a):
    db_session.commit()
    r = _register(client, admin_a, SoftAuthenticator())
    full = {"Authorization": f"Bearer {r.json()['access_token']}"}
    pk = client.get("/auth/passkeys", headers=full).json()[0]
    assert client.post(f"/auth/passkeys/{pk['id']}/remove", json={"current_password": "wrong"},
                       headers=full).status_code == 401
    assert client.post(f"/auth/passkeys/{pk['id'] + 999}/remove", json={"current_password": "password"},
                       headers=full).status_code == 404
    assert client.post(f"/auth/passkeys/{pk['id']}/remove", json={"current_password": "password"},
                       headers=full).status_code == 204
    db_session.refresh(admin_a)
    assert admin_a.passkey_enabled is False
    assert client.get("/api/v1/projects", headers=full).status_code == 401
    assert _audit(db_session, "PASSKEY_REMOVED")
    assert client.post("/auth/login", json={"email": admin_a.email, "password": "password"}).status_code == 200


def test_admin_reset_removes_passkeys(client, db_session, admin_a, system_admin):
    db_session.commit()
    auth = SoftAuthenticator()
    assert _register(client, admin_a, auth).status_code == 200
    r = client.post(f"/api/v1/users/{admin_a.id}/mfa/reset",
                    json={"reason": "Lost the security key, verified by phone"}, headers=auth_headers(system_admin))
    assert r.status_code == 200 and r.json()["passkey_enabled"] is False
    assert db_session.scalar(select(PasskeyCredential).where(PasskeyCredential.user_id == admin_a.id)) is None
    reset = _audit(db_session, "MFA_RESET")[0]
    assert reset.event_metadata["passkeys_removed"] == 1


def test_totp_user_can_also_use_a_passkey(client, db_session, admin_a):
    """Both factors enrolled: either completes sign-in."""
    from tests.auth.test_mfa import _code  # noqa: F401 (same helpers as the TOTP tests)
    db_session.commit()
    admin_a.mfa_enabled = True
    admin_a.mfa_nonce = "n" * 32
    db_session.commit()
    mfa_headers = {"Authorization": "Bearer " + create_access_token(subject=admin_a.id,
                                                                    token_version=admin_a.token_version, amr=AMR_MFA)}
    auth = SoftAuthenticator()
    assert _register(client, admin_a, auth, headers=mfa_headers).status_code == 200
    r = client.post("/auth/login", json={"email": admin_a.email, "password": "password"})
    assert r.status_code == 401 and r.json()["detail"] == "MFA code required"
    _, r = _login(client, admin_a, auth)
    assert r.status_code == 200


# --------------------------------------------------------------------------- verification unit tests
def test_cbor_decoder_bounds():
    for bad in (b"", b"\x5f", b"\x9b\xff\xff\xff\xff\xff\xff\xff\xff", b"\xc1\x00", b"\x62a"):
        with pytest.raises(webauthn.WebAuthnError):
            webauthn.cbor_decode(bad)
    assert webauthn.cbor_decode(cbor({1: [b"x", "y", -3, True, None]}))[0] == {1: [b"x", "y", -3, True, None]}


def test_weak_or_unknown_keys_are_refused():
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.cose_public_key(cbor({1: 3, 3: -257, -1: b"\x01" * 128, -2: b"\x01\x00\x01"}))  # RSA-1024
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.cose_public_key(cbor({1: 2, 3: -35, -1: 2, -2: b"x" * 48, -3: b"y" * 48}))  # ES384 unsupported
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.cose_public_key(cbor({1: 2, 3: -7, -1: 1, -2: b"\x00" * 32, -3: b"\x00" * 32}))  # not on curve


def test_origin_policy(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "webauthn_rp_id", "app.example.com")
    assert s.webauthn_origin_allowed("https://app.example.com")
    assert s.webauthn_origin_allowed("https://app.example.com:8443")
    assert not s.webauthn_origin_allowed("http://app.example.com")
    assert not s.webauthn_origin_allowed("https://evil-app.example.com")
    assert not s.webauthn_origin_allowed("https://ingest.example.com")
    monkeypatch.setattr(s, "webauthn_origins", "https://console.example.com")
    assert s.webauthn_origin_allowed("https://console.example.com")
    assert not s.webauthn_origin_allowed("https://app.example.com")
