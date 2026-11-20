"""Session renewal: same sign-in and authentication level, new expiry, absolute cap."""
from __future__ import annotations

import time

import jwt

from app.core import mfa
from app.core.config import get_settings
from app.core.security import AMR_MFA, create_access_token, decode_access_token


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_refresh_keeps_sign_in_time_and_method(client, admin_a):
    signed_in = int(time.time()) - 600
    old = create_access_token(subject=admin_a.id, token_version=admin_a.token_version or 0, auth_time=signed_in)
    r = client.post("/auth/refresh", headers=_h(old))
    assert r.status_code == 200
    body = r.json()
    new = decode_access_token(body["access_token"])
    assert new["auth_time"] == signed_in and new["amr"] == "pwd"
    assert new["exp"] >= decode_access_token(old)["exp"]
    assert body["session_expires_at"] == signed_in + get_settings().session_max_hours * 3600
    assert client.get("/auth/me", headers=_h(body["access_token"])).status_code == 200


def test_refresh_keeps_mfa_level(client, db_session, admin_a):
    admin_a.mfa_enabled, admin_a.mfa_nonce = True, mfa.new_nonce()
    db_session.commit()
    token = create_access_token(subject=admin_a.id, token_version=admin_a.token_version or 0, amr=AMR_MFA)
    r = client.post("/auth/refresh", headers=_h(token))
    assert r.status_code == 200 and decode_access_token(r.json()["access_token"])["amr"] == "mfa"


def test_session_cannot_be_renewed_past_the_maximum(client, admin_a):
    too_old = int(time.time()) - get_settings().session_max_hours * 3600 - 1
    token = create_access_token(subject=admin_a.id, token_version=admin_a.token_version or 0, auth_time=too_old)
    r = client.post("/auth/refresh", headers=_h(token))
    assert r.status_code == 401 and "maximum length" in r.text


def test_revoked_or_expired_sessions_cannot_be_renewed(client, db_session, admin_a):
    from datetime import timedelta

    token = create_access_token(subject=admin_a.id, token_version=admin_a.token_version or 0)
    admin_a.token_version = (admin_a.token_version or 0) + 1      # "sign out everywhere"
    db_session.commit()
    assert client.post("/auth/refresh", headers=_h(token)).status_code == 401
    expired = create_access_token(subject=admin_a.id, token_version=admin_a.token_version,
                                  expires_delta=timedelta(seconds=-1))
    assert client.post("/auth/refresh", headers=_h(expired)).status_code == 401


def test_mfa_pending_sessions_cannot_be_renewed(client, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    token = create_access_token(subject=admin_a.id, token_version=admin_a.token_version or 0)
    assert client.post("/auth/refresh", headers=_h(token)).status_code == 403


def test_auth_time_cannot_be_after_expiry(admin_a):
    s = get_settings()
    bad = jwt.encode({"sub": str(admin_a.id), "ver": 0, "exp": int(time.time()) + 60, "auth_time": int(time.time()) + 3600},
                     s.jwt_secret_key, algorithm="HS256")
    try:
        decode_access_token(bad)
        assert False, "accepted"
    except jwt.InvalidTokenError:
        pass


def test_legacy_tokens_without_auth_time_still_work(client, admin_a):
    s = get_settings()
    legacy = jwt.encode({"sub": str(admin_a.id), "ver": admin_a.token_version or 0, "exp": int(time.time()) + 600},
                        s.jwt_secret_key, algorithm="HS256")
    assert client.get("/auth/me", headers=_h(legacy)).status_code == 200
    assert client.post("/auth/refresh", headers=_h(legacy)).status_code == 200
