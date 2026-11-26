"""Operator MFA: TOTP primitives, enrolment, login, enforcement, recovery, reset."""
from __future__ import annotations

import types

import pytest
from sqlalchemy import select

from app.core import mfa
from app.core.config import get_settings
from app.core.security import AMR_MFA, create_access_token, decode_access_token
from app.models.audit_log import AuditLog
from app.models.user import User
from tests.conftest import auth_headers

T0 = 1_800_000_000.0  # fixed clock, aligned to a 30 s step boundary


@pytest.fixture()
def clock(monkeypatch):
    state = types.SimpleNamespace(t=T0)
    monkeypatch.setattr(mfa, "time", types.SimpleNamespace(time=lambda: state.t))
    return state


def _code(user: User, at: float) -> str:
    return mfa.totp(mfa.derive_secret(user.id, user.mfa_nonce), at)


def _mfa_headers(user: User) -> dict[str, str]:
    return {"Authorization": "Bearer " + create_access_token(subject=user.id, token_version=user.token_version,
                                                             amr=AMR_MFA)}


def _enrol(client, db_session, user: User, clock) -> tuple[str, list[str]]:
    r = client.post("/auth/mfa/setup", json={"current_password": "password"}, headers=auth_headers(user))
    assert r.status_code == 200, r.text
    db_session.refresh(user)
    r = client.post("/auth/mfa/enable", json={"code": _code(user, clock.t)}, headers=auth_headers(user))
    assert r.status_code == 200, r.text
    db_session.refresh(user)
    return r.json()["access_token"], r.json()["recovery_codes"]


def _audit_types(db_session, user: User) -> list[str]:
    rows = db_session.execute(select(AuditLog.event_type).where(AuditLog.target_id == str(user.id))).scalars()
    return list(rows)


# ------------------------------------------------------------------------------------ primitives
def test_hotp_and_totp_match_rfc_test_vectors():
    secret = b"12345678901234567890"
    # RFC 4226 appendix D
    assert [mfa.hotp(secret, c) for c in range(3)] == ["755224", "287082", "359152"]
    # RFC 6238 appendix B (SHA1, T=59 -> 94287082; six-digit truncation)
    assert mfa.totp(secret, 59) == "287082"
    assert mfa.totp(secret, 1111111109) == "081804"


def test_verify_totp_accepts_one_step_of_drift_and_rejects_replay():
    secret = b"12345678901234567890"
    step = mfa.current_step(T0)
    for delta in (-1, 0, 1):
        code = mfa.hotp(secret, step + delta)
        assert mfa.verify_totp(secret, code, None, now=T0) == step + delta
    assert mfa.verify_totp(secret, mfa.hotp(secret, step + 2), None, now=T0) is None
    assert mfa.verify_totp(secret, mfa.hotp(secret, step - 2), None, now=T0) is None
    current = mfa.hotp(secret, step)
    assert mfa.verify_totp(secret, current, last_step=step, now=T0) is None  # replay
    assert mfa.verify_totp(secret, mfa.hotp(secret, step - 1), last_step=step, now=T0) is None  # older
    assert mfa.verify_totp(secret, "12345", None, now=T0) is None
    assert mfa.verify_totp(secret, "abcdef", None, now=T0) is None


def test_secrets_are_derived_per_user_and_nonce():
    a = mfa.derive_secret(1, "n1")
    assert len(a) == 20
    assert a != mfa.derive_secret(2, "n1") and a != mfa.derive_secret(1, "n2")
    uri = mfa.provisioning_uri(a, "ops@example.com", "HoneyShield")
    assert uri.startswith("otpauth://totp/HoneyShield:ops@example.com?")
    assert "secret=" + mfa.secret_base32(a) in uri and "period=30" in uri and "digits=6" in uri


# ------------------------------------------------------------------------------------ enrolment + login
def test_enrolment_then_login_requires_second_factor(client, db_session, admin_a, clock):
    db_session.commit()
    old_headers = auth_headers(admin_a)
    assert client.post("/auth/mfa/setup", json={"current_password": "wrong-password"},
                       headers=old_headers).status_code == 401
    r = client.post("/auth/mfa/setup", json={"current_password": "password"}, headers=old_headers)
    assert r.status_code == 200
    body = r.json()
    db_session.refresh(admin_a)
    assert body["secret"] == mfa.secret_base32(mfa.derive_secret(admin_a.id, admin_a.mfa_nonce))
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert admin_a.mfa_enabled is False

    assert client.post("/auth/mfa/enable", json={"code": "000000" if _code(admin_a, clock.t) != "000000" else "111111"},
                       headers=old_headers).status_code == 401
    r = client.post("/auth/mfa/enable", json={"code": _code(admin_a, clock.t)}, headers=old_headers)
    assert r.status_code == 200
    token, codes = r.json()["access_token"], r.json()["recovery_codes"]
    assert decode_access_token(token)["amr"] == "mfa"
    assert len(codes) == 10 and len(set(codes)) == 10
    db_session.refresh(admin_a)
    assert admin_a.mfa_enabled is True and admin_a.mfa_enabled_at is not None

    # Nothing secret is stored: no TOTP secret, no plaintext recovery code.
    stored = repr((admin_a.mfa_nonce, admin_a.mfa_recovery_hashes))
    assert body["secret"] not in stored
    assert not any(mfa.normalize_recovery_code(c) in stored for c in codes)

    # Password-only sessions issued before enrolment stop working; the MFA session works.
    assert client.get("/api/v1/projects", headers=old_headers).status_code == 401
    assert client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    login = {"email": admin_a.email, "password": "password"}
    r = client.post("/auth/login", json=login)
    assert r.status_code == 401 and r.json()["detail"] == "MFA code required"
    # Wrong password never reveals that MFA is enabled.
    r = client.post("/auth/login", json={**login, "password": "nope-nope"})
    assert r.json()["detail"] == "Invalid email or password"
    # The enrolment code's step cannot be replayed.
    assert client.post("/auth/login", json={**login, "otp": _code(admin_a, clock.t)}).status_code == 401
    clock.t += 30
    r = client.post("/auth/login", json={**login, "otp": _code(admin_a, clock.t)})
    assert r.status_code == 200
    assert decode_access_token(r.json()["access_token"])["amr"] == "mfa"
    types_ = _audit_types(db_session, admin_a)
    assert {"MFA_SETUP_STARTED", "MFA_ENABLED", "AUTH_MFA_FAILURE"} <= set(types_)


def test_recovery_codes_work_once(client, db_session, admin_a, clock):
    db_session.commit()
    _, codes = _enrol(client, db_session, admin_a, clock)
    login = {"email": admin_a.email, "password": "password"}
    r = client.post("/auth/login", json={**login, "otp": codes[0].upper()})
    assert r.status_code == 200
    assert client.post("/auth/login", json={**login, "otp": codes[0]}).status_code == 401
    db_session.refresh(admin_a)
    assert len(admin_a.mfa_recovery_hashes) == 9
    assert "MFA_RECOVERY_CODE_USED" in _audit_types(db_session, admin_a)


def test_regenerating_recovery_codes_requires_totp_and_invalidates_old(client, db_session, admin_a, clock):
    db_session.commit()
    _, codes = _enrol(client, db_session, admin_a, clock)
    headers = _mfa_headers(admin_a)
    assert client.post("/auth/mfa/recovery-codes", json={"code": codes[0]}, headers=headers).status_code == 422
    clock.t += 30
    r = client.post("/auth/mfa/recovery-codes", json={"code": _code(admin_a, clock.t)}, headers=headers)
    assert r.status_code == 200
    new_codes = r.json()["recovery_codes"]
    assert not set(new_codes) & set(codes)
    login = {"email": admin_a.email, "password": "password"}
    assert client.post("/auth/login", json={**login, "otp": codes[1]}).status_code == 401
    assert client.post("/auth/login", json={**login, "otp": new_codes[0]}).status_code == 200


def test_second_factor_attempts_are_rate_limited_per_account(client, db_session, admin_a, clock):
    db_session.commit()
    _enrol(client, db_session, admin_a, clock)
    from app.core.rate_limit import reset_all_limiters
    reset_all_limiters()  # enrolment's confirmation code counted as an attempt; start clean
    good = _code(admin_a, clock.t + 30)
    wrong = "123456" if good != "123456" else "654321"
    login = {"email": admin_a.email, "password": "password", "otp": wrong}
    statuses = [client.post("/auth/login", json=login).status_code for _ in range(5)]
    assert statuses == [401] * 5
    clock.t += 30
    r = client.post("/auth/login", json={**login, "otp": good})
    assert r.status_code == 429  # even the right code is refused while throttled


# ------------------------------------------------------------------------------------ enforcement
def test_required_role_gets_enrolment_only_session(client, db_session, admin_a, user_a, clock, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    db_session.commit()
    pending = auth_headers(admin_a)
    r = client.get("/api/v1/projects", headers=pending)
    assert r.status_code == 403 and r.json()["detail"] == "MFA enrolment required"
    me = client.get("/auth/me", headers=pending).json()
    assert me["mfa_required"] is True and me["mfa_enrollment_required"] is True
    assert client.post("/auth/change-password", json={"current_password": "password",
                                                      "new_password": "another-long-password"},
                       headers=pending).status_code == 403
    # Roles outside the policy are unaffected.
    assert client.get("/api/v1/honey-tokens", headers=auth_headers(user_a)).status_code == 200

    token, _ = _enrol(client, db_session, admin_a, clock)
    full = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/projects", headers=full).status_code == 200
    assert client.get("/auth/me", headers=full).json()["mfa_enrollment_required"] is False
    # MFA cannot be switched off for a role that requires it.
    clock.t += 30
    r = client.post("/auth/mfa/disable", json={"current_password": "password", "code": _code(admin_a, clock.t)},
                    headers=full)
    assert r.status_code == 403


def test_pending_session_is_refused_for_streams(db_session, admin_a, monkeypatch):
    from app.core.auth_exceptions import MfaEnrollmentRequiredError
    from app.core.security import resolve_access_token
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    token = create_access_token(subject=admin_a.id)
    with pytest.raises(MfaEnrollmentRequiredError):
        resolve_access_token(token, db_session)
    assert resolve_access_token(token, db_session, allow_mfa_pending=True) is admin_a


def test_login_with_stale_pending_header_still_works(client, db_session, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_required_roles", "TENANT_ADMIN")
    db_session.commit()
    r = client.post("/auth/login", json={"email": admin_a.email, "password": "password"},
                    headers=auth_headers(admin_a))
    assert r.status_code == 200
    assert decode_access_token(r.json()["access_token"])["amr"] == "pwd"


def test_optional_disable_revokes_sessions(client, db_session, admin_a, clock):
    db_session.commit()
    token, codes = _enrol(client, db_session, admin_a, clock)
    full = {"Authorization": f"Bearer {token}"}
    assert client.post("/auth/mfa/disable", json={"current_password": "wrong-password", "code": codes[0]},
                       headers=full).status_code == 401
    r = client.post("/auth/mfa/disable", json={"current_password": "password", "code": codes[0]}, headers=full)
    assert r.status_code == 204
    db_session.refresh(admin_a)
    assert admin_a.mfa_enabled is False and admin_a.mfa_nonce is None and admin_a.mfa_recovery_hashes is None
    assert client.get("/api/v1/projects", headers=full).status_code == 401
    assert "MFA_DISABLED" in _audit_types(db_session, admin_a)


# ------------------------------------------------------------------------------------ admin reset
def test_admin_reset_clears_mfa_and_revokes_sessions(client, db_session, admin_a, admin_b, user_a,
                                                     system_admin, clock):
    db_session.commit()
    token, _ = _enrol(client, db_session, admin_a, clock)
    sa = auth_headers(system_admin)
    reason = {"reason": "Lost phone, identity verified by video call"}
    assert client.post(f"/api/v1/users/{admin_a.id}/mfa/reset", json={"reason": "short"},
                       headers=sa).status_code == 422
    # Tenant isolation and role checks.
    assert client.post(f"/api/v1/users/{admin_a.id}/mfa/reset", json=reason,
                       headers=auth_headers(admin_b)).status_code == 404
    assert client.post(f"/api/v1/users/{admin_a.id}/mfa/reset", json=reason,
                       headers=auth_headers(user_a)).status_code == 403
    assert client.post(f"/api/v1/users/{system_admin.id}/mfa/reset", json=reason,
                       headers=sa).status_code == 409  # not one's own

    r = client.post(f"/api/v1/users/{admin_a.id}/mfa/reset", json=reason, headers=sa)
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    assert client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    row = db_session.execute(select(AuditLog).where(AuditLog.event_type == "MFA_RESET")).scalar_one()
    assert row.actor_user_id == system_admin.id and row.event_metadata["reason"] == reason["reason"]
    # The user can log in with the password again (and re-enrol).
    assert client.post("/auth/login", json={"email": admin_a.email, "password": "password"}).status_code == 200


def test_user_listing_shows_mfa_state(client, db_session, admin_a, system_admin, clock):
    db_session.commit()
    _enrol(client, db_session, admin_a, clock)
    rows = client.get("/api/v1/users", headers=auth_headers(system_admin)).json()
    assert {r["email"]: r["mfa_enabled"] for r in rows}[admin_a.email] is True
