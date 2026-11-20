"""HONEY-029: logout and password change revoke every outstanding token."""
from __future__ import annotations

from tests.conftest import auth_headers


def test_logout_revokes_existing_tokens(client, db_session, admin_a):
    headers = auth_headers(admin_a)
    assert client.get("/api/v1/projects", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/projects", headers=headers).status_code == 401


def test_password_change_requires_current_password_and_revokes_tokens(client, db_session, admin_a):
    db_session.commit()
    headers = auth_headers(admin_a)
    bad = client.post("/auth/change-password", json={"current_password": "wrong",
                                                     "new_password": "a-much-better-passphrase"}, headers=headers)
    assert bad.status_code == 401
    ok = client.post("/auth/change-password", json={"current_password": "password",
                                                    "new_password": "a-much-better-passphrase"}, headers=headers)
    assert ok.status_code == 204
    assert client.get("/api/v1/projects", headers=headers).status_code == 401
    assert client.post("/auth/login", json={"email": admin_a.email, "password": "password"}).status_code == 401
    assert client.post("/auth/login", json={"email": admin_a.email,
                                            "password": "a-much-better-passphrase"}).status_code == 200


def test_short_new_password_is_rejected(client, admin_a):
    resp = client.post("/auth/change-password", json={"current_password": "password", "new_password": "short"},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 422


def test_me_returns_identity_and_tenant(client, admin_a, tenant_a):
    body = client.get("/auth/me", headers=auth_headers(admin_a)).json()
    assert body == {"id": admin_a.id, "email": admin_a.email, "role": "TENANT_ADMIN", "tenant_id": tenant_a.id,
                    "tenant_slug": tenant_a.slug, "mfa_enabled": False, "mfa_required": False,
                    "mfa_enrollment_required": False, "passkey_enabled": False, "passkeys": 0}


def test_audit_log_listing_is_tenant_scoped(client, db_session, admin_a, admin_b, user_a, system_admin, token_a):
    client.post("/auth/logout", headers=auth_headers(admin_b))
    client.get("/api/v1/projects", headers=auth_headers(admin_a))
    rows_a = client.get("/api/v1/audit-logs", headers=auth_headers(admin_a)).json()
    assert all(r["tenant_id"] == admin_a.tenant_id for r in rows_a)
    assert "AUTH_LOGOUT" not in [r["event_type"] for r in rows_a]
    assert client.get("/api/v1/audit-logs", headers=auth_headers(user_a)).status_code == 403
    everything = client.get("/api/v1/audit-logs?event_type=AUTH_LOGOUT", headers=auth_headers(system_admin)).json()
    assert [r["event_type"] for r in everything] == ["AUTH_LOGOUT"]
