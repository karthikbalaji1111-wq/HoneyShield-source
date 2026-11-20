"""Personal API keys: scope, isolation, lifecycle, abuse control and secrecy."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core import mfa
from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from tests.conftest import auth_headers


def _create(client, user, **kw):
    body = {"name": "ci", "scope": "read", **kw}
    r = client.post("/api/v1/api-keys", json=body, headers=auth_headers(user))
    assert r.status_code == 201, r.text
    return r.json()


def _key_headers(raw):
    return {"Authorization": f"Bearer {raw}"}


def test_key_is_shown_once_and_authenticates_as_its_owner(client, db_session, admin_a, project_a):
    created = _create(client, admin_a)
    raw = created["api_key"]
    assert raw.startswith(created["key_id"] + ".") and created["scope"] == "read"
    listed = client.get("/api/v1/api-keys", headers=auth_headers(admin_a)).json()
    assert [k["key_id"] for k in listed] == [created["key_id"]] and "api_key" not in listed[0]
    r = client.get("/api/v1/projects", headers=_key_headers(raw))
    assert r.status_code == 200 and project_a.domain in r.text
    db_session.expire_all()
    stored = db_session.query(ApiKey).one()
    assert stored.last_used_at is not None
    assert raw.split(".", 1)[1] not in (stored.secret_hash, str(stored.__dict__))
    audit = db_session.query(AuditLog).filter_by(event_type="API_KEY_CREATED").one()
    assert raw.split(".", 1)[1] not in str(audit.event_metadata) and audit.target_id == created["key_id"]


def test_read_keys_cannot_write_and_write_keys_can(client, admin_a, project_a):
    read = _create(client, admin_a, scope="read")["api_key"]
    write = _create(client, admin_a, scope="write", name="rotation")["api_key"]
    path = f"/api/v1/projects/{project_a.domain}/honey-tokens/generate"
    assert client.post(path, json={"token_type": "URL"}, headers=_key_headers(read)).status_code == 403
    assert client.post(path, json={"token_type": "URL"}, headers=_key_headers(write)).status_code == 201


def test_keys_follow_the_owner_role_and_tenant(client, admin_a, user_a, project_a, project_b):
    viewer_key = _create(client, user_a, scope="write")["api_key"]
    path = f"/api/v1/projects/{project_a.domain}/honey-tokens/generate"
    assert client.post(path, json={"token_type": "URL"}, headers=_key_headers(viewer_key)).status_code == 403
    admin_key = _create(client, admin_a)["api_key"]
    r = client.get(f"/api/v1/projects/{project_b.domain}", headers=_key_headers(admin_key))
    assert r.status_code in (403, 404)


@pytest.mark.parametrize("mutate", ["revoke", "expire", "wrong_secret", "unknown_id", "malformed", "disable_user"])
def test_invalid_keys_are_refused(client, db_session, admin_a, user_a, mutate):
    created = _create(client, user_a)
    raw = created["api_key"]
    if mutate == "revoke":
        assert client.delete(f"/api/v1/api-keys/{created['key_id']}", headers=auth_headers(user_a)).status_code == 200
    elif mutate == "expire":
        key = db_session.query(ApiKey).one()
        key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.commit()
    elif mutate == "wrong_secret":
        raw = raw[:-4] + "AAAA"
    elif mutate == "unknown_id":
        raw = "hsk_0000000000000000." + raw.split(".", 1)[1]
    elif mutate == "malformed":
        raw = "hsk_nonsense"
    elif mutate == "disable_user":
        user_a.is_active = False
        db_session.commit()
    r = client.get("/api/v1/detection-events", headers=_key_headers(raw))
    assert r.status_code in (401, 403), r.text


def test_keys_cannot_manage_accounts_or_keys(client, admin_a):
    raw = _create(client, admin_a, scope="write")["api_key"]
    h = _key_headers(raw)
    assert client.post("/api/v1/api-keys", json={"name": "x"}, headers=h).status_code == 403
    assert client.get("/api/v1/api-keys", headers=h).status_code == 403
    assert client.get("/api/v1/users", headers=h).status_code == 403
    assert client.post("/api/v1/users", json={"email": "x@tenant-a.com", "password": "p" * 12,
                                             "role": "TENANT_USER"}, headers=h).status_code == 403
    assert client.get("/auth/me", headers=h).status_code == 401
    assert client.post("/auth/change-password", json={"current_password": "password", "new_password": "y" * 12},
                       headers=h).status_code == 401          # even with the right current password
    assert client.post("/auth/refresh", headers=h).status_code == 401
    assert client.post("/auth/logout", headers=h).status_code == 401


def test_admins_see_and_revoke_keys_in_their_scope_only(client, admin_a, admin_b, user_a, system_admin):
    viewer_key = _create(client, user_a)
    admin_key = _create(client, admin_a)
    other = _create(client, admin_b)
    ids = lambda u: {k["key_id"] for k in client.get("/api/v1/api-keys", headers=auth_headers(u)).json()}
    assert ids(user_a) == {viewer_key["key_id"]}
    assert ids(admin_a) == {viewer_key["key_id"], admin_key["key_id"]}
    assert other["key_id"] in ids(system_admin)
    assert client.delete(f"/api/v1/api-keys/{admin_key['key_id']}", headers=auth_headers(user_a)).status_code == 404
    assert client.delete(f"/api/v1/api-keys/{other['key_id']}", headers=auth_headers(admin_a)).status_code == 404
    r = client.delete(f"/api/v1/api-keys/{viewer_key['key_id']}", headers=auth_headers(admin_a))
    assert r.status_code == 200 and r.json()["revoked_at"]


def test_creating_keys_needs_a_full_session(client, db_session, admin_a):
    admin_a.mfa_enabled, admin_a.mfa_nonce = True, mfa.new_nonce()
    db_session.commit()
    password_only = {"Authorization": f"Bearer {create_access_token(subject=str(admin_a.id))}"}
    assert client.post("/api/v1/api-keys", json={"name": "x"}, headers=password_only).status_code == 401


def test_keys_of_an_mfa_user_work_without_a_code(client, db_session, admin_a):
    raw = _create(client, admin_a)["api_key"]
    admin_a.mfa_enabled, admin_a.mfa_nonce = True, mfa.new_nonce()
    db_session.commit()
    assert client.get("/api/v1/projects", headers=_key_headers(raw)).status_code == 200


def test_bad_key_floods_are_throttled_per_ip(client, admin_a):
    raw = _create(client, admin_a)["api_key"]
    codes = [client.get("/api/v1/projects", headers=_key_headers(f"hsk_{i:016x}.junk")).status_code
             for i in range(25)]
    assert codes.count(401) == 20 and codes[-1] == 429
    # The flood also blocks the real key from that address for the rest of the minute.
    assert client.get("/api/v1/projects", headers=_key_headers(raw)).status_code == 429


def test_validation_and_quota(client, admin_a, monkeypatch):
    from app.services import api_keys
    for body in ({"name": ""}, {"name": "x", "scope": "admin"}, {"name": "x", "expires_in_days": 0},
                 {"name": "x", "expires_in_days": 366}):
        assert client.post("/api/v1/api-keys", json=body, headers=auth_headers(admin_a)).status_code == 422
    monkeypatch.setattr(api_keys, "MAX_ACTIVE_KEYS_PER_USER", 2)
    _create(client, admin_a)
    _create(client, admin_a)
    r = client.post("/api/v1/api-keys", json={"name": "third"}, headers=auth_headers(admin_a))
    assert r.status_code in (409, 422) and "At most 2" in r.text


def test_expiry_is_set_from_the_request(client, admin_a):
    k = _create(client, admin_a, expires_in_days=7)
    expires = datetime.fromisoformat(k["expires_at"].replace("Z", "+00:00"))
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    assert timedelta(days=6, hours=23) < expires - datetime.now(timezone.utc) <= timedelta(days=7)


def test_revocation_is_audited(client, db_session, admin_a):
    k = _create(client, admin_a)
    client.delete(f"/api/v1/api-keys/{k['key_id']}", headers=auth_headers(admin_a))
    rec = db_session.query(AuditLog).filter_by(event_type="API_KEY_REVOKED").one()
    assert rec.target_id == k["key_id"] and rec.actor_user_id == admin_a.id
