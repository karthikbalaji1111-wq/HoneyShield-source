"""PATCH /users/{id} with is_active (used to crash with a NameError)."""
from __future__ import annotations

from app.models.audit_log import AuditLog
from app.models.user import User
from tests.conftest import auth_headers


def test_patch_deactivate_then_reactivate_succeeds(client, db_session, admin_a, user_a):
    original_version = user_a.token_version

    resp = client.patch(f"/api/v1/users/{user_a.id}", json={"is_active": False}, headers=auth_headers(admin_a))
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_active"] is False

    resp = client.patch(f"/api/v1/users/{user_a.id}", json={"is_active": True}, headers=auth_headers(admin_a))
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_active"] is True

    db_session.expire_all()
    user = db_session.get(User, user_a.id)
    assert user.is_active is True
    # Both state changes are security changes and must invalidate sessions.
    assert user.token_version == original_version + 2

    events = [a.event_type for a in db_session.query(AuditLog).filter_by(target_id=str(user_a.id))]
    assert "USER_DEACTIVATED" in events
    assert "USER_ACTIVATED" in events


def test_patch_with_unchanged_is_active_records_no_status_event(client, db_session, admin_a, user_a):
    resp = client.patch(f"/api/v1/users/{user_a.id}", json={"is_active": True}, headers=auth_headers(admin_a))
    assert resp.status_code == 200, resp.text
    events = [a.event_type for a in db_session.query(AuditLog).filter_by(target_id=str(user_a.id))]
    assert "USER_ACTIVATED" not in events and "USER_DEACTIVATED" not in events
