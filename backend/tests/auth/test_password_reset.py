"""Password reset: admin-issued and self-service single-use links."""
from __future__ import annotations

import email
import email.policy
import socketserver
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.core import mfa
from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.audit_log import AuditLog
from app.services import password_reset
from tests.alerting.test_channels import _SMTPHandler
from tests.conftest import auth_headers

NEW = "a-brand-new-passphrase-42"


def _token(url: str) -> str:
    assert "/console/#reset=" in url
    return url.split("#reset=", 1)[1]


def _issue(client, admin, user, reason="User forgot their password (ticket 123)"):
    return client.post(f"/api/v1/users/{user.id}/password-reset", json={"reason": reason},
                       headers=auth_headers(admin))


def _confirm(client, token, password=NEW):
    return client.post("/auth/password-reset/confirm", json={"token": token, "new_password": password})


def _login(client, user, password):
    return client.post("/auth/login", json={"email": user.email, "password": password})


def _audits(db_session, event_type):
    db_session.expire_all()
    return db_session.query(AuditLog).filter_by(event_type=event_type).all()


# ------------------------------------------------------------------ admin-issued links

def test_admin_issued_link_resets_password_and_revokes_sessions(client, db_session, admin_a, user_a):
    old_session = {"Authorization": f"Bearer {create_access_token(subject=str(user_a.id), token_version=user_a.token_version or 0)}"}
    assert client.get("/auth/me", headers=old_session).status_code == 200
    r = _issue(client, admin_a, user_a)
    assert r.status_code == 201, r.text
    body = r.json()
    expires = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
    assert timedelta(minutes=29) < expires - datetime.now(timezone.utc) <= timedelta(minutes=30)
    issued, = _audits(db_session, "PASSWORD_RESET_ISSUED")
    assert issued.event_metadata["reason"].startswith("User forgot") and issued.actor_user_id == admin_a.id

    assert _confirm(client, _token(body["reset_url"])).status_code == 204
    assert client.get("/auth/me", headers=old_session).status_code == 401          # sessions revoked
    assert _login(client, user_a, "password").status_code == 401
    assert _login(client, user_a, NEW).status_code == 200
    assert len(_audits(db_session, "PASSWORD_RESET_COMPLETED")) == 1


def test_link_works_once(client, admin_a, user_a):
    token = _token(_issue(client, admin_a, user_a).json()["reset_url"])
    assert _confirm(client, token).status_code == 204
    assert _confirm(client, token, "yet-another-passphrase-7").status_code == 401


def test_link_dies_when_sessions_are_revoked(client, db_session, admin_a, user_a):
    token = _token(_issue(client, admin_a, user_a).json()["reset_url"])
    user_a.token_version = (user_a.token_version or 0) + 1      # e.g. "log out everywhere"
    db_session.commit()
    assert _confirm(client, token).status_code == 401


def test_expired_tampered_and_garbage_links_are_refused(client, db_session, user_a):
    expired, _ = password_reset.issue(user_a, now=datetime.now(timezone.utc) - timedelta(minutes=31))
    good, _ = password_reset.issue(user_a)
    uid, exp, mac = good.split(".", 2)
    far_future = f"{uid}.{int(exp) + 86400}.{mac}"
    for token in (expired, f"{uid}.{exp}.{mac[:-2]}xx", f"{int(uid) + 1}.{exp}.{mac}", far_future,
                  "not.a.token-at-all", "1234567890"):
        assert _confirm(client, token).status_code == 401, token
    assert len(_audits(db_session, "PASSWORD_RESET_FAILED")) == 6
    assert _confirm(client, good).status_code == 204              # the genuine one still works


def test_disabled_account_cannot_be_reset(client, db_session, admin_a, user_a):
    token = _token(_issue(client, admin_a, user_a).json()["reset_url"])
    user_a.is_active = False
    db_session.commit()
    assert _confirm(client, token).status_code == 401
    assert _issue(client, admin_a, user_a).status_code in (400, 409, 422)


def test_reset_scope_follows_user_management_rules(client, admin_a, admin_b, user_a, system_admin):
    assert _issue(client, admin_b, user_a).status_code == 404     # other tenant
    assert _issue(client, admin_a, system_admin).status_code == 404
    assert _issue(client, user_a, admin_a).status_code == 403      # viewers cannot
    assert _issue(client, admin_a, admin_a).status_code in (400, 409, 422)   # not for yourself
    assert _issue(client, admin_a, user_a, reason="short").status_code == 422
    assert _issue(client, system_admin, user_a).status_code == 201


def test_password_policy_applies(client, admin_a, user_a):
    token = _token(_issue(client, admin_a, user_a).json()["reset_url"])
    assert _confirm(client, token, "short-11ch").status_code == 422
    assert _confirm(client, token, "password-but-too-long-" * 5).status_code == 422
    assert _confirm(client, token, NEW).status_code == 204


def test_reset_does_not_remove_mfa(client, db_session, admin_a, user_a):
    user_a.mfa_enabled, user_a.mfa_nonce = True, mfa.new_nonce()
    db_session.commit()
    token = _token(_issue(client, admin_a, user_a).json()["reset_url"])
    assert _confirm(client, token).status_code == 204
    r = _login(client, user_a, NEW)
    assert r.status_code == 401 and "MFA" in r.text                  # still needs the authenticator


# ------------------------------------------------------------------ self-service

@pytest.fixture()
def smtp_server(monkeypatch):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SMTPHandler)
    srv.daemon_threads = True
    srv.messages = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    s = get_settings()
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", srv.server_address[1])
    monkeypatch.setattr(s, "smtp_security", "none")
    monkeypatch.setattr(s, "smtp_from", "no-reply@honeyshield.example")
    monkeypatch.setattr(s, "control_plane_hostnames", ["app.honeyshield.example"])
    yield srv
    srv.shutdown()
    srv.server_close()


def test_self_service_needs_smtp(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "smtp_host", None)
    r = client.post("/auth/password-reset/request", json={"email": "anyone@example.com"})
    assert r.status_code == 503


def _deliver(db_session):
    from app.services import account_mail
    return account_mail.run_once(db_session)


def test_self_service_emails_a_working_link(client, db_session, user_a, smtp_server):
    from app.models.mail_outbox import MailOutbox
    r = client.post("/auth/password-reset/request", json={"email": user_a.email.upper()})
    assert r.status_code == 202
    assert smtp_server.messages == []                      # the API never sends: the worker does
    row = db_session.query(MailOutbox).one()
    assert row.kind == "password_reset" and row.console_base == "https://app.honeyshield.example"
    assert _deliver(db_session) == {"SENT": 1}
    (rcpts, raw), = smtp_server.messages
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert rcpts == [user_a.email] and msg["Subject"] == "Reset your HoneyShield password"
    body = msg.get_content()
    url = next(line for line in body.splitlines() if "#reset=" in line).strip()
    assert url.startswith("https://app.honeyshield.example/console/#reset=")
    assert _confirm(client, _token(url)).status_code == 204
    assert _login(client, user_a, NEW).status_code == 200
    assert len(_audits(db_session, "PASSWORD_RESET_REQUESTED")) == 1


def test_self_service_does_not_reveal_whether_an_account_exists(client, db_session, user_a, smtp_server):
    known = client.post("/auth/password-reset/request", json={"email": user_a.email})
    unknown = client.post("/auth/password-reset/request", json={"email": "nobody@tenant-a.com"})
    assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())
    _deliver(db_session)
    assert len(smtp_server.messages) == 1
    unknown_audit, = _audits(db_session, "PASSWORD_RESET_REQUESTED_UNKNOWN")
    assert unknown_audit.event_metadata == {"email_domain": "tenant-a.com"}


def test_self_service_is_rate_limited(client, db_session, user_a, smtp_server):
    codes = [client.post("/auth/password-reset/request", json={"email": user_a.email}).status_code
             for _ in range(4)]
    assert codes == [202, 202, 202, 429]                      # 3 per address per 15 minutes
    codes = [client.post("/auth/password-reset/request", json={"email": f"x{i}@example.com"}).status_code
             for i in range(3)]
    assert 429 in codes                                        # 5 per source address per minute
    _deliver(db_session)
    assert len(smtp_server.messages) == 3


def test_queue_stores_no_secret_and_expires_stale_mail(client, db_session, user_a, smtp_server):
    from datetime import datetime, timedelta, timezone

    from app.models.mail_outbox import MailOutbox
    client.post("/auth/password-reset/request", json={"email": user_a.email})
    row = db_session.query(MailOutbox).one()
    assert set(c.name for c in MailOutbox.__table__.columns) >= {"user_id", "console_base"}
    assert not any("reset=" in str(getattr(row, c.name) or "") for c in MailOutbox.__table__.columns)
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=20)
    db_session.commit()
    assert _deliver(db_session) == {"EXPIRED": 1} and smtp_server.messages == []


def test_mail_retries_then_gives_up(client, db_session, user_a, smtp_server, monkeypatch):
    from app.models.mail_outbox import MailOutbox
    from app.services import account_mail
    client.post("/auth/password-reset/request", json={"email": user_a.email})
    def boom(msg, rcpts, timeout):
        raise ConnectionRefusedError()
    assert account_mail.run_once(db_session, mailer=boom) == {"PENDING": 1}
    row = db_session.query(MailOutbox).one()
    assert row.attempts == 1 and row.last_error == "ConnectionRefusedError"
    from datetime import datetime, timezone
    for _ in range(account_mail.MAX_ATTEMPTS):
        row.next_attempt_at = datetime.now(timezone.utc)
        db_session.commit()
        account_mail.run_once(db_session, mailer=boom)
    db_session.expire_all()
    assert db_session.get(MailOutbox, row.id).status == "FAILED"


def test_smtp_failure_is_not_revealed(client, user_a, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", 1)
    monkeypatch.setattr(s, "smtp_security", "none")
    monkeypatch.setattr(s, "smtp_from", "no-reply@honeyshield.example")
    r = client.post("/auth/password-reset/request", json={"email": user_a.email})
    assert r.status_code == 202


def test_overlong_new_password_is_a_validation_error_not_a_crash(client, user_a):
    """Regression: change-password returned 500 for passwords over bcrypt's 72-byte limit."""
    r = client.post("/auth/change-password", json={"current_password": "password", "new_password": "é" * 40},
                    headers=auth_headers(user_a))
    assert r.status_code == 422


def test_console_invite_flow_new_user_sets_their_own_password(client, db_session, admin_a, tenant_a, tenant_b):
    """What the console's "Add user" does: create with a throwaway password nobody keeps, issue a
    set-up link, and the person chooses their password through it. A tenant admin's new user lands in
    the admin's tenant even if another tenant is named."""
    import secrets
    throwaway = secrets.token_urlsafe(24) + "-Aa1"
    r = client.post("/api/v1/users", json={"email": "New.Analyst@tenant-a.com", "password": throwaway,
                                           "role": "TENANT_USER", "tenant_id": tenant_a.id}, headers=auth_headers(admin_a))
    assert r.status_code == 201, r.text
    new = r.json()
    assert new["email"] == "new.analyst@tenant-a.com" and new["tenant_id"] == tenant_a.id
    cross = client.post("/api/v1/users", json={"email": "x@tenant-b.com", "password": throwaway, "role": "TENANT_USER",
                                               "tenant_id": tenant_b.id}, headers=auth_headers(admin_a))
    assert cross.status_code in (400, 403, 409, 422)
    link = client.post(f"/api/v1/users/{new['id']}/password-reset",
                       json={"reason": "New account: set-up link issued at creation"}, headers=auth_headers(admin_a))
    assert link.status_code == 201
    assert _confirm(client, _token(link.json()["reset_url"])).status_code == 204
    assert client.post("/auth/login", json={"email": "new.analyst@tenant-a.com", "password": throwaway}).status_code == 401
    assert client.post("/auth/login", json={"email": "new.analyst@tenant-a.com", "password": NEW}).status_code == 200


def test_admin_set_passwords_follow_the_same_length_policy(client, admin_a, user_a, tenant_a):
    """12 characters minimum whether the person chooses it or an admin sets it through the API."""
    h = auth_headers(admin_a)
    short = "elevenchars"                                         # 11
    r = client.post("/api/v1/users", json={"email": "s@tenant-a.com", "password": short, "role": "TENANT_USER",
                                           "tenant_id": tenant_a.id}, headers=h)
    assert r.status_code == 422
    assert client.patch(f"/api/v1/users/{user_a.id}", json={"password": short}, headers=h).status_code == 422
    assert client.patch(f"/api/v1/users/{user_a.id}", json={"password": short + "!"}, headers=h).status_code == 200
