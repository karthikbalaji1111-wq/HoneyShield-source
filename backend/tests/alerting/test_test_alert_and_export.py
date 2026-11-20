"""'Send test alert' (no fake evidence) and CSV export (scoped, masked, injection-safe)."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.models.alerting import OutboxEvent, OutboxStatus
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.services import alerting
from app.services.alerting import webhook
from tests.conftest import auth_headers

KEY = "alerting-master-key-for-tests-0123456789abcdef"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "integration_signing_key", KEY)
    monkeypatch.setattr(s, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(s, "smtp_from", "alerts@honeyshield.example")
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: ["93.184.216.34"])


def _dest(client, admin, **kw):
    r = client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/hs", **kw},
                    headers=auth_headers(admin))
    assert r.status_code == 201, r.text
    return r.json()


# ----------------------------------------------------------------------- test alerts

def test_test_alert_goes_through_the_worker_without_creating_evidence(client, db_session, admin_a):
    dest = _dest(client, admin_a)
    r = client.post(f"/api/v1/alert-destinations/{dest['destination_id']}/test", headers=auth_headers(admin_a))
    assert r.status_code == 202
    sent = []
    result = alerting.run_once(db_session, sender=lambda t, h, b, timeout: sent.append((h, b)) or 200)
    assert result == {"DELIVERED": 1}
    headers, body = sent[0]
    assert b'"type":"honeyshield.test"' in body and b'"source":"TEST"' in body
    expected = webhook.signature(dest["signing_secret"], headers["X-HS-Timestamp"], body)
    assert headers["X-HS-Signature"] == expected and headers["X-HS-Event"] == "0"
    assert db_session.query(DetectionEvent).count() == 0
    deliveries = client.get("/api/v1/alert-destinations/deliveries", headers=auth_headers(admin_a)).json()
    assert deliveries[0]["is_test"] is True and deliveries[0]["detection_event_id"] is None
    assert deliveries[0]["status"] == "DELIVERED"
    assert deliveries[0]["created_at"] and deliveries[0]["created_at"] <= deliveries[0]["delivered_at"]
    assert db_session.query(AuditLog).filter_by(event_type="ALERT_TEST_REQUESTED").count() == 1


def test_test_alert_formats(client, db_session, admin_a):
    slack = _dest(client, admin_a, format="SLACK")
    mail = _dest(client, admin_a, url="mailto:soc@example.com", format="EMAIL")
    syslog = _dest(client, admin_a, url="syslog+tls://siem.example.com:6514", format="SYSLOG_CEF")
    for d in (slack, mail, syslog):
        assert client.post(f"/api/v1/alert-destinations/{d['destination_id']}/test",
                           headers=auth_headers(admin_a)).status_code == 202
    bodies, mails, frames = [], [], []
    alerting.run_once(db_session, sender=lambda t, h, b, timeout: bodies.append(b) or 200,
                      mailer=lambda m, r, timeout: mails.append(m), syslog=lambda t, f, timeout: frames.append(f))
    assert b"test alert" in bodies[0]
    assert mails[0]["Subject"] == "[HoneyShield] Test alert: this destination works"
    assert b"honeytoken.TEST" in frames[0]


def test_test_alerts_are_scoped_limited_and_refused_when_disabled(client, admin_a, admin_b, user_a):
    dest = _dest(client, admin_a)
    path = f"/api/v1/alert-destinations/{dest['destination_id']}/test"
    assert client.post(path, headers=auth_headers(admin_b)).status_code == 404
    assert client.post(path, headers=auth_headers(user_a)).status_code == 403
    codes = [client.post(path, headers=auth_headers(admin_a)).status_code for _ in range(6)]
    assert codes == [202] * 5 + [429]
    other = _dest(client, admin_a, url="https://hooks.example.com/other")
    client.delete(f"/api/v1/alert-destinations/{other['destination_id']}", headers=auth_headers(admin_a))
    assert client.post(f"/api/v1/alert-destinations/{other['destination_id']}/test",
                       headers=auth_headers(admin_a)).status_code == 422


def test_failed_test_alert_is_dead_lettered_with_a_test_message(client, db_session, admin_a):
    dest = _dest(client, admin_a)
    client.post(f"/api/v1/alert-destinations/{dest['destination_id']}/test", headers=auth_headers(admin_a))
    alerting.run_once(db_session, sender=lambda t, h, b, timeout: 410)
    row = db_session.query(OutboxEvent).one()
    assert row.status == OutboxStatus.DEAD
    rec = db_session.query(AuditLog).filter_by(event_type="ALERT_DELIVERY_FAILED").one()
    assert rec.message.startswith("Test alert delivery")


# ----------------------------------------------------------------------- CSV export

def _rows(resp):
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")
    return list(csv.DictReader(io.StringIO(resp.content.decode("utf-8-sig"))))


def test_export_masks_tokens_and_neutralises_formulas(client, db_session, admin_a, token_a):
    assert client.get(f"/t/{token_a.token_value}", headers={"User-Agent": "=HYPERLINK(\"http://evil\")"}).status_code == 204
    assert client.get(f"/t/{token_a.token_value}", headers={"User-Agent": "@SUM(1+1)"}).status_code == 204
    r = client.get("/api/v1/detection-events/export", headers=auth_headers(admin_a))
    rows = _rows(r)
    assert len(rows) == 2 and r.headers["x-export-rows"] == "2"
    assert "attachment" in r.headers["content-disposition"]
    assert token_a.token_value not in r.content.decode()
    assert all(row["request_path"] == "/t/{token}" for row in rows)
    assert {row["user_agent"][0] for row in rows} == {"'"}
    assert db_session.query(AuditLog).filter_by(event_type="EVENTS_EXPORTED").one().event_metadata["rows"] == 2


def test_export_is_tenant_scoped(client, admin_a, admin_b, token_a, token_b):
    client.get(f"/t/{token_a.token_value}")
    client.get(f"/t/{token_b.token_value}")
    rows_a = _rows(client.get("/api/v1/detection-events/export", headers=auth_headers(admin_a)))
    rows_b = _rows(client.get("/api/v1/detection-events/export", headers=auth_headers(admin_b)))
    assert len(rows_a) == 1 and len(rows_b) == 1 and rows_a[0]["event_id"] != rows_b[0]["event_id"]


def test_export_filters(client, db_session, admin_a, token_a):
    for _ in range(3):
        client.get(f"/t/{token_a.token_value}")
    events = db_session.query(DetectionEvent).order_by(DetectionEvent.id).all()
    cut = events[1].triggered_at
    cut = cut if cut.tzinfo else cut.replace(tzinfo=timezone.utc)
    since = (cut - timedelta(microseconds=1)).isoformat()
    rows = _rows(client.get("/api/v1/detection-events/export", params={"since": since}, headers=auth_headers(admin_a)))
    assert {int(r["event_id"]) for r in rows} == {events[1].id, events[2].id}
    rows = _rows(client.get("/api/v1/detection-events/export", params={"severity": "CRITICAL"},
                            headers=auth_headers(admin_a)))
    assert rows == []


def test_viewers_can_export_their_tenant(client, user_a, token_a):
    client.get(f"/t/{token_a.token_value}")
    rows = _rows(client.get("/api/v1/detection-events/export", headers=auth_headers(user_a)))
    assert len(rows) == 1
