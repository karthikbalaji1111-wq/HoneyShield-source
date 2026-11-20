"""HONEY-007: transactional outbox, webhook delivery, retries, dead letter, SSRF and tenancy."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.models.alerting import AlertDestination, AlertFormat, OutboxEvent, OutboxStatus
from app.models.audit_log import AuditLog
from app.models.enums import EventSeverity
from app.services import alerting
from app.services.alerting import webhook
from tests.conftest import auth_headers

KEY = "alerting-master-key-for-tests-0123456789abcdef"
PUBLIC = ["93.184.216.34"]


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: PUBLIC)


class Recorder:
    def __init__(self, codes):
        self.codes = list(codes)
        self.calls = []

    def __call__(self, target, headers, body, timeout):
        self.calls.append((target, headers, body))
        code = self.codes.pop(0) if len(self.codes) > 1 else self.codes[0]
        if isinstance(code, Exception):
            raise code
        return code


def _dest(client, admin, **kw):
    body = {"url": "https://hooks.example.com/hs", **kw}
    resp = client.post("/api/v1/alert-destinations", json=body, headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _rows(db_session):
    db_session.expire_all()
    return db_session.query(OutboxEvent).order_by(OutboxEvent.id).all()


# ----------------------------------------------------------------- SSRF validation

@pytest.mark.parametrize("url,resolved", [
    ("http://hooks.example.com/x", PUBLIC),
    ("https://localhost/x", PUBLIC),
    ("https://127.0.0.1/x", None),
    ("https://10.1.2.3/x", None),
    ("https://169.254.169.254/latest/meta-data", None),
    ("https://[::1]/x", None),
    ("https://[::ffff:127.0.0.1]/x", None),
    ("https://100.64.0.1/x", None),
    ("https://user:pw@hooks.example.com/x", PUBLIC),
    ("https://hooks.example.com:22/x", PUBLIC),
    ("https://metadata.google.internal/x", PUBLIC),
    ("https://rebind.example.com/x", ["93.184.216.34", "10.0.0.5"]),
    ("https://private.example.com/x", ["192.168.1.10"]),
    ("ftp://hooks.example.com/x", PUBLIC),
])
def test_unsafe_webhook_urls_are_refused(url, resolved):
    with pytest.raises(webhook.UnsafeWebhookURL):
        webhook.validate_url(url, resolver=lambda h, p: resolved or PUBLIC)


def test_public_https_url_is_accepted():
    t = webhook.validate_url("https://hooks.example.com:8443/a?b=1", resolver=lambda h, p: PUBLIC)
    assert (t.host, t.port, t.path, t.addresses) == ("hooks.example.com", 8443, "/a?b=1", tuple(PUBLIC))


def test_api_rejects_unsafe_destination(client, admin_a):
    resp = client.post("/api/v1/alert-destinations", json={"url": "https://169.254.169.254/"},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 422


# ----------------------------------------------------------------- transactional enqueue

def test_detection_enqueues_delivery_in_the_same_transaction(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    rows = _rows(db_session)
    assert len(rows) == 1 and rows[0].status == OutboxStatus.PENDING
    assert rows[0].detection_event.honey_token_id == token_a.id


def test_failed_event_transaction_queues_nothing(db_session, admin_a, token_a, client):
    from app.repositories.detection_event import DetectionEventRepository
    from app.repositories.honey_token import HoneyTokenRepository
    from app.services.detection_event import DetectionEventService
    from app.models.enums import EventSource

    _dest(client, admin_a)
    svc = DetectionEventService(db_session, DetectionEventRepository(db_session), HoneyTokenRepository(db_session))
    svc._persist_event(token=token_a, ip_address="203.0.113.1", request_path="/x", http_method="GET",
                       severity=EventSeverity.HIGH, user_agent=None, headers=None, source=EventSource.PUBLIC_INGEST,
                       commit=False)
    assert len(_rows(db_session)) == 1
    db_session.rollback()
    assert _rows(db_session) == []


def test_min_severity_project_scope_and_tenant_isolation(client, db_session, admin_a, admin_b, project_a, token_a,
                                                         token_b):
    _dest(client, admin_a, min_severity="CRITICAL")                       # URL hits are HIGH: skipped
    _dest(client, admin_a, project_domain=project_a.domain, label="a-only")
    _dest(client, admin_b, label="tenant-b")
    client.get(f"/t/{token_a.token_value}")
    rows = _rows(db_session)
    assert [r.destination.label for r in rows] == ["a-only"]
    client.get(f"/t/{token_b.token_value}")
    assert sorted(r.destination.label for r in _rows(db_session)) == ["a-only", "tenant-b"]


# ----------------------------------------------------------------- delivery

def test_successful_delivery_is_signed_minimal_and_marked_delivered(client, db_session, admin_a, token_a):
    dest = _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder([204])
    assert alerting.run_once(db_session, sender=sender) == {"DELIVERED": 1}
    target, headers, body = sender.calls[0]
    assert target.addresses == tuple(PUBLIC) and target.host == "hooks.example.com"
    expected = webhook.signature(dest["signing_secret"], headers["X-HS-Timestamp"], body)
    assert headers["X-HS-Signature"] == expected
    payload = json.loads(body)
    assert payload["data"]["severity"] == "HIGH" and payload["data"]["source"] == "PUBLIC_INGEST"
    assert token_a.token_value not in body.decode()
    row = _rows(db_session)[0]
    assert row.status == OutboxStatus.DELIVERED and row.attempts == 1 and row.delivered_at
    assert alerting.run_once(db_session, sender=sender) == {}             # never delivered twice


def test_transient_failures_retry_with_backoff_then_dead_letter(client, db_session, admin_a, token_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "alert_max_attempts", 3)
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder([503])
    assert alerting.run_once(db_session, sender=sender) == {"PENDING": 1}
    row = _rows(db_session)[0]
    assert row.attempts == 1 and row.last_status_code == 503
    assert alerting._aware(row.next_attempt_at) > datetime.now(timezone.utc)
    assert alerting.run_once(db_session, sender=sender) == {}             # not due yet
    for _ in range(2):
        row = _rows(db_session)[0]
        row.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.commit()
        alerting.run_once(db_session, sender=sender)
    row = _rows(db_session)[0]
    assert row.status == OutboxStatus.DEAD and row.attempts == 3
    audit = db_session.query(AuditLog).filter_by(event_type="ALERT_DELIVERY_FAILED").one()
    assert audit.event_metadata["attempts"] == 3


def test_network_errors_are_retried(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder([ConnectionRefusedError()])) == {"PENDING": 1}
    assert _rows(db_session)[0].last_error == "ConnectionRefusedError"


def test_permanent_rejection_is_not_retried(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder([410])) == {"DEAD": 1}


def test_dns_rebinding_at_delivery_time_is_blocked(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder([200])
    assert alerting.run_once(db_session, sender=sender, resolver=lambda h, p: ["127.0.0.1"]) == {"DEAD": 1}
    assert sender.calls == []
    assert "unsafe destination" in _rows(db_session)[0].last_error


def test_disabled_destination_is_not_called(client, db_session, admin_a, token_a):
    dest = _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    assert client.delete(f"/api/v1/alert-destinations/{dest['destination_id']}",
                         headers=auth_headers(admin_a)).status_code == 200
    sender = Recorder([200])
    assert alerting.run_once(db_session, sender=sender) == {"DEAD": 1} and sender.calls == []


def test_expired_lease_is_reclaimed(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    client.get(f"/t/{token_a.token_value}")
    ids = alerting.claim_due(db_session, 10)
    assert len(ids) == 1 and alerting.claim_due(db_session, 10) == []     # leased
    later = datetime.now(timezone.utc) + alerting.LEASE + timedelta(seconds=1)
    assert alerting.claim_due(db_session, 10, now=later) == ids            # worker crashed: reclaim


def test_slack_format_payload(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="SLACK")
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder([200])
    alerting.run_once(db_session, sender=sender)
    payload = json.loads(sender.calls[0][2])
    assert set(payload) == {"text"} and "HIGH" in payload["text"]


# ----------------------------------------------------------------- API authorization

def test_destination_management_is_tenant_scoped(client, admin_a, admin_b, user_a, token_a, db_session):
    a = _dest(client, admin_a)
    assert client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/x"},
                       headers=auth_headers(user_a)).status_code == 403
    listing_b = client.get("/api/v1/alert-destinations", headers=auth_headers(admin_b)).json()
    assert listing_b == []
    assert client.delete(f"/api/v1/alert-destinations/{a['destination_id']}",
                         headers=auth_headers(admin_b)).status_code == 404
    listing_a = client.get("/api/v1/alert-destinations", headers=auth_headers(admin_a)).json()
    assert "signing_secret" not in listing_a[0]
    client.get(f"/t/{token_a.token_value}")
    assert len(client.get("/api/v1/alert-destinations/deliveries", headers=auth_headers(admin_a)).json()) == 1
    assert client.get("/api/v1/alert-destinations/deliveries", headers=auth_headers(admin_b)).json() == []


def test_tenant_admin_cannot_target_another_tenant(client, admin_a, tenant_b):
    resp = client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/x",
                                                          "tenant_slug": tenant_b.slug}, headers=auth_headers(admin_a))
    assert resp.status_code == 403


def test_system_admin_must_name_tenant(client, system_admin, tenant_a):
    url = {"url": "https://hooks.example.com/x"}
    assert client.post("/api/v1/alert-destinations", json=url, headers=auth_headers(system_admin)).status_code == 422
    resp = client.post("/api/v1/alert-destinations", json={**url, "tenant_slug": tenant_a.slug},
                       headers=auth_headers(system_admin))
    assert resp.status_code == 201


def test_real_http_sender_connects_to_the_pinned_address():
    """The stdlib sender talks HTTP to the validated address, sending the original Host header."""
    import http.server
    import threading

    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["host"] = self.headers["Host"]
            seen["sig"] = self.headers["X-HS-Signature"]
            seen["body"] = self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        target = webhook.ValidatedTarget("http", "receiver.example.com", server.server_port, "/in", ("127.0.0.1",))
        code = webhook.http_sender(target, {"X-HS-Signature": "v1=abc", "Content-Type": "application/json"},
                                   b'{"a":1}', 5.0)
    finally:
        server.shutdown()
    assert code == 202
    assert seen == {"host": f"receiver.example.com:{server.server_port}", "sig": "v1=abc", "body": b'{"a":1}'}


def test_destination_creation_does_not_require_dns_but_blocks_private_answers(client, admin_a, monkeypatch):
    def no_dns(host, port):
        raise OSError("no resolver on the internal network")
    monkeypatch.setattr(webhook, "default_resolver", no_dns)
    assert client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/x"},
                       headers=auth_headers(admin_a)).status_code == 201
    monkeypatch.setattr(webhook, "default_resolver", lambda h, p: ["10.0.0.7"])
    assert client.post("/api/v1/alert-destinations", json={"url": "https://intranet.example.com/x"},
                       headers=auth_headers(admin_a)).status_code == 422
