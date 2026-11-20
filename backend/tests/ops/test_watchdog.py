"""Watchdog: the end-to-end self-test, health checks, notices and the dead-man's-switch heartbeat."""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.core import selftest
from app.core.config import get_settings
from app.models.alerting import AlertDestination, AlertFormat, OutboxEvent, OutboxStatus
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity
from app.services.system_status import get_status, put_status
from app.workers import watchdog

KEY = "test-integration-signing-key-0123456789abcdef"
HEARTBEAT = "https://hc-ping.example/abc"
HEARTBEAT_FAIL = "https://hc-ping.example/abc/fail"
WEBHOOK = "https://hooks.example/notify"


class Net:
    """Fake network: probe requests go to the real app through the test client; the rest is recorded."""

    def __init__(self, client, *, deliver_probe=True, probe_status=None, probe_error=None, webhook_status=200):
        self.client, self.deliver_probe = client, deliver_probe
        self.probe_status, self.probe_error, self.webhook_status = probe_status, probe_error, webhook_status
        self.calls: list[tuple[str, str, bytes | None, dict]] = []

    def __call__(self, method, url, *, body=None, headers=None, connect=None, timeout=10.0, verify=True,
                 ca_file=None):
        self.calls.append((method, url, body, headers or {}))
        parts = urllib.parse.urlsplit(url)
        if parts.hostname == "ingest.example.test":
            if self.probe_error:
                raise self.probe_error
            if self.probe_status:
                return self.probe_status, b"", None
            if not self.deliver_probe:
                return 204, b"", None  # the edge answered for a backend that is down
            r = self.client.get(parts.path + "?" + parts.query)
            return r.status_code, r.content, None
        if url == WEBHOOK:
            return self.webhook_status, b"ok", None
        return 200, b"OK", None

    def urls(self, prefix):
        return [c for c in self.calls if c[1].startswith(prefix)]


@pytest.fixture()
def settings(monkeypatch):
    s = get_settings()
    for name, value in {"integration_signing_key": KEY, "public_ingest_base_url": "https://ingest.example.test",
                        "watchdog_heartbeat_url": HEARTBEAT, "watchdog_heartbeat_fail_url": HEARTBEAT_FAIL,
                        "watchdog_notify_webhook_url": WEBHOOK, "watchdog_probe_timeout_seconds": 2.0,
                        "watchdog_instance_name": "test-box"}.items():
        monkeypatch.setattr(s, name, value)
    return s


def _healthy_components(db_session):
    put_status(db_session, "outbox_worker", {"pid": 1})
    put_status(db_session, "checkpoint", {"ok": True})
    put_status(db_session, "backup", {"state": "ok", "last_success_at": datetime.now(timezone.utc).isoformat(),
                                      "offsite": True})


def _check(state, name):
    return next(c for c in state["checks"] if c["name"] == name)


def test_probe_route_records_nonce_but_no_event(client, db_session, settings):
    db_session.commit()
    token = selftest.probe_token(settings)
    r = client.get(f"/t/{token}?n={'a' * 32}")
    assert r.status_code == 204
    assert get_status(db_session, "selftest_probe").value["nonce"] == "a" * 32
    assert db_session.query(DetectionEvent).count() == 0
    # Without a well-formed nonce nothing is written; any other value is an ordinary unknown token.
    client.get(f"/t/{token}?n=zz")
    assert get_status(db_session, "selftest_probe").value["nonce"] == "a" * 32
    assert client.get(f"/t/{'0' * 32}?n={'b' * 32}").status_code == 204
    assert get_status(db_session, "selftest_probe").value["nonce"] == "a" * 32


def test_healthy_cycle_pings_the_heartbeat(client, db_session, settings):
    _healthy_components(db_session)
    net = Net(client)
    state = watchdog.cycle(db_session, settings, sender=net)
    assert state["healthy"] is True, state["checks"]
    assert _check(state, "selftest")["ok"] and "recorded" in _check(state, "selftest")["detail"]
    assert [c[1] for c in net.urls("https://hc-ping")] == [HEARTBEAT]
    assert net.urls(WEBHOOK) == []  # nothing to report
    assert get_status(db_session, "watchdog").value["healthy"] is True


def test_backend_down_is_detected_notified_reminded_and_cleared(client, db_session, settings, monkeypatch):
    _healthy_components(db_session)
    down = Net(client, deliver_probe=False)
    state = watchdog.cycle(db_session, settings, sender=down)
    probe = _check(state, "selftest")
    assert not probe["ok"] and probe["severity"] == "critical" and "not recorded" in probe["detail"]
    assert state["healthy"] is False
    # The dead-man's switch is told about the failure; the operator gets one notice.
    assert [c[1] for c in down.urls("https://hc-ping")] == [HEARTBEAT_FAIL]
    notices = down.urls(WEBHOOK)
    assert len(notices) == 1
    text = json.loads(notices[0][2])["text"]
    assert "test-box" in text and "Detection self-test" in text

    _healthy_components(db_session)
    again = Net(client, deliver_probe=False)
    watchdog.cycle(db_session, settings, sender=again)
    assert again.urls(WEBHOOK) == []  # no repeat within WATCHDOG_REMIND_HOURS

    # Reminder once the interval has passed.
    row = get_status(db_session, "watchdog")
    value = dict(row.value)
    value["last_notice_at"] = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
    put_status(db_session, "watchdog", value)
    _healthy_components(db_session)
    later = Net(client, deliver_probe=False)
    watchdog.cycle(db_session, settings, sender=later)
    assert "still failing" in json.loads(later.urls(WEBHOOK)[0][2])["title"]

    _healthy_components(db_session)
    fixed = Net(client)
    state = watchdog.cycle(db_session, settings, sender=fixed)
    assert state["healthy"] is True
    recovery = json.loads(fixed.urls(WEBHOOK)[0][2])
    assert "all checks pass again" in recovery["title"] and "Detection self-test" in recovery["text"]


def test_unreachable_ingest_host(client, db_session, settings):
    _healthy_components(db_session)
    state = watchdog.cycle(db_session, settings, sender=Net(client, probe_error=ConnectionRefusedError("refused")))
    assert "could not be reached" in _check(state, "selftest")["detail"]
    state = watchdog.cycle(db_session, settings, sender=Net(client, probe_status=502))
    assert "HTTP 502" in _check(state, "selftest")["detail"]


def test_undelivered_notice_is_retried(client, db_session, settings):
    _healthy_components(db_session)
    net = Net(client, deliver_probe=False, webhook_status=500)
    state = watchdog.cycle(db_session, settings, sender=net)
    assert state["pending_notice"] and state["notice_errors"]
    _healthy_components(db_session)
    net2 = Net(client, deliver_probe=False)
    state = watchdog.cycle(db_session, settings, sender=net2)
    assert len(net2.urls(WEBHOOK)) == 1 and not state["pending_notice"]


def test_stalled_worker_and_dead_alerts(client, db_session, settings, tenant_a, token_a):
    _healthy_components(db_session)
    dest = AlertDestination(tenant_id=tenant_a.id, url="https://siem.example/x", format=AlertFormat.HONEYSHIELD,
                            min_severity=EventSeverity.LOW)
    db_session.add(dest)
    db_session.commit()
    assert client.get(f"/t/{token_a.token_value}").status_code == 204
    row = db_session.query(OutboxEvent).one()
    row.status = OutboxStatus.DEAD
    db_session.commit()
    # Worker heartbeat 10 minutes old.
    put_status(db_session, "outbox_worker", {"pid": 1})
    from app.models.system_status import SystemStatus
    db_session.query(SystemStatus).filter_by(key="outbox_worker").update(
        {"updated_at": datetime.now(timezone.utc) - timedelta(minutes=10)})
    db_session.commit()
    state = watchdog.run_checks(db_session, settings, datetime.now(timezone.utc) - timedelta(minutes=5),
                                sender=Net(client))
    by = {c.name: c for c in state}
    assert not by["alert_worker"].ok and "10 min" in by["alert_worker"].detail
    assert not by["alerts"].ok and "1 alert(s) could not be delivered" in by["alerts"].detail


def test_stuck_pending_alerts(client, db_session, settings, tenant_a, token_a):
    _healthy_components(db_session)
    db_session.add(AlertDestination(tenant_id=tenant_a.id, url="https://siem.example/x",
                                    format=AlertFormat.HONEYSHIELD, min_severity=EventSeverity.LOW))
    db_session.commit()
    client.get(f"/t/{token_a.token_value}")
    row = db_session.query(OutboxEvent).one()
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=30)
    db_session.commit()
    result = watchdog.check_alerts(db_session, settings, datetime.now(timezone.utc))
    assert not result.ok and "waited more than 15 min" in result.detail


def test_backups_checkpoints_and_missing_components(db_session, settings):
    assert watchdog.check_backups(db_session, settings).severity == "warning"  # never configured
    old = (datetime.now(timezone.utc) - timedelta(hours=40)).isoformat()
    put_status(db_session, "backup", {"state": "error", "last_success_at": old, "last_error": "S3 403"})
    r = watchdog.check_backups(db_session, settings)
    assert not r.ok and r.severity == "critical" and "S3 403" in r.detail
    put_status(db_session, "backup", {"state": "ok", "last_success_at": datetime.now(timezone.utc).isoformat(),
                                      "offsite": False})
    r = watchdog.check_backups(db_session, settings)
    assert not r.ok and r.severity == "warning" and "this server only" in r.detail
    assert not watchdog.check_checkpoints(db_session, settings).ok  # none yet
    assert not watchdog.check_alert_worker(db_session).ok


def test_edge_spool_backlog(tmp_path, settings, monkeypatch):
    spool, state = tmp_path / "ingest.jsonl", tmp_path / "position.json"
    monkeypatch.setattr(settings, "watchdog_spool_path", str(spool))
    monkeypatch.setattr(settings, "watchdog_spool_state_path", str(state))
    assert watchdog.check_edge_spool(settings).ok  # no file yet
    line = json.dumps({"request_id": "a" * 32, "time": time.time() - 3600, "uri": "/t/x"}) + "\n"
    spool.write_text(line)
    r = watchdog.check_edge_spool(settings)
    assert not r.ok and "waited 60 min" in r.detail
    state.write_text(json.dumps({"inode": os.stat(spool).st_ino, "offset": len(line)}))
    assert watchdog.check_edge_spool(settings).ok  # everything replayed


def test_disk_space(settings, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "watchdog_disk_path", str(tmp_path))

    class St:
        f_frsize, f_blocks = 4096, 25_000_000  # ~100 GB
        f_bavail = 500_000  # ~2 GB, 2 %
    monkeypatch.setattr(watchdog.os, "statvfs", lambda p: St)
    r = watchdog.check_disk(settings)
    assert not r.ok and r.severity == "critical"
    St.f_bavail = 2_000_000  # 8 %
    assert watchdog.check_disk(settings).severity == "warning"
    St.f_bavail = 10_000_000
    assert watchdog.check_disk(settings).ok


def _cert(days: float) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ingest.example.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=30)).not_valid_after(now + timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _serving(der: bytes, trusted: bool = True):
    import ssl

    def sender(method, url, *, verify=True, **kw):
        if verify and not trusted:
            err = ssl.SSLCertVerificationError("certificate verify failed")
            err.verify_message = "self-signed certificate"
            raise err
        return 200, b"", der
    return sender


def test_certificate_expiry_and_trust(settings, monkeypatch):
    monkeypatch.setattr(settings, "control_plane_hostnames", ["app.example.test"])
    assert watchdog.check_certificates(settings, sender=_serving(_cert(80))).ok
    r = watchdog.check_certificates(settings, sender=_serving(_cert(10)))
    assert not r.ok and r.severity == "warning" and "expires in" in r.detail
    assert "app.example.test" in r.detail and "ingest.example.test" in r.detail
    r = watchdog.check_certificates(settings, sender=_serving(_cert(-2)))
    assert not r.ok and r.severity == "critical" and "expired" in r.detail
    r = watchdog.check_certificates(settings, sender=_serving(_cert(80), trusted=False))
    assert not r.ok and r.severity == "warning" and "self-signed certificate" in r.detail


def test_notice_formats(settings, monkeypatch):
    sent = []

    def sender(method, url, *, body=None, headers=None, **kw):
        sent.append((url, body, headers))
        return 200, b"", None

    monkeypatch.setattr(settings, "watchdog_notify_webhook_url", "https://ntfy.sh/my-topic")
    watchdog.notify_webhook(settings, "Title", "Body text", sender)
    assert sent[-1][1] == b"Body text" and sent[-1][2]["Title"] == "Title"
    monkeypatch.setattr(settings, "watchdog_notify_webhook_url", "https://discord.com/api/webhooks/1/x")
    watchdog.notify_webhook(settings, "Title", "Body text", sender)
    payload = json.loads(sent[-1][1])
    assert payload["content"].startswith("Title") and payload["text"].startswith("Title")


def test_email_notice_uses_smtp(settings, monkeypatch):
    monkeypatch.setattr(settings, "watchdog_notify_webhook_url", None)
    monkeypatch.setattr(settings, "watchdog_notify_email", "ops@example.com")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from", "honeyshield@example.com")
    got = []
    errors = watchdog.send_notice(settings, "T", "B", mailer=lambda msg, rcpt, timeout: got.append((msg, rcpt)))
    assert errors == [] and got[0][1] == ["ops@example.com"] and got[0][0]["Subject"] == "T"


def test_settings_validation(monkeypatch):
    from app.core.config import Settings
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 40)
    with pytest.raises(ValueError):
        Settings(watchdog_heartbeat_url="ftp://x")
    with pytest.raises(ValueError):
        Settings(watchdog_probe_connect="no-port")
    with pytest.raises(ValueError):
        Settings(watchdog_notify_email="two@a.com,b@c.com")
    assert Settings(watchdog_probe_connect="172.28.0.10:443").watchdog_probe_connect == "172.28.0.10:443"


def test_system_status_api_is_for_system_admins(client, db_session, settings, admin_a, system_admin):
    from tests.conftest import auth_headers
    _healthy_components(db_session)
    watchdog.cycle(db_session, settings, sender=Net(client))
    assert client.get("/api/v1/system/status", headers=auth_headers(admin_a)).status_code == 403
    r = client.get("/api/v1/system/status", headers=auth_headers(system_admin))
    assert r.status_code == 200
    body = r.json()
    assert body["watchdog"]["healthy"] is True and body["watchdog_age_seconds"] is not None
    assert body["backup"]["offsite"] is True
    assert "access_key" not in r.text.lower() and "secret" not in r.text.lower()
