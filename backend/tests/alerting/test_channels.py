"""Email (SMTP) and SIEM (syslog over TLS, CEF) alert channels.

Unit tests cover validation and formatting. The integration tests talk to a real SMTP server
and a real TLS syslog listener on loopback, so smtplib, STARTTLS-less relays, TLS certificate
verification and RFC 5425 framing are exercised for real.
"""
from __future__ import annotations

import email
import email.policy
import shutil
import socket
import socketserver
import ssl
import subprocess
import threading
from email.message import EmailMessage

import pytest

from app.core.config import get_settings
from app.models.alerting import AlertDestination, AlertFormat, OutboxEvent, OutboxStatus
from app.models.audit_log import AuditLog
from app.services import alerting
from app.services.alerting import channels, webhook
from app.services.alerting.webhook import UnsafeWebhookURL, ValidatedTarget
from tests.conftest import auth_headers

KEY = "alerting-master-key-for-tests-0123456789abcdef"
PUBLIC = ["93.184.216.34"]


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "integration_signing_key", KEY)
    monkeypatch.setattr(s, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(s, "smtp_from", "alerts@honeyshield.example")
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: PUBLIC)


# ------------------------------------------------------------------------- validation

@pytest.mark.parametrize("url", [
    "mailto:soc@example.com",
    "mailto:soc@example.com,oncall@example.org",
    "mailto:first.last+tag@sub.example.co.uk",
])
def test_valid_mailto(url):
    assert channels.parse_mailto(url)


@pytest.mark.parametrize("url", [
    "mailto:",
    "mailto:not-an-address",
    "mailto:soc@example.com?cc=attacker@evil.example",
    "mailto:soc@example.com%0d%0aBcc:attacker@evil.example",
    "mailto:soc@localhost",
    "mailto:soc@printer.local",
    "mailto:soc@corp.internal",
    "mailto:" + ",".join(f"u{i}@example.com" for i in range(11)),
    "https://example.com",
])
def test_invalid_mailto(url):
    with pytest.raises(UnsafeWebhookURL):
        channels.parse_mailto(url)


def test_duplicate_recipients_are_collapsed():
    assert channels.parse_mailto("mailto:a@example.com,a@example.com,b@example.com") == ["a@example.com", "b@example.com"]


def test_syslog_tls_url_is_accepted():
    t = channels.validate_syslog_url("syslog+tls://siem.example.com:6514", resolver=lambda h, p: PUBLIC)
    assert (t.scheme, t.host, t.port, t.addresses) == ("tls", "siem.example.com", 6514, tuple(PUBLIC))
    assert channels.validate_syslog_url("syslog+tls://siem.example.com", resolve=False).port == 6514


@pytest.mark.parametrize("url,resolved", [
    ("syslog+tcp://siem.example.com:514", PUBLIC),            # plain TCP needs the dev flag
    ("syslog+tls://siem.example.com:514", PUBLIC),            # wrong port for TLS
    ("syslog+tls://siem.example.com:22", PUBLIC),
    ("syslog+tls://10.0.0.5:6514", None),
    ("syslog+tls://127.0.0.1:6514", None),
    ("syslog+tls://169.254.169.254:6514", None),
    ("syslog+tls://localhost:6514", PUBLIC),
    ("syslog+tls://siem.corp.internal:6514", PUBLIC),
    ("syslog+tls://rebind.example.com:6514", ["93.184.216.34", "10.0.0.7"]),
    ("syslog+tls://user:pw@siem.example.com:6514", PUBLIC),
    ("syslog+tls://siem.example.com:6514/path", PUBLIC),
    ("udp://siem.example.com:514", PUBLIC),
])
def test_unsafe_syslog_urls_are_refused(url, resolved):
    with pytest.raises(UnsafeWebhookURL):
        channels.validate_syslog_url(url, resolver=lambda h, p: resolved or PUBLIC)


def test_plain_syslog_only_with_the_development_flag():
    t = channels.validate_syslog_url("syslog+tcp://siem.example.com:514", allow_plain=True,
                                     resolver=lambda h, p: PUBLIC)
    assert t.scheme == "tcp"


def test_operator_allowed_private_networks():
    import ipaddress

    allowed = (ipaddress.ip_network("10.20.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
               ipaddress.ip_network("169.254.0.0/16"))
    t = channels.validate_syslog_url("syslog+tls://siem.corp.example:6514", resolver=lambda h, p: ["10.20.1.5"],
                                     allowed_private=allowed)
    assert t.addresses == ("10.20.1.5",)
    assert webhook.validate_url("https://hooks.corp.example/x", resolver=lambda h, p: ["10.20.1.6"],
                                allowed_private=allowed).addresses == ("10.20.1.6",)
    # Outside the allowed network, and the never-allowed classes even when "allowed".
    for addr in ("10.30.0.1", "127.0.0.1", "169.254.169.254"):
        with pytest.raises(UnsafeWebhookURL):
            channels.validate_syslog_url("syslog+tls://siem.corp.example:6514", resolver=lambda h, p, a=addr: [a],
                                         allowed_private=allowed)


def test_allowed_private_cidrs_setting_is_parsed_and_validated(monkeypatch):
    from app.core.config import Settings

    s = Settings(jwt_secret_key="x" * 40, alert_allowed_private_cidrs="10.0.0.0/8, 192.168.10.0/24")
    assert [str(n) for n in s.alert_private_networks] == ["10.0.0.0/8", "192.168.10.0/24"]
    with pytest.raises(ValueError):
        Settings(jwt_secret_key="x" * 40, alert_allowed_private_cidrs="10.0.0.0/8,not-a-network")


def test_smtp_settings_are_validated():
    from app.core.config import Settings

    with pytest.raises(ValueError, match="SMTP_FROM"):
        Settings(jwt_secret_key="x" * 40, smtp_host="smtp.example.com")
    with pytest.raises(ValueError, match="together"):
        Settings(jwt_secret_key="x" * 40, smtp_host="smtp.example.com", smtp_from="a@example.com",
                 smtp_username="u")


# ------------------------------------------------------------------------- formatting

DATA = {
    "delivery_id": 7, "event_id": 42, "severity": "HIGH", "source": "PUBLIC_INGEST", "token_type": "URL",
    "decoy_id": "dcy_1", "token_label": "vpn|backup=old\nline", "project": "shop.example",
    "ip_address": "203.0.113.9", "http_method": "GET", "request_path": "/t/{token}",
    "triggered_at": "2026-11-17T10:00:00+00:00", "triggered_ms": 1794823200000,
}


def test_cef_escapes_header_and_extension_values():
    msg = channels.cef_message(DATA)
    header, ext = msg.split("|", 7)[:7], msg.split("|", 7)[7]
    assert header[:4] == ["CEF:0", "HoneyShield", "HoneyShield", "1"]
    assert header[4] == "honeytoken.URL" and header[6] == "8"
    assert "cs3=vpn|backup\\=old\\nline" in ext
    assert "src=203.0.113.9" in ext and "cn1=42" in ext and "rt=1794823200000" in ext
    assert "\n" not in msg


def test_syslog_frame_is_octet_counted_rfc5424():
    frame = channels.syslog_frame("CEF:0|x", "CRITICAL", "ingest.example.com", "hs-7")
    count, rest = frame.split(b" ", 1)
    assert int(count) == len(rest)
    assert rest.startswith(b"<82>1 ")  # authpriv(10)*8 + crit(2)
    assert b" ingest.example.com honeyshield - hs-7 - " in rest


def test_email_is_signed_and_header_safe():
    body = channels.email_body(DATA)
    msg = channels.build_email(DATA, "alerts@honeyshield.example", ["soc@example.com"],
                               {"X-HS-Signature": "v1=abc"}, body)
    assert "\n" not in msg["Subject"] and msg["Subject"].startswith("[HoneyShield HIGH] URL decoy")
    assert msg["X-HS-Signature"] == "v1=abc" and msg["Auto-Submitted"] == "auto-generated"


# --------------------------------------------------------------- API + worker pipeline

def _dest(client, admin, **kw):
    resp = client.post("/api/v1/alert-destinations", json=kw, headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _hit(client, token):
    assert client.get(f"/t/{token.token_value}").status_code == 204


def _rows(db_session):
    db_session.expire_all()
    return db_session.query(OutboxEvent).order_by(OutboxEvent.id).all()


class MailRecorder:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.sent: list[tuple[EmailMessage, list[str]]] = []

    def __call__(self, msg, recipients, timeout):
        if self.error:
            raise self.error
        self.sent.append((msg, recipients))


class SyslogRecorder:
    def __init__(self):
        self.frames: list[tuple[ValidatedTarget, bytes]] = []

    def __call__(self, target, frame, timeout):
        self.frames.append((target, frame))


def test_email_destination_requires_smtp(client, admin_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "smtp_host", None)
    r = client.post("/api/v1/alert-destinations", json={"url": "mailto:soc@example.com", "format": "EMAIL"},
                    headers=auth_headers(admin_a))
    assert r.status_code == 503


def test_api_rejects_invalid_channel_urls(client, admin_a):
    for body in ({"url": "mailto:soc@example.com?bcc=x@evil.example", "format": "EMAIL"},
                 {"url": "https://hooks.example.com/x", "format": "EMAIL"},
                 {"url": "syslog+tls://10.0.0.1:6514", "format": "SYSLOG_CEF"},
                 {"url": "mailto:soc@example.com", "format": "SYSLOG_CEF"},
                 {"url": "syslog+tls://siem.example.com:6514", "format": "HONEYSHIELD"}):
        r = client.post("/api/v1/alert-destinations", json=body, headers=auth_headers(admin_a))
        assert r.status_code == 422, (body, r.text)


def test_email_alert_is_delivered_signed_and_audited(client, db_session, admin_a, token_a):
    created = _dest(client, admin_a, url="mailto:soc@example.com,oncall@example.com", format="EMAIL",
                    min_severity="LOW")
    assert created["signing_secret"]
    _hit(client, token_a)
    mailer = MailRecorder()
    assert alerting.run_once(db_session, mailer=mailer) == {"DELIVERED": 1}
    (msg, recipients), = mailer.sent
    assert recipients == ["soc@example.com", "oncall@example.com"]
    body = msg.get_content()
    assert token_a.token_value not in body and token_a.token_value not in msg["Subject"]
    expected = webhook.signature(created["signing_secret"], msg["X-HS-Timestamp"], body.encode())
    assert msg["X-HS-Signature"] == expected
    audit = db_session.query(AuditLog).filter_by(event_type="ALERT_DESTINATION_CREATED").one()
    assert audit.event_metadata["host"] == "example.com" and "soc" not in str(audit.event_metadata)


def test_email_rejected_by_relay_goes_dead(client, db_session, admin_a, token_a):
    _dest(client, admin_a, url="mailto:soc@example.com", format="EMAIL", min_severity="LOW")
    _hit(client, token_a)
    alerting.run_once(db_session, mailer=MailRecorder(channels.PermanentDeliveryError("all recipients refused")))
    row, = _rows(db_session)
    assert row.status == OutboxStatus.DEAD and "rejected" in row.last_error
    assert db_session.query(AuditLog).filter_by(event_type="ALERT_DELIVERY_FAILED").count() == 1


def test_email_network_failure_is_retried(client, db_session, admin_a, token_a):
    _dest(client, admin_a, url="mailto:soc@example.com", format="EMAIL", min_severity="LOW")
    _hit(client, token_a)
    alerting.run_once(db_session, mailer=MailRecorder(ConnectionRefusedError()))
    row, = _rows(db_session)
    assert row.status == OutboxStatus.PENDING and row.attempts == 1 and row.last_error == "ConnectionRefusedError"


def test_email_waits_when_smtp_is_removed(client, db_session, admin_a, token_a, monkeypatch):
    _dest(client, admin_a, url="mailto:soc@example.com", format="EMAIL", min_severity="LOW")
    _hit(client, token_a)
    monkeypatch.setattr(get_settings(), "smtp_host", None)
    alerting.run_once(db_session, mailer=MailRecorder())
    row, = _rows(db_session)
    assert row.status == OutboxStatus.PENDING and row.attempts == 0 and row.last_error == "SMTP not configured"


def test_syslog_alert_is_delivered_as_cef(client, db_session, admin_a, token_a):
    created = _dest(client, admin_a, url="syslog+tls://siem.example.com:6514", format="SYSLOG_CEF",
                    min_severity="LOW")
    assert created["signing_secret"] is None
    _hit(client, token_a)
    rec = SyslogRecorder()
    assert alerting.run_once(db_session, syslog=rec) == {"DELIVERED": 1}
    (target, frame), = rec.frames
    assert target.addresses == tuple(PUBLIC) and target.port == 6514
    assert b"CEF:0|HoneyShield|HoneyShield|1|honeytoken.URL|" in frame
    assert token_a.token_value.encode() not in frame


def test_syslog_destination_resolving_private_at_delivery_goes_dead(client, db_session, admin_a, token_a, monkeypatch):
    _dest(client, admin_a, url="syslog+tls://siem.example.com:6514", format="SYSLOG_CEF", min_severity="LOW")
    _hit(client, token_a)
    rec = SyslogRecorder()
    alerting.run_once(db_session, syslog=rec, resolver=lambda h, p: ["10.0.0.9"])
    row, = _rows(db_session)
    assert row.status == OutboxStatus.DEAD and "unsafe destination" in row.last_error and not rec.frames


# ------------------------------------------------------------------ real SMTP server

class _SMTPHandler(socketserver.StreamRequestHandler):
    def _send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        server = self.server
        self._send("220 test-smtp ready")
        rcpts: list[str] = []
        while True:
            line = self.rfile.readline().decode(errors="replace").rstrip("\r\n")
            if not line:
                return
            cmd = line.split(" ", 1)[0].upper()
            if cmd in ("EHLO", "HELO"):
                self._send("250-test-smtp")
                self._send("250 8BITMIME")
            elif cmd == "MAIL":
                rcpts = []
                self._send("250 OK")
            elif cmd == "RCPT":
                addr = line.split(":", 1)[1].strip(" <>")
                if "reject" in addr:
                    self._send("550 5.1.1 no such user")
                else:
                    rcpts.append(addr)
                    self._send("250 OK")
            elif cmd == "DATA":
                self._send("354 go ahead")
                data = b""
                while not data.endswith(b"\r\n.\r\n"):
                    chunk = self.rfile.readline()
                    if not chunk:
                        return
                    data += chunk
                server.messages.append((rcpts, data[:-5]))
                self._send("250 queued")
            elif cmd == "QUIT":
                self._send("221 bye")
                return
            else:
                self._send("250 OK")


@pytest.fixture()
def smtp_server():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _SMTPHandler)
    srv.daemon_threads = True
    srv.messages = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_real_smtp_delivery(client, db_session, admin_a, token_a, smtp_server, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", smtp_server.server_address[1])
    monkeypatch.setattr(s, "smtp_security", "none")
    _dest(client, admin_a, url="mailto:soc@example.com", format="EMAIL", min_severity="LOW")
    _hit(client, token_a)
    assert alerting.run_once(db_session) == {"DELIVERED": 1}
    (rcpts, raw), = smtp_server.messages
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert rcpts == ["soc@example.com"]
    assert msg["From"] == "alerts@honeyshield.example" and msg["X-HS-Signature"].startswith("v1=")
    assert "A HoneyShield decoy was triggered" in msg.get_content()


def test_real_smtp_rejection_is_permanent(client, db_session, admin_a, token_a, smtp_server, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(s, "smtp_port", smtp_server.server_address[1])
    monkeypatch.setattr(s, "smtp_security", "none")
    _dest(client, admin_a, url="mailto:reject@example.com", format="EMAIL", min_severity="LOW")
    _hit(client, token_a)
    alerting.run_once(db_session)
    row, = _rows(db_session)
    assert row.status == OutboxStatus.DEAD and not smtp_server.messages


# --------------------------------------------------------------- real TLS syslog listener

@pytest.fixture()
def tls_cert(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=siem.test",
                    "-addext", "subjectAltName=DNS:siem.test", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)
    return key, crt


@pytest.fixture()
def syslog_server(tls_cert):
    key, crt = tls_cert
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    lsock = socket.create_server(("127.0.0.1", 0))
    received: list[bytes] = []
    errors: list[Exception] = []

    def serve():
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    data = b""
                    while chunk := tls.recv(65536):
                        data += chunk
                    received.append(data)
            except (ssl.SSLError, OSError) as exc:
                errors.append(exc)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield lsock.getsockname()[1], crt, received, errors
    lsock.close()


def test_real_tls_syslog_delivery(syslog_server):
    port, crt, received, _ = syslog_server
    ctx = ssl.create_default_context(cafile=str(crt))
    target = ValidatedTarget("tls", "siem.test", port, "", ("127.0.0.1",))
    frame = channels.syslog_frame(channels.cef_message(DATA), "HIGH", "ingest.example.com", "hs-7")
    channels.syslog_sender(target, frame, 5.0, context=ctx)
    for _ in range(100):
        if received:
            break
        threading.Event().wait(0.02)
    assert received == [frame]
    count, rest = received[0].split(b" ", 1)
    assert int(count) == len(rest) and b"CEF:0|HoneyShield" in rest


def test_tls_syslog_refuses_an_untrusted_certificate(syslog_server):
    port, _crt, received, _ = syslog_server
    target = ValidatedTarget("tls", "siem.test", port, "", ("127.0.0.1",))
    with pytest.raises(ssl.SSLError):
        channels.syslog_sender(target, b"5 hello", 5.0)  # default trust store: self-signed refused
    assert not received


def test_tls_syslog_refuses_a_hostname_mismatch(syslog_server):
    port, crt, received, _ = syslog_server
    ctx = ssl.create_default_context(cafile=str(crt))
    target = ValidatedTarget("tls", "other.test", port, "", ("127.0.0.1",))
    with pytest.raises(ssl.SSLError):
        channels.syslog_sender(target, b"5 hello", 5.0, context=ctx)
    assert not received


def test_plain_tcp_syslog_is_not_lost_when_the_receiver_talks_back():
    """Regression: closing right after the write with unread input sends a TCP RST, and the
    receiver may drop data it already accepted. The sender half-closes and drains first."""
    lsock = socket.create_server(("127.0.0.1", 0))
    received: list[bytes] = []

    def serve():
        conn, _ = lsock.accept()
        with conn:
            conn.sendall(b"220 hello from the receiver\n" * 50)   # unread by the client
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
            received.append(data)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    frame = channels.syslog_frame(channels.cef_message(DATA), "HIGH", "ingest.example.com", "hs-9")
    target = ValidatedTarget("tcp", "siem.test", lsock.getsockname()[1], "", ("127.0.0.1",))
    channels.syslog_sender(target, frame, 5.0)
    t.join(5)
    lsock.close()
    assert received == [frame]
