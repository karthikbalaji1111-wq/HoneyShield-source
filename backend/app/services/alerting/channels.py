"""Non-HTTP alert channels: email through an SMTP relay, and syslog/CEF to a SIEM.

EMAIL   url = ``mailto:soc@example.com,oncall@example.com`` (1-10 recipients). Sent through the
        operator's SMTP relay (SMTP_HOST, STARTTLS or implicit TLS; plain only outside
        production). Carries X-HS-Delivery / X-HS-Timestamp / X-HS-Signature headers so a mail
        pipeline can verify the alert came from HoneyShield.
SYSLOG  url = ``syslog+tls://siem.example.com:6514`` (RFC 5425: RFC 5424 messages,
        octet-counted, over TLS with certificate and host-name verification). The message body
        is ArcSight CEF, which Splunk, QRadar, Sentinel, Elastic and ArcSight parse natively.
        ``syslog+tcp://`` (port 514/601) only when ALERT_ALLOW_HTTP_WEBHOOKS (development).

The SSRF rules of the webhook channel apply to the syslog host: every resolved address must be
public (or inside ALERT_ALLOWED_PRIVATE_CIDRS), and the connection is pinned to the address
that was validated.
"""
from __future__ import annotations

import re
import smtplib
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Any

from app.services.alerting import webhook as _webhook
from app.services.alerting.webhook import Resolver, UnsafeWebhookURL, ValidatedTarget, is_public_address

MAX_RECIPIENTS = 10
SYSLOG_TLS_PORTS = {6514}
SYSLOG_TCP_PORTS = {514, 601}
_EMAIL = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")

CEF_SEVERITY = {"LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
SYSLOG_SEVERITY = {"LOW": 5, "MEDIUM": 4, "HIGH": 3, "CRITICAL": 2}  # notice, warning, err, crit
SYSLOG_FACILITY = 10  # authpriv


class PermanentDeliveryError(Exception):
    """The receiver rejected the alert; retrying will not help."""


# ------------------------------------------------------------------------------- validation

def parse_mailto(url: str) -> list[str]:
    if len(url) > 2048:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != "mailto" or parts.query or parts.fragment or parts.netloc:
        raise UnsafeWebhookURL("Email destinations use mailto:address[,address...] with no parameters")
    raw = urllib.parse.unquote(parts.path)
    if any(c in raw for c in "\r\n\0<>\"()"):
        raise UnsafeWebhookURL("Invalid character in email address")
    addrs = [a.strip() for a in raw.split(",") if a.strip()]
    if not addrs:
        raise UnsafeWebhookURL("At least one email address is required")
    if len(addrs) > MAX_RECIPIENTS:
        raise UnsafeWebhookURL(f"At most {MAX_RECIPIENTS} recipients")
    for a in addrs:
        domain = a.rsplit("@", 1)[-1].lower()
        if not _EMAIL.match(a) or domain == "localhost" or domain.endswith(_BLOCKED_SUFFIXES):
            raise UnsafeWebhookURL(f"Invalid email address: {a[:80]}")
    return sorted(set(addrs), key=addrs.index)


def validate_syslog_url(url: str, allow_plain: bool = False, resolver: Resolver | None = None,
                        resolve: bool = True, allowed_private: tuple = ()) -> ValidatedTarget:
    import ipaddress

    resolver = resolver or _webhook.default_resolver
    if len(url) > 2048:
        raise UnsafeWebhookURL("URL too long")
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("syslog+tls", "syslog+tcp") or (scheme == "syslog+tcp" and not allow_plain):
        raise UnsafeWebhookURL("Syslog destinations must use syslog+tls://host:6514")
    if parts.username or parts.password or parts.fragment or parts.query or parts.path not in ("", "/"):
        raise UnsafeWebhookURL("Syslog URL must be syslog+tls://host:port with nothing else")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeWebhookURL("Syslog URL must have a host")
    try:
        port = parts.port or (6514 if scheme == "syslog+tls" else 514)
    except ValueError as exc:
        raise UnsafeWebhookURL("Invalid port") from exc
    if port not in (SYSLOG_TLS_PORTS if scheme == "syslog+tls" else SYSLOG_TCP_PORTS):
        raise UnsafeWebhookURL("Syslog port is not allowed (TLS: 6514)")
    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeWebhookURL("Syslog host is not public")
    literal = None
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    if literal is not None and not is_public_address(str(literal), allowed_private):
        raise UnsafeWebhookURL("Syslog host is not public")
    addresses: tuple[str, ...] = ()
    if resolve:
        try:
            resolved = [str(literal)] if literal is not None else resolver(host, port)
        except OSError as exc:
            raise UnsafeWebhookURL("Syslog host does not resolve") from exc
        if not resolved or not all(is_public_address(a, allowed_private) for a in resolved):
            raise UnsafeWebhookURL("Syslog host resolves to a non-public address")
        addresses = tuple(resolved)
    return ValidatedTarget("tls" if scheme == "syslog+tls" else "tcp", host, port, "", addresses)


# ------------------------------------------------------------------------------------- CEF

def _cef_header(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return (str(value).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n"))


def cef_message(data: dict[str, Any]) -> str:
    sev = data["severity"]
    ext: list[tuple[str, Any]] = [
        ("rt", data.get("triggered_ms")),
        ("src", data.get("ip_address")),
        ("requestMethod", data.get("http_method")),
        ("request", data.get("request_path")),
        ("externalId", data.get("delivery_id")),
        ("cn1Label", "eventId"), ("cn1", data.get("event_id")),
        ("cs1Label", "decoyId"), ("cs1", data.get("decoy_id")),
        ("cs2Label", "project"), ("cs2", data.get("project")),
        ("cs3Label", "decoyLabel"), ("cs3", data.get("token_label")),
        ("cs4Label", "detectionSource"), ("cs4", data.get("source")),
        ("cs5Label", "tokenType"), ("cs5", data.get("token_type")),
    ]
    extension = " ".join(f"{k}={_cef_ext(v)}" for k, v in ext if v not in (None, ""))
    header = "|".join(_cef_header(x) for x in (
        "CEF:0", "HoneyShield", "HoneyShield", "1", f"honeytoken.{data['token_type']}",
        f"Honeytoken triggered: {data['token_type']}", CEF_SEVERITY.get(sev, 5)))
    return f"{header}|{extension}"


def syslog_frame(message: str, severity: str, hostname: str, msgid: str, now: datetime | None = None) -> bytes:
    """RFC 5424 message with RFC 5425/6587 octet-counting framing."""
    now = now or datetime.now(timezone.utc)
    pri = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.get(severity, 4)
    ts = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    host = re.sub(r"[^\x21-\x7e]", "", hostname)[:255] or "-"
    msg = f"<{pri}>1 {ts} {host} honeyshield - {msgid[:32]} - \ufeff{message}".encode("utf-8")
    return str(len(msg)).encode() + b" " + msg


# ------------------------------------------------------------------------------- transports

SyslogSender = Callable[[ValidatedTarget, bytes, float], None]
Mailer = Callable[[EmailMessage, list[str], float], None]


def syslog_sender(target: ValidatedTarget, frame: bytes, timeout: float,
                  context: ssl.SSLContext | None = None) -> None:
    sock = socket.create_connection((target.addresses[0], target.port), timeout)
    try:
        if target.scheme == "tls":
            sock = (context or ssl.create_default_context()).wrap_socket(sock, server_hostname=target.host)
        sock.sendall(frame)
        # Close gracefully. Closing right after the write while the server's TLS 1.3 session tickets
        # (or anything else) sit unread makes the kernel send a TCP RST, and the receiver may then
        # discard data it had already accepted: an alert reported as delivered but lost at the SIEM.
        # A close_notify exchange (TLS) or half-close plus drain (TCP) consumes pending input first.
        sock.settimeout(min(timeout, 3.0))
        if target.scheme == "tls":
            try:
                sock = sock.unwrap()
            except (ssl.SSLError, OSError):
                pass  # peer closed without close_notify or did not answer in time: data was sent
        else:
            try:
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(4096):
                    pass
            except OSError:
                pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def build_email(data: dict[str, Any], sender: str, recipients: list[str], headers: dict[str, str],
                body: str) -> EmailMessage:
    msg = EmailMessage()
    label = data.get("token_label") or data.get("decoy_id")
    subject = f"[HoneyShield {data['severity']}] {data['token_type']} decoy '{label}' triggered in {data['project']}"
    if data.get("source") == "TEST":
        subject = "[HoneyShield] Test alert: this destination works"
    msg["Subject"] = re.sub(r"[\r\n]+", " ", subject)[:200]
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
    msg["Auto-Submitted"] = "auto-generated"
    for k, v in headers.items():
        msg[k] = v
    msg.set_content(body)
    return msg


def email_body(data: dict[str, Any]) -> str:
    if data.get("source") == "TEST":
        return ("This is a HoneyShield test alert. No decoy was triggered.\n\n"
                "If you received it, this email destination is configured correctly.\n"
                f"Delivery id: {data.get('delivery_id')}\n")
    lines = [
        "A HoneyShield decoy was triggered. Any interaction with a decoy is suspicious.",
        "",
        f"Severity:        {data['severity']}",
        f"Decoy type:      {data['token_type']}",
        f"Decoy:           {data.get('token_label') or '-'} ({data.get('decoy_id')})",
        f"Project:         {data.get('project')}",
        f"Source IP:       {data.get('ip_address')}",
        f"Request:         {data.get('http_method') or '-'} {data.get('request_path') or '-'}",
        f"Detection path:  {data.get('source')}",
        f"Triggered at:    {data.get('triggered_at')}",
        f"Event id:        {data.get('event_id')}",
        f"Delivery id:     {data.get('delivery_id')}",
        "",
        "Investigate in the HoneyShield console. This message is signed: see the X-HS-Signature header.",
    ]
    return "\n".join(lines) + "\n"


def make_smtp_mailer(settings) -> Mailer:
    def send(msg: EmailMessage, recipients: list[str], timeout: float) -> None:
        if not settings.smtp_host:
            raise RuntimeError("SMTP is not configured")
        context = ssl.create_default_context()
        if settings.smtp_security == "tls":
            client: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=timeout,
                                                    context=context)
        else:
            client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=timeout)
        try:
            client.ehlo()
            if settings.smtp_security == "starttls":
                client.starttls(context=context)
                client.ehlo()
            if settings.smtp_username:
                client.login(settings.smtp_username, settings.smtp_password)
            try:
                refused = client.send_message(msg, from_addr=settings.smtp_from, to_addrs=recipients)
            except smtplib.SMTPRecipientsRefused as exc:
                raise PermanentDeliveryError("all recipients refused") from exc
            except smtplib.SMTPResponseException as exc:
                if 500 <= exc.smtp_code < 600:
                    raise PermanentDeliveryError(f"SMTP {exc.smtp_code}") from exc
                raise
            if refused and len(refused) == len(recipients):
                raise PermanentDeliveryError("all recipients refused")
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                pass
    return send
