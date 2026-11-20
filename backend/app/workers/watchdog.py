"""Watchdog: ``python -m app.workers.watchdog`` (``--once`` runs a single cycle and exits).

A detection system that fails quietly looks exactly like one with nothing to report. Every
WATCHDOG_INTERVAL_SECONDS this process proves that HoneyShield still works and tells the operator,
on a channel that does not depend on HoneyShield's own alert pipeline, when it does not:

* ``selftest``      sends a self-test hit through the public entry point and waits until the
                    backend has written it to the database (app/core/selftest.py).
* ``database``      the database answers.
* ``alert_worker``  the alert worker is running (it writes a heartbeat every 30 s).
* ``alerts``        no alert was given up on since the last cycle and none has waited too long.
* ``edge_spool``    hits the edge held during an outage are being replayed, not piling up.
* ``checkpoints``   the evidence checkpointer finished a cycle recently.
* ``backups``       the last encrypted backup is recent (warning only when backups are off).
* ``certificates``  the TLS certificates the edge serves are valid and not about to expire.
* ``disk``          enough free space where the spool (and usually the database) lives.

Problems are sent to WATCHDOG_NOTIFY_WEBHOOK_URL (ntfy, Slack, Discord, any webhook) and/or
WATCHDOG_NOTIFY_EMAIL when they start, as a reminder every WATCHDOG_REMIND_HOURS while a critical
one lasts, and when everything recovers. After every cycle without a critical problem the
watchdog requests WATCHDOG_HEARTBEAT_URL; an outside service (Healthchecks.io and similar) warns
the operator when those requests stop, which covers the server itself going down.

Results are kept in system_status (key ``watchdog``) for the console and /metrics.
"""
from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Callable

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core import decoy_paths, selftest
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.services.system_status import age_seconds, get_status, put_status

logger = logging.getLogger("honeyshield.watchdog")

CRITICAL = "critical"
WARNING = "warning"
STATUS_KEY = "watchdog"
ALIVE_FILE = "/tmp/watchdog.alive"

LABELS = {
    "database": "Database",
    "selftest": "Detection self-test",
    "alert_worker": "Alert worker",
    "alerts": "Alert delivery",
    "edge_spool": "Outage buffer",
    "checkpoints": "Evidence checkpoints",
    "backups": "Backups",
    "certificates": "TLS certificates",
    "disk": "Disk space",
}


@dataclass
class CheckResult:
    name: str
    ok: bool
    severity: str = CRITICAL
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return LABELS.get(self.name, self.name)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _minutes(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)} s"
    if seconds < 5400:
        return f"{int(seconds // 60)} min"
    return f"{seconds / 3600:.1f} h"


# ---------------------------------------------------------------------------------------- HTTP

def _connection(url: str, connect: str | None, timeout: float, verify: bool,
                ca_file: str | None) -> tuple[http.client.HTTPConnection, urllib.parse.SplitResult]:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    target_host, target_port = host, port
    if connect:
        h, _, p = connect.rpartition(":")
        target_host, target_port = h.strip("[]"), int(p)
    if parts.scheme == "https":
        ctx = ssl.create_default_context(cafile=ca_file) if verify else ssl._create_unverified_context()  # noqa: S323
        conn: http.client.HTTPConnection = _SNIHTTPSConnection(target_host, target_port, server_hostname=host,
                                                                timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(target_host, target_port, timeout=timeout)
    return conn, parts


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to one address while presenting (and verifying) another host name."""

    def __init__(self, host: str, port: int, *, server_hostname: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._server_hostname = server_hostname
        self._ctx = context
        self.peer_cert_der: bytes | None = None

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self._server_hostname)
        self.peer_cert_der = self.sock.getpeercert(binary_form=True)


def http_request(method: str, url: str, *, body: bytes | None = None, headers: dict[str, str] | None = None,
                 connect: str | None = None, timeout: float = 10.0, verify: bool = True,
                 ca_file: str | None = None) -> tuple[int, bytes, bytes | None]:
    """One request; returns (status, first 64 KiB of the body, the server's DER certificate)."""
    conn, parts = _connection(url, connect, timeout, verify, ca_file)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    hdrs = {"User-Agent": "HoneyShield-Watchdog/1", "Host": parts.netloc}
    hdrs.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(65536)
        return resp.status, data, getattr(conn, "peer_cert_der", None)
    finally:
        conn.close()


# ---------------------------------------------------------------------------------------- checks

def check_database(session: Session) -> CheckResult:
    try:
        session.execute(text("SELECT 1"))
        return CheckResult("database", True)
    except Exception as exc:
        session.rollback()
        return CheckResult("database", False, detail=f"The database is not answering ({type(exc).__name__}).")


def probe_base_url(settings: Settings) -> str | None:
    return settings.watchdog_probe_url or settings.public_ingest_base_url


def check_selftest(session: Session, settings: Settings, *, sender: Callable[..., tuple] = http_request,
                   sleep: Callable[[float], None] = time.sleep) -> tuple[CheckResult, bytes | None]:
    base = probe_base_url(settings)
    if not base:
        return CheckResult("selftest", False, WARNING,
                           "Not configured: set PUBLIC_INGEST_BASE_URL or WATCHDOG_PROBE_URL."), None
    nonce = secrets.token_hex(16)
    url = f"{base.rstrip('/')}{decoy_paths.link_path(settings, selftest.probe_token(settings))}?n={nonce}"
    started = time.monotonic()
    cert = None
    try:
        status, _, cert = sender("GET", url, connect=settings.watchdog_probe_connect,
                                 timeout=settings.watchdog_probe_timeout_seconds,
                                 verify=settings.watchdog_probe_verify_tls, ca_file=settings.watchdog_probe_ca_file)
    except ssl.SSLCertVerificationError as exc:
        return CheckResult("selftest", False, detail=f"The ingest host's TLS certificate is not valid: "
                                                     f"{exc.verify_message or exc}."), None
    except (OSError, http.client.HTTPException) as exc:
        return CheckResult("selftest", False, detail=f"The ingest host could not be reached ({type(exc).__name__}: "
                                                     f"{exc}). Decoys cannot report anything right now."), None
    if status == 429:
        return CheckResult("selftest", True, WARNING, "The edge rate-limited the self-test; skipped this cycle.",
                           {"status": status}), cert
    if status != 204:
        return CheckResult("selftest", False, detail=f"The ingest host answered HTTP {status} instead of 204: "
                                                     "decoy hits are not reaching HoneyShield."), cert
    deadline = started + settings.watchdog_probe_timeout_seconds
    while True:
        session.expire_all()
        row = get_status(session, selftest.PROBE_KEY)
        session.rollback()  # end the read transaction so the next poll sees new commits
        if row is not None and row.value.get("nonce") == nonce:
            ms = int((time.monotonic() - started) * 1000)
            return CheckResult("selftest", True, detail=f"Self-test hit recorded in {ms} ms.",
                               data={"latency_ms": ms, "via_edge": bool(row.value.get("via_edge"))}), cert
        if time.monotonic() >= deadline:
            return CheckResult("selftest", False, detail=(
                "The self-test hit was answered but not recorded: the backend or database is failing. "
                "The edge is holding hits for replay, but nothing new is being detected or alerted.")), cert
        sleep(0.5)


def check_alert_worker(session: Session) -> CheckResult:
    age = age_seconds(get_status(session, "outbox_worker"))
    if age is None:
        return CheckResult("alert_worker", False, detail="The alert worker has never reported in. Alerts are not "
                                                         "being sent.")
    if age > 180:
        return CheckResult("alert_worker", False, detail=f"The alert worker has not reported in for {_minutes(age)}. "
                                                         "Alerts are not being sent.")
    return CheckResult("alert_worker", True, data={"age_seconds": int(age)})


def check_alerts(session: Session, settings: Settings, since: datetime) -> CheckResult:
    from app.models.alerting import OutboxEvent, OutboxStatus
    from app.models.mail_outbox import MailOutbox

    dead = session.scalar(select(func.count()).select_from(OutboxEvent).where(
        OutboxEvent.status == OutboxStatus.DEAD, OutboxEvent.is_test.is_(False), OutboxEvent.updated_at >= since)) or 0
    cutoff = _now() - timedelta(minutes=settings.watchdog_alert_backlog_minutes)
    stuck = session.scalar(select(func.count()).select_from(OutboxEvent).where(
        OutboxEvent.status.in_([OutboxStatus.PENDING, OutboxStatus.IN_FLIGHT]),
        OutboxEvent.created_at < cutoff)) or 0
    mail_failed = session.scalar(select(func.count()).select_from(MailOutbox).where(
        MailOutbox.status == "FAILED", MailOutbox.updated_at >= since)) or 0
    problems = []
    if dead:
        problems.append(f"{dead} alert(s) could not be delivered in the last hour and were given up on "
                        "(see Alerts in the console)")
    if stuck:
        problems.append(f"{stuck} alert(s) have waited more than {settings.watchdog_alert_backlog_minutes} min")
    if problems:
        return CheckResult("alerts", False, detail="; ".join(problems) + ".",
                           data={"dead": dead, "stuck": stuck, "mail_failed": mail_failed})
    if mail_failed:
        return CheckResult("alerts", False, WARNING, f"{mail_failed} account email(s) (password reset) failed.",
                           {"mail_failed": mail_failed})
    return CheckResult("alerts", True, data={"dead": 0, "stuck": 0})


def check_checkpoints(session: Session, settings: Settings) -> CheckResult:
    row = get_status(session, "checkpoint")
    if row is None:
        return CheckResult("checkpoints", False, WARNING, "The checkpointer has not finished a cycle yet.")
    age = age_seconds(row) or 0
    limit = 3 * settings.checkpoint_interval_seconds
    if age > limit:
        return CheckResult("checkpoints", False, detail=f"No evidence checkpoint for {_minutes(age)} "
                                                        "(expected every "
                                                        f"{_minutes(settings.checkpoint_interval_seconds)}).")
    if not row.value.get("ok", False):
        return CheckResult("checkpoints", False, WARNING, row.value.get("error") or "The last checkpoint failed.")
    return CheckResult("checkpoints", True, data={"age_seconds": int(age)})


def check_backups(session: Session, settings: Settings) -> CheckResult:
    row = get_status(session, "backup")
    if row is None or row.value.get("state") == "not_configured":
        return CheckResult("backups", False, WARNING, "Backups are not set up. If this server is lost, every "
                                                      "record goes with it (docs/backup-and-restore.md).")
    last_ok = _parse_time(row.value.get("last_success_at"))
    if last_ok is None:
        return CheckResult("backups", False, detail="No backup has succeeded yet"
                           + (f": {row.value.get('last_error')}" if row.value.get("last_error") else "."))
    age = (_now() - last_ok).total_seconds()
    if age > settings.backup_max_age_hours * 3600:
        err = row.value.get("last_error")
        return CheckResult("backups", False, detail=f"The last successful backup is {_minutes(age)} old"
                           + (f"; latest error: {err}" if err else "") + ".")
    if row.value.get("offsite") is False:
        return CheckResult("backups", False, WARNING, "Backups are kept on this server only; set BACKUP_S3_BUCKET "
                                                      "so they survive losing the server.",
                           {"age_seconds": int(age)})
    return CheckResult("backups", True, data={"age_seconds": int(age)})


def check_edge_spool(settings: Settings) -> CheckResult | None:
    spool = settings.watchdog_spool_path
    if not spool:
        return None
    try:
        st = os.stat(spool)
    except FileNotFoundError:
        return CheckResult("edge_spool", True, data={"pending_bytes": 0})
    except OSError as exc:
        return CheckResult("edge_spool", False, WARNING, f"Cannot read the outage buffer ({type(exc).__name__}).")
    offset = 0
    if settings.watchdog_spool_state_path:
        try:
            with open(settings.watchdog_spool_state_path) as fh:
                state = json.load(fh)
            if state.get("inode") == st.st_ino:
                offset = int(state.get("offset", 0))
        except (OSError, ValueError):
            offset = 0
    pending = max(0, st.st_size - offset)
    if not pending:
        return CheckResult("edge_spool", True, data={"pending_bytes": 0})
    oldest = None
    try:
        with open(spool, "rb") as fh:
            fh.seek(offset)
            line = fh.readline(65536)
        oldest = float(json.loads(line).get("time"))
    except (OSError, ValueError, TypeError, AttributeError):
        oldest = None
    waited = time.time() - oldest if oldest else None
    if waited is not None and waited > settings.watchdog_spool_max_minutes * 60:
        return CheckResult("edge_spool", False, detail=(
            f"Hits captured during an outage have waited {_minutes(waited)} to be replayed "
            f"({pending} bytes). Check the ingest-replay service."), data={"pending_bytes": pending})
    return CheckResult("edge_spool", True, data={"pending_bytes": pending})


def certificate_days_left(der: bytes) -> float:
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    return (cert.not_valid_after_utc - _now()).total_seconds() / 86400


def check_certificates(settings: Settings, ingest_cert: bytes | None = None,
                       sender: Callable[..., tuple] = http_request) -> CheckResult | None:
    """Expiry and trust of the certificates the edge serves for the ingest and operator hosts.

    Each host gets its own verified handshake, so an untrusted (self-signed) certificate is reported
    even when the self-test itself runs with WATCHDOG_PROBE_VERIFY_TLS=false.
    """
    base = probe_base_url(settings)
    if not base or not base.startswith("https://"):
        return None
    found: dict[str, float] = {}
    problems: list[str] = []
    untrusted: list[str] = []
    hosts = [urllib.parse.urlsplit(base).hostname or ""] + list(settings.control_plane_hostnames[:1])
    for i, host in enumerate(hosts):
        der = None
        try:
            _, _, der = sender("HEAD", f"https://{host}/", connect=settings.watchdog_probe_connect, timeout=10.0,
                               verify=True, ca_file=settings.watchdog_probe_ca_file)
        except ssl.SSLCertVerificationError as exc:
            untrusted.append(f"{host} ({exc.verify_message or 'not trusted'})")
            try:
                _, _, der = sender("HEAD", f"https://{host}/", connect=settings.watchdog_probe_connect,
                                   timeout=10.0, verify=False)
            except (OSError, http.client.HTTPException):
                der = None
        except (OSError, http.client.HTTPException):
            der = None
        if der is None and i == 0:
            der = ingest_cert
        if not der:
            continue
        try:
            days = certificate_days_left(der)
        except Exception:
            continue
        found[host] = round(days, 1)
        if days < 0:
            problems.append(f"{host} expired {abs(int(days))} day(s) ago")
        elif days < settings.watchdog_cert_warn_days:
            problems.append(f"{host} expires in {int(days)} day(s)")
    if not found and not untrusted:
        return None
    if problems:
        worst = min(found.values())
        return CheckResult("certificates", False, CRITICAL if worst < 3 else WARNING,
                           "Certificate " + "; ".join(problems) + ". Renew it before visitors and decoys fail.",
                           {"days_left": found})
    if untrusted:
        return CheckResult("certificates", False, WARNING,
                           "Browsers and decoy targets will not trust the certificate of " + "; ".join(untrusted)
                           + ". Install a real certificate (docs/deployment-guide.md, section 2).",
                           {"days_left": found})
    return CheckResult("certificates", True, data={"days_left": found})


def check_disk(settings: Settings) -> CheckResult | None:
    path = settings.watchdog_disk_path
    if not path:
        return None
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if not total:
        return None
    pct = 100.0 * free / total
    data = {"free_bytes": free, "free_percent": round(pct, 1)}
    if pct < settings.watchdog_disk_min_free_percent / 2 or free < 512 * 1024 * 1024:
        return CheckResult("disk", False, detail=f"Only {pct:.1f}% ({free // (1024 * 1024)} MB) free. The database "
                                                 "stops accepting writes when the disk fills.", data=data)
    if pct < settings.watchdog_disk_min_free_percent:
        return CheckResult("disk", False, WARNING, f"Disk space is getting low: {pct:.1f}% free.", data)
    return CheckResult("disk", True, data=data)


def run_checks(session: Session, settings: Settings, since: datetime, *,
               sender: Callable[..., tuple] = http_request) -> list[CheckResult]:
    results = [check_database(session)]
    if not results[0].ok:
        return results
    probe, cert = check_selftest(session, settings, sender=sender)
    results.append(probe)
    for name, fn in (("alert_worker", lambda: check_alert_worker(session)),
                     ("alerts", lambda: check_alerts(session, settings, since)),
                     ("checkpoints", lambda: check_checkpoints(session, settings)),
                     ("backups", lambda: check_backups(session, settings))):
        try:
            results.append(fn())
        except Exception as exc:
            session.rollback()
            logger.exception("Watchdog check %s failed to run", name)
            results.append(CheckResult(name, False, WARNING, f"The check itself failed ({type(exc).__name__})."))
    for extra in (check_edge_spool(settings), check_certificates(settings, cert, sender), check_disk(settings)):
        if extra is not None:
            results.append(extra)
    return results


# ---------------------------------------------------------------------------------------- notices

def instance_name(settings: Settings) -> str:
    if settings.watchdog_instance_name:
        return settings.watchdog_instance_name
    if settings.control_plane_hostnames:
        return settings.control_plane_hostnames[0]
    return socket.gethostname()


def compose_message(settings: Settings, failing: list[CheckResult], recovered: list[str], *,
                    reminder: bool = False) -> tuple[str, str]:
    name = instance_name(settings)
    stamp = _now().strftime("%Y-%m-%d %H:%M UTC")
    if not failing:
        title = f"HoneyShield {name}: all checks pass again"
        body = f"Fixed: {', '.join(recovered)}.\nChecked {stamp}."
        return title, body
    critical = [c for c in failing if c.severity == CRITICAL]
    kind = "still failing" if reminder else ("problem" if len(failing) == 1 else "problems")
    title = f"HoneyShield {name}: {len(failing)} {kind}" + (" (critical)" if critical else "")
    lines = [f"- {c.label}: {c.detail}" for c in failing]
    if recovered:
        lines.append(f"Fixed since the last notice: {', '.join(recovered)}.")
    lines.append(f"Checked {stamp}.")
    return title, "\n".join(lines)


def notify_webhook(settings: Settings, title: str, body: str, sender: Callable[..., tuple] = http_request) -> None:
    url = settings.watchdog_notify_webhook_url
    fmt = settings.watchdog_notify_format
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if fmt == "auto":
        fmt = "text" if host == "ntfy.sh" or host.startswith("ntfy.") else "json"
    if fmt == "text":
        payload = body.encode()
        headers = {"Content-Type": "text/plain; charset=utf-8", "Title": title.encode("ascii", "replace").decode()}
    else:
        message = f"{title}\n{body}"
        payload = json.dumps({"text": message, "content": message[:2000], "title": title}).encode()
        headers = {"Content-Type": "application/json"}
    status, data, _ = sender("POST", url, body=payload, headers=headers, timeout=10.0)
    if not 200 <= status < 300:
        raise RuntimeError(f"notification webhook answered HTTP {status}")


def notify_email(settings: Settings, title: str, body: str, mailer=None) -> None:
    from app.services.alerting.channels import make_smtp_mailer

    if not settings.smtp_host:
        raise RuntimeError("WATCHDOG_NOTIFY_EMAIL needs SMTP_HOST")
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = settings.smtp_from
    msg["To"] = settings.watchdog_notify_email
    msg.set_content(body + "\n")
    (mailer or make_smtp_mailer(settings))(msg, [settings.watchdog_notify_email], 15.0)


def send_notice(settings: Settings, title: str, body: str, *, sender: Callable[..., tuple] = http_request,
                mailer=None) -> list[str]:
    """Send on every configured channel; returns the errors (an empty list means delivered)."""
    errors = []
    if settings.watchdog_notify_webhook_url:
        try:
            notify_webhook(settings, title, body, sender)
        except Exception as exc:
            errors.append(f"webhook: {type(exc).__name__}: {exc}")
    if settings.watchdog_notify_email:
        try:
            notify_email(settings, title, body, mailer)
        except Exception as exc:
            errors.append(f"email: {type(exc).__name__}")
    return errors


def ping_heartbeat(settings: Settings, healthy: bool, sender: Callable[..., tuple] = http_request) -> str | None:
    url = settings.watchdog_heartbeat_url if healthy else settings.watchdog_heartbeat_fail_url
    if not url:
        return None
    try:
        status, _, _ = sender("GET", url, timeout=10.0)
        return None if 200 <= status < 300 else f"heartbeat answered HTTP {status}"
    except Exception as exc:
        return f"heartbeat failed: {type(exc).__name__}"


# ---------------------------------------------------------------------------------------- cycle

def cycle(session: Session, settings: Settings | None = None, *, sender: Callable[..., tuple] = http_request,
          mailer=None) -> dict[str, Any]:
    settings = settings or get_settings()
    previous = get_status(session, STATUS_KEY)
    prev = dict(previous.value) if previous else {}
    session.rollback()
    now = _now()
    # Alerts given up on are counted over the last hour, so the problem stays visible (and is not
    # reported as "fixed" one cycle later just because no new one failed).
    since = now - timedelta(seconds=max(3600, settings.watchdog_interval_seconds))

    results = run_checks(session, settings, since, sender=sender)
    failing = [r for r in results if not r.ok]
    failing_names = sorted(r.name for r in failing)
    prev_failing = sorted(prev.get("failing", []))
    critical = [r for r in failing if r.severity == CRITICAL]

    recovered = [LABELS.get(n, n) for n in prev_failing if n not in failing_names]
    new = [n for n in failing_names if n not in prev_failing]
    last_notice = _parse_time(prev.get("last_notice_at"))
    reminder_due = bool(critical) and (last_notice is None or
                                       now - last_notice >= timedelta(hours=settings.watchdog_remind_hours))
    notice_errors: list[str] = []
    notified = False
    channels = bool(settings.watchdog_notify_webhook_url or settings.watchdog_notify_email)
    if channels and (new or (recovered and not failing) or reminder_due or prev.get("pending_notice")):
        title, body = compose_message(settings, failing, recovered, reminder=not new and bool(failing))
        notice_errors = send_notice(settings, title, body, sender=sender, mailer=mailer)
        notified = not notice_errors
        if notice_errors:
            logger.warning("Watchdog notice not delivered: %s", "; ".join(notice_errors))
    heartbeat_error = ping_heartbeat(settings, healthy=not critical, sender=sender)
    if heartbeat_error:
        logger.warning("Watchdog %s", heartbeat_error)

    for r in failing:
        (logger.error if r.severity == CRITICAL else logger.warning)("Watchdog %s: %s", r.name, r.detail)
    state = {
        "last_cycle_at": now.isoformat(),
        "healthy": not critical,
        "failing": failing_names,
        "checks": [asdict(r) | {"label": r.label} for r in results],
        "last_notice_at": now.isoformat() if notified else prev.get("last_notice_at"),
        # A notice that could not be sent is retried next cycle.
        "pending_notice": bool(notice_errors) or None,
        "notice_errors": notice_errors or None,
        "heartbeat_error": heartbeat_error,
        "channels": {"webhook": bool(settings.watchdog_notify_webhook_url),
                     "email": bool(settings.watchdog_notify_email),
                     "heartbeat": bool(settings.watchdog_heartbeat_url)},
    }
    try:
        put_status(session, STATUS_KEY, state)
    except Exception:
        session.rollback()
        logger.exception("Could not store the watchdog status")
    return state


_stop = threading.Event()


def _handle(signum, _frame) -> None:
    _stop.set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.workers.watchdog")
    parser.add_argument("--once", action="store_true", help="Run one cycle, print the results and exit "
                                                            "(exit 1 when a critical check fails).")
    parser.add_argument("--test-notice", action="store_true", help="Send a test notice and heartbeat, then exit.")
    args = parser.parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    from app.db.session import SessionLocal

    if args.test_notice:
        errors = send_notice(settings, f"HoneyShield {instance_name(settings)}: test notice",
                             "Watchdog notices reach this channel.")
        hb = ping_heartbeat(settings, healthy=True)
        for e in errors + ([hb] if hb else []):
            print(f"FAIL: {e}")
        if not (settings.watchdog_notify_webhook_url or settings.watchdog_notify_email):
            print("No notice channel is configured (WATCHDOG_NOTIFY_WEBHOOK_URL / WATCHDOG_NOTIFY_EMAIL).")
            return 1
        print("Sent." if not errors and not hb else "Some channels failed.")
        return 0 if not errors and not hb else 1

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    logger.info("Watchdog started (every %ss)", settings.watchdog_interval_seconds)
    while not _stop.is_set():
        session = SessionLocal()
        try:
            state = cycle(session, settings)
        except Exception:
            logger.exception("Watchdog cycle failed")
            state = None
        finally:
            session.close()
        try:
            with open(ALIVE_FILE, "a"):
                os.utime(ALIVE_FILE, None)
        except OSError:
            pass
        if args.once:
            for c in (state or {}).get("checks", []):
                print(f"{'OK  ' if c['ok'] else 'FAIL'} {c['label']:<22} {c['detail']}")
            return 0 if state and state["healthy"] else 1
        _stop.wait(settings.watchdog_interval_seconds)
    logger.info("Watchdog stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
