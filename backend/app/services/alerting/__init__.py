"""Durable alert delivery through a transactional outbox.

Persist first, notify second:
  1. ``enqueue_for_event`` runs inside the detection transaction and inserts one
     OutboxEvent per matching destination. Commit makes event + deliveries durable together.
  2. The worker (``python -m app.workers.outbox``) claims due rows with a lease
     (``FOR UPDATE SKIP LOCKED`` on PostgreSQL, so several workers never double-claim),
     delivers outside any transaction, then records the outcome.
  3. Failures retry with capped exponential backoff and jitter; permanent failures and
     exhausted retries become DEAD and are audited. Receivers de-duplicate on X-HS-Delivery.

Detection never depends on a webhook being reachable.
"""
from __future__ import annotations

import json
import logging
import random
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select, text, update
from sqlalchemy.orm import Session

from app.core.attack import techniques_for
from app.models.alerting import AlertDestination, AlertFormat, OutboxEvent, OutboxStatus
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity
from app.models.honey_token import HoneyToken
from app.services.alerting import channels, pagerduty, siem, webhook

logger = logging.getLogger(__name__)

SEVERITY_RANK = {EventSeverity.LOW: 0, EventSeverity.MEDIUM: 1, EventSeverity.HIGH: 2, EventSeverity.CRITICAL: 3}
LEASE = timedelta(seconds=120)
MAX_ERROR_CHARS = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def enqueue_for_event(session: Session, event: DetectionEvent, token: HoneyToken) -> int:
    """Queue deliveries for a just-flushed event. Must run inside the event's transaction."""
    tenant_id = token.project.tenant_id
    stmt = select(AlertDestination).where(
        AlertDestination.tenant_id == tenant_id,
        AlertDestination.is_active.is_(True),
        or_(AlertDestination.project_id.is_(None), AlertDestination.project_id == token.project_id),
    )
    count = 0
    now = _now()
    for dest in session.scalars(stmt):
        if SEVERITY_RANK[event.severity] < SEVERITY_RANK[dest.min_severity]:
            continue
        session.add(OutboxEvent(tenant_id=tenant_id, detection_event_id=event.id, destination_id=dest.id,
                                status=OutboxStatus.PENDING, next_attempt_at=now))
        count += 1
    return count


def event_data(event: DetectionEvent, delivery_id: int) -> dict[str, Any]:
    token = event.honey_token
    project = token.project
    triggered = _aware(event.triggered_at)
    return {
        "delivery_id": delivery_id,
        "event_id": event.id,
        "severity": event.severity.value,
        "source": event.source.value,
        "token_type": token.token_type.value,
        "decoy_id": token.decoy_id,
        "token_label": token.label,
        "project": project.domain,
        "ip_address": event.ip_address,
        "http_method": event.http_method,
        # Public hits carry the token value in the path (/t/<value>); never ship it to a third party.
        "request_path": (event.request_path or "").replace(token.token_value, "{token}"),
        "triggered_at": triggered.isoformat() if triggered else None,
        "triggered_ms": int(triggered.timestamp() * 1000) if triggered else None,
        "attack": [{"id": t["id"], "name": t["name"]} for t in techniques_for(token.token_type.value, event.request_path)],
    }


def test_event_data(dest: AlertDestination, delivery_id: int) -> dict[str, Any]:
    """Synthetic, clearly labelled payload for 'send test alert' (no detection event exists)."""
    now = _now()
    return {
        "delivery_id": delivery_id, "event_id": 0, "severity": "LOW", "source": "TEST", "token_type": "TEST",
        "decoy_id": "test", "token_label": "HoneyShield test alert - no decoy was triggered",
        "project": "honeyshield-test", "ip_address": "192.0.2.1", "http_method": "GET",
        "request_path": "/test-alert", "triggered_at": now.isoformat(), "triggered_ms": int(now.timestamp() * 1000),
        "attack": [],
    }


def build_payload(event: DetectionEvent | None, dest: AlertDestination, delivery_id: int,
                  data: dict[str, Any] | None = None) -> dict[str, Any]:
    data = dict(data) if data is not None else event_data(event, delivery_id)
    data.pop("triggered_ms")
    if dest.format == AlertFormat.SLACK:
        if data["source"] == "TEST":
            return {"text": "HoneyShield test alert: this destination is configured correctly. No decoy was triggered."}
        return {"text": (f"HoneyShield {data['severity']} alert: {data['token_type']} decoy "
                         f"'{data['token_label'] or data['decoy_id']}' in {data['project']} triggered from "
                         f"{data['ip_address']} ({data['source']}) at {data['triggered_at']}. Event #{data['event_id']}."
                         + _attack_suffix(data))}
    if dest.format == AlertFormat.PAGERDUTY:
        return pagerduty.event(data, pagerduty.parse_url(dest.url).routing_key)
    kind = "honeyshield.test" if data["source"] == "TEST" else "honeyshield.detection"
    return {"type": kind, "version": 1, "data": data}


def _attack_suffix(data: dict[str, Any]) -> str:
    ids = [t["id"] for t in data.get("attack") or []]
    return f" ATT&CK: {', '.join(ids)}." if ids else ""


def check_destination(url: str, fmt: AlertFormat, settings: Any, *, resolve: bool = True,
                      resolver: webhook.Resolver | None = None):
    """Validate a destination for its channel. Raises webhook.UnsafeWebhookURL."""
    allowed = settings.alert_private_networks
    if fmt == AlertFormat.EMAIL:
        return channels.parse_mailto(url)
    if fmt == AlertFormat.SYSLOG_CEF:
        return channels.validate_syslog_url(url, allow_plain=settings.alert_allow_http_webhooks, resolver=resolver,
                                            resolve=resolve, allowed_private=allowed)
    if fmt == AlertFormat.PAGERDUTY:
        # The routing key is checked here; the Events API host goes through the same SSRF checks
        # as any webhook (it is a fixed public host, but the resolve-and-pin still applies).
        return webhook.validate_url(pagerduty.parse_url(url).endpoint, resolver=resolver, resolve=resolve,
                                    allowed_private=allowed)
    if fmt == AlertFormat.SPLUNK_HEC:
        return webhook.validate_url(siem.parse_splunk(url).endpoint, resolver=resolver, resolve=resolve,
                                    allowed_private=allowed, https_ports=siem.SPLUNK_PORTS)
    if fmt == AlertFormat.SENTINEL:
        return webhook.validate_url(siem.parse_sentinel(url).endpoint, resolver=resolver, resolve=resolve,
                                    allowed_private=allowed)
    return webhook.validate_url(url, allow_http=settings.alert_allow_http_webhooks, resolver=resolver,
                                resolve=resolve, allowed_private=allowed)


def destination_host(url: str, fmt: AlertFormat) -> str:
    """For audit records: where alerts go, without paths or secrets in query strings."""
    if fmt == AlertFormat.EMAIL:
        return ",".join(sorted({a.rsplit("@", 1)[-1].lower() for a in channels.parse_mailto(url)}))
    if fmt == AlertFormat.PAGERDUTY:
        return urllib.parse.urlsplit(pagerduty.parse_url(url).endpoint).hostname or ""
    if fmt == AlertFormat.SPLUNK_HEC:
        return siem.parse_splunk(url).host
    if fmt == AlertFormat.SENTINEL:
        return siem.parse_sentinel(url).host
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def claim_due(session: Session, batch: int, now: datetime | None = None) -> list[int]:
    """Lease up to ``batch`` due deliveries and return their ids (commits the lease)."""
    now = now or _now()
    if session.get_bind().dialect.name == "postgresql":
        rows = session.execute(text(
            "UPDATE outbox_events SET status = 'IN_FLIGHT', lease_until = :lease, updated_at = now() "
            "WHERE id IN (SELECT id FROM outbox_events "
            "  WHERE (status = 'PENDING' AND next_attempt_at <= :now) "
            "     OR (status = 'IN_FLIGHT' AND lease_until < :now) "
            "  ORDER BY next_attempt_at, id LIMIT :n FOR UPDATE SKIP LOCKED) RETURNING id"),
            {"now": now, "lease": now + LEASE, "n": batch}).scalars().all()
    else:  # SQLite: single writer, no SKIP LOCKED
        ids = session.scalars(select(OutboxEvent.id).where(or_(
            (OutboxEvent.status == OutboxStatus.PENDING) & (OutboxEvent.next_attempt_at <= now),
            (OutboxEvent.status == OutboxStatus.IN_FLIGHT) & (OutboxEvent.lease_until < now),
        )).order_by(OutboxEvent.next_attempt_at, OutboxEvent.id).limit(batch)).all()
        if ids:
            session.execute(update(OutboxEvent).where(OutboxEvent.id.in_(ids)).values(
                status=OutboxStatus.IN_FLIGHT, lease_until=now + LEASE))
        rows = ids
    session.commit()
    return list(rows)


def _backoff(attempts: int) -> timedelta:
    base = min(3600.0, 30.0 * (2 ** max(0, attempts - 1)))
    return timedelta(seconds=base * (0.8 + 0.4 * random.random()))


def _audit_dead(session: Session, row: OutboxEvent, reason: str) -> None:
    from app.repositories.audit_log import AuditLogRepository
    from app.services.audit_log import AuditLogService

    AuditLogService(session=session, audit_repo=AuditLogRepository(session)).record_action(
        event_type="ALERT_DELIVERY_FAILED",
        severity="WARNING",
        message=(f"Test alert delivery {row.id} abandoned: {reason}" if row.is_test else
                 f"Alert delivery {row.id} for detection event {row.detection_event_id} abandoned: {reason}"),
        actor_source="alert_worker",
        target_entity="alert_destination",
        target_id=row.destination.public_id,
        tenant_id=row.tenant_id,
        event_metadata={"outbox_id": row.id, "attempts": row.attempts, "last_status_code": row.last_status_code},
    )


def deliver_one(session: Session, outbox_id: int, *, sender: webhook.Sender | None = None,
                resolver: webhook.Resolver | None = None, now: datetime | None = None,
                mailer: channels.Mailer | None = None,
                syslog: channels.SyslogSender | None = None,
                requester: webhook.Requester | None = None) -> OutboxStatus:
    from app.core.config import get_settings

    settings = get_settings()
    now = now or _now()
    row = session.get(OutboxEvent, outbox_id)
    if row is None or row.status != OutboxStatus.IN_FLIGHT:
        return row.status if row else OutboxStatus.DEAD
    dest = row.destination

    def finish(status: OutboxStatus, error: str | None = None, code: int | None = None) -> OutboxStatus:
        row.status = status
        row.lease_until = None
        row.last_error = (error or None) and error[:MAX_ERROR_CHARS]
        row.last_status_code = code
        if status == OutboxStatus.DELIVERED:
            row.delivered_at = now
        if status == OutboxStatus.DEAD:
            _audit_dead(session, row, error or "unknown")
        session.commit()
        return status

    def postpone(reason: str) -> OutboxStatus:
        row.status, row.lease_until, row.next_attempt_at = OutboxStatus.PENDING, None, now + timedelta(minutes=5)
        row.last_error = reason
        session.commit()
        return OutboxStatus.PENDING

    if not dest.is_active:
        return finish(OutboxStatus.DEAD, "destination disabled")
    if not settings.integration_signing_key:
        return postpone("signing key not configured")
    if dest.format == AlertFormat.EMAIL and not settings.smtp_host:
        return postpone("SMTP not configured")
    try:
        target = check_destination(dest.url, dest.format, settings, resolver=resolver)
    except webhook.UnsafeWebhookURL as exc:
        row.attempts += 1
        return finish(OutboxStatus.DEAD, f"unsafe destination: {exc}")

    data = test_event_data(dest, row.id) if row.is_test else event_data(row.detection_event, row.id)
    ts = str(int(now.timestamp()))
    secret = webhook.signing_secret(settings.integration_signing_key, dest.public_id, dest.key_salt)
    timeout = settings.alert_delivery_timeout_seconds
    row.attempts += 1
    code: int | None = None
    error: str | None = None
    # Codes this receiver may answer for a while and then accept (otherwise a 4xx is final).
    retry_codes = {408, 425, 429}
    try:
        if dest.format == AlertFormat.EMAIL:
            body = channels.email_body(data)
            headers = {"X-HS-Delivery": str(row.id), "X-HS-Event": str(row.detection_event_id or 0),
                       "X-HS-Timestamp": ts, "X-HS-Signature": webhook.signature(secret, ts, body.encode())}
            msg = channels.build_email(data, settings.smtp_from, target, headers, body)
            (mailer or channels.make_smtp_mailer(settings))(msg, target, timeout)
        elif dest.format == AlertFormat.SYSLOG_CEF:
            frame = channels.syslog_frame(channels.cef_message(data), data["severity"],
                                          settings.ingest_hostname or "honeyshield", f"hs-{row.id}", now)
            (syslog or channels.syslog_sender)(target, frame, timeout)
        elif dest.format == AlertFormat.SPLUNK_HEC:
            hec = siem.parse_splunk(dest.url)
            body_bytes = json.dumps(siem.splunk_body(data, hec.index, settings.ingest_hostname or "honeyshield"),
                                    separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json", "User-Agent": "HoneyShield-Alerts/1",
                       "Authorization": f"Splunk {hec.token}",
                       "X-Splunk-Request-Channel": siem.splunk_channel(dest.public_id)}
            code = (sender or webhook.http_sender)(target, headers, body_bytes, timeout)
            if not 200 <= code < 300:
                error = f"HTTP {code}"
        elif dest.format == AlertFormat.SENTINEL:
            az = siem.parse_sentinel(dest.url)
            try:
                token = siem.TOKENS.get(az, requester or webhook.http_request, resolver, timeout,
                                        settings.alert_private_networks)
            except siem.TokenError as exc:
                if exc.permanent:
                    raise channels.PermanentDeliveryError(str(exc)) from exc
                raise
            body_bytes = json.dumps([siem.sentinel_record(data)], separators=(",", ":")).encode()
            headers = {"Content-Type": "application/json", "User-Agent": "HoneyShield-Alerts/1",
                       "Authorization": f"Bearer {token}", "x-ms-client-request-id": str(uuid.uuid4())}
            code = (sender or webhook.http_sender)(target, headers, body_bytes, timeout)
            if code == 401:
                siem.TOKENS.forget(az)  # expired or revoked early: fetch a new one next time
            # A new role assignment on the DCR takes up to 30 minutes to apply (403 until then).
            retry_codes = retry_codes | {401, 403}
            if not 200 <= code < 300:
                error = f"HTTP {code}"
        else:
            body_bytes = json.dumps(build_payload(row.detection_event, dest, row.id, data), separators=(",", ":")).encode()
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "HoneyShield-Alerts/1",
                "X-HS-Delivery": str(row.id),
                "X-HS-Event": str(row.detection_event_id or 0),
                "X-HS-Timestamp": ts,
                "X-HS-Signature": webhook.signature(secret, ts, body_bytes),
            }
            code = (sender or webhook.http_sender)(target, headers, body_bytes, timeout)
            if not 200 <= code < 300:
                error = f"HTTP {code}"
    except channels.PermanentDeliveryError as exc:
        return finish(OutboxStatus.DEAD, f"rejected: {exc}")
    except Exception as exc:  # network failure: retry
        code, error = None, (str(exc) if isinstance(exc, siem.TokenError) else f"{type(exc).__name__}")
    if error is None:
        return finish(OutboxStatus.DELIVERED, code=code)
    if code is not None and 400 <= code < 500 and code not in retry_codes:
        return finish(OutboxStatus.DEAD, error, code)  # receiver rejected it; retrying will not help
    if row.attempts >= settings.alert_max_attempts:
        return finish(OutboxStatus.DEAD, f"retries exhausted ({error})", code)
    row.status = OutboxStatus.PENDING
    row.lease_until = None
    row.last_error = error
    row.last_status_code = code
    row.next_attempt_at = now + _backoff(row.attempts)
    session.commit()
    return OutboxStatus.PENDING


def run_once(session: Session, *, sender: webhook.Sender | None = None,
             resolver: webhook.Resolver | None = None, batch: int | None = None,
             mailer: channels.Mailer | None = None, syslog: channels.SyslogSender | None = None,
             requester: webhook.Requester | None = None) -> dict[str, int]:
    from app.core.config import get_settings

    results: dict[str, int] = {}
    for outbox_id in claim_due(session, batch or get_settings().alert_worker_batch_size):
        try:
            status = deliver_one(session, outbox_id, sender=sender, resolver=resolver, mailer=mailer,
                                 syslog=syslog, requester=requester)
        except Exception:
            logger.exception("Alert delivery %s crashed; lease will expire and it will be retried", outbox_id)
            session.rollback()
            continue
        results[status.value] = results.get(status.value, 0) + 1
    return results


def backlog(session: Session) -> dict[str, int]:
    rows = session.execute(text("SELECT status, count(*) FROM outbox_events GROUP BY status")).all()
    return {status: n for status, n in rows}


def wait(seconds: float) -> None:
    time.sleep(seconds)
