"""Account mail delivered by the worker (password reset links).

The API enqueues a row with only the user id; the worker builds the single-use link from the user's
current password hash and session version at send time, so nothing usable is ever stored. Rows
older than ``MAX_AGE`` are expired instead of sent (a link that arrives an hour late is noise).
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from app.models.mail_outbox import MailOutbox
from app.models.user import User

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
MAX_AGE = timedelta(minutes=15)
LEASE = timedelta(seconds=60)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def enqueue_password_reset(session: Session, user: User, console_base: str) -> MailOutbox:
    row = MailOutbox(kind="password_reset", user_id=user.id, console_base=console_base[:300], status="PENDING",
                     attempts=0, next_attempt_at=_now())
    session.add(row)
    session.flush()
    return row


def _claim(session: Session, batch: int) -> list[int]:
    now = _now()
    if session.get_bind().dialect.name == "postgresql":
        ids = session.execute(text(
            "UPDATE mail_outbox SET next_attempt_at = :lease, updated_at = now() WHERE id IN ("
            " SELECT id FROM mail_outbox WHERE status = 'PENDING' AND next_attempt_at <= :now"
            " ORDER BY next_attempt_at, id LIMIT :n FOR UPDATE SKIP LOCKED) RETURNING id"),
            {"now": now, "lease": now + LEASE, "n": batch}).scalars().all()
    else:
        ids = session.scalars(select(MailOutbox.id).where(MailOutbox.status == "PENDING",
                                                          MailOutbox.next_attempt_at <= now)
                              .order_by(MailOutbox.next_attempt_at, MailOutbox.id).limit(batch)).all()
        if ids:
            session.execute(update(MailOutbox).where(MailOutbox.id.in_(ids)).values(next_attempt_at=now + LEASE))
    session.commit()
    return list(ids)


def run_once(session: Session, *, mailer=None, batch: int = 20) -> dict[str, int]:
    """Send due account mail. ``mailer(msg, recipients, timeout)`` defaults to the SMTP relay."""
    from app.core.config import get_settings
    from app.services import password_reset
    from app.services.alerting import channels

    settings = get_settings()
    results: dict[str, int] = {}
    if not settings.smtp_host:
        return results
    for row_id in _claim(session, batch):
        row = session.get(MailOutbox, row_id)
        user = session.get(User, row.user_id)
        status = "SENT"
        if _now() - _aware(row.created_at) > MAX_AGE:
            status = "EXPIRED"
        elif user is None or not user.is_active:
            status = "FAILED"
            row.last_error = "account missing or disabled"
        else:
            token, expires = password_reset.issue(user)
            msg = password_reset.email_message(user.email, password_reset.reset_url(row.console_base, token), expires)
            row.attempts += 1
            try:
                (mailer or channels.make_smtp_mailer(settings))(msg, [user.email], settings.alert_delivery_timeout_seconds)
                row.sent_at = _now()
            except channels.PermanentDeliveryError as exc:
                status, row.last_error = "FAILED", f"rejected: {exc}"[:300]
            except Exception as exc:  # noqa: BLE001 - transient: retry with backoff
                row.last_error = type(exc).__name__
                if row.attempts >= MAX_ATTEMPTS:
                    status = "FAILED"
                else:
                    status = "PENDING"
                    row.next_attempt_at = _now() + timedelta(seconds=min(300, 15 * 2 ** row.attempts)
                                                             * (0.8 + 0.4 * random.random()))
        row.status = status
        session.commit()
        results[status] = results.get(status, 0) + 1
    return results
