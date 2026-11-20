"""Password reset with stateless, single-use links.

token = "<user id>.<expiry epoch>.<mac>", mac = HMAC-SHA256(key, user id | expiry |
current password hash | token_version). Nothing is stored:
* the link dies when the password changes (the hash is in the MAC), so it works once;
* "log out everywhere" or an admin MFA reset (token_version bump) also kills it;
* it expires after RESET_TTL.

Two ways to get a link:
* self-service ``POST /auth/password-reset/request`` emails it (needs SMTP); the response is
  identical whether or not the address exists;
* an administrator issues one for a user in their scope and hands it over out of band.

Completing a reset sets the password and revokes every session. It does NOT remove MFA: an
enrolled user still needs their authenticator (or a recovery code) to sign in afterwards.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth_exceptions import AuthenticationError
from app.models.user import User

RESET_TTL = timedelta(minutes=30)
INVALID = "Invalid or expired reset link"


def _key() -> bytes:
    from app.core.config import get_settings

    return hmac.new(get_settings().jwt_secret_key.encode(), b"honeyshield-password-reset-v1", hashlib.sha256).digest()


def _mac(user: User, exp: int) -> str:
    msg = f"{user.id}|{exp}|{user.hashed_password}|{user.token_version or 0}".encode()
    return base64.urlsafe_b64encode(hmac.new(_key(), msg, hashlib.sha256).digest()).decode().rstrip("=")


def issue(user: User, now: datetime | None = None) -> tuple[str, datetime]:
    now = now or datetime.now(timezone.utc)
    expires = now + RESET_TTL
    exp = int(expires.timestamp())
    return f"{user.id}.{exp}.{_mac(user, exp)}", expires


def resolve(session: Session, token: str, now: datetime | None = None, lock: bool = False) -> User:
    """Return the user a valid token belongs to; raise AuthenticationError otherwise."""
    now = now or datetime.now(timezone.utc)
    try:
        uid_s, exp_s, mac = token.split(".", 2)
        uid, exp = int(uid_s), int(exp_s)
    except (AttributeError, ValueError):
        raise AuthenticationError(INVALID) from None
    if exp < int(now.timestamp()) or exp > int((now + RESET_TTL + timedelta(minutes=1)).timestamp()):
        raise AuthenticationError(INVALID)
    stmt = select(User).where(User.id == uid)
    if lock:
        stmt = stmt.with_for_update()
    user = session.scalar(stmt.execution_options(populate_existing=True))
    if user is None or not user.is_active or not hmac.compare_digest(_mac(user, exp), mac):
        raise AuthenticationError(INVALID)
    return user


def reset_url(base: str, token: str) -> str:
    return f"{base.rstrip('/')}/console/#reset={token}"


def console_base(request_base_url: str) -> str:
    from app.core.config import get_settings

    hosts = get_settings().control_plane_hostnames
    return f"https://{hosts[0]}" if hosts else request_base_url.rstrip("/")


def email_message(to: str, url: str, expires: datetime):
    from email.message import EmailMessage
    from email.utils import format_datetime, make_msgid

    from app.core.config import get_settings

    settings = get_settings()
    msg = EmailMessage()
    msg["Subject"] = "Reset your HoneyShield password"
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain=settings.smtp_from.rsplit("@", 1)[-1])
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(
        "Someone asked to reset the password of this HoneyShield account.\n\n"
        f"Open this link within {int(RESET_TTL.total_seconds() // 60)} minutes to choose a new password "
        f"(it works once):\n\n{url}\n\n"
        "If you did not ask for this, ignore this message; your password stays the same. "
        "Multi-factor authentication is not changed by a reset.\n")
    return msg
