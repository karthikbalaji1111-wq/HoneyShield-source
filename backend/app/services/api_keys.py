"""Personal API keys: creation, verification, listing and revocation.

Key format: ``hsk_<16 hex>.<43 url-safe chars>`` (public id, then a 256-bit secret). Only
HMAC-SHA256(key derived from JWT_SECRET_KEY, "id|secret") is stored; rotating JWT_SECRET_KEY
invalidates every key, like every session.

A key authenticates as its owner: role, tenant and active status are read live on each request,
so disabling the user or moving them disables or re-scopes the key. 'read' keys may only use
GET/HEAD/OPTIONS. Keys cannot create keys, and creation needs a full (MFA-satisfied) session.

Abuse control: failed key checks are counted per source IP and refused once over the budget
before any database lookup; valid keys get a per-key request budget.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth_exceptions import ForbiddenError, InvalidTokenError
from app.models.api_key import KEY_PREFIX, ApiKey, new_public_id
from app.models.user import User

logger = logging.getLogger(__name__)

MAX_ACTIVE_KEYS_PER_USER = 25
MAX_DAYS = 365
FAILURES_PER_MINUTE_PER_IP = 20
READ_METHODS = {"GET", "HEAD", "OPTIONS"}
LAST_USED_GRANULARITY = timedelta(minutes=1)
INVALID = "Invalid API key"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _key() -> bytes:
    from app.core.config import get_settings

    return hmac.new(get_settings().jwt_secret_key.encode(), b"honeyshield-api-key-v1", hashlib.sha256).digest()


def _hash(public_id: str, secret: str) -> str:
    return hmac.new(_key(), f"{public_id}|{secret}".encode(), hashlib.sha256).hexdigest()


def looks_like_api_key(token: str) -> bool:
    return token.startswith(KEY_PREFIX)


def create(session: Session, user: User, name: str, scope: str, days: int) -> tuple[str, ApiKey]:
    if scope not in ("read", "write"):
        raise ValueError("scope must be read or write")
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f"expiry must be 1-{MAX_DAYS} days")
    active = session.scalar(select(ApiKey.id).where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None),
                                                   ApiKey.expires_at > _now()).limit(1).offset(MAX_ACTIVE_KEYS_PER_USER - 1))
    if active is not None:
        from app.core.exceptions import BusinessRuleViolationError
        raise BusinessRuleViolationError(f"At most {MAX_ACTIVE_KEYS_PER_USER} active API keys per user")
    public_id = new_public_id()
    secret = secrets.token_urlsafe(32)
    key = ApiKey(public_id=public_id, user_id=user.id, tenant_id=user.tenant_id, name=name, scope=scope,
                 secret_hash=_hash(public_id, secret), expires_at=_now() + timedelta(days=days))
    session.add(key)
    session.flush()
    return f"{public_id}.{secret}", key


def _touch(session: Session, key: ApiKey) -> None:
    """Record last use at most once a minute, in its own transaction (reads never commit)."""
    last = _aware(key.last_used_at)
    if last is not None and _now() - last < LAST_USED_GRANULARITY:
        return
    try:
        with Session(bind=session.get_bind()) as side:
            side.query(ApiKey).filter(ApiKey.id == key.id).update({"last_used_at": _now()})
            side.commit()
    except Exception:  # noqa: BLE001 - bookkeeping must never fail a request
        logger.warning("Could not record API key use", exc_info=True)


def resolve(session: Session, token: str, method: str, client_ip: str) -> tuple[User, ApiKey]:
    """Verify a key and return (owner, key). Raises InvalidTokenError / ForbiddenError."""
    from fastapi import HTTPException

    from app.core.config import get_settings
    from app.core.rate_limit import api_limiter, integration_auth_failure_limiter
    from app.core.security import require_active_identity

    settings = get_settings()
    fail_key = f"apikey-fail:{client_ip}"
    if settings.rate_limit_enabled and integration_auth_failure_limiter.peek(fail_key) >= FAILURES_PER_MINUTE_PER_IP:
        raise HTTPException(status_code=429, detail="Too many invalid API key attempts",
                            headers={"Retry-After": "60"})

    def fail() -> InvalidTokenError:
        if settings.rate_limit_enabled:
            integration_auth_failure_limiter.increment(fail_key)
        return InvalidTokenError(INVALID)

    public_id, _, secret = token.partition(".")
    if not public_id.startswith(KEY_PREFIX) or len(public_id) > 40 or not secret or len(secret) > 100:
        raise fail()
    key = session.scalar(select(ApiKey).where(ApiKey.public_id == public_id))
    if key is None or not hmac.compare_digest(key.secret_hash, _hash(public_id, secret)):
        raise fail()
    if key.revoked_at is not None or _aware(key.expires_at) <= _now():
        raise fail()
    user = session.get(User, key.user_id)
    if user is None:
        raise fail()
    require_active_identity(user)
    if key.scope == "read" and method.upper() not in READ_METHODS:
        raise ForbiddenError("This API key is read-only")
    if settings.rate_limit_enabled:
        allowed, retry = api_limiter.check_and_increment(
            f"api_key:{key.public_id}", settings.rate_limit_per_minute_authenticated,
            settings.rate_limit_global_per_minute, window_seconds=60)
        if not allowed:
            raise HTTPException(status_code=429, detail="API rate limit exceeded",
                                headers={"Retry-After": str(retry)})
    _touch(session, key)
    return user, key


def visible_to(actor: User):
    """Keys an actor may list/revoke: their own; a tenant admin also their tenant's; sysadmin all."""
    from app.models.enums import Role

    stmt = select(ApiKey).order_by(ApiKey.id.desc())
    if actor.role == Role.SYSTEM_ADMIN:
        return stmt
    if actor.role == Role.TENANT_ADMIN:
        return stmt.where(ApiKey.tenant_id == actor.tenant_id)
    return stmt.where(ApiKey.user_id == actor.id)


def revoke(session: Session, actor: User, public_id: str) -> ApiKey:
    key = session.scalar(visible_to(actor).where(ApiKey.public_id == public_id).with_for_update())
    if key is None:
        from app.core.exceptions import IntegrationNotFoundError
        raise IntegrationNotFoundError("API key not found")
    if key.revoked_at is None:
        key.revoked_at = _now()
        key.revoked_by_user_id = actor.id
    return key


__all__ = ["create", "resolve", "revoke", "visible_to", "looks_like_api_key", "ForbiddenError"]
