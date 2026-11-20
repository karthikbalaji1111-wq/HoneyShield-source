"""Passkeys as a second factor (WebAuthn): registration, sign-in, removal, admin reset.

Why: authenticator-app codes can be phished. A fake sign-in page asks for the password and the
six-digit code and replays both within the code's 30 seconds. A passkey signs a challenge bound to
the real operator host name (the RP ID), so a look-alike site gets nothing it can use.

Sign-in with a passkey is password + passkey: ``/auth/passkey/login/options`` checks the password
(same throttles and audit as ``/auth/login``) and issues a single-use challenge for that user;
``/auth/passkey/login`` verifies the browser's signature and issues an MFA session.

A user with a passkey counts as MFA-enrolled (``User.has_second_factor``). Once a user has a passkey
they may turn the authenticator app off, even when their role requires MFA, which leaves only the
phishing-resistant factor. An administrator's MFA reset removes passkeys too.

Challenges live in ``passkey_challenges``: random 32 bytes, bound to one user and purpose, valid
for five minutes, consumed with a conditional UPDATE so a response can never be replayed, even
across API replicas.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core import webauthn
from app.core.auth_exceptions import AuthenticationError, ForbiddenError
from app.core.config import get_settings
from app.core.exceptions import BusinessRuleViolationError, PasskeyNotFoundError, ValidationError
from app.models.passkey import PasskeyChallenge, PasskeyCredential
from app.models.user import User

if TYPE_CHECKING:
    from app.services.audit_log import AuditLogService

CHALLENGE_TTL = timedelta(minutes=5)
MAX_PASSKEYS_PER_USER = 10
TIMEOUT_MS = 120_000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def user_handle(user: User) -> bytes:
    """Opaque, stable WebAuthn user handle: reveals neither the user id nor the email address."""
    return hmac.new(get_settings().mfa_key_bytes, f"webauthn-user|{user.id}".encode(), hashlib.sha256).digest()[:16]


def _alg_name(alg: int) -> str:
    return {webauthn.ALG_ES256: "ES256", webauthn.ALG_EDDSA: "EdDSA", webauthn.ALG_RS256: "RS256"}.get(alg, str(alg))


class PasskeyService:
    def __init__(self, session: Session, audit_service: Optional["AuditLogService"] = None) -> None:
        self.session = session
        self.audit = audit_service

    # ------------------------------------------------------------------ helpers
    def _record(self, user: User, event_type: str, severity: str, message: str, source: str | None,
                actor: User | None = None, metadata: dict | None = None) -> None:
        if not self.audit:
            return
        self.audit.record_action(
            event_type=event_type, severity=severity, message=message, actor_source=source or "api",
            actor_user_id=(actor or user).id, target_entity="user", target_id=str(user.id),
            tenant_id=user.tenant_id, event_metadata=metadata)

    def _lock(self, user: User) -> User:
        stmt = (select(User).where(User.id == user.id).with_for_update()
                .execution_options(populate_existing=True))
        return self.session.execute(stmt).scalar_one()

    def credentials(self, user: User) -> list[PasskeyCredential]:
        return list(self.session.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id)
                                         .order_by(PasskeyCredential.id)))

    def _new_challenge(self, user: User, purpose: str) -> PasskeyChallenge:
        # Expired challenges are useless; drop them opportunistically (small table).
        self.session.execute(delete(PasskeyChallenge).where(PasskeyChallenge.expires_at < _now() - timedelta(hours=1)))
        row = PasskeyChallenge(public_id=secrets.token_urlsafe(24), user_id=user.id, purpose=purpose,
                               challenge=webauthn.b64url_encode(secrets.token_bytes(32)),
                               expires_at=_now() + CHALLENGE_TTL)
        self.session.add(row)
        self.session.flush()
        return row

    def _consume(self, public_id: str, purpose: str) -> PasskeyChallenge:
        """Mark the challenge used (exactly once) and return it; raises when unknown, expired or used."""
        if not isinstance(public_id, str) or not 8 <= len(public_id) <= 64:
            raise AuthenticationError("Passkey verification failed")
        now = _now()
        result = self.session.execute(
            update(PasskeyChallenge)
            .where(PasskeyChallenge.public_id == public_id, PasskeyChallenge.purpose == purpose,
                   PasskeyChallenge.used_at.is_(None), PasskeyChallenge.expires_at > now)
            .values(used_at=now))
        if result.rowcount != 1:
            self.session.rollback()
            raise AuthenticationError("Passkey request expired or already used; start again")
        return self.session.scalars(select(PasskeyChallenge).where(PasskeyChallenge.public_id == public_id)).one()

    def _fail(self, user: User, source: str | None, reason: str, event: str = "AUTH_PASSKEY_FAILURE") -> None:
        try:
            self.session.rollback()
            self._record(user, event, "WARNING", f"Passkey verification failed for user ID {user.id}", source,
                         metadata={"reason": reason[:200]})
            self.session.commit()
        except Exception:
            self.session.rollback()
        raise AuthenticationError("Passkey verification failed")

    def _sync_flag(self, user: User) -> None:
        count = self.session.scalar(select(func.count()).select_from(PasskeyCredential)
                                    .where(PasskeyCredential.user_id == user.id)) or 0
        user.passkey_enabled = count > 0

    # ------------------------------------------------------------------ registration
    def begin_registration(self, user: User) -> dict[str, Any]:
        settings = get_settings()
        existing = self.credentials(user)
        if len(existing) >= MAX_PASSKEYS_PER_USER:
            raise BusinessRuleViolationError(f"At most {MAX_PASSKEYS_PER_USER} passkeys per account")
        row = self._new_challenge(user, "register")
        self.session.commit()
        return {
            "challenge_id": row.public_id,
            "options": {
                "challenge": row.challenge,
                "rp": {"id": settings.webauthn_rp, "name": settings.mfa_issuer},
                "user": {"id": webauthn.b64url_encode(user_handle(user)), "name": user.email,
                         "displayName": user.email},
                "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in webauthn.SUPPORTED_ALGS],
                "timeout": TIMEOUT_MS,
                "attestation": "none",
                "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"},
                "excludeCredentials": [{"type": "public-key", "id": c.credential_id,
                                        **({"transports": c.transports} if c.transports else {})}
                                       for c in existing],
            },
        }

    def finish_registration(self, user: User, challenge_id: str, credential: dict[str, Any], name: str,
                            source: str | None) -> PasskeyCredential:
        settings = get_settings()
        name = (name or "").strip()
        if not 1 <= len(name) <= 64:
            raise ValidationError("Give the passkey a name of 1-64 characters (for example 'Work laptop')")
        challenge = self._consume(challenge_id, "register")
        if challenge.user_id != user.id:
            self._fail(user, source, "challenge belongs to another user")
        try:
            new = webauthn.verify_registration(credential, challenge=webauthn.b64url_decode(challenge.challenge),
                                               rp_id=settings.webauthn_rp, origin_ok=settings.webauthn_origin_allowed)
        except webauthn.WebAuthnError as exc:
            self._fail(user, source, f"registration: {exc}")
        cred_id = webauthn.b64url_encode(new.credential_id)
        if self.session.scalar(select(PasskeyCredential.id).where(PasskeyCredential.credential_id == cred_id)):
            self.session.rollback()
            raise BusinessRuleViolationError("This passkey is already registered")
        transports = credential.get("response", {}).get("transports") if isinstance(credential, dict) else None
        if not (isinstance(transports, list) and all(isinstance(t, str) and len(t) <= 32 for t in transports)
                and len(transports) <= 8):
            transports = None
        locked = self._lock(user)
        row = PasskeyCredential(user_id=locked.id, credential_id=cred_id,
                                public_key=webauthn.b64url_encode(new.public_key), alg=new.alg,
                                sign_count=new.sign_count, name=name, transports=transports)
        self.session.add(row)
        self.session.flush()
        self._sync_flag(locked)
        self._record(locked, "PASSKEY_REGISTERED", "INFO", f"Passkey '{name}' registered for user ID {locked.id}",
                     source, metadata={"passkey_id": row.id, "algorithm": _alg_name(new.alg),
                                       "user_verified": new.user_verified})
        self.session.commit()
        return row

    # ------------------------------------------------------------------ sign-in
    def begin_login(self, user: User) -> dict[str, Any]:
        """For a user whose password was just verified."""
        creds = self.credentials(user)
        if not creds:
            raise BusinessRuleViolationError("No passkey is registered for this account")
        row = self._new_challenge(user, "login")
        self.session.commit()
        return {
            "challenge_id": row.public_id,
            "options": {
                "challenge": row.challenge,
                "rpId": get_settings().webauthn_rp,
                "timeout": TIMEOUT_MS,
                "userVerification": "preferred",
                "allowCredentials": [{"type": "public-key", "id": c.credential_id,
                                      **({"transports": c.transports} if c.transports else {})} for c in creds],
            },
        }

    def finish_login(self, challenge_id: str, credential: dict[str, Any], source: str | None) -> User:
        settings = get_settings()
        challenge = self._consume(challenge_id, "login")
        user = self.session.get(User, challenge.user_id)
        if user is None or not user.is_active:
            self.session.rollback()
            raise AuthenticationError("Passkey verification failed")
        try:
            cred_id = webauthn.b64url_encode(webauthn.assertion_credential_id(credential))
        except webauthn.WebAuthnError as exc:
            self._fail(user, source, f"assertion: {exc}")
        stored = self.session.scalars(select(PasskeyCredential).where(
            PasskeyCredential.credential_id == cred_id, PasskeyCredential.user_id == user.id)
            .with_for_update()).one_or_none()
        if stored is None:
            self._fail(user, source, "unknown credential for this user")
        try:
            result = webauthn.verify_assertion(
                credential, challenge=webauthn.b64url_decode(challenge.challenge), rp_id=settings.webauthn_rp,
                origin_ok=settings.webauthn_origin_allowed, public_key=webauthn.b64url_decode(stored.public_key),
                stored_sign_count=stored.sign_count)
        except webauthn.WebAuthnError as exc:
            event = "PASSKEY_CLONE_SUSPECTED" if "counter" in str(exc) else "AUTH_PASSKEY_FAILURE"
            self._fail(user, source, f"assertion: {exc}", event)
        if result.user_handle is not None and not hmac.compare_digest(result.user_handle, user_handle(user)):
            self._fail(user, source, "user handle mismatch")
        stored.sign_count = result.sign_count
        stored.last_used_at = _now()
        self.session.commit()
        return user

    # ------------------------------------------------------------------ removal
    def delete(self, user: User, passkey_id: int, source: str | None) -> None:
        from app.services.mfa import mfa_required_for

        locked = self._lock(user)
        row = self.session.scalars(select(PasskeyCredential).where(
            PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == locked.id)).one_or_none()
        if row is None:
            self.session.rollback()
            raise PasskeyNotFoundError("Passkey not found")
        remaining = len(self.credentials(locked)) - 1
        if remaining == 0 and not locked.mfa_enabled and mfa_required_for(locked):
            self.session.rollback()
            raise ForbiddenError("Your role requires two-factor authentication: add another passkey or set up "
                                 "an authenticator app before removing your last passkey")
        name = row.name
        self.session.delete(row)
        self.session.flush()
        self._sync_flag(locked)
        if not locked.has_second_factor:
            # The account just lost its last second factor: end every session (as turning MFA off does).
            locked.token_version = (locked.token_version or 0) + 1
        self._record(locked, "PASSKEY_REMOVED", "WARNING", f"Passkey '{name}' removed for user ID {locked.id}",
                     source, metadata={"passkey_id": passkey_id, "remaining": remaining})
        self.session.commit()

    def remove_all(self, user: User) -> int:
        """Used by the administrator MFA reset (inside its transaction; no commit here)."""
        n = self.session.execute(delete(PasskeyCredential).where(PasskeyCredential.user_id == user.id)).rowcount
        user.passkey_enabled = False
        return n or 0


def describe(row: PasskeyCredential) -> dict[str, Any]:
    return {"id": row.id, "name": row.name, "algorithm": _alg_name(row.alg),
            "created_at": _aware(row.created_at).isoformat() if row.created_at else None,
            "last_used_at": _aware(row.last_used_at).isoformat() if row.last_used_at else None}
