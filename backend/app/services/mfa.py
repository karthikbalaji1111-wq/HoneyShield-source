"""Operator MFA lifecycle: enrolment, second-factor verification, recovery, reset.

State lives on ``users``: ``mfa_nonce`` (secret derivation input; set at setup, kept when
enabled), ``mfa_enabled``, ``mfa_last_step`` (replay guard), ``mfa_recovery_hashes`` (keyed hashes
of unused recovery codes). Every state change is audited in the same transaction.
"""
from __future__ import annotations

import hmac
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import mfa
from app.core.auth_exceptions import AuthenticationError, ForbiddenError
from app.core.config import get_settings
from app.core.exceptions import BusinessRuleViolationError, RateLimitExceededError, ValidationError
from app.core.rate_limit import login_limiter
from app.models.user import User

if TYPE_CHECKING:
    from app.services.audit_log import AuditLogService

# Per-account second-factor attempts per minute (on top of the per-IP login limiter). Six-digit
# codes have 10^6 values and three are valid at a time: 5/min bounds online guessing to roughly
# 1 success per 66,000 minutes per account.
MFA_ATTEMPTS_PER_MINUTE = 5


def mfa_required_for(user: User) -> bool:
    return user.role.value in get_settings().mfa_required_role_names


class MfaService:
    def __init__(self, session: Session, audit_service: Optional["AuditLogService"] = None) -> None:
        self.session = session
        self.audit = audit_service

    # ------------------------------------------------------------------ helpers
    def _lock(self, user: User) -> User:
        """Re-read the user row under FOR UPDATE so concurrent codes cannot both pass the replay guard."""
        stmt = (select(User).where(User.id == user.id).with_for_update()
                .execution_options(populate_existing=True))
        return self.session.execute(stmt).scalar_one()

    def _throttle(self, user: User) -> None:
        settings = get_settings()
        allowed, retry_after = login_limiter.check_and_increment(
            f"mfa:{user.id}", MFA_ATTEMPTS_PER_MINUTE, settings.login_global_attempts_per_minute, window_seconds=60)
        if not allowed:
            raise RateLimitExceededError("Too many MFA attempts", retry_after=retry_after)

    def _record(self, user: User, event_type: str, severity: str, message: str, source: str | None,
                actor: User | None = None, metadata: dict | None = None) -> None:
        if not self.audit:
            return
        self.audit.record_action(
            event_type=event_type, severity=severity, message=message, actor_source=source or "api",
            actor_user_id=(actor or user).id, target_entity="user", target_id=str(user.id),
            tenant_id=user.tenant_id, event_metadata=metadata)

    def _fail(self, user: User, source: str | None, reason: str) -> None:
        """Audit a failed second factor in its own commit, then raise a uniform 401."""
        try:
            self.session.rollback()
            self._record(user, "AUTH_MFA_FAILURE", "WARNING", f"Invalid MFA code for user ID {user.id}",
                         source, metadata={"reason": reason})
            self.session.commit()
        except Exception:
            self.session.rollback()
        raise AuthenticationError("Invalid MFA code")

    def _new_recovery_codes(self, user: User) -> list[str]:
        codes = mfa.generate_recovery_codes()
        user.mfa_recovery_hashes = [mfa.hash_recovery_code(user.id, c) for c in codes]
        return codes

    def _clear(self, user: User) -> None:
        user.mfa_enabled = False
        user.mfa_nonce = None
        user.mfa_last_step = None
        user.mfa_recovery_hashes = None
        user.mfa_enabled_at = None

    # ------------------------------------------------------------------ verification
    def verify_second_factor(self, user: User, code: str | None, source: str | None,
                             allow_recovery: bool = True) -> User:
        """Check a TOTP or recovery code for an MFA-enabled user. Commits on success; raises otherwise."""
        code = (code or "").strip()
        self._throttle(user)
        if not code or len(code) > 32:
            self._fail(user, source, "malformed")
        locked = self._lock(user)
        secret = mfa.derive_secret(locked.id, locked.mfa_nonce or "")
        if mfa.looks_like_totp(code):
            step = mfa.verify_totp(secret, code, locked.mfa_last_step)
            if step is None:
                self._fail(locked, source, "totp_mismatch_or_replay")
            locked.mfa_last_step = step
            self.session.commit()
            return locked
        if allow_recovery and mfa.looks_like_recovery_code(code):
            wanted = mfa.hash_recovery_code(locked.id, code)
            remaining = list(locked.mfa_recovery_hashes or [])
            match = next((h for h in remaining if hmac.compare_digest(h, wanted)), None)
            if match is None:
                self._fail(locked, source, "recovery_mismatch")
            remaining.remove(match)
            locked.mfa_recovery_hashes = remaining  # reassign so the JSON change is persisted
            self._record(locked, "MFA_RECOVERY_CODE_USED", "WARNING",
                         f"Recovery code used for user ID {locked.id}", source,
                         metadata={"remaining_codes": len(remaining)})
            self.session.commit()
            return locked
        self._fail(locked, source, "malformed")
        raise AssertionError("unreachable")

    # ------------------------------------------------------------------ enrolment
    def begin_setup(self, user: User, source: str | None) -> dict:
        locked = self._lock(user)
        if locked.mfa_enabled:
            raise BusinessRuleViolationError("MFA is already enabled; disable it or ask an administrator to reset it")
        locked.mfa_nonce = mfa.new_nonce()
        locked.mfa_last_step = None
        self._record(locked, "MFA_SETUP_STARTED", "INFO", f"MFA setup started for user ID {locked.id}", source)
        self.session.commit()
        secret = mfa.derive_secret(locked.id, locked.mfa_nonce)
        settings = get_settings()
        return {
            "secret": mfa.secret_base32(secret),
            "otpauth_uri": mfa.provisioning_uri(secret, locked.email, settings.mfa_issuer),
            "algorithm": "SHA1", "digits": mfa.DIGITS, "period": mfa.PERIOD_SECONDS,
        }

    def enable(self, user: User, code: str, source: str | None) -> tuple[User, list[str]]:
        self._throttle(user)
        locked = self._lock(user)
        if locked.mfa_enabled:
            raise BusinessRuleViolationError("MFA is already enabled")
        if not locked.mfa_nonce:
            raise ValidationError("Start MFA setup first")
        step = mfa.verify_totp(mfa.derive_secret(locked.id, locked.mfa_nonce), (code or "").strip(), None)
        if step is None:
            self._fail(locked, source, "enrolment_code_mismatch")
        locked.mfa_enabled = True
        locked.mfa_last_step = step
        locked.mfa_enabled_at = datetime.now(timezone.utc)
        codes = self._new_recovery_codes(locked)
        self._record(locked, "MFA_ENABLED", "INFO", f"MFA enabled for user ID {locked.id}", source)
        self.session.commit()
        return locked, codes

    def disable(self, user: User, code: str, source: str | None) -> None:
        # With a passkey the account keeps a (phishing-resistant) second factor, so the authenticator
        # app may go even when the role requires MFA.
        if mfa_required_for(user) and not user.passkey_enabled:
            raise ForbiddenError("MFA is mandatory for your role; add a passkey first to turn the authenticator "
                                 "app off")
        if not user.mfa_enabled:
            raise BusinessRuleViolationError("MFA is not enabled")
        locked = self.verify_second_factor(user, code, source)
        self._clear(locked)
        locked.token_version = (locked.token_version or 0) + 1
        self._record(locked, "MFA_DISABLED", "WARNING", f"MFA disabled for user ID {locked.id}", source)
        self.session.commit()

    def regenerate_recovery_codes(self, user: User, code: str, source: str | None) -> list[str]:
        if not user.mfa_enabled:
            raise BusinessRuleViolationError("MFA is not enabled")
        if not mfa.looks_like_totp((code or "").strip()):
            raise ValidationError("A current authenticator code is required")
        locked = self.verify_second_factor(user, code, source, allow_recovery=False)
        codes = self._new_recovery_codes(locked)
        self._record(locked, "MFA_RECOVERY_CODES_REGENERATED", "INFO",
                     f"Recovery codes regenerated for user ID {locked.id}", source)
        self.session.commit()
        return codes

    def admin_reset(self, actor: User, target: User, reason: str, source: str | None) -> User:
        """Clear a user's MFA (lost device). Revokes every session; the user re-enrols at next login."""
        if actor.id == target.id:
            raise BusinessRuleViolationError("Ask another administrator to reset your own MFA")
        locked = self._lock(target)
        self._clear(locked)
        from app.services.passkeys import PasskeyService
        removed = PasskeyService(self.session).remove_all(locked)
        locked.token_version = (locked.token_version or 0) + 1
        self._record(locked, "MFA_RESET", "WARNING", f"MFA reset for user ID {locked.id} by user ID {actor.id}",
                     source, actor=actor, metadata={"reason": reason, "passkeys_removed": removed})
        self.session.commit()
        return locked
