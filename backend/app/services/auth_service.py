"""Authentication service — identity verification and token issuance."""
from __future__ import annotations

import hashlib


from typing import TYPE_CHECKING, Optional

from sqlalchemy.orm import Session

from app.core.auth_exceptions import AuthenticationError, InactiveUserError
from app.core.security import create_access_token, verify_password, get_password_hash, require_active_identity
from app.models.user import User
from app.repositories.user_repository import UserRepository

if TYPE_CHECKING:
    from app.services.audit_log import AuditLogService

# Same bcrypt cost for absent users; this is not a real account credential.
_DUMMY_HASH = get_password_hash("dummy-password-not-used-by-any-account")


class AuthService:
    """Authenticate users and issue JWT access tokens."""

    def __init__(self, session: Session, audit_service: Optional["AuditLogService"] = None) -> None:
        """Initialise the service with a request-scoped database session.

        Args:
            session: SQLAlchemy session used for user lookups.
            audit_service: Optional audit service for recording security events.
        """
        self.session = session
        self.audit_service = audit_service
        self._user_repo = UserRepository(session)

    def authenticate(self, email: str, password: str, source_ip: str | None = None, *,
                     otp: str | None = None, defer_second_factor: bool = False) -> User:
        """Verify credentials and return the active User.

        Args:
            email: The user-supplied email address.
            password: The user-supplied plaintext password.
            source_ip: Optional client IP address for forensic auditing.

        Returns:
            The authenticated, active User object.

        Raises:
            AuthenticationError: If the email does not exist or the
                password does not match the stored hash.
            InactiveUserError: If the user account is disabled.
        """
        # Per-account failure budget (credential stuffing spread over many IPs). Keyed by the
        # normalised address, so unknown addresses are throttled exactly like real ones and the
        # 429 reveals nothing about which accounts exist. Checked before any password work.
        from app.core.config import get_settings
        from app.core.rate_limit import login_account_failure_limiter
        settings = get_settings()
        account_key = "acct:" + hashlib.sha256(email.strip().lower().encode()).hexdigest()
        window = settings.login_account_failure_window_seconds
        if (settings.rate_limit_enabled and settings.login_account_failures_allowed
                and login_account_failure_limiter.peek(account_key, window) >= settings.login_account_failures_allowed):
            if self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="AUTH_ACCOUNT_THROTTLED", severity="WARNING",
                        message="Login refused: too many failed attempts for this account",
                        actor_source=source_ip or "api",
                        event_metadata={"email_domain": email.rsplit("@", 1)[-1][:253].lower(),
                                        "ip_address": source_ip})
                    self.session.commit()
                except Exception:
                    self.session.rollback()
            from app.core.exceptions import RateLimitExceededError
            raise RateLimitExceededError("Too many failed sign-in attempts for this account; try again later",
                                         retry_after=window)

        user = self._user_repo.get_by_email(email)

        # Intentionally identical error for unknown email and wrong password
        # to prevent user enumeration.
        verified = verify_password(password, user.hashed_password if user else _DUMMY_HASH)
        if user is None or not verified:
            if settings.rate_limit_enabled:
                login_account_failure_limiter.increment(account_key, window)
            if self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="AUTH_LOGIN_FAILURE",
                        severity="WARNING",
                        message=f"Failed login attempt for email '{email}'",
                        actor_source=source_ip or "api",
                        target_entity="user",
                        target_id=str(user.id) if user else None,
                        tenant_id=user.tenant_id if user else None,
                        event_metadata={"email": email, "ip_address": source_ip} if source_ip else {"email": email},
                    )
                    self.session.commit()
                except Exception:
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
            raise AuthenticationError("Invalid email or password")

        try:
            require_active_identity(user)
        except Exception:
            if self.audit_service:
                try:
                    self.audit_service.record_action(
                        event_type="AUTH_LOGIN_FAILURE",
                        severity="WARNING",
                        message=f"Failed login attempt for disabled account '{email}'",
                        actor_source=source_ip or "api",
                        target_entity="user",
                        target_id=str(user.id),
                        tenant_id=user.tenant_id,
                        event_metadata={"email": email, "ip_address": source_ip, "reason": "account_disabled"} if source_ip else {"email": email, "reason": "account_disabled"},
                    )
                    self.session.commit()
                except Exception:
                    try:
                        self.session.rollback()
                    except Exception:
                        pass
            raise

        # The password is correct. With defer_second_factor the caller completes sign-in with a
        # passkey (app/services/passkeys.py), which records the successful login itself.
        if defer_second_factor:
            return user

        # Second factor. Only reached after a correct password, so "MFA code required"
        # reveals nothing to someone who does not already hold the password.
        if user.has_second_factor:
            from app.core.auth_exceptions import MfaRequiredError
            if not user.mfa_enabled:
                # Passkeys only: no code can complete this sign-in (/auth/passkey/login can).
                raise MfaRequiredError("Passkey required")
            if not (otp or "").strip():
                raise MfaRequiredError("MFA code required")
            from app.services.mfa import MfaService
            user = MfaService(self.session, self.audit_service).verify_second_factor(user, otp, source_ip)

        if self.audit_service:
            try:
                self.audit_service.record_action(
                    event_type="AUTH_LOGIN_SUCCESS",
                    severity="INFO",
                    message=f"User '{user.email}' logged in successfully",
                    actor_source=source_ip or "api",
                    target_entity="user",
                    target_id=str(user.id),
                    actor_user_id=user.id,
                    tenant_id=user.tenant_id,
                    event_metadata={"email": user.email, "ip_address": source_ip} if source_ip else {"email": user.email},
                )
                self.session.commit()
            except Exception:
                try:
                    self.session.rollback()
                except Exception:
                    pass

        return user

    def create_token_for_user(self, user: User) -> str:
        """Issue a JWT access token for the given user.

        The JWT payload contains only {sub: user_id, exp: expiry}.

        Args:
            user: A verified, active User object.

        Returns:
            A signed JWT access token string.
        """
        from app.core.security import AMR_MFA, AMR_PASSWORD
        # authenticate() only returns a user with a second factor after verifying it (TOTP or recovery
        # code); the passkey sign-in issues its own MFA session.
        amr = AMR_MFA if user.has_second_factor else AMR_PASSWORD
        return create_access_token(subject=user.id, token_version=user.token_version, amr=amr)
