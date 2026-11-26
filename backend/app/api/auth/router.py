"""Auth router: login, logout (revoke all sessions) and password change."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.auth_service import AuthService
from app.core.config import get_settings
from app.core.rate_limit import login_limiter, password_reset_email_limiter

from app.api.dependencies import get_audit_log_service
from app.services.audit_log import AuditLogService

router = APIRouter(prefix="/auth", tags=["auth"])

SessionDependency = Annotated[Session, Depends(get_db)]


def _get_auth_service(
    session: SessionDependency,
    audit_service: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> AuthService:
    """Provide an AuthService bound to the request-scoped session."""
    return AuthService(session=session, audit_service=audit_service)


AuthServiceDependency = Annotated[AuthService, Depends(_get_auth_service)]


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain a JWT access token",
    description=(
        "Accepts email and password credentials. "
        "Returns a Bearer JWT token on success. "
        "Returns HTTP 401 for invalid credentials or disabled accounts."
    ),
)
def login(body: LoginRequest, auth_service: AuthServiceDependency, request: Request) -> TokenResponse:
    """Authenticate the user and return a JWT access token.

    All credential verification and token creation is delegated to AuthService.
    This endpoint performs no database access and contains no security logic.
    """
    settings = get_settings()
    from app.core.ip_trust import extract_client_ip
    source = extract_client_ip(request, settings)
    allowed, retry_after = login_limiter.check_and_increment(
        source,
        settings.login_attempts_per_minute,
        settings.login_global_attempts_per_minute,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Login rate limit exceeded", headers={"Retry-After": str(retry_after)})
    user = auth_service.authenticate(email=body.email, password=body.password, source_ip=source, otp=body.otp)
    token = auth_service.create_token_for_user(user)
    return TokenResponse(access_token=token)


# ---------------------------------------------------------------------------------- session lifecycle
# Access tokens are short-lived JWTs bound to users.token_version; bumping the version
# revokes every outstanding token of that user (all devices) on the next request, and live
# streams within the revalidation window.

from pydantic import Field  # noqa: E402

from app.api.dependencies import CurrentUser, MfaPendingSession  # noqa: E402
from app.core.auth_exceptions import AuthenticationError  # noqa: E402
from app.core.security import get_password_hash, validate_password_bytes, verify_password  # noqa: E402
from app.schemas.base import SchemaBase  # noqa: E402
from app.schemas.user import Password  # noqa: E402


class MeResponse(SchemaBase):
    id: int
    email: str
    role: str
    tenant_id: int | None
    tenant_slug: str | None
    mfa_enabled: bool
    mfa_required: bool
    # True when this session may only enrol MFA (role requires it, not yet enabled).
    mfa_enrollment_required: bool
    # mfa_enabled is the authenticator app (TOTP); passkeys are counted separately.
    passkey_enabled: bool = False
    passkeys: int = 0


@router.get("/me", response_model=MeResponse, summary="The authenticated user")
def me(auth: MfaPendingSession, session: SessionDependency) -> MeResponse:
    from app.models.tenant import Tenant
    from app.services.mfa import mfa_required_for
    user, amr = auth
    tenant = session.get(Tenant, user.tenant_id) if user.tenant_id else None
    required = mfa_required_for(user)
    from sqlalchemy import func, select

    from app.models.passkey import PasskeyCredential
    passkeys = session.scalar(select(func.count()).select_from(PasskeyCredential)
                              .where(PasskeyCredential.user_id == user.id)) or 0
    return MeResponse(id=user.id, email=user.email, role=user.role.value, tenant_id=user.tenant_id,
                      tenant_slug=tenant.slug if tenant else None, mfa_enabled=user.mfa_enabled,
                      mfa_required=required, mfa_enrollment_required=required and amr != "mfa",
                      passkey_enabled=user.passkey_enabled, passkeys=passkeys)


class PasswordChangeRequest(SchemaBase):
    current_password: str = Field(max_length=200)
    # Password: rejects > 72 UTF-8 bytes (bcrypt limit) with 422 instead of failing later.
    new_password: Password = Field(min_length=12, max_length=200)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT,
             summary="Revoke all of the caller's sessions")
def logout(auth: MfaPendingSession, session: SessionDependency) -> None:
    user = auth[0]
    user.token_version = (user.token_version or 0) + 1
    get_audit_log_service(session, user).record_action(
        event_type="AUTH_LOGOUT", severity="INFO", message=f"User ID {user.id} logged out (all sessions revoked)",
        actor_source="api", actor_user_id=user.id, target_entity="user", target_id=str(user.id),
        tenant_id=user.tenant_id)
    session.commit()


class RefreshResponse(SchemaBase):
    access_token: str
    token_type: str = "bearer"
    session_expires_at: int = Field(description="Epoch seconds after which the session cannot be renewed.")


@router.post("/refresh", response_model=RefreshResponse,
             summary="Renew the current session (same sign-in, new expiry, up to SESSION_MAX_HOURS)")
def refresh(user: CurrentUser, request: Request) -> RefreshResponse:
    import time

    from app.core.security import create_access_token, decode_access_token

    raw = request.headers.get("authorization", "")[7:].strip()
    payload = decode_access_token(raw)  # already verified by CurrentUser (JWT sessions only)
    session_end = payload["auth_time"] + get_settings().session_max_hours * 3600
    if time.time() >= session_end:
        raise AuthenticationError("Session reached its maximum length; sign in again")
    token = create_access_token(subject=user.id, token_version=user.token_version, amr=payload["amr"],
                                auth_time=payload["auth_time"])
    return RefreshResponse(access_token=token, session_expires_at=session_end)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT,
             summary="Change the caller's password and revoke all sessions")
def change_password(body: PasswordChangeRequest, user: CurrentUser, session: SessionDependency,
                    request: Request) -> None:
    settings = get_settings()
    from app.core.ip_trust import extract_client_ip
    allowed, retry_after = login_limiter.check_and_increment(
        f"pwchange:{user.id}", 5, settings.login_global_attempts_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many attempts", headers={"Retry-After": str(retry_after)})
    validate_password_bytes(body.new_password)
    if not verify_password(body.current_password, user.hashed_password):
        get_audit_log_service(session, user).record_action(
            event_type="PASSWORD_CHANGE_FAILED", severity="WARNING", message=f"Wrong current password for user ID {user.id}",
            actor_source=extract_client_ip(request, settings), actor_user_id=user.id, target_entity="user",
            target_id=str(user.id), tenant_id=user.tenant_id)
        session.commit()
        raise AuthenticationError("Current password is incorrect")
    if body.new_password == body.current_password:
        from app.core.exceptions import ValidationError
        raise ValidationError("The new password must differ from the current one")
    user.hashed_password = get_password_hash(body.new_password)
    user.token_version = (user.token_version or 0) + 1
    get_audit_log_service(session, user).record_action(
        event_type="PASSWORD_CHANGE", severity="INFO", message=f"User ID {user.id} changed their password",
        actor_source="api", actor_user_id=user.id, target_entity="user", target_id=str(user.id),
        tenant_id=user.tenant_id)
    session.commit()


# ---------------------------------------------------------------------------------- operator MFA
# TOTP (RFC 6238) with derived secrets, replay protection, hashed recovery codes.

class MfaSetupRequest(SchemaBase):
    current_password: str = Field(max_length=200)


class MfaSetupResponse(SchemaBase):
    secret: str
    otpauth_uri: str
    algorithm: str
    digits: int
    period: int


class MfaCodeRequest(SchemaBase):
    code: str = Field(min_length=6, max_length=32)


class MfaEnableResponse(SchemaBase):
    access_token: str
    token_type: str = "bearer"
    recovery_codes: list[str]


class MfaDisableRequest(SchemaBase):
    current_password: str = Field(max_length=200)
    code: str = Field(min_length=6, max_length=32)


class RecoveryCodesResponse(SchemaBase):
    recovery_codes: list[str]


def _mfa_service(session: Session, user):
    from app.services.mfa import MfaService
    return MfaService(session, get_audit_log_service(session, user))


def _source(request: Request) -> str:
    from app.core.ip_trust import extract_client_ip
    return extract_client_ip(request, get_settings())


def _require_password(user, password: str, session: Session, request: Request) -> None:
    allowed, retry_after = login_limiter.check_and_increment(
        f"mfa-pw:{user.id}", 5, get_settings().login_global_attempts_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many attempts", headers={"Retry-After": str(retry_after)})
    if not verify_password(password, user.hashed_password):
        get_audit_log_service(session, user).record_action(
            event_type="MFA_PASSWORD_CHECK_FAILED", severity="WARNING",
            message=f"Wrong password during MFA change for user ID {user.id}", actor_source=_source(request),
            actor_user_id=user.id, target_entity="user", target_id=str(user.id), tenant_id=user.tenant_id)
        session.commit()
        raise AuthenticationError("Current password is incorrect")


@router.post("/mfa/setup", response_model=MfaSetupResponse,
             summary="Start MFA enrolment: returns the TOTP secret and otpauth:// URI")
def mfa_setup(body: MfaSetupRequest, auth: MfaPendingSession, session: SessionDependency,
              request: Request) -> MfaSetupResponse:
    user = auth[0]
    _require_password(user, body.current_password, session, request)
    return MfaSetupResponse(**_mfa_service(session, user).begin_setup(user, _source(request)))


@router.post("/mfa/enable", response_model=MfaEnableResponse,
             summary="Confirm enrolment with a current code; returns an MFA session and recovery codes")
def mfa_enable(body: MfaCodeRequest, auth: MfaPendingSession, session: SessionDependency,
               request: Request) -> MfaEnableResponse:
    from app.core.security import AMR_MFA, create_access_token
    user = auth[0]
    user, codes = _mfa_service(session, user).enable(user, body.code, _source(request))
    token = create_access_token(subject=user.id, token_version=user.token_version, amr=AMR_MFA)
    return MfaEnableResponse(access_token=token, recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT,
             summary="Disable MFA (not allowed for roles that require it); revokes all sessions")
def mfa_disable(body: MfaDisableRequest, user: CurrentUser, session: SessionDependency, request: Request) -> None:
    _require_password(user, body.current_password, session, request)
    _mfa_service(session, user).disable(user, body.code, _source(request))


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesResponse,
             summary="Replace all recovery codes (requires a current authenticator code)")
def mfa_recovery_codes(body: MfaCodeRequest, user: CurrentUser, session: SessionDependency,
                       request: Request) -> RecoveryCodesResponse:
    return RecoveryCodesResponse(
        recovery_codes=_mfa_service(session, user).regenerate_recovery_codes(user, body.code, _source(request)))


# ------------------------------------------------------------------------------ passkeys
# Phishing-resistant second factor (app/services/passkeys.py). Sign-in is password + passkey.

class PasskeyPasswordRequest(SchemaBase):
    current_password: str = Field(max_length=200)


class PasskeyOptionsResponse(SchemaBase):
    challenge_id: str
    options: dict


class PasskeyRegisterRequest(SchemaBase):
    challenge_id: str = Field(min_length=8, max_length=64)
    name: str = Field(min_length=1, max_length=64)
    credential: dict


class PasskeyInfo(SchemaBase):
    id: int
    name: str
    algorithm: str
    created_at: str | None = None
    last_used_at: str | None = None


class PasskeyRegisterResponse(SchemaBase):
    passkey: PasskeyInfo
    # A session that counts as MFA (the account now has a second factor).
    access_token: str
    token_type: str = "bearer"


class PasskeyLoginOptionsRequest(SchemaBase):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(max_length=200)


class PasskeyLoginRequest(SchemaBase):
    challenge_id: str = Field(min_length=8, max_length=64)
    credential: dict


def _passkeys(session: Session, user=None):
    from app.services.passkeys import PasskeyService
    return PasskeyService(session, get_audit_log_service(session, user))


def _login_throttle(request: Request) -> str:
    settings = get_settings()
    source = _source(request)
    allowed, retry_after = login_limiter.check_and_increment(
        source, settings.login_attempts_per_minute, settings.login_global_attempts_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Login rate limit exceeded", headers={"Retry-After": str(retry_after)})
    return source


@router.post("/passkeys/register/options", response_model=PasskeyOptionsResponse,
             summary="Start adding a passkey (requires the current password)")
def passkey_register_options(body: PasskeyPasswordRequest, auth: MfaPendingSession, session: SessionDependency,
                             request: Request) -> PasskeyOptionsResponse:
    user = auth[0]
    _require_password(user, body.current_password, session, request)
    return PasskeyOptionsResponse(**_passkeys(session, user).begin_registration(user))


@router.post("/passkeys/register", response_model=PasskeyRegisterResponse,
             summary="Finish adding a passkey; returns an MFA session")
def passkey_register(body: PasskeyRegisterRequest, auth: MfaPendingSession, session: SessionDependency,
                     request: Request) -> PasskeyRegisterResponse:
    from app.core.security import AMR_MFA, create_access_token, decode_access_token
    from app.services.passkeys import describe
    user = auth[0]
    row = _passkeys(session, user).finish_registration(user, body.challenge_id, body.credential, body.name,
                                                       _source(request))
    session.refresh(user)
    auth_time = None
    try:
        auth_time = decode_access_token(request.headers.get("authorization", "")[7:].strip()).get("auth_time")
    except Exception:
        auth_time = None
    token = create_access_token(subject=user.id, token_version=user.token_version, amr=AMR_MFA, auth_time=auth_time)
    return PasskeyRegisterResponse(passkey=PasskeyInfo(**describe(row)), access_token=token)


@router.get("/passkeys", response_model=list[PasskeyInfo], summary="The caller's passkeys")
def passkey_list(user: CurrentUser, session: SessionDependency) -> list[PasskeyInfo]:
    from app.services.passkeys import describe
    return [PasskeyInfo(**describe(r)) for r in _passkeys(session, user).credentials(user)]


@router.post("/passkeys/{passkey_id}/remove", status_code=status.HTTP_204_NO_CONTENT,
             summary="Remove one of the caller's passkeys (requires the current password)")
def passkey_remove(passkey_id: int, body: PasskeyPasswordRequest, user: CurrentUser, session: SessionDependency,
                   request: Request) -> None:
    _require_password(user, body.current_password, session, request)
    _passkeys(session, user).delete(user, passkey_id, _source(request))


@router.post("/passkey/login/options", response_model=PasskeyOptionsResponse,
             summary="Sign-in step 1: check the password and get a passkey challenge")
def passkey_login_options(body: PasskeyLoginOptionsRequest, auth_service: AuthServiceDependency,
                          session: SessionDependency, request: Request) -> PasskeyOptionsResponse:
    source = _login_throttle(request)
    user = auth_service.authenticate(email=body.email, password=body.password, source_ip=source,
                                     defer_second_factor=True)
    return PasskeyOptionsResponse(**_passkeys(session, user).begin_login(user))


@router.post("/passkey/login", response_model=TokenResponse,
             summary="Sign-in step 2: verify the passkey and get an MFA session")
def passkey_login(body: PasskeyLoginRequest, session: SessionDependency, request: Request) -> TokenResponse:
    from app.core.security import AMR_MFA, create_access_token
    source = _login_throttle(request)
    user = _passkeys(session).finish_login(body.challenge_id, body.credential, source)
    audit = get_audit_log_service(session, user)
    try:
        audit.record_action(event_type="AUTH_LOGIN_SUCCESS", severity="INFO",
                            message=f"User '{user.email}' logged in successfully with a passkey",
                            actor_source=source, target_entity="user", target_id=str(user.id),
                            actor_user_id=user.id, tenant_id=user.tenant_id,
                            event_metadata={"email": user.email, "ip_address": source, "method": "passkey"})
        session.commit()
    except Exception:
        session.rollback()
    return TokenResponse(access_token=create_access_token(subject=user.id, token_version=user.token_version,
                                                          amr=AMR_MFA))


# ------------------------------------------------------------------------------ password reset
# Stateless single-use links (app/services/password_reset.py). Self-service needs SMTP.

class PasswordResetRequest(SchemaBase):
    email: str = Field(min_length=3, max_length=254)


class PasswordResetConfirm(SchemaBase):
    token: str = Field(min_length=10, max_length=200)
    new_password: Password = Field(min_length=12, max_length=200)  # same policy as change-password


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED,
             summary="Email a password reset link (same response whether or not the account exists)")
def password_reset_request(body: PasswordResetRequest, session: SessionDependency, request: Request) -> dict[str, str]:
    import hashlib

    from app.core.exceptions import ServiceNotConfiguredError
    from app.repositories.user_repository import UserRepository
    from app.services import password_reset

    settings = get_settings()
    if not settings.smtp_host:
        raise ServiceNotConfiguredError("Self-service password reset is not available; ask an administrator")
    source = _source(request)
    email_key = hashlib.sha256(body.email.strip().lower().encode()).hexdigest()
    for limiter, key, limit, window in ((login_limiter, f"pwreset-ip:{source}", 5, 60),
                                        (password_reset_email_limiter, f"pwreset-email:{email_key}", 3, 900)):
        allowed, retry_after = limiter.check_and_increment(key, limit, settings.login_global_attempts_per_minute,
                                                           window_seconds=window)
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many reset requests",
                                headers={"Retry-After": str(retry_after)})
    user = UserRepository(session).get_by_email(body.email.strip().lower())
    audit = get_audit_log_service(session, None)
    if user is not None and user.is_active:
        # Queued for the worker: the API has no internet egress, and the queue stores no secret
        # (the worker builds the single-use link at send time).
        from app.services import account_mail
        account_mail.enqueue_password_reset(session, user, password_reset.console_base(str(request.base_url)))
        audit.record_action(
            event_type="PASSWORD_RESET_REQUESTED", severity="INFO",
            message=f"Password reset link queued for email to user ID {user.id}", actor_source=source,
            target_entity="user", target_id=str(user.id), tenant_id=user.tenant_id)
        session.commit()
    else:
        audit.record_action(
            event_type="PASSWORD_RESET_REQUESTED_UNKNOWN", severity="WARNING",
            message="Password reset requested for an unknown or disabled account", actor_source=source,
            event_metadata={"email_domain": body.email.rsplit("@", 1)[-1][:253].lower()})
        session.commit()
    return {"status": "If the account exists, a reset link has been emailed."}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT,
             summary="Set a new password with a reset link; revokes every session")
def password_reset_confirm(body: PasswordResetConfirm, session: SessionDependency, request: Request) -> None:
    from app.core.auth_exceptions import AuthenticationError
    from app.services import password_reset

    settings = get_settings()
    source = _source(request)
    allowed, retry_after = login_limiter.check_and_increment(
        f"pwreset-confirm:{source}", 10, settings.login_global_attempts_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many attempts", headers={"Retry-After": str(retry_after)})
    validate_password_bytes(body.new_password)
    try:
        user = password_reset.resolve(session, body.token, lock=True)
    except AuthenticationError:
        get_audit_log_service(session, None).record_action(
            event_type="PASSWORD_RESET_FAILED", severity="WARNING", message="Invalid or expired password reset link used",
            actor_source=source)
        session.commit()
        raise
    if verify_password(body.new_password, user.hashed_password):
        from app.core.exceptions import ValidationError
        raise ValidationError("The new password must differ from the current one")
    user.hashed_password = get_password_hash(body.new_password)
    user.token_version = (user.token_version or 0) + 1
    get_audit_log_service(session, user).record_action(
        event_type="PASSWORD_RESET_COMPLETED", severity="WARNING",
        message=f"Password reset completed for user ID {user.id}; all sessions revoked", actor_source=source,
        actor_user_id=user.id, target_entity="user", target_id=str(user.id), tenant_id=user.tenant_id)
    session.commit()
