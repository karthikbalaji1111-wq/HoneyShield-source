from __future__ import annotations

import bcrypt
import jwt
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import get_settings

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed one."""
    if len(plain_password.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False


def validate_password_bytes(password: str) -> str:
    if len(password.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 UTF-8 bytes")
    return password


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    validate_password_bytes(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


AMR_PASSWORD = "pwd"
AMR_MFA = "mfa"


def create_access_token(subject: str | Any, expires_delta: timedelta | None = None, token_version: int = 0,
                        amr: str = AMR_PASSWORD, auth_time: int | None = None) -> str:
    """Create a JWT access token containing the subject identity."""
    settings = get_settings()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    
    # Version is an invalidation counter, never a role or tenant claim.
    # "amr" records how the session authenticated (password only, or password + second factor).
    if amr not in (AMR_PASSWORD, AMR_MFA):
        raise ValueError("Unsupported authentication method")
    # "auth_time": when the user actually signed in. Renewal (/auth/refresh) keeps it, so a
    # session cannot be extended beyond SESSION_MAX_HOURS by refreshing.
    if auth_time is None:
        auth_time = int(datetime.now(timezone.utc).timestamp())
    to_encode = {"exp": expire, "sub": str(subject), "ver": token_version, "amr": amr, "auth_time": int(auth_time)}
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token.
    
    Returns the decoded payload.
    Raises jwt.InvalidTokenError or jwt.ExpiredSignatureError on failure.
    """
    settings = get_settings()
    if len(token) > 4096:
        raise jwt.InvalidTokenError("Token exceeds size limit")
    header = jwt.get_unverified_header(token)
    if "crit" in header:
        raise jwt.InvalidTokenError("Unsupported critical header")
    payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm],
                         options={"require": ["sub", "exp", "ver"]})
    if not isinstance(payload["sub"], str) or not re.fullmatch(r"[1-9][0-9]*", payload["sub"]):
        raise jwt.InvalidTokenError("Invalid subject")
    if type(payload["ver"]) is not int or payload["ver"] < 0:
        raise jwt.InvalidTokenError("Invalid session version")
    payload.setdefault("amr", AMR_PASSWORD)  # tokens issued before MFA support: password only
    if "auth_time" not in payload:  # tokens issued before renewal support: assume issued at sign-in
        payload["auth_time"] = int(payload["exp"]) - settings.access_token_expire_minutes * 60
    if type(payload["auth_time"]) is not int or payload["auth_time"] > int(payload["exp"]):
        raise jwt.InvalidTokenError("Invalid authentication time")
    if payload["amr"] not in (AMR_PASSWORD, AMR_MFA):
        raise jwt.InvalidTokenError("Invalid authentication method")
    return payload


def require_active_identity(user) -> None:
    from app.core.auth_exceptions import InactiveUserError, InvalidTokenError
    from app.models.enums import Role
    if not user.is_active:
        raise InactiveUserError("Account is disabled")
    if user.role == Role.SYSTEM_ADMIN:
        if user.tenant_id is not None:
            raise InvalidTokenError("Invalid account scope")
    elif user.role in (Role.TENANT_ADMIN, Role.TENANT_USER):
        if user.tenant_id is None or user.tenant is None or not user.tenant.is_active:
            raise InactiveUserError("Tenant access is unavailable")
    else:
        raise InvalidTokenError("Invalid account role")


def resolve_access_token(token, session, allow_mfa_pending: bool = False, with_amr: bool = False):
    """Resolve a bearer token to its live user.

    MFA: a password-only session of an MFA-enabled account is refused (401; log in
    again with a code). A password-only session of a role that must use MFA but has not enrolled
    is "MFA pending": it may only reach the enrolment endpoints (``allow_mfa_pending``); anything
    else is 403.
    """
    from app.core.auth_exceptions import InvalidTokenError, MfaEnrollmentRequiredError, UserNotFoundError
    from app.repositories.user_repository import UserRepository
    try:
        payload = decode_access_token(token)
    except jwt.InvalidTokenError:
        raise InvalidTokenError("Invalid or expired authentication token") from None
    user = UserRepository(session).get_by_id(int(payload["sub"]))
    if user is None:
        raise UserNotFoundError("Authenticated user no longer exists")
    require_active_identity(user)
    if user.token_version != payload["ver"]:
        raise InvalidTokenError("Authentication session has been revoked")
    amr = payload["amr"]
    if user.has_second_factor and amr != AMR_MFA:
        raise InvalidTokenError("MFA verification required")
    if amr != AMR_MFA and not allow_mfa_pending:
        if user.role.value in get_settings().mfa_required_role_names:
            raise MfaEnrollmentRequiredError("MFA enrolment required")
    return (user, amr) if with_amr else user
