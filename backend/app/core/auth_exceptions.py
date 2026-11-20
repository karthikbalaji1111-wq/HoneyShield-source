"""Authentication exceptions."""
from __future__ import annotations

from app.core.exceptions import HoneyShieldException


class AuthenticationError(HoneyShieldException):
    """Raised when credentials are invalid or authentication fails."""


class InvalidTokenError(HoneyShieldException):
    """Raised when a JWT token is missing, malformed, or expired."""


class UserNotFoundError(HoneyShieldException):
    """Raised when a user identity resolved from a token does not exist."""


class InactiveUserError(HoneyShieldException):
    """Raised when an authenticated user account is disabled."""


class UnauthorizedError(HoneyShieldException):
    """Raised when a request lacks required authentication."""


class ForbiddenError(HoneyShieldException):
    """Raised when an authenticated user lacks permission for the operation."""


class MfaRequiredError(AuthenticationError):
    """Password accepted but the account requires a TOTP or recovery code (HTTP 401)."""


class MfaEnrollmentRequiredError(ForbiddenError):
    """The caller's role requires MFA and the session has not completed it (HTTP 403)."""
