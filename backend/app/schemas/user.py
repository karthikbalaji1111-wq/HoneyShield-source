"""User schemas (DTOs)."""
from __future__ import annotations

from datetime import datetime

from typing import Annotated
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from app.core.security import validate_password_bytes

Password = Annotated[str, AfterValidator(validate_password_bytes)]


def normalize_email(value: str | None) -> str | None:
    """HONEY-022: one identity per mailbox regardless of letter case or stray whitespace."""
    return value.strip().lower() if isinstance(value, str) else value


Email = Annotated[str, AfterValidator(normalize_email)]

from app.models.enums import Role


class UserCreate(BaseModel):
    """Payload for creating a new user."""

    email: Email = Field(..., max_length=254, pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="User's email address (stored lower-case).")
    password: Password = Field(..., min_length=12, title="Password", description="Plaintext password, 12 characters to 72 UTF-8 bytes (same policy as a self-chosen password).")
    role: Role = Field(..., title="Role", description="User's role within the system.")
    tenant_id: int | None = Field(None, title="Tenant ID", description="Tenant to bind the user to. System admins can leave this null.")


class UserUpdate(BaseModel):
    """Payload for updating an existing user.

    Fields omitted from the request body remain unchanged. Fields explicitly
    provided (including null) are validated against RBAC and tenant invariants.
    """

    email: Email | None = Field(None, max_length=254, pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="New email address (stored lower-case).")
    password: Password | None = Field(None, min_length=12, title="Password", description="New plaintext password, 12 characters to 72 UTF-8 bytes.")
    role: Role | None = Field(None, title="Role", description="New role.")
    is_active: bool | None = Field(None, title="Is Active", description="Account active status.")
    tenant_id: int | None = Field(
        default=None,
        title="Tenant ID",
        description="Target tenant ID. Omit to preserve current tenant. Explicit null unbinds tenant scope (SYSTEM_ADMIN only).",
    )


class UserResponse(BaseModel):
    """User representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., title="Id", description="User database identifier.")
    email: str = Field(..., pattern="^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", title="Email", description="User's email address.")
    role: Role = Field(..., title="Role", description="User's role.")
    is_active: bool = Field(..., title="Is Active", description="Whether the user account is active.")
    tenant_id: int | None = Field(None, title="Tenant Id", description="Identifier of the owning tenant.")
    mfa_enabled: bool = Field(False, title="MFA Enabled", description="Whether the user has enrolled TOTP MFA.")
    passkey_enabled: bool = Field(False, title="Passkey Enabled", description="Whether the user has a passkey.")
    created_at: datetime = Field(..., title="Created At", description="User creation timestamp.")
    updated_at: datetime = Field(..., title="Updated At", description="User last-update timestamp.")


class MfaResetRequest(BaseModel):
    """Administrator reset of a user's MFA (lost device). The reason is stored in the audit log."""

    reason: str = Field(..., min_length=10, max_length=1000, title="Reason")


class PasswordResetIssueRequest(BaseModel):
    """Administrator-issued password reset link. The reason is stored in the audit log."""

    reason: str = Field(..., min_length=10, max_length=1000, title="Reason")


class PasswordResetIssued(BaseModel):
    reset_url: str = Field(description="Single-use link; give it to the user out of band. Shown once.")
    expires_at: datetime
