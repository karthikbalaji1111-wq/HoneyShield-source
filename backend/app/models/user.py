from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, BigInteger, Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import Role


class User(BaseModel):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("(role = 'SYSTEM_ADMIN' AND tenant_id IS NULL) OR "
                        "(role IN ('TENANT_ADMIN', 'TENANT_USER') AND tenant_id IS NOT NULL)",
                        name="role_tenant_scope"),
        CheckConstraint("token_version >= 0", name="token_version_nonnegative"),
        CheckConstraint("(NOT mfa_enabled) OR mfa_nonce IS NOT NULL", name="mfa_enabled_has_nonce"),
        Index("ix_users_tenant_created_at_id", "tenant_id", text("created_at DESC"), text("id DESC")),
        # Case-insensitive identity; created by migration 20261113_05.
        Index("uq_users_email_lower", func.lower(text("email")), unique=True),
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, validate_strings=True,
                                          create_constraint=True, name="valid_user_role", length=50), nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    tenant_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)

    # Operator MFA. The TOTP secret is derived from MFA_SECRET_KEY + id + nonce and is
    # never stored; recovery codes are stored only as keyed hashes.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    mfa_nonce: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_last_step: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    mfa_recovery_hashes: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    mfa_enabled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # True while the user has at least one passkey (app/services/passkeys.py); kept in step with
    # passkey_credentials so every token check can see it without another query.
    passkey_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False,
                                                  server_default=text("false"))

    @property
    def has_second_factor(self) -> bool:
        """An authenticator app (TOTP) or at least one passkey."""
        return bool(self.mfa_enabled or self.passkey_enabled)

    tenant: Mapped["Tenant"] = relationship("Tenant")
