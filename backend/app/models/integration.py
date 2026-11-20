"""Customer integration credentials (CUSTOMER_HOOK reporting)."""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

INTEGRATION_SCOPES = ("report", "manifest")


def new_integration_public_id() -> str:
    return "hsi_" + secrets.token_hex(12)


def new_key_salt() -> str:
    return secrets.token_hex(16)


class IntegrationCredential(BaseModel):
    """A per-project, report-only credential for a customer's detection middleware.

    The signing secret is never stored. It is derived on demand as
    HMAC-SHA256(INTEGRATION_SIGNING_KEY, public_id | key_salt) and shown to the creator
    once. ``key_salt`` alone is useless without the server master key.
    """

    __tablename__ = "integration_credentials"

    public_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, default=new_integration_public_id)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    key_salt: Mapped[str] = mapped_column(String(64), nullable=False, default=new_key_salt)
    scopes: Mapped[str] = mapped_column(String(100), nullable=False, default="report,manifest")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped["Project"] = relationship("Project")

    def has_scope(self, scope: str) -> bool:
        return scope in {s.strip() for s in self.scopes.split(",")}
