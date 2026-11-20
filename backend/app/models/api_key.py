"""Personal API keys for automation (CI pipelines, SIEM pull, scripts)."""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

KEY_PREFIX = "hsk_"


def new_public_id() -> str:
    return KEY_PREFIX + secrets.token_hex(8)


class ApiKey(BaseModel):
    """A key acts as its owner (role and tenant are read live from the user on every request).

    Only an HMAC of the secret is stored. ``scope`` 'read' allows GET/HEAD only.
    """

    __tablename__ = "api_keys"
    __table_args__ = (CheckConstraint("scope IN ('read', 'write')", name="scope_valid"),)

    public_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, default=new_public_id)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tenant_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    scope: Mapped[str] = mapped_column(String(10), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
