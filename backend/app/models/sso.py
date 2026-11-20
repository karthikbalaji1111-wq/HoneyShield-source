"""One-time codes that hand an SSO sign-in from the callback to the console."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class SsoLoginCode(BaseModel):
    """Single use, 60 seconds. Only the SHA-256 of the code is stored."""

    __tablename__ = "sso_login_codes"

    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    amr: Mapped[str] = mapped_column(String(10), nullable=False)
    auth_time: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
