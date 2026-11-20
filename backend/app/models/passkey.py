"""Passkeys (WebAuthn credentials) and their single-use challenges (app/services/passkeys.py)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class PasskeyCredential(BaseModel):
    """A registered passkey. Only the public key is stored; the private key never leaves the device."""

    __tablename__ = "passkey_credentials"

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False,
                                         index=True)
    credential_id: Mapped[str] = mapped_column(String(1400), nullable=False, unique=True)  # base64url
    public_key: Mapped[str] = mapped_column(Text, nullable=False)  # base64url COSE_Key
    alg: Mapped[int] = mapped_column(Integer, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    transports: Mapped[Optional[list[Any]]] = mapped_column(JSON, nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class PasskeyChallenge(BaseModel):
    """A challenge issued for one registration or sign-in; usable once, for a few minutes."""

    __tablename__ = "passkey_challenges"
    __table_args__ = (
        CheckConstraint("purpose IN ('register', 'login')", name="purpose_valid"),
        Index("ix_passkey_challenges_expires_at", "expires_at"),
    )

    public_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)
    challenge: Mapped[str] = mapped_column(String(128), nullable=False)  # base64url
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
