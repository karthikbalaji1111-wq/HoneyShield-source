"""Outgoing account mail (password reset), sent by the worker - the API has no internet egress."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class MailOutbox(BaseModel):
    """No secret is stored: the worker builds the single-use link from the user's current state at
    send time. ``console_base`` is the public console origin the link points to."""

    __tablename__ = "mail_outbox"
    __table_args__ = (
        CheckConstraint("kind IN ('password_reset')", name="kind_valid"),
        CheckConstraint("status IN ('PENDING', 'SENT', 'FAILED', 'EXPIRED')", name="status_valid"),
        Index("ix_mail_outbox_status_next_attempt_at", "status", "next_attempt_at"),
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    console_base: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
