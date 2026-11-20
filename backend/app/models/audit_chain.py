"""Tamper-evident chain over the administrative audit log."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.base import ImmutableBaseModel


class AuditChainLink(ImmutableBaseModel):
    """One append-only link per audit record, in sealing order.

    record_hash = SHA-256(prev_hash || "\\n" || canonical(audit record)). Links are written by
    the sealer (app.services.audit_chain.seal) after the audit record has committed, so request
    handling never waits on a global lock. Same immutability trigger and INSERT/SELECT-only
    grants as audit_logs.
    """

    __tablename__ = "audit_chain"

    seq: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    audit_log_id: Mapped[int] = mapped_column(Integer, ForeignKey("audit_logs.id"), nullable=False, unique=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditChainHead(Base):
    """Single row (id = 1) holding the chain head; row-locked while sealing."""

    __tablename__ = "audit_chain_head"
    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc),
        server_default=func.now(), onupdate=func.now())


class AuditChainAnchor(Base):
    """Where the audit chain starts after a retention purge (single row, id = 1)."""

    __tablename__ = "audit_chain_anchor"
    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    purged_through_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    records_purged: Mapped[int] = mapped_column(BigInteger, nullable=False)
    purged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), server_default=func.now())
