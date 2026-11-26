"""Tamper-evident evidence chain."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.base import ImmutableBaseModel


class EvidenceChainLink(ImmutableBaseModel):
    """One append-only link per detection event, per tenant.

    record_hash = SHA-256(prev_hash || "\\n" || canonical(event)). Protected by the same
    immutability trigger and INSERT/SELECT-only grants as detection_events.
    """

    __tablename__ = "evidence_chain"
    __table_args__ = (UniqueConstraint("tenant_id", "seq", name="uq_evidence_chain_tenant_id"),)

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    detection_event_id: Mapped[int] = mapped_column(Integer, ForeignKey("detection_events.id"), nullable=False,
                                                    unique=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class EvidenceChainHead(Base):
    """Current head per tenant; row-locked while appending so links are strictly ordered."""

    __tablename__ = "evidence_chain_heads"

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc),
        server_default=func.now(), onupdate=func.now())


class EvidenceChainAnchor(Base):
    """Where a tenant's chain starts after a retention purge (app.services.retention).

    Verification starts from (purged_through_seq, anchor_hash) instead of the genesis hash. The
    purged links and events are in the write-once archive written before the purge.
    """

    __tablename__ = "evidence_chain_anchors"

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), primary_key=True)
    purged_through_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    events_purged: Mapped[int] = mapped_column(BigInteger, nullable=False)
    purged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), server_default=func.now())
