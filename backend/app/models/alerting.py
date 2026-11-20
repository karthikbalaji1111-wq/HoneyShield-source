"""Durable alerting: destinations and the transactional outbox (HONEY-007)."""
from __future__ import annotations

import secrets
from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import EventSeverity


class AlertFormat(str, PyEnum):
    HONEYSHIELD = "HONEYSHIELD"  # signed JSON envelope (SIEM, SOAR, custom receivers)
    SLACK = "SLACK"              # {"text": ...}; also accepted by Teams/Mattermost incoming webhooks
    EMAIL = "EMAIL"              # mailto:a@b,c@d through the operator's SMTP relay
    SYSLOG_CEF = "SYSLOG_CEF"    # syslog+tls://siem:6514, RFC 5424/5425 with an ArcSight CEF body


class OutboxStatus(str, PyEnum):
    PENDING = "PENDING"
    IN_FLIGHT = "IN_FLIGHT"
    DELIVERED = "DELIVERED"
    DEAD = "DEAD"


def new_destination_public_id() -> str:
    return "hsd_" + secrets.token_hex(12)


class AlertDestination(BaseModel):
    """A tenant-owned alert destination (webhook, email or syslog). Its signing secret is derived, never stored."""

    __tablename__ = "alert_destinations"

    public_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, default=new_destination_public_id)
    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    # Null: every project of the tenant.
    project_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("projects.id"), nullable=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    format: Mapped[AlertFormat] = mapped_column(
        Enum(AlertFormat, native_enum=False, validate_strings=True, length=20), nullable=False,
        default=AlertFormat.HONEYSHIELD)
    min_severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity, native_enum=False, validate_strings=True, length=50), nullable=False,
        default=EventSeverity.MEDIUM)
    key_salt: Mapped[str] = mapped_column(String(64), nullable=False, default=lambda: secrets.token_hex(16))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)


class OutboxEvent(BaseModel):
    """One pending delivery of one detection event to one destination.

    Inserted in the same transaction as the detection event, so a committed event always
    has its deliveries queued and a rolled-back event never alerts.
    """

    __tablename__ = "outbox_events"
    __table_args__ = (
        UniqueConstraint("detection_event_id", "destination_id", name="uq_outbox_events_detection_event_id"),
        Index("ix_outbox_events_status_next_attempt_at", "status", "next_attempt_at"),
        CheckConstraint("is_test OR detection_event_id IS NOT NULL", name="event_or_test"),
    )

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    # Null only for a test delivery (is_test), which never creates a detection event.
    detection_event_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("detection_events.id"), nullable=True)
    is_test: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    destination_id: Mapped[int] = mapped_column(Integer, ForeignKey("alert_destinations.id"), nullable=False)
    status: Mapped[OutboxStatus] = mapped_column(
        Enum(OutboxStatus, native_enum=False, validate_strings=True, length=20), nullable=False,
        default=OutboxStatus.PENDING)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    destination: Mapped[AlertDestination] = relationship("AlertDestination")
    detection_event: Mapped[Optional["DetectionEvent"]] = relationship("DetectionEvent")
