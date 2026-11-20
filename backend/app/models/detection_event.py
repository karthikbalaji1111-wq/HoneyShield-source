from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import ImmutableBaseModel
from app.models.enums import EventSeverity, EventSource


class DetectionEvent(ImmutableBaseModel):
    __tablename__ = "detection_events"
    __table_args__ = (
        Index("ix_detection_events_honey_token_id_triggered_at", "honey_token_id", "triggered_at"),
        # Serves ORDER BY triggered_at DESC, id DESC and the (triggered_at, id) keyset cursor.
        Index("ix_detection_events_triggered_at_id", "triggered_at", "id"),
        # Tenant-scoped listing, export, statistics and analytics (migration 20261118_02).
        Index("ix_detection_events_tenant_id_triggered_at_id", "tenant_id", "triggered_at", "id"),
        # One public event per edge request id (migration 20261119_01): an edge-captured hit that is
        # replayed after an outage can never be stored twice.
        Index("uq_detection_events_public_request", "idempotency_key", unique=True,
              postgresql_where=text("source = 'PUBLIC_INGEST' AND idempotency_key IS NOT NULL"),
              sqlite_where=text("source = 'PUBLIC_INGEST' AND idempotency_key IS NOT NULL")),
        # A manually entered event must always name the user who entered it.
        CheckConstraint(
            "source <> 'MANUAL' OR created_by_user_id IS NOT NULL",
            name="manual_event_has_creator",
        ),
        # A customer-hook event must name the integration that reported it and carry its
        # idempotency key; the pair is unique so retries and replays store nothing new.
        CheckConstraint(
            "source <> 'CUSTOMER_HOOK' OR (integration_credential_id IS NOT NULL AND idempotency_key IS NOT NULL)",
            name="hook_event_has_integration",
        ),
        UniqueConstraint("integration_credential_id", "idempotency_key", name="uq_detection_events_integration_credential_id"),
    )

    # Provenance (HONEY-006). Deliberately no default: every insert path must state
    # where the evidence came from, so a forgotten label fails instead of being guessed.
    source: Mapped[EventSource] = mapped_column(
        Enum(EventSource, native_enum=False, validate_strings=True, create_constraint=True,
             name="valid_event_source", length=32),
        nullable=False,
        index=True,
    )
    # No ON DELETE action on purpose: SET NULL would be an UPDATE that the immutability
    # trigger rejects (see HONEY-010). Users are deactivated, not deleted.
    created_by_user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    integration_credential_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("integration_credentials.id"), nullable=True
    )
    idempotency_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    honey_token_id: Mapped[int] = mapped_column(Integer, ForeignKey("honey_tokens.id"), nullable=False, index=True)
    # Derived from the decoy's project by the database on insert (PostgreSQL BEFORE INSERT trigger;
    # SQLite: an equivalent trigger below). Never set by the application; not part of the evidence hash.
    tenant_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_path: Mapped[str] = mapped_column(Text, nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    headers: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity, native_enum=False, validate_strings=True, length=50),
        nullable=False,
        index=True,
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    honey_token: Mapped["HoneyToken"] = relationship(
        "HoneyToken",
        back_populates="detection_events",
    )



# SQLite (tests, development): fill tenant_id after insert, like the PostgreSQL trigger does.
from sqlalchemy import DDL, event as _sa_event  # noqa: E402

_sa_event.listen(
    DetectionEvent.__table__, "after_create",
    DDL("""
        CREATE TRIGGER IF NOT EXISTS trg_detection_events_tenant_sqlite
        AFTER INSERT ON detection_events WHEN NEW.tenant_id IS NULL
        BEGIN
            UPDATE detection_events SET tenant_id = (
                SELECT p.tenant_id FROM honey_tokens t JOIN projects p ON p.id = t.project_id
                WHERE t.id = NEW.honey_token_id)
            WHERE id = NEW.id;
        END
    """).execute_if(dialect="sqlite"),
)
