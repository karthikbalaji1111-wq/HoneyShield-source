"""Detection-event request and response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.models.enums import EventSeverity, EventSource
from app.schemas.base import SchemaBase


class DetectionEventCreate(SchemaBase):
    """Request payload used to record a detection event."""

    token_value: str = Field(
        min_length=1,
        max_length=512,
        description="Globally unique honey-token value that was triggered.",
    )
    ip_address: str = Field(
        min_length=1,
        max_length=45,
        description="Source IP address observed for the event.",
    )
    request_path: str = Field(
        min_length=1,
        max_length=2048,
        description="Request path observed during the event.",
    )
    http_method: str = Field(
        min_length=1,
        max_length=10,
        description="HTTP method observed during the event.",
    )
    severity: EventSeverity = Field(description="Classified event severity.")
    reason: str = Field(
        min_length=10,
        max_length=1000,
        description="Why this event is being entered by hand (e.g. the incident or report it reproduces). "
        "Stored in the immutable audit record; manual events are labelled MANUAL and never PUBLIC_INGEST.",
    )
    user_agent: str | None = Field(
        default=None,
        max_length=1024,
        description="Optional request user-agent value.",
    )
    headers: dict[str, Any] | None = Field(
        default=None,
        description="Optional captured request headers.",
    )

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 10:
            raise ValueError("reason must describe why the event is entered manually (at least 10 characters)")
        return value

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        """Validate that ip_address is a valid IPv4 or IPv6 format (F-028)."""
        from app.core.ip_trust import normalize_ip
        try:
            return normalize_ip(value)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: '{value}'") from exc

    @field_validator("headers")
    @classmethod
    def validate_and_sanitize_headers(cls, value: dict[str, Any] | None) -> dict[str, str] | None:
        """Sanitize, filter, and bound request headers before persistence (F-013)."""
        from app.core.header_security import sanitize_forensic_headers
        return sanitize_forensic_headers(value)


class DetectionEventResponse(SchemaBase):
    """Detection-event representation returned by the API."""

    id: int = Field(description="Detection-event database identifier.")
    honey_token_id: int = Field(description="Identifier of the triggered honey token.")
    ip_address: str = Field(description="Source IP address observed for the event.")
    user_agent: str | None = Field(description="Optional request user-agent value.")
    request_path: str = Field(description="Request path observed during the event.")
    http_method: str = Field(description="HTTP method observed during the event.")
    headers: dict[str, Any] | None = Field(description="Captured request headers.")
    severity: EventSeverity = Field(description="Classified event severity.")
    source: EventSource = Field(
        description="Provenance: PUBLIC_INGEST (observed by HoneyShield), MANUAL (entered by a user), "
        "CUSTOMER_HOOK (reported by a customer integration), LEGACY_UNVERIFIED (pre-provenance record)."
    )
    created_by_user_id: int | None = Field(
        default=None, description="User who entered a MANUAL event; null for observed events."
    )
    triggered_at: datetime = Field(description="Time at which the event was triggered.")
    created_at: datetime = Field(description="Event persistence timestamp.")
    decoy_id: str | None = Field(default=None, description="Public identifier of the triggered decoy (never its secret value).")
    decoy_type: str | None = Field(default=None, description="Decoy type: URL, LINK, PIXEL, FORM_FIELD or API_KEY.")
    decoy_label: str | None = Field(default=None, description="Operator-given label of the decoy.")
    project_domain: str | None = Field(default=None, description="Domain of the project the decoy belongs to.")


class DetectionEventStatisticsResponse(SchemaBase):
    """Aggregated detection-event counts."""

    total_events: int = Field(description="Total number of recorded events.")
    today_events: int = Field(description="Number of events recorded today in UTC.")


class DetectionEventActivityDay(SchemaBase):
    """Events recorded on one UTC day."""

    date: str = Field(description="UTC day, YYYY-MM-DD.")
    total: int = Field(description="Events on that day.")
    by_severity: dict[str, int] = Field(description="Events per severity (LOW, MEDIUM, HIGH, CRITICAL).")
