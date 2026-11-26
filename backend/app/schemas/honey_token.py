"""Honey-token request and response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

import json

from pydantic import Field, field_validator

from app.models.enums import HoneyTokenType
from app.schemas.base import SchemaBase


class HoneyTokenCreate(SchemaBase):
    """Request payload used to create a honey token."""

    project_domain: str = Field(
        min_length=1,
        max_length=253,
        description="Domain of the project that owns the token.",
    )
    token_type: HoneyTokenType = Field(description="Honey-token category.")
    token_value: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="SYSTEM_ADMIN only. Omit to have HoneyShield generate the value and artifact.",
    )
    label: str | None = Field(
        default=None,
        max_length=255,
        description="Optional human-readable token label.",
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured token metadata (only with an explicit token_value).",
    )

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        """Arbitrary metadata cannot consume unbounded storage."""
        if value is not None and len(json.dumps(value, default=str)) > 8192:
            raise ValueError("metadata must serialise to at most 8 KiB")
        return value


class HoneyTokenGenerate(SchemaBase):
    """Request payload used to dynamically generate a honey token."""

    token_type: HoneyTokenType = Field(description="Honey-token category to generate.")
    generator_params: dict[str, Any] | None = Field(
        default=None,
        description="Optional generation-specific parameters (e.g., provider_style).",
    )

    @field_validator("generator_params")
    @classmethod
    def bound_params(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(json.dumps(value, default=str)) > 2048:
            raise ValueError("generator_params must serialise to at most 2 KiB")
        return value


class HoneyTokenRevoke(SchemaBase):
    """Request payload used to revoke a honey token."""

    token_value: str = Field(
        min_length=1,
        max_length=512,
        description="Globally unique honey-token value to revoke.",
    )


class HoneyTokenRotate(SchemaBase):
    """Request payload used to rotate a honey token."""

    old_token_value: str = Field(
        min_length=1,
        max_length=512,
        description="Existing honey-token value to replace.",
    )
    new_token_value: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description="SYSTEM_ADMIN only. Omit to generate a new value and a matching artifact.",
    )


class HoneyTokenResponse(SchemaBase):
    """Honey-token representation returned by the API."""

    id: int = Field(description="Honey-token database identifier.")
    project_id: int = Field(description="Identifier of the owning project.")
    token_type: HoneyTokenType = Field(description="Honey-token category.")
    token_value: str = Field(description="Globally unique honey-token value.")
    decoy_id: str = Field(description="Opaque public identifier used by customer integrations. Not secret.")
    label: str | None = Field(description="Optional human-readable token label.")
    metadata: dict[str, Any] | None = Field(
        validation_alias="token_metadata",
        description="Optional structured token metadata.",
    )
    is_active: bool = Field(description="Whether the token is active.")
    created_at: datetime = Field(description="Token creation timestamp.")
    updated_at: datetime = Field(description="Token last-update timestamp.")
    last_triggered_at: datetime | None = Field(
        default=None, description="When the decoy last fired (list endpoint); null if it never has.")
    files: list[str] = Field(
        default_factory=list, description=(
            "Bait files this decoy can be downloaded as (GET /api/v1/honey-tokens/{decoy_id}/files/{kind}); "
            "listed for administrators only."))
