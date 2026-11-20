"""Project request and response schemas."""
from __future__ import annotations

import re

from datetime import datetime

from pydantic import Field, field_validator

from app.schemas.base import SchemaBase


class ProjectCreate(SchemaBase):
    """Request payload used to create a project."""

    tenant_slug: str = Field(
        min_length=1,
        max_length=100,
        description="Slug of the tenant that owns the project.",
    )
    name: str = Field(
        min_length=1,
        max_length=255,
        description="Human-readable project name.",
    )
    domain: str = Field(
        min_length=1,
        max_length=253,
        description="Customer hostname this project protects (e.g. app.example.com). Stored lower-case.",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        """HONEY-024: a hostname, not a URL, path or free text."""
        host = value.strip().lower().rstrip(".")
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or not all(
                re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ValueError("domain must be a hostname such as app.example.com")
        return host


class ProjectResponse(SchemaBase):
    """Project representation returned by the API."""

    id: int = Field(description="Project database identifier.")
    tenant_id: int = Field(description="Identifier of the owning tenant.")
    name: str = Field(description="Human-readable project name.")
    domain: str = Field(description="Domain associated with the project.")
    is_active: bool = Field(description="Whether the project is active.")
    created_at: datetime = Field(description="Project creation timestamp.")
    updated_at: datetime = Field(description="Project last-update timestamp.")
