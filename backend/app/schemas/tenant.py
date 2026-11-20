"""Tenant request and response schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.base import SchemaBase


class TenantCreate(SchemaBase):
    """Request payload used to create a tenant."""

    name: str = Field(
        min_length=1,
        max_length=255,
        description="Human-readable tenant name.",
    )
    slug: str = Field(
        min_length=2,
        max_length=63,
        # Slugs travel in URLs, query strings, file names and log lines: lower-case letters, digits
        # and inner hyphens only (a DNS label). Applies to new tenants; existing slugs keep working.
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
        description="Unique tenant identifier: lower-case letters, digits and hyphens, 2-63 characters.",
    )


class TenantResponse(SchemaBase):
    """Tenant representation returned by the API."""

    id: int = Field(description="Tenant database identifier.")
    name: str = Field(description="Human-readable tenant name.")
    slug: str = Field(description="Unique tenant identifier.")
    is_active: bool = Field(description="Whether the tenant is active.")
    created_at: datetime = Field(description="Tenant creation timestamp.")
    updated_at: datetime = Field(description="Tenant last-update timestamp.")
