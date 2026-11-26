from __future__ import annotations

from enum import Enum as PyEnum


class HoneyTokenType(str, PyEnum):
    URL = "URL"
    FORM_FIELD = "FORM_FIELD"
    LINK = "LINK"
    PIXEL = "PIXEL"
    API_KEY = "API_KEY"
    DNS = "DNS"
    AWS_KEY = "AWS_KEY"
    DOCUMENT = "DOCUMENT"


class EventSeverity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSource(str, PyEnum):
    """Provenance of a detection event.

    PUBLIC_INGEST: HoneyShield itself observed the interaction on a public ingest route.
    MANUAL: an authenticated user entered the event through the API.
    CUSTOMER_HOOK: reported by an authenticated customer integration; IP, path and time are
        asserted by the customer, not observed by HoneyShield.
    CLOUD_AUDIT: read from the cloud provider's audit log (AWS CloudTrail); address, time and user
        agent are as the provider recorded them.
    LEGACY_UNVERIFIED: recorded before provenance existed; origin cannot be established.
    """

    PUBLIC_INGEST = "PUBLIC_INGEST"
    MANUAL = "MANUAL"
    CUSTOMER_HOOK = "CUSTOMER_HOOK"
    CLOUD_AUDIT = "CLOUD_AUDIT"
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"


class Role(str, PyEnum):
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    TENANT_USER = "TENANT_USER"
