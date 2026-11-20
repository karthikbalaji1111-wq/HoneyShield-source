from __future__ import annotations

from enum import Enum as PyEnum


class HoneyTokenType(str, PyEnum):
    URL = "URL"
    FORM_FIELD = "FORM_FIELD"
    LINK = "LINK"
    PIXEL = "PIXEL"
    API_KEY = "API_KEY"


class EventSeverity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSource(str, PyEnum):
    """Provenance of a detection event (HONEY-006).

    PUBLIC_INGEST: HoneyShield itself observed the interaction on a public ingest route.
    MANUAL: an authenticated user entered the event through the API.
    CUSTOMER_HOOK: reported by an authenticated customer integration; IP, path and time are
        asserted by the customer, not observed by HoneyShield.
    LEGACY_UNVERIFIED: recorded before provenance existed; origin cannot be established.
    """

    PUBLIC_INGEST = "PUBLIC_INGEST"
    MANUAL = "MANUAL"
    CUSTOMER_HOOK = "CUSTOMER_HOOK"
    LEGACY_UNVERIFIED = "LEGACY_UNVERIFIED"


class Role(str, PyEnum):
    SYSTEM_ADMIN = "SYSTEM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    TENANT_USER = "TENANT_USER"
