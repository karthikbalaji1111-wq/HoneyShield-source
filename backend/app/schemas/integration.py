"""Customer-integration schemas (control plane and CUSTOMER_HOOK wire contract)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.base import SchemaBase

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_DECOY_RE = re.compile(r"^dcy_[0-9a-f]{24}$")
#: Header or field names that would carry a credential. Reports containing them are rejected
#: outright rather than filtered, so a misconfigured client is noticed instead of half-working.
CREDENTIAL_NAME_FRAGMENTS = ("authorization", "cookie", "api-key", "api_key", "apikey", "token",
                             "secret", "password", "passwd", "session", "credential", "signature")
MAX_REPORT_HEADERS = 20


class IntegrationCredentialCreate(SchemaBase):
    label: str | None = Field(default=None, max_length=255, description="Where this credential is deployed.")


class IntegrationCredentialResponse(SchemaBase):
    integration_id: str = Field(validation_alias="public_id", description="Public identifier (X-HS-Integration).")
    label: str | None
    scopes: list[str]
    is_active: bool
    created_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    @field_validator("scopes", mode="before")
    @classmethod
    def _split(cls, value):
        return [s for s in value.split(",") if s] if isinstance(value, str) else value


class IntegrationCredentialCreated(IntegrationCredentialResponse):
    secret: str = Field(description="Signing secret. Shown once; HoneyShield cannot show it again.")


class IntegrationReport(BaseModel):
    """One decoy interaction observed by customer code. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decoy_id: str = Field(description="Opaque decoy identifier from the manifest. Never the key itself.")
    idempotency_key: str = Field(description="16-64 chars [A-Za-z0-9_-]; identical keys are stored once.")
    observed_at: datetime = Field(description="When the customer saw the interaction (RFC 3339, timezone required).")
    source_ip: str = Field(max_length=45, description="Client IP as determined by the customer's trusted-proxy logic.")
    http_method: str | None = Field(default=None, max_length=10)
    request_path: str | None = Field(default=None, max_length=2048, description="Path only; any query is dropped.")
    user_agent: str | None = Field(default=None, max_length=4096)
    headers: dict[str, str] | None = Field(default=None, description="Forensic allowlist only; never credentials.")

    @field_validator("decoy_id")
    @classmethod
    def _decoy(cls, v: str) -> str:
        if not _DECOY_RE.match(v):
            raise ValueError("decoy_id has an invalid format")
        return v

    @field_validator("idempotency_key")
    @classmethod
    def _idem(cls, v: str) -> str:
        if not _IDEMPOTENCY_RE.match(v):
            raise ValueError("idempotency_key must be 16-64 characters of [A-Za-z0-9_-]")
        return v

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        now = datetime.now(timezone.utc)
        if v > now + timedelta(minutes=5) or v < now - timedelta(hours=24):
            raise ValueError("observed_at must be within the last 24 hours")
        return v.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        from app.core.ip_trust import normalize_ip

        return normalize_ip(v)

    @field_validator("http_method")
    @classmethod
    def _method(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.upper()
        if v not in ALLOWED_METHODS:
            raise ValueError("http_method is not an allowed verb")
        return v

    @field_validator("request_path")
    @classmethod
    def _path(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.split("?", 1)[0].split("#", 1)[0]
        if v and not v.startswith("/"):
            raise ValueError("request_path must be a path")
        return v

    @field_validator("user_agent")
    @classmethod
    def _ua(cls, v: str | None) -> str | None:
        return v[:1024] if v else v

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if not v:
            return None
        if len(v) > MAX_REPORT_HEADERS:
            raise ValueError("too many headers")
        for name in v:
            low = name.lower()
            if any(fragment in low for fragment in CREDENTIAL_NAME_FRAGMENTS):
                # The value is deliberately not echoed or logged.
                raise ValueError("credential-bearing headers must never be reported")
        return v


class IntegrationReportAccepted(BaseModel):
    status: str = "accepted"


#: Windows Security log events the domain-controller collector reports for an Active Directory decoy.
DIRECTORY_EVENT_IDS = frozenset({4624, 4625, 4662, 4768, 4769, 4771, 4776})
_HEX_CODE_RE = re.compile(r"^0x[0-9A-Fa-f]{1,8}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$")


def _plain(value: str | None, limit: int) -> str | None:
    """Printable text only: names from the event log, never markup or control characters."""
    if value is None:
        return None
    value = value.strip()
    if value in ("", "-"):
        return None
    if len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("value is too long or contains control characters")
    return value


class DirectoryReport(BaseModel):
    """One Windows Security event about an Active Directory decoy, read on a domain controller."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decoy_id: str
    idempotency_key: str = Field(description="16-64 chars [A-Za-z0-9_-]; the collector derives it from the "
                                             "controller and the event record id.")
    observed_at: datetime = Field(description="The event's TimeCreated (RFC 3339, timezone required).")
    windows_event_id: int = Field(description="4624, 4625, 4662, 4768, 4769, 4771 or 4776.")
    succeeded: bool = Field(description="Audit Success (true) or Audit Failure (false).")
    domain_controller: str = Field(description="The controller that logged the event.")
    target_name: str = Field(description="The account the event names, as the client presented it.")
    source_ip: str | None = Field(default=None, max_length=64, description="IpAddress; omitted when the event has none.")
    workstation: str | None = Field(default=None, max_length=255)
    actor: str | None = Field(default=None, max_length=256,
                              description="The account that asked for the ticket (4769) or read the object (4662).")
    status: str | None = Field(default=None, description="Status or SubStatus code, e.g. 0x18.")
    logon_type: int | None = Field(default=None, ge=0, le=13)
    ticket_encryption: str | None = Field(default=None, description="TicketEncryptionType, e.g. 0x17 (RC4).")
    record_id: int | None = Field(default=None, ge=0, le=2**63 - 1)

    @field_validator("decoy_id")
    @classmethod
    def _decoy(cls, v: str) -> str:
        if not _DECOY_RE.match(v):
            raise ValueError("decoy_id has an invalid format")
        return v

    @field_validator("idempotency_key")
    @classmethod
    def _idem(cls, v: str) -> str:
        if not _IDEMPOTENCY_RE.match(v):
            raise ValueError("idempotency_key must be 16-64 characters of [A-Za-z0-9_-]")
        return v

    @field_validator("observed_at")
    @classmethod
    def _observed(cls, v: datetime) -> datetime:
        return IntegrationReport._observed(v)

    @field_validator("windows_event_id")
    @classmethod
    def _event(cls, v: int) -> int:
        if v not in DIRECTORY_EVENT_IDS:
            raise ValueError("windows_event_id is not a reported event")
        return v

    @field_validator("domain_controller")
    @classmethod
    def _dc(cls, v: str) -> str:
        if not _HOST_RE.match(v):
            raise ValueError("domain_controller must be a host name")
        return v

    @field_validator("target_name")
    @classmethod
    def _target(cls, v: str) -> str:
        value = _plain(v, 256)
        if value is None:
            raise ValueError("target_name is required")
        return value

    @field_validator("workstation")
    @classmethod
    def _workstation(cls, v: str | None) -> str | None:
        return _plain(v, 255)

    @field_validator("actor")
    @classmethod
    def _actor(cls, v: str | None) -> str | None:
        return _plain(v, 256)

    @field_validator("status", "ticket_encryption")
    @classmethod
    def _hex(cls, v: str | None) -> str | None:
        if v is None or v in ("", "-"):
            return None
        if not _HEX_CODE_RE.match(v):
            raise ValueError("codes are hexadecimal, e.g. 0x18")
        return v.lower()

    @field_validator("source_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        import ipaddress

        from app.core.ip_trust import normalize_ip

        if v is None or v in ("", "-"):
            return None
        ip = ipaddress.ip_address(normalize_ip(v))
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return str(ip.ipv4_mapped)  # the event log writes ::ffff:10.0.0.5 for IPv4 clients
        return str(ip)
