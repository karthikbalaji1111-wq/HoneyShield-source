"""Alert destinations (webhook, Slack/Teams, email, syslog/CEF, PagerDuty) and delivery status.

TENANT_ADMIN or above, tenant-scoped."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field
from sqlalchemy import select

from app.api.dependencies import SessionDependency, TenantAdminRequired, get_audit_log_service
from app.core.auth_exceptions import ForbiddenError
from app.core.config import get_settings
from app.core.exceptions import (
    IntegrationNotFoundError,
    ProjectNotFoundError,
    ServiceNotConfiguredError,
    TenantNotFoundError,
    ValidationError,
)
from app.models.alerting import AlertDestination, AlertFormat, OutboxEvent, OutboxStatus
from app.models.enums import EventSeverity, Role
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.base import SchemaBase
from app.services import alerting
from app.services.alerting import webhook

router = APIRouter(prefix="/alert-destinations", tags=["alerting"])


class AlertDestinationCreate(SchemaBase):
    url: str = Field(max_length=2048, description=(
        "HONEYSHIELD/SLACK: https URL on a public host. EMAIL: mailto:a@example.com[,b@example.com]. "
        "SYSLOG_CEF: syslog+tls://siem.example.com:6514. PAGERDUTY: pagerduty://<integration key> "
        "(pagerduty+eu:// for the EU region)."))
    label: str | None = Field(default=None, max_length=255)
    format: AlertFormat = AlertFormat.HONEYSHIELD
    min_severity: EventSeverity = EventSeverity.MEDIUM
    project_domain: str | None = Field(default=None, max_length=253, description="Limit to one project.")
    tenant_slug: str | None = Field(default=None, max_length=100, description="SYSTEM_ADMIN only.")


class AlertDestinationResponse(SchemaBase):
    destination_id: str
    label: str | None
    url: str
    format: AlertFormat
    min_severity: EventSeverity
    project_id: int | None
    is_active: bool
    created_at: datetime


class AlertDestinationCreated(AlertDestinationResponse):
    signing_secret: str | None = Field(description=(
        "Verify X-HS-Signature (webhook and email headers) with this. Shown once. None for SYSLOG_CEF, "
        "which relies on TLS server authentication instead, and for PAGERDUTY, which authenticates "
        "HoneyShield by the integration key."))


class DeliveryResponse(SchemaBase):
    id: int
    detection_event_id: int | None
    is_test: bool = False
    destination_id: str
    status: OutboxStatus
    attempts: int
    last_status_code: int | None
    last_error: str | None
    next_attempt_at: datetime
    delivered_at: datetime | None
    created_at: datetime | None = None


def _out(dest: AlertDestination, model=AlertDestinationResponse, **extra):
    return model(destination_id=dest.public_id, label=dest.label, url=dest.url, format=dest.format,
                 min_severity=dest.min_severity, project_id=dest.project_id, is_active=dest.is_active,
                 created_at=dest.created_at, **extra)


def _tenant_scope(user: User) -> int | None:
    return None if user.role == Role.SYSTEM_ADMIN else user.tenant_id


@router.post("", response_model=AlertDestinationCreated, status_code=status.HTTP_201_CREATED,
             summary="Create an alert destination")
def create_destination(payload: AlertDestinationCreate, session: SessionDependency, user: TenantAdminRequired):
    settings = get_settings()
    if not settings.integration_signing_key:
        raise ServiceNotConfiguredError("Alert delivery is not configured on this deployment")
    if payload.format == AlertFormat.EMAIL and not settings.smtp_host:
        raise ServiceNotConfiguredError("Email alerts are not configured on this deployment (SMTP_HOST)")
    try:
        # Syntax, scheme, port, credentials and literal-IP checks always apply here. DNS is only
        # advisory at creation: the API runs on an internal network that may not resolve public
        # names. The authoritative resolve-and-pin check runs in the worker at every delivery.
        alerting.check_destination(payload.url, payload.format, settings, resolve=False)
        if payload.format != AlertFormat.EMAIL:
            # (destination_host, not the URL's host: a PagerDuty URL's "host" is its integration key,
            # which must never be sent to a DNS resolver)
            host = alerting.destination_host(payload.url, payload.format)
            try:
                resolved = webhook.default_resolver(host, 443)
            except OSError:
                resolved = []
            allowed = settings.alert_private_networks
            if resolved and not all(webhook.is_public_address(a, allowed) for a in resolved):
                raise webhook.UnsafeWebhookURL("Destination host resolves to a non-public address")
    except webhook.UnsafeWebhookURL as exc:
        raise ValidationError(str(exc)) from exc

    tenant_id = _tenant_scope(user)
    if tenant_id is None:
        if not payload.tenant_slug:
            raise ValidationError("tenant_slug is required for SYSTEM_ADMIN")
        tenant = session.scalar(select(Tenant).where(Tenant.slug == payload.tenant_slug))
        if tenant is None:
            raise TenantNotFoundError("Tenant not found")
        tenant_id = tenant.id
    elif payload.tenant_slug:
        raise ForbiddenError("tenant_slug may only be set by SYSTEM_ADMIN")
    project_id = None
    if payload.project_domain:
        project = session.scalar(select(Project).where(Project.domain == payload.project_domain,
                                                       Project.tenant_id == tenant_id))
        if project is None:
            raise ProjectNotFoundError(f"Project '{payload.project_domain}' not found")
        project_id = project.id

    dest = AlertDestination(tenant_id=tenant_id, project_id=project_id, label=payload.label, url=payload.url,
                            format=payload.format, min_severity=payload.min_severity, created_by_user_id=user.id)
    session.add(dest)
    session.flush()
    get_audit_log_service(session, user).record_action(
        event_type="ALERT_DESTINATION_CREATED", severity="INFO",
        message=f"Alert destination {dest.public_id} created", actor_source="api", actor_user_id=user.id,
        target_entity="alert_destination", target_id=dest.public_id, tenant_id=tenant_id, project_id=project_id,
        event_metadata={"format": dest.format.value, "min_severity": dest.min_severity.value,
                        "host": alerting.destination_host(dest.url, dest.format)},
    )
    session.commit()
    secret = None
    if dest.format not in (AlertFormat.SYSLOG_CEF, AlertFormat.PAGERDUTY):
        secret = webhook.signing_secret(settings.integration_signing_key, dest.public_id, dest.key_salt)
    return _out(dest, AlertDestinationCreated, signing_secret=secret)


def _scoped(session, user: User):
    stmt = select(AlertDestination).order_by(AlertDestination.id.desc())
    tenant_id = _tenant_scope(user)
    if tenant_id is not None:
        stmt = stmt.where(AlertDestination.tenant_id == tenant_id)
    return stmt


@router.get("", response_model=list[AlertDestinationResponse], summary="List alert destinations")
def list_destinations(session: SessionDependency, user: TenantAdminRequired):
    return [_out(d) for d in session.scalars(_scoped(session, user))]


@router.delete("/{destination_id}", response_model=AlertDestinationResponse, summary="Disable a destination")
def disable_destination(destination_id: str, session: SessionDependency, user: TenantAdminRequired):
    dest = session.scalar(_scoped(session, user).where(AlertDestination.public_id == destination_id))
    if dest is None:
        raise IntegrationNotFoundError("Alert destination not found")
    if dest.is_active:
        dest.is_active = False
        get_audit_log_service(session, user).record_action(
            event_type="ALERT_DESTINATION_DISABLED", severity="WARNING",
            message=f"Alert destination {dest.public_id} disabled", actor_source="api", actor_user_id=user.id,
            target_entity="alert_destination", target_id=dest.public_id, tenant_id=dest.tenant_id)
        session.commit()
    return _out(dest)


@router.get("/deliveries", response_model=list[DeliveryResponse], summary="Recent alert deliveries")
def list_deliveries(session: SessionDependency, user: TenantAdminRequired,
                    status_filter: Annotated[OutboxStatus | None, Query(alias="status")] = None,
                    limit: Annotated[int, Query(ge=1, le=500)] = 100):
    stmt = select(OutboxEvent).order_by(OutboxEvent.id.desc()).limit(limit)
    tenant_id = _tenant_scope(user)
    if tenant_id is not None:
        stmt = stmt.where(OutboxEvent.tenant_id == tenant_id)
    if status_filter is not None:
        stmt = stmt.where(OutboxEvent.status == status_filter)
    return [DeliveryResponse(id=r.id, detection_event_id=r.detection_event_id, is_test=r.is_test,
                             destination_id=r.destination.public_id,
                             status=r.status, attempts=r.attempts, last_status_code=r.last_status_code,
                             last_error=r.last_error, next_attempt_at=r.next_attempt_at, delivered_at=r.delivered_at,
                             created_at=r.created_at)
            for r in session.scalars(stmt)]


class TestAlertQueued(SchemaBase):
    delivery_id: int
    status: OutboxStatus


@router.post("/{destination_id}/test", response_model=TestAlertQueued, status_code=status.HTTP_202_ACCEPTED,
             summary="Queue a clearly labelled test alert to this destination")
def send_test_alert(destination_id: str, session: SessionDependency, user: TenantAdminRequired):
    """Goes through the worker like a real alert (same SSRF checks, retries and signing), but no
    detection event exists for it. Watch the result under /deliveries (is_test = true)."""
    from datetime import timezone as _tz

    from fastapi import HTTPException

    from app.core.rate_limit import api_limiter

    dest = session.scalar(_scoped(session, user).where(AlertDestination.public_id == destination_id))
    if dest is None:
        raise IntegrationNotFoundError("Alert destination not found")
    if not dest.is_active:
        raise ValidationError("Destination is disabled")
    allowed, retry = api_limiter.check_and_increment(f"alert-test:{dest.public_id}", 5, 10_000, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many test alerts for this destination",
                            headers={"Retry-After": str(retry)})
    row = OutboxEvent(tenant_id=dest.tenant_id, detection_event_id=None, is_test=True, destination_id=dest.id,
                      status=OutboxStatus.PENDING, next_attempt_at=datetime.now(_tz.utc))
    session.add(row)
    session.flush()
    get_audit_log_service(session, user).record_action(
        event_type="ALERT_TEST_REQUESTED", severity="INFO", message=f"Test alert queued for {dest.public_id}",
        actor_source="api", actor_user_id=user.id, target_entity="alert_destination", target_id=dest.public_id,
        tenant_id=dest.tenant_id, event_metadata={"outbox_id": row.id})
    session.commit()
    return TestAlertQueued(delivery_id=row.id, status=row.status)
