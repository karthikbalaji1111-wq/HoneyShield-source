"""Version 1 detection-event API routes."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.dependencies import CurrentUser, TenantAdminRequired, get_detection_event_service
from app.schemas.detection_event import (
    DetectionEventActivityDay,
    DetectionEventCreate,
    DetectionEventResponse,
    DetectionEventStatisticsResponse,
)
from app.core.attack import techniques_for
from app.core.redaction import redact, viewer_sees_secrets
from app.models.enums import EventSeverity
from app.schemas.error import ErrorResponse
from app.services.detection_event import DetectionEventService

router = APIRouter(prefix="/detection-events", tags=["detection-events"])


@router.post(
    "",
    response_model=DetectionEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record a detection event",
    description="Records an immutable event for a triggered honey token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "TENANT_ADMIN role or above required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def create_detection_event(
    payload: DetectionEventCreate,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    _: TenantAdminRequired,
) -> DetectionEventResponse:
    """Record and serialize a detection event. Requires TENANT_ADMIN or above."""
    return service.record_event(
        token_value=payload.token_value,
        ip_address=payload.ip_address,
        request_path=payload.request_path,
        http_method=payload.http_method,
        severity=payload.severity,
        user_agent=payload.user_agent,
        headers=payload.headers,
        reason=payload.reason,
    )


@router.get(
    "",
    response_model=list[DetectionEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List recent detection events",
    description="Lists recent events globally or for one honey token.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Supplied honey token does not exist.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Request or domain validation failed.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def list_detection_events(
    service: Annotated[
        DetectionEventService,
        Depends(get_detection_event_service),
    ],
    user: CurrentUser,
    token_value: Annotated[
        str | None,
        Query(
            max_length=512,
            description="Optional honey-token value used to scope results.",
        ),
    ] = None,
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=1000,
            description="Maximum number of recent events to return.",
        ),
    ] = 100,
    offset: Annotated[
        int,
        Query(
            ge=0,
            description="Offset for offset-based pagination.",
        ),
    ] = 0,
    cursor: Annotated[
        int | None,
        Query(
            description="Keyset cursor: return events strictly older than this event ID.",
        ),
    ] = None,
    severity: Annotated[
        list[EventSeverity] | None,
        Query(description="Only these severities (repeat the parameter for several)."),
    ] = None,
    ip_address: Annotated[
        str | None,
        Query(max_length=64, description="Only events from this source address (IPv4 or IPv6)."),
    ] = None,
    since: Annotated[datetime | None, Query(description="Only events triggered at or after this time.")] = None,
    until: Annotated[datetime | None, Query(description="Only events triggered before this time.")] = None,
    decoy_id: Annotated[str | None, Query(max_length=40, description="Only events of this decoy (its public id).")] = None,
) -> list[DetectionEventResponse]:
    """List and serialize recent detection events. TENANT_USER viewers see masked paths."""
    events = service.list_recent_events(
        token_value=token_value,
        limit=limit,
        offset=offset,
        cursor=cursor,
        severities=severity,
        ip_address=ip_address,
        since=_aware(since),
        until=_aware(until),
        decoy_id=decoy_id,
    )
    unmasked = viewer_sees_secrets(user)
    return [_event_view(event, unmasked) for event in events]


def _event_view(event, unmasked: bool) -> DetectionEventResponse:
    view = DetectionEventResponse.model_validate(event)
    token = event.honey_token
    # Decoy identity helps triage; the secret token value is never part of the response.
    view.decoy_id, view.decoy_type, view.decoy_label = token.decoy_id, token.token_type.value, token.label
    view.project_domain = token.project.domain if token.project else None
    view.attack = techniques_for(view.decoy_type)
    if not unmasked:
        secret = token.token_value
        view.request_path = redact(view.request_path, secret)
        view.headers = redact(view.headers, secret)
        view.user_agent = redact(view.user_agent, secret)
    return view


def _aware(dt: datetime | None) -> datetime | None:
    """Query datetimes without an offset are UTC."""
    from datetime import timezone as _tz
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=_tz.utc)


@router.get(
    "/statistics",
    response_model=DetectionEventStatisticsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detection-event statistics",
    description="Returns global total and current UTC-day event counts.",
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected server error.",
        },
    },
)
def get_detection_event_statistics(
    service: Annotated[
        DetectionEventService,
        Depends(get_detection_event_service),
    ],
    _: CurrentUser,
) -> DetectionEventStatisticsResponse:
    """Retrieve and serialize detection-event statistics. Requires authentication."""
    return service.get_statistics()


@router.get(
    "/activity",
    response_model=list[DetectionEventActivityDay],
    summary="Events per day and severity",
    description=("Events per UTC day over the last `days` days (today included), oldest first, empty days "
                 "included. Same tenant scope as the list endpoint. 503 if it exceeds the analytics time budget."),
)
def get_detection_event_activity(
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    _: CurrentUser,
    days: Annotated[int, Query(ge=1, le=90, description="Window in days (1-90).")] = 14,
) -> list[DetectionEventActivityDay]:
    return service.get_activity(days)


# --------------------------------------------------------------------------- CSV export
EXPORT_MAX_ROWS = 50_000
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (OWASP): attacker-controlled fields such as the
    user agent or request path must never execute when the file is opened in Excel/Sheets."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


@router.get(
    "/export",
    summary="Export detection events as CSV (newest first, at most 50,000 rows)",
    description=("Same tenant scope as the list endpoint. Token values are always replaced by {token}, "
                 "so the file can be shared. Cells that a spreadsheet would treat as formulas are prefixed "
                 "with an apostrophe."),
    response_class=Response,
)
def export_detection_events(
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    user: CurrentUser,
    since: Annotated[datetime | None, Query(description="Only events triggered at or after this time.")] = None,
    until: Annotated[datetime | None, Query(description="Only events triggered before this time.")] = None,
    severity: Annotated[EventSeverity | None, Query()] = None,
    ip_address: Annotated[str | None, Query(max_length=64, description="Only events from this source address.")] = None,
    decoy_id: Annotated[str | None, Query(max_length=40, description="Only events of this decoy (its public id).")] = None,
) -> Response:
    import csv
    import io
    from datetime import timezone as _tz

    from app.api.dependencies import get_audit_log_service

    since, until = _aware(since), _aware(until)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(["event_id", "triggered_at", "severity", "source", "token_type", "decoy_id", "decoy_label",
                     "project", "ip_address", "http_method", "request_path", "user_agent", "created_by_user_id"])
    rows, cursor, truncated = 0, None, False
    # The query applies every filter (time range, severity, address) and the keyset cursor, so each
    # page is exactly the next rows to write.
    while rows < EXPORT_MAX_ROWS:
        page = service.list_recent_events(limit=1000, cursor=cursor, since=since, until=until,
                                          severities=[severity] if severity else None, ip_address=ip_address,
                                          decoy_id=decoy_id)
        if not page:
            break
        for event in page:
            cursor = event.id
            triggered = _aware(event.triggered_at)
            token = event.honey_token
            secret = token.token_value
            writer.writerow([_csv_safe(v) for v in (
                event.id, triggered.isoformat() if triggered else "", event.severity.value, event.source.value,
                token.token_type.value, token.decoy_id, token.label, token.project.domain, event.ip_address,
                event.http_method, redact(event.request_path or "", secret, "{token}"),
                redact(event.user_agent or "", secret, "{token}"), event.created_by_user_id)])
            rows += 1
            if rows >= EXPORT_MAX_ROWS:
                truncated = True
                break
    audit = get_audit_log_service(service.session, user)
    audit.record_action(
        event_type="EVENTS_EXPORTED", severity="INFO", message=f"User ID {user.id} exported {rows} detection event(s)",
        actor_source="api", actor_user_id=user.id, tenant_id=user.tenant_id,
        event_metadata={"rows": rows, "truncated": truncated, "since": since.isoformat() if since else None,
                        "until": until.isoformat() if until else None,
                        "severity": severity.value if severity else None,
                        "ip_address": ip_address, "decoy_id": decoy_id})
    service.session.commit()
    stamp = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%SZ")
    headers = {"Content-Disposition": f'attachment; filename="honeyshield-events-{stamp}.csv"',
               "Cache-Control": "no-store", "X-Export-Rows": str(rows), "X-Export-Truncated": str(truncated).lower()}
    return Response(content=buf.getvalue().encode("utf-8-sig"), media_type="text/csv; charset=utf-8", headers=headers)


# Declared last, with an int converter, so /stats, /activity and /export are never captured.
@router.get(
    "/{event_id:int}",
    response_model=DetectionEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get one detection event",
    description=("One event in the caller's scope, e.g. the event an alert delivery reported. "
                 "Another tenant's event is reported as not found. TENANT_USER viewers see masked paths."),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse, "description": "Authentication required."},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse, "description": "No such event in your scope."},
    },
)
def get_detection_event(
    event_id: Annotated[int, Path(ge=1, le=2**63 - 1, description="Detection event id.")],
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    user: CurrentUser,
) -> DetectionEventResponse:
    return _event_view(service.get_event(event_id), viewer_sees_secrets(user))
