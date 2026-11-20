"""CUSTOMER_HOOK endpoints served on the ingest host (signed requests only).

GET  /integrations/v1/manifest  -> decoys the customer's middleware should recognise
POST /integrations/v1/events    -> report one decoy interaction (always 202 when authenticated)

Responses for authenticated reports never reveal whether a decoy_id exists, belongs to
another project, or was a duplicate: all are 202. Authentication failures are 401 with one
generic body regardless of the reason; the reason is logged server-side only.
"""
from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.orm import Session

from app.api.dependencies import get_detection_event_service
from app.core import metrics
from app.core.config import get_settings
from app.core.exceptions import ServiceNotConfiguredError
from app.core.ip_trust import extract_client_ip
from app.core.rate_limit import (
    integration_auth_failure_limiter,
    integration_evidence_counter,
    integration_report_limiter,
)
from app.db.session import get_db
from app.schemas.integration import IntegrationReport
from app.api.dependencies import get_audit_log_service
from app.services.detection_event import DetectionEventService
from app.services.integration import IntegrationReportService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/integrations/v1", tags=["integrations"])

MAX_REPORT_BYTES = 16 * 1024
AUTH_FAILURES_PER_MINUTE_PER_IP = 30
EVIDENCE_CAP_PER_MINUTE = 60

_ACCEPTED = {"status": "accepted"}


def _json(status: int, body: dict, retry_after: int | None = None) -> JSONResponse:
    headers = {"Retry-After": str(retry_after)} if retry_after else None
    return JSONResponse(status_code=status, content=body, headers=headers)


def _unauthorized() -> JSONResponse:
    return _json(401, {"detail": "Integration authentication failed"})


async def _authenticate(request: Request, session: Session, scope: str):
    """Returns (credential, body, error_response)."""
    settings = get_settings()
    client_ip = extract_client_ip(request, settings)
    fail_key = f"intfail:{client_ip}"
    # Refuse early once an IP has produced too many failures this window.
    if settings.rate_limit_enabled and integration_auth_failure_limiter.peek(fail_key) >= AUTH_FAILURES_PER_MINUTE_PER_IP:
        return None, b"", _json(429, {"detail": "Too many failed integration requests"}, 60)

    body = await request.body()
    if len(body) > MAX_REPORT_BYTES:
        return None, b"", _json(413, {"detail": "Report too large"})
    try:
        result = IntegrationReportService(session).authenticate(
            request.headers, request.method, request.scope["path"], body, scope)
    except ServiceNotConfiguredError:
        return None, b"", _json(503, {"detail": "Customer integrations are not configured"})
    if result.credential is None:
        if settings.rate_limit_enabled:
            integration_auth_failure_limiter.increment(fail_key)
        logger.warning("Integration auth failed (%s) from %s", result.failure, client_ip)
        metrics.inc("honeyshield_integration_reports_total", outcome=f"auth_{result.failure}")
        return None, b"", _unauthorized()

    if settings.rate_limit_enabled:
        allowed, retry = integration_report_limiter.check_and_increment(
            key=f"int:{result.credential.public_id}",
            limit=settings.integration_reports_per_minute,
            global_limit=10 * settings.integration_reports_per_minute,
        )
        if not allowed:
            # Visible to the customer (their client retries with backoff); never a silent drop.
            return None, b"", _json(429, {"detail": "Integration report rate exceeded"}, retry)
    return result.credential, body, None


@router.get("/manifest", summary="Decoys for customer middleware (signed)")
async def get_manifest(request: Request, session: Annotated[Session, Depends(get_db)]):
    cred, _, error = await _authenticate(request, session, "manifest")
    if error is not None:
        return error
    return _json(200, IntegrationReportService(session).manifest(cred))


@router.post("/events", status_code=202, summary="Report a decoy interaction (signed)")
async def post_event(
    request: Request,
    session: Annotated[Session, Depends(get_db)],
    event_service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
):
    cred, body, error = await _authenticate(request, session, "report")
    if error is not None:
        return error
    try:
        report = IntegrationReport.model_validate(json.loads(body or b"null"))
    except (ValueError, PydanticValidationError):
        # Generic message: invalid values (possibly credentials sent by mistake) are never echoed.
        return _json(422, {"detail": "Report validation failed"})

    reports = IntegrationReportService(session)
    audit = get_audit_log_service(session, None)
    token = reports.resolve_decoy(cred, report.decoy_id)
    if token is None:
        logger.info("Integration %s reported an unknown decoy", cred.public_id)
        return _json(202, _ACCEPTED)

    if reports.report_leaks_secret(token, report):
        audit.record_action(
            event_type="INTEGRATION_REPORT_REJECTED_SECRET",
            severity="WARNING",
            message="Integration report contained the decoy key itself; rejected and not stored",
            actor_source="integration",
            target_entity="integration_credential",
            target_id=cred.public_id,
            tenant_id=cred.project.tenant_id,
            project_id=cred.project_id,
            event_metadata={"decoy_id": token.decoy_id},
        )
        session.commit()
        return _json(422, {"detail": "Report validation failed"})

    settings = get_settings()
    count = (integration_evidence_counter.increment(f"hook:{cred.id}:{token.id}:{report.source_ip}")
             if settings.rate_limit_enabled else None)
    if count is not None and count > EVIDENCE_CAP_PER_MINUTE:
        if count == EVIDENCE_CAP_PER_MINUTE + 1:
            audit.record_action(
                event_type="DETECTION_HITS_SUPPRESSED",
                severity="WARNING",
                message=f"More than {EVIDENCE_CAP_PER_MINUTE} integration reports per minute for one decoy "
                        "and source; further reports in this window are not stored individually",
                actor_source="integration",
                target_entity="honey_token",
                target_id=token.id,
                tenant_id=cred.project.tenant_id,
                project_id=cred.project_id,
                event_metadata={"ip_address": report.source_ip, "integration_id": cred.public_id,
                                "per_minute_cap": EVIDENCE_CAP_PER_MINUTE},
            )
            session.commit()
        return _json(202, _ACCEPTED)

    stored = reports.record(cred, token, report, event_service)
    metrics.inc("honeyshield_integration_reports_total", outcome="recorded" if stored else "duplicate")
    return _json(202, _ACCEPTED)
