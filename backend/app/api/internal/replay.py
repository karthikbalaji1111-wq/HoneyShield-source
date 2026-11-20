"""Recovery of decoy hits the edge captured while the backend could not record them.

When the backend errors, times out or is unreachable, the edge (nginx) answers the visitor exactly as
for a normal hit and appends the request to a spool file. The replay worker
(``app.workers.ingest_replay``) sends spooled hits here once the backend is back.

* Internal only: the edge returns 404 for ``/internal/`` on both public hosts, and the host-routing
  middleware refuses it on them too. Every request must also carry a signature made with a key
  derived from ``INTEGRATION_SIGNING_KEY``, so reaching the address is not enough.
* Each hit is recorded with the time the edge saw it and the edge's request id. One public event per
  request id (database index), so a hit the backend stored just before failing is not stored twice.
* The same per-source cap as live ingestion applies, counted in the minute the edge saw the hit.
"""
from __future__ import annotations

import hmac
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import get_audit_log_service, get_detection_event_service
from app.core import decoy_paths, metrics
from app.core.config import get_settings
from app.core.exceptions import ValidationError
from app.core.replay_signing import replay_key, sign
from app.schemas.base import SchemaBase
from app.services.detection_event import DetectionEventService, DuplicatePublicHitError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/v1", tags=["internal"], include_in_schema=False)

SIGNATURE_WINDOW_SECONDS = 300
MAX_AGE = timedelta(days=30)        # older captures are refused rather than silently back-dated
MAX_FUTURE = timedelta(minutes=5)   # clock skew between edge and backend
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")


class CapturedHit(SchemaBase):
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$", description="nginx $request_id")
    time: float = Field(gt=0, description="When the edge received the request (epoch seconds)")
    remote_addr: str = Field(max_length=64)
    method: str = Field(max_length=10)
    uri: str = Field(max_length=4096, description="Normalised request path as the edge saw it")
    user_agent: str | None = Field(default=None, max_length=4096)
    referer: str | None = Field(default=None, max_length=4096)
    accept: str | None = Field(default=None, max_length=1024)
    accept_language: str | None = Field(default=None, max_length=1024)


class ReplayBatch(SchemaBase):
    entries: list[CapturedHit] = Field(max_length=500)


class ReplayResult(SchemaBase):
    recorded: int = 0
    duplicates: int = 0
    not_a_decoy: int = 0
    suppressed: int = 0
    rejected: int = 0


def _token_value(uri: str) -> str | None:
    """Token value of a captured decoy path (custom DECOY_*_PATH prefixes included)."""
    return decoy_paths.token_from_path(get_settings(), uri)


async def _verified_body(request: Request, timestamp: str, signature: str) -> bytes:
    settings = get_settings()
    if not settings.integration_signing_key:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Replay is not configured")
    try:
        skew = abs(time.time() - int(timestamp))
    except ValueError:
        skew = SIGNATURE_WINDOW_SECONDS + 1
    body = await request.body()
    expected = sign(replay_key(settings.integration_signing_key), timestamp, body)
    if skew > SIGNATURE_WINDOW_SECONDS or not hmac.compare_digest(expected, signature or ""):
        metrics.inc("honeyshield_ingest_replay_requests_total", outcome="rejected_signature")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid replay signature")
    return body


@router.post("/ingest-replay", response_model=ReplayResult)
async def replay_captured_hits(
    request: Request,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    x_hs_timestamp: Annotated[str, Header()] = "",
    x_hs_signature: Annotated[str, Header()] = "",
) -> ReplayResult:
    body = await _verified_body(request, x_hs_timestamp, x_hs_signature)
    batch = ReplayBatch.model_validate_json(body)
    # Database work is blocking: keep it off the event loop.
    return await run_in_threadpool(_replay, service, batch)


def _replay(service: DetectionEventService, batch: ReplayBatch) -> ReplayResult:
    from app.core.ip_trust import normalize_ip

    settings = get_settings()
    cap = settings.ingestion_rate_limit_per_minute_token
    now = datetime.now(timezone.utc)
    result = ReplayResult()
    noted_floods: set[tuple[str, int, int]] = set()

    for hit in batch.entries:
        seen_at = datetime.fromtimestamp(hit.time, tz=timezone.utc)
        value = _token_value(hit.uri)
        if not (now - MAX_AGE <= seen_at <= now + MAX_FUTURE) or not _REQUEST_ID.match(hit.request_id):
            result.rejected += 1
            continue
        token = service.find_token_for_ingest(value) if value else None
        if token is None:
            result.not_a_decoy += 1
            continue
        try:
            source_ip = normalize_ip(hit.remote_addr)
        except ValueError:
            result.rejected += 1
            continue
        minute = int(hit.time // 60)
        stored = service.event_repo.count_for_source_in_window(
            honey_token_id=token.id, ip_address=source_ip,
            start=datetime.fromtimestamp(minute * 60, tz=timezone.utc),
            end=datetime.fromtimestamp(minute * 60 + 60, tz=timezone.utc))
        if stored >= cap:
            result.suppressed += 1
            if (source_ip, token.id, minute) not in noted_floods:
                noted_floods.add((source_ip, token.id, minute))
                service.record_suppressed_hits(token, source_ip, cap)
            continue
        headers = {k: v for k, v in (("user-agent", hit.user_agent), ("referer", hit.referer),
                                     ("accept", hit.accept), ("accept-language", hit.accept_language)) if v}
        try:
            service.record_public_hit(
                token=token, ip_address=source_ip, request_path=hit.uri.split("?", 1)[0],
                http_method=hit.method.upper(), user_agent=hit.user_agent, headers=headers,
                request_id=hit.request_id, triggered_at=seen_at)
            result.recorded += 1
        except DuplicatePublicHitError:
            result.duplicates += 1
        except ValidationError:
            result.rejected += 1

    for outcome in ("recorded", "duplicates", "not_a_decoy", "suppressed", "rejected"):
        if getattr(result, outcome):
            metrics.inc("honeyshield_ingest_replay_hits_total", float(getattr(result, outcome)), outcome=outcome)
    if result.recorded or result.duplicates or result.suppressed:
        audit = get_audit_log_service(service.session, None)
        audit.record_action(
            event_type="DETECTION_EVENTS_RECOVERED", severity="WARNING",
            message=(f"Recovered {result.recorded} decoy hit(s) captured at the edge while the backend was "
                     f"unavailable ({result.duplicates} already stored, {result.suppressed} over the per-source cap)"),
            actor_source="edge_replay", event_metadata=result.model_dump())
        service.session.commit()
        logger.warning("Edge replay: %s", result.model_dump())
    return result
