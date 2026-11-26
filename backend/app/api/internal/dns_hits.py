"""DNS decoy hits delivered by the DNS listener (app/workers/dns_listener.py).

* Internal only, like /internal/v1/ingest-replay: refused on both public hosts and signed with a key
  derived from INTEGRATION_SIGNING_KEY under its own label.
* The backend decides what a hit is: the name must be inside DNS_TOKEN_ZONE and its token label must
  belong to a DNS decoy. The listener only forwards names that look like one.
* One event per listener request id (the same partial unique index as edge hits), and the same
  per-source cap as every public hit, counted in the minute the query arrived.
* An empty batch is the listener's heartbeat; the watchdog uses it to tell "no lookups" from
  "listener down".
"""
from __future__ import annotations

import hmac
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import get_detection_event_service
from app.core import metrics
from app.core.config import get_settings
from app.core.dns_tokens import token_label
from app.core.exceptions import ValidationError
from app.core.replay_signing import dns_hits_key, sign
from app.models.enums import HoneyTokenType
from app.schemas.base import SchemaBase
from app.services.detection_event import DetectionEventService, DuplicatePublicHitError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/v1", tags=["internal"], include_in_schema=False)

SIGNATURE_WINDOW_SECONDS = 300
MAX_AGE = timedelta(days=30)
MAX_FUTURE = timedelta(minutes=5)
STATUS_KEY = "dns_listener"
#: What a DNS event stores besides resolver, name and type. Never accepted from an HTTP request.
DNS_CONTEXT = frozenset({"dns-query-type", "dns-transport", "dns-client-subnet"})


class DnsHit(SchemaBase):
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    time: float = Field(gt=0, description="When the listener received the query (epoch seconds)")
    resolver: str = Field(max_length=64, description="Address the query came from")
    transport: Literal["udp", "tcp"]
    qname: str = Field(min_length=1, max_length=1100)
    qtype: str = Field(max_length=10, pattern=r"^[A-Z0-9]+$")
    ecs: str | None = Field(default=None, max_length=64, description="EDNS client subnet, if sent")


class DnsBatch(SchemaBase):
    entries: list[DnsHit] = Field(max_length=500)


class DnsResult(SchemaBase):
    recorded: int = 0
    duplicates: int = 0
    not_a_decoy: int = 0
    suppressed: int = 0
    rejected: int = 0


async def _verified_body(request: Request, timestamp: str, signature: str) -> bytes:
    settings = get_settings()
    if not settings.integration_signing_key or not settings.dns_token_zone:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "DNS decoys are not configured")
    try:
        skew = abs(time.time() - int(timestamp))
    except ValueError:
        skew = SIGNATURE_WINDOW_SECONDS + 1
    body = await request.body()
    expected = sign(dns_hits_key(settings.integration_signing_key), timestamp, body)
    if skew > SIGNATURE_WINDOW_SECONDS or not hmac.compare_digest(expected, signature or ""):
        metrics.inc("honeyshield_dns_hits_total", outcome="rejected_signature")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid signature")
    return body


@router.post("/dns-hits", response_model=DnsResult)
async def receive_dns_hits(
    request: Request,
    service: Annotated[DetectionEventService, Depends(get_detection_event_service)],
    x_hs_timestamp: Annotated[str, Header()] = "",
    x_hs_signature: Annotated[str, Header()] = "",
) -> DnsResult:
    body = await _verified_body(request, x_hs_timestamp, x_hs_signature)
    batch = DnsBatch.model_validate_json(body)
    return await run_in_threadpool(_record, service, batch)


def _record(service: DetectionEventService, batch: DnsBatch) -> DnsResult:
    from app.core.ip_trust import normalize_ip
    from app.services.system_status import put_status

    settings = get_settings()
    zone = settings.dns_token_zone
    cap = settings.ingestion_rate_limit_per_minute_token
    now = datetime.now(timezone.utc)
    result = DnsResult()
    noted_floods: set[tuple[str, int, int]] = set()

    for hit in batch.entries:
        seen_at = datetime.fromtimestamp(hit.time, tz=timezone.utc)
        if not now - MAX_AGE <= seen_at <= now + MAX_FUTURE:
            result.rejected += 1
            continue
        qname = hit.qname.lower()
        label = token_label(qname, zone)
        token = service.find_token_for_ingest(label) if label else None
        if token is None or token.token_type != HoneyTokenType.DNS:
            result.not_a_decoy += 1
            continue
        try:
            source_ip = normalize_ip(hit.resolver)
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
        context = {"dns-query-type": hit.qtype, "dns-transport": hit.transport, "dns-client-subnet": hit.ecs}
        try:
            service.record_public_hit(
                token=token, ip_address=source_ip, request_path=qname, http_method=hit.qtype,
                user_agent=None, headers=context, request_id=hit.request_id, triggered_at=seen_at,
                allowed_headers=DNS_CONTEXT)
            result.recorded += 1
        except DuplicatePublicHitError:
            result.duplicates += 1
        except ValidationError:
            result.rejected += 1

    for outcome in ("recorded", "duplicates", "not_a_decoy", "suppressed", "rejected"):
        if getattr(result, outcome):
            metrics.inc("honeyshield_dns_hits_total", float(getattr(result, outcome)), outcome=outcome)
    try:
        put_status(service.session, STATUS_KEY, {"zone": zone, "last_batch": len(batch.entries)})
    except Exception:
        logger.exception("Could not record the DNS listener heartbeat")
        service.session.rollback()
    return result
