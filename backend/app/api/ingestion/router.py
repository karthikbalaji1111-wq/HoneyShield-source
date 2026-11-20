"""Public ingestion API routes with forensic abuse control and trusted IP extraction.

Evidence guarantee (HONEY-001)
------------------------------
A hit on a *valid* token is persisted regardless of how saturated the shared
admission limiter is. Noise from invalid tokens, other IPs, or a full key table
can therefore never blind detection. Repeats from the same (IP, token) beyond a
per-minute cap are not stored individually; the first suppressed hit in each
window writes one DETECTION_HITS_SUPPRESSED audit record instead.

No validity oracle
------------------
The HTTP response (204 / GIF / 429) depends only on the caller's request rate,
never on whether the token exists, so the endpoints cannot be used to test
whether a value is a honey token.

The token is resolved before any limiter decision. That costs one indexed lookup
per request, which must be bounded at the edge (Nginx ``limit_req``).
"""
from __future__ import annotations

import logging
import re
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, Response, status

from app.api.dependencies import get_detection_event_service
from app.core import metrics, selftest
from app.core.config import get_settings
from app.core.exceptions import ValidationError
from app.core.ip_trust import extract_client_ip, is_ip_in_trusted_proxies
from app.core.rate_limit import ingestion_limiter, ingestion_valid_hit_counter
from app.services.detection_event import DetectionEventService, DuplicatePublicHitError

_EDGE_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ingestion"])

# 1x1 transparent GIF, byte-for-byte the image nginx's empty_gif serves: when the backend is down the
# edge answers pixel hits itself (see proxy/templates), and the two responses must be indistinguishable.
_TRANSPARENT_GIF = bytes.fromhex(
    "47494638396101000100800100000000ffffff21f9040100000100"
    "2c00000000010001000002024c01003b"
)

ServiceDependency = Annotated[DetectionEventService, Depends(get_detection_event_service)]


def edge_request_id(request: Request, settings) -> str | None:
    """The edge's id for this request, if it came through the trusted edge.

    nginx sets X-Request-ID to its own 32-hex $request_id (overwriting anything the client sent).
    It is stored with the event so a hit the edge captured during an outage, and replays later,
    is never stored twice. A request that did not come from a trusted proxy cannot supply one.
    """
    peer = request.client.host if request.client else ""
    if not is_ip_in_trusted_proxies(peer, settings.trusted_proxies):
        return None
    value = request.headers.get("x-request-id", "")
    return value if _EDGE_REQUEST_ID.match(value) else None


def _record_probe(request: Request, service: DetectionEventService, settings) -> None:
    """The watchdog's self-test request: note its nonce (app/core/selftest.py). Never an event."""
    nonce = request.query_params.get("n")
    if not selftest.valid_nonce(nonce):
        return
    from datetime import datetime, timezone

    from app.services.system_status import put_status
    try:
        put_status(service.session, selftest.PROBE_KEY, {
            "nonce": nonce,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "via_edge": edge_request_id(request, settings) is not None,
        })
        metrics.inc("honeyshield_ingest_requests_total", outcome="selftest")
    except Exception:
        logger.exception("Could not record the watchdog self-test hit")
        try:
            service.session.rollback()
        except Exception:
            pass


def _response_allowed(client_ip: str) -> tuple[bool, int]:
    """Response-rate decision for one caller. Counts every request, valid or not."""
    settings = get_settings()
    return ingestion_limiter.check_and_increment(
        key=f"ingest_ip:{client_ip}",
        limit=settings.ingestion_rate_limit_per_minute_ip,
        global_limit=settings.rate_limit_global_per_minute,
        window_seconds=60,
    )


def _ingest(request: Request, service: DetectionEventService, token_value: str) -> tuple[bool, int]:
    """Record a valid hit (subject only to the per-source cap) and decide the response.

    Returns ``(allowed, retry_after)`` for the HTTP response only.
    """
    settings = get_settings()
    client_ip = extract_client_ip(request, settings)

    probe = selftest.is_probe(token_value, settings)
    if probe:
        _record_probe(request, service, settings)

    token = None if probe else service.find_token_for_ingest(token_value)
    if token is not None:
        cap = settings.ingestion_rate_limit_per_minute_token
        count = (
            ingestion_valid_hit_counter.increment(f"valid:{client_ip}:{token.id}")
            if settings.rate_limit_enabled
            else None
        )
        try:
            # None means rate limiting is off or the counter table is full: fail open, record.
            if count is None or count <= cap:
                metrics.inc("honeyshield_ingest_requests_total", outcome="valid_recorded")
                try:
                    service.record_public_hit(
                        token=token,
                        ip_address=client_ip,
                        # Raw ASGI path, not request.url (which is rebuilt from the Host header).
                        # (custom DECOY_*_PATH prefixes: the path as requested, app/middleware/decoy_paths.py)
                        request_path=request.scope.get("hs_decoy_path") or request.scope.get("path", ""),
                        http_method=request.method,
                        user_agent=request.headers.get("user-agent"),
                        headers=dict(request.headers),
                        request_id=edge_request_id(request, settings),
                    )
                except DuplicatePublicHitError:
                    pass  # this exact request is already stored (edge retry): nothing to add
            elif count == cap + 1:
                metrics.inc("honeyshield_ingest_requests_total", outcome="valid_suppressed")
                service.record_suppressed_hits(token, client_ip, cap)
            else:
                metrics.inc("honeyshield_ingest_requests_total", outcome="valid_suppressed")
        except ValidationError:
            logger.warning("Rejected malformed public hit for honey token %s", token.id)

    elif not probe:
        metrics.inc("honeyshield_ingest_requests_total", outcome="invalid_token")

    if not settings.rate_limit_enabled:
        return True, 0
    allowed, retry = _response_allowed(client_ip)
    if not allowed:
        metrics.inc("honeyshield_ingest_requests_total", outcome="throttled_response")
    return allowed, retry


def _too_many(retry_after: int) -> Response:
    return Response(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(retry_after)},
    )


@router.get(
    "/t/{token_value}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Trigger a URL honey token",
    description="Public ingestion endpoint for URL and link honey tokens.",
    response_class=Response,
)
def trigger_url_token(
    token_value: Annotated[str, Path(description="Honey-token value embedded in the URL.")],
    request: Request,
    service: ServiceDependency,
) -> Response:
    """Accept a URL honey-token trigger."""
    allowed, retry_after = _ingest(request, service, token_value)
    if not allowed:
        return _too_many(retry_after)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/px/{token_value}.gif",
    summary="Trigger a tracking pixel honey token",
    description="Public ingestion endpoint for tracking pixel honey tokens.",
    response_class=Response,
)
def trigger_pixel_token(
    token_value: Annotated[str, Path(description="Honey-token value embedded in the pixel URL.")],
    request: Request,
    service: ServiceDependency,
) -> Response:
    """Accept a tracking-pixel honey-token trigger and return a transparent GIF."""
    clean_token = token_value[:-4] if token_value.endswith(".gif") else token_value
    allowed, retry_after = _ingest(request, service, clean_token)
    if not allowed:
        return _too_many(retry_after)
    return Response(content=_TRANSPARENT_GIF, media_type="image/gif", status_code=status.HTTP_200_OK)


@router.post(
    "/collect/{token_value}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Collect a programmable honey token trigger",
    description="Public ingestion endpoint for form-field and programmable honey tokens.",
    response_class=Response,
)
def collect_token(
    token_value: Annotated[str, Path(description="Honey-token value embedded in the collection URL.")],
    request: Request,
    service: ServiceDependency,
) -> Response:
    """Accept a programmable honey-token trigger."""
    allowed, retry_after = _ingest(request, service, token_value)
    if not allowed:
        return _too_many(retry_after)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
