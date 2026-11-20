"""GET /metrics (Prometheus). Exists only when METRICS_TOKEN is set; requires that bearer token.

Served on the control-plane host only (the ingest host 404s everything but ingest routes).
Exposes counts and states, never token values, IPs, emails or request contents.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Header, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import text

from app.core import metrics
from app.core.config import get_settings
from app.db.session import SessionLocal, engine

router = APIRouter(include_in_schema=False)


@router.get("/metrics")
def prometheus(request: Request, authorization: str | None = Header(default=None)) -> Response:
    token = get_settings().metrics_token
    if not token:
        return Response(status_code=404)
    presented = (authorization or "")[7:] if (authorization or "").lower().startswith("bearer ") else ""
    if not hmac.compare_digest(presented.encode(), token.encode()):
        return Response(status_code=404)

    from app.services.event_broadcaster import STATS, get_broadcaster

    extra: list[tuple[str, str, dict[str, str], float]] = [
        ("honeyshield_stream_subscribers", "gauge", {}, get_broadcaster().subscriber_count),
        ("honeyshield_stream_dropped_events_total", "counter", {}, STATS["dropped_events"]),
        ("honeyshield_stream_rejected_subscriptions_total", "counter", {}, STATS["rejected_subscriptions"]),
        ("honeyshield_stream_relayed_in_total", "counter", {}, STATS["relayed_in"]),
        ("honeyshield_stream_relay_publish_errors_total", "counter", {}, STATS["relay_publish_errors"]),
    ]
    from app.core import shared_state

    redis_up = shared_state.healthy()
    if redis_up is not None:
        extra.append(("honeyshield_shared_state_up", "gauge", {}, 1.0 if redis_up else 0.0))
        extra.append(("honeyshield_shared_state_errors_total", "counter", {}, shared_state.STATS["redis_errors"]))
        extra.append(("honeyshield_shared_state_fallbacks_total", "counter", {},
                      shared_state.STATS["redis_fallbacks"]))
    pool = engine.pool
    for attr, name in (("checkedout", "honeyshield_db_pool_checked_out"), ("size", "honeyshield_db_pool_size"),
                       ("overflow", "honeyshield_db_pool_overflow")):
        fn = getattr(pool, attr, None)
        if callable(fn):
            try:
                extra.append((name, "gauge", {}, float(fn())))
            except Exception:
                pass
    up = 1.0
    session = request.app.dependency_overrides and None
    try:
        from app.db.session import get_db
        override = request.app.dependency_overrides.get(get_db)
        gen = override() if override else None
        session = next(gen) if gen else SessionLocal()
        for status, n in session.execute(text("SELECT status, count(*) FROM outbox_events GROUP BY status")).all():
            extra.append(("honeyshield_alert_outbox", "gauge", {"status": status}, float(n)))
        oldest = session.execute(text(
            "SELECT min(next_attempt_at) FROM outbox_events WHERE status = 'PENDING'")).scalar()
        if oldest is not None:
            from datetime import datetime, timezone
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            extra.append(("honeyshield_alert_oldest_pending_seconds", "gauge", {},
                          max(0.0, (datetime.now(timezone.utc) - oldest).total_seconds())))
    except Exception:
        up = 0.0
    finally:
        if session is not None and not request.app.dependency_overrides:
            session.close()
    extra.append(("honeyshield_database_up", "gauge", {}, up))
    return PlainTextResponse(metrics.render(extra), media_type="text/plain; version=0.0.4")
