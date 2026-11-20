"""Cluster-shared state (Redis) for running several API replicas (HONEY-026).

What is shared when REDIS_URL is set
* rate-limit windows (``app.core.rate_limit``): every replica counts against one budget;
* the live event stream (``app.services.event_broadcaster``): an event recorded on one replica
  reaches clients connected to any replica.

Redis is never a dependency of detection or evidence. Each call has a short timeout. After a
failure the breaker stays open for ``BREAKER_SECONDS`` and callers use their process-local
fallback: limiters keep enforcing per-process limits and the stream delivers to local clients.
Durable alerting goes through the database outbox and does not use Redis.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

BREAKER_SECONDS = 10.0
SOCKET_TIMEOUT = 0.25

_client: Any = None
_client_url: str | None = None
_open_until = 0.0
_lock = threading.Lock()
STATS: dict[str, int] = {"redis_errors": 0, "redis_fallbacks": 0}


def _url() -> str | None:
    from app.core.config import get_settings

    return get_settings().redis_url


def configured() -> bool:
    return bool(_url())


def client() -> Any | None:
    """A Redis client, or None when not configured or the breaker is open."""
    global _client, _client_url
    url = _url()
    if not url:
        return None
    if time.monotonic() < _open_until:
        STATS["redis_fallbacks"] += 1
        return None
    with _lock:
        if _client is None or _client_url != url:
            import redis

            _client = redis.Redis.from_url(url, socket_timeout=SOCKET_TIMEOUT, socket_connect_timeout=SOCKET_TIMEOUT,
                                           health_check_interval=30, decode_responses=True)
            _client_url = url
        return _client


def failed(exc: BaseException) -> None:
    """Record a Redis failure and open the breaker."""
    global _open_until
    STATS["redis_errors"] += 1
    first = time.monotonic() >= _open_until
    _open_until = time.monotonic() + BREAKER_SECONDS
    if first:
        logger.warning("Shared state (Redis) unavailable; using process-local fallback for %ss: %s",
                       BREAKER_SECONDS, type(exc).__name__)


def healthy() -> bool | None:
    """True/False for a configured Redis, None when not configured (used by readiness)."""
    if not configured():
        return None
    c = client()
    if c is None:
        return False
    try:
        return bool(c.ping())
    except Exception as exc:  # noqa: BLE001 - any client error means unavailable
        failed(exc)
        return False


def reset_for_tests() -> None:
    global _client, _client_url, _open_until
    with _lock:
        _client, _client_url, _open_until = None, None, 0.0
