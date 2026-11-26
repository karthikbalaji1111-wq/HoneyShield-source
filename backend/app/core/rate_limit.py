"""Bounded rate limiting and admission control for HoneyShield.

Two layers
* ``FixedWindowLimiter``: process-local, thread-safe, memory-bounded (max_keys). Admission
  decisions use a sliding-window counter (previous window weighted by its remaining overlap),
  so bursts straddling a window boundary cannot get twice the limit; ``increment``/``peek``
  remain plain per-window counters (evidence caps).
* ``SharedLimiter``: the same interface backed by Redis when REDIS_URL is set, so every API
  replica counts against one budget. Windows are keyed by wall-clock window number
  (the same sliding estimate, current + previous key); each check is one atomic Lua call with a
  short timeout. If Redis is unavailable the
  limiter falls back to its process-local window (``app.core.shared_state`` breaker): limits
  remain enforced per process, never silently removed. Evidence counters fail open, as before.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional


class FixedWindowLimiter:
    """Thread-safe bounded fixed-window rate limiter for in-process admission control.

    One instance tracks ONE window length: calls with different ``window_seconds`` on the same
    instance reset each other's counts. Give each window length its own limiter.
    """

    def __init__(
        self,
        max_keys: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the rate limiter with a maximum key capacity and clock source."""
        self._clock = clock
        self._max_keys = max_keys
        self._window: Optional[int] = None
        self._counts: dict[str, int] = {}
        self._total: int = 0
        # Previous window, for the sliding-window estimate of admission decisions.
        self._prev_counts: dict[str, int] = {}
        self._prev_total: int = 0
        self._lock = threading.Lock()

    def _roll(self, current_window: int) -> None:
        """Advance to ``current_window`` (caller holds the lock)."""
        if self._window == current_window:
            return
        if self._window is not None and current_window == self._window + 1:
            self._prev_counts, self._prev_total = self._counts, self._total
        else:
            self._prev_counts, self._prev_total = {}, 0
        self._window = current_window
        self._counts = {}
        self._total = 0

    def allow(self, key: str, limit: int, global_limit: int, window_seconds: int = 60) -> bool:
        """Evaluate whether a request key is within limits (backward-compatible)."""
        allowed, _ = self.check_and_increment(key, limit, global_limit, window_seconds=window_seconds)
        return allowed

    def check_and_increment(
        self,
        key: str,
        limit: int,
        global_limit: int,
        window_seconds: int = 60,
    ) -> tuple[bool, int]:
        """Check if request is allowed, record it if allowed, and return (allowed, retry_after).

        Sliding-window counter: the estimate is ``previous * (1 - elapsed fraction) + current``.
        Unlike a plain fixed window, a burst straddling a window boundary cannot get twice the
        limit through.

        Args:
            key: Rate limit identifier (e.g., client IP, user ID, or composite key).
            limit: Maximum allowed requests for this key per window.
            global_limit: Maximum allowed requests across all keys per window.
            window_seconds: Duration of the rate-limiting window in seconds.

        Returns:
            A tuple of (is_allowed: bool, retry_after_seconds: int).
        """
        now = self._clock()
        current_window = int(now // window_seconds)
        seconds_into_window = now % window_seconds
        weight = 1.0 - seconds_into_window / window_seconds
        retry_after = max(1, int(window_seconds - seconds_into_window))

        with self._lock:
            self._roll(current_window)

            if self._prev_total * weight + self._total + 1 > global_limit:
                return False, retry_after

            current_count = self._counts.get(key)
            if current_count is None and len(self._counts) >= self._max_keys:
                # Defend against memory exhaustion from high-cardinality attacker keys
                return False, retry_after
            if self._prev_counts.get(key, 0) * weight + (current_count or 0) + 1 > limit:
                return False, retry_after
            self._counts[key] = (current_count or 0) + 1
            self._total += 1
            return True, 0

    def increment(self, key: str, window_seconds: int = 60) -> int | None:
        """Count one occurrence of ``key`` in the current window and return the new count.

        Unlike ``check_and_increment`` this never refuses: it is a counter, not an
        admission decision. Counts keep growing past any limit so callers can tell
        the first over-limit occurrence (``count == limit + 1``) from later ones.

        Returns ``None`` when the key table is full and the key is not yet tracked;
        callers protecting evidence must treat that as "under the limit" (fail open).
        """
        current_window = int(self._clock() // window_seconds)
        with self._lock:
            self._roll(current_window)
            if key not in self._counts and len(self._counts) >= self._max_keys:
                return None
            count = self._counts.get(key, 0) + 1
            self._counts[key] = count
            self._total += 1
            return count

    def peek(self, key: str, window_seconds: int = 60) -> int:
        """Current count for ``key`` in this window without recording anything."""
        current_window = int(self._clock() // window_seconds)
        with self._lock:
            if self._window != current_window:
                return 0
            return self._counts.get(key, 0)

    def reset(self) -> None:
        """Reset all rate limiter counters to initial state (for testing / restart)."""
        with self._lock:
            self._window = None
            self._counts = {}
            self._total = 0
            self._prev_counts = {}
            self._prev_total = 0


_CHECK_AND_INCREMENT = """
local w = tonumber(ARGV[4])
local ptotal = tonumber(redis.call('GET', KEYS[4]) or '0')
local total = tonumber(redis.call('GET', KEYS[2]) or '0')
if ptotal * w + total + 1 > tonumber(ARGV[2]) then return 0 end
local pcount = tonumber(redis.call('GET', KEYS[3]) or '0')
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if pcount * w + count + 1 > tonumber(ARGV[1]) then return 0 end
redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('INCR', KEYS[2]); redis.call('EXPIRE', KEYS[2], ARGV[3])
return 1
"""
_INCREMENT = """
local total = tonumber(redis.call('GET', KEYS[2]) or '0')
if total >= tonumber(ARGV[2]) then return 0 end
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count >= tonumber(ARGV[1]) then return 0 end
redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('INCR', KEYS[2]); redis.call('EXPIRE', KEYS[2], ARGV[3])
return 1
"""
_INCREMENT = """
local count = redis.call('INCR', KEYS[1]); redis.call('EXPIRE', KEYS[1], ARGV[1])
redis.call('INCR', KEYS[2]); redis.call('EXPIRE', KEYS[2], ARGV[1])
return count
"""


class SharedLimiter(FixedWindowLimiter):
    """Cluster-wide fixed windows in Redis, with this process's window as the fallback."""

    KEY_PREFIX = "hs:rl"

    def __init__(self, name: str, max_keys: int = 4096, clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time) -> None:
        super().__init__(max_keys=max_keys, clock=clock)
        self.name = name
        self._wall = wall_clock

    def _keys(self, key: str, window_seconds: int) -> tuple[list[str], int, int]:
        """[current key, current total, previous key, previous total], TTL, retry-after."""
        now = self._wall()
        window = int(now // window_seconds)
        retry_after = max(1, int(window_seconds - (now % window_seconds)))
        base = f"{self.KEY_PREFIX}:{self.name}:{window_seconds}:{window}"
        prev = f"{self.KEY_PREFIX}:{self.name}:{window_seconds}:{window - 1}"
        # Kept for two windows: the next window reads this one as its "previous".
        return ([f"{base}:k:{key}", f"{base}:total", f"{prev}:k:{key}", f"{prev}:total"],
                2 * window_seconds + 5, retry_after)

    def _weight(self, window_seconds: int) -> float:
        return 1.0 - (self._wall() % window_seconds) / window_seconds

    def check_and_increment(self, key: str, limit: int, global_limit: int,
                            window_seconds: int = 60) -> tuple[bool, int]:
        from app.core import shared_state

        r = shared_state.client()
        if r is not None:
            keys, ttl, retry_after = self._keys(key, window_seconds)
            try:
                allowed = r.eval(_CHECK_AND_INCREMENT, 4, *keys, limit, global_limit, ttl,
                                 repr(self._weight(window_seconds)))
                return (True, 0) if int(allowed) == 1 else (False, retry_after)
            except Exception as exc:  # noqa: BLE001 - fall back to the local window
                shared_state.failed(exc)
        return super().check_and_increment(key, limit, global_limit, window_seconds=window_seconds)

    def increment(self, key: str, window_seconds: int = 60) -> int | None:
        from app.core import shared_state

        r = shared_state.client()
        if r is not None:
            keys, ttl, _ = self._keys(key, window_seconds)
            try:
                return int(r.eval(_INCREMENT, 2, *keys[:2], ttl))
            except Exception as exc:  # noqa: BLE001
                shared_state.failed(exc)
        return super().increment(key, window_seconds=window_seconds)

    def peek(self, key: str, window_seconds: int = 60) -> int:
        from app.core import shared_state

        r = shared_state.client()
        if r is not None:
            keys, _, _ = self._keys(key, window_seconds)
            try:
                return int(r.get(keys[0]) or 0)
            except Exception as exc:  # noqa: BLE001
                shared_state.failed(exc)
        return super().peek(key, window_seconds=window_seconds)


# Shared instances (Redis-backed when REDIS_URL is set, process-local otherwise)
login_limiter = SharedLimiter("login", max_keys=4096)
api_limiter = SharedLimiter("api", max_keys=8192)
# Response-rate control for ALL public ingestion requests (valid or not).
ingestion_limiter = SharedLimiter("ingest", max_keys=8192)
# Per-(IP, valid token) evidence counter. Separate from ingestion_limiter so that
# noise from invalid tokens or other IPs can never stop a valid hit being recorded.
ingestion_valid_hit_counter = SharedLimiter("ingest-valid", max_keys=16384)
# Customer integrations: failures are limited per source IP (so a misbehaving or hostile
# client cannot burn a real integration's budget), successes per authenticated integration.
integration_auth_failure_limiter = SharedLimiter("hook-authfail", max_keys=8192)
integration_report_limiter = SharedLimiter("hook-report", max_keys=8192)
integration_evidence_counter = SharedLimiter("hook-evidence", max_keys=16384)
# Self-service password reset: per-address budget over 15 minutes (its own window length).
password_reset_email_limiter = SharedLimiter("pwreset-email", max_keys=8192)
# Failed passwords per account (any source IP), LOGIN_ACCOUNT_FAILURE_WINDOW_SECONDS window.
login_account_failure_limiter = SharedLimiter("login-account", max_keys=65536)


def reset_all_limiters() -> None:
    """Reset all active rate limiters across the application."""
    login_limiter.reset()
    api_limiter.reset()
    ingestion_limiter.reset()
    ingestion_valid_hit_counter.reset()
    integration_auth_failure_limiter.reset()
    integration_report_limiter.reset()
    integration_evidence_counter.reset()
    password_reset_email_limiter.reset()
    login_account_failure_limiter.reset()
