"""HONEY-026: several API replicas share rate limits and the live stream through Redis.

Without Redis (unreachable), limiters keep enforcing per-process limits and the stream still
reaches local clients. With HS_TEST_REDIS_URL, two limiter/broadcaster instances stand in for
two replicas (each has its own process-local state) and must share one budget and one stream.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import threading
import time

import pytest

from app.core import shared_state
from app.core.config import get_settings
from app.core.rate_limit import SharedLimiter
from app.services.event_broadcaster import STATS, EventBroadcaster

REDIS_URL = os.environ.get("HS_TEST_REDIS_URL")


@pytest.fixture(autouse=True)
def isolated_shared_state(monkeypatch):
    shared_state.reset_for_tests()
    yield
    shared_state.reset_for_tests()


def _name() -> str:
    return f"t-{secrets.token_hex(4)}"


# ----------------------------------------------------------------- Redis unavailable

def test_unreachable_redis_falls_back_to_local_limits(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", "redis://127.0.0.1:1/0")
    limiter = SharedLimiter(_name())
    errors = shared_state.STATS["redis_errors"]
    results = [limiter.check_and_increment("ip:1", 3, 1000)[0] for _ in range(5)]
    assert results == [True, True, True, False, False]       # still enforced, per process
    assert shared_state.STATS["redis_errors"] == errors + 1  # breaker opened after one failure
    assert limiter.increment("ip:2") == 1 and limiter.peek("ip:2") == 1
    assert shared_state.healthy() is False


def test_breaker_skips_redis_until_it_closes(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", "redis://127.0.0.1:1/0")
    limiter = SharedLimiter(_name())
    limiter.check_and_increment("k", 10, 10)
    fallbacks = shared_state.STATS["redis_fallbacks"]
    t0 = time.monotonic()
    for _ in range(20):
        limiter.check_and_increment("k", 100, 100)
    assert time.monotonic() - t0 < 0.5                       # no 0.25 s timeouts while open
    assert shared_state.STATS["redis_fallbacks"] >= fallbacks + 20


def test_not_configured_is_reported_as_none(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", None)
    assert shared_state.healthy() is None and shared_state.client() is None


def test_relay_message_handling_is_tenant_scoped_and_ignores_own_origin():
    b = EventBroadcaster()
    delivered: list[tuple[dict, int]] = []
    b._deliver_local = lambda e, t: delivered.append((e, t))  # type: ignore[method-assign]
    assert b.handle_relay_message(f'{{"o": "{b.instance_id}", "t": 1, "e": {{"x": 1}}}}') is False
    assert b.handle_relay_message('{"o": "other", "t": 2, "e": {"x": 2}}') is True
    for bad in ("not json", '{"o": "other"}', '{"o": "other", "t": "1", "e": {}}', '{"o": "x", "t": 1, "e": []}'):
        assert b.handle_relay_message(bad) is False
    assert delivered == [({"x": 2}, 2)]


def test_publish_without_redis_still_reaches_local_clients(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", "redis://127.0.0.1:1/0")
    b = EventBroadcaster()

    async def run():
        q: asyncio.Queue = asyncio.Queue()
        b.subscribe(1, q)
        b.publish({"event_id": 1}, 1)
        return await asyncio.wait_for(q.get(), 1)

    assert asyncio.run(run()) == {"event_id": 1}


# ----------------------------------------------------------------- real Redis

needs_redis = pytest.mark.skipif(not REDIS_URL, reason="HS_TEST_REDIS_URL not set (real Redis)")


@pytest.fixture()
def redis_on(monkeypatch):
    monkeypatch.setattr(get_settings(), "redis_url", REDIS_URL)
    assert shared_state.healthy() is True


@needs_redis
@pytest.mark.redis
def test_two_replicas_share_one_per_key_budget(redis_on):
    name = _name()
    a, b = SharedLimiter(name), SharedLimiter(name)        # separate local state, like two processes
    results = [(a if i % 2 else b).check_and_increment("ip:203.0.113.9", 5, 10_000)[0] for i in range(10)]
    assert results.count(True) == 5 and results[5:] == [False] * 5
    allowed, retry = a.check_and_increment("ip:203.0.113.9", 5, 10_000)
    assert not allowed and 1 <= retry <= 60
    assert a._counts == {} and b._counts == {}             # nothing fell back to local state


@needs_redis
@pytest.mark.redis
def test_two_replicas_share_the_global_budget(redis_on):
    name = _name()
    a, b = SharedLimiter(name), SharedLimiter(name)
    allowed = [(a if i % 2 else b).check_and_increment(f"ip:{i}", 100, 7)[0] for i in range(12)]
    assert allowed.count(True) == 7


@needs_redis
@pytest.mark.redis
def test_counters_are_shared_and_expire(redis_on):
    name = _name()
    a, b = SharedLimiter(name), SharedLimiter(name)
    assert [a.increment("valid:1"), b.increment("valid:1"), a.increment("valid:1")] == [1, 2, 3]
    assert b.peek("valid:1") == 3
    r = shared_state.client()
    ttl = r.ttl(a._keys("valid:1", 60)[0][0])
    assert 60 < ttl <= 125  # kept two windows: the next one reads it as its previous window


@needs_redis
@pytest.mark.redis
def test_live_event_reaches_clients_on_another_replica(redis_on):
    a, b = EventBroadcaster(), EventBroadcaster()
    assert a.start_relay() and b.start_relay()
    relayed = STATS["relayed_in"]
    try:
        async def run():
            own, other_tenant, remote = asyncio.Queue(), asyncio.Queue(), asyncio.Queue()
            a.subscribe(1, own)
            b.subscribe(1, remote)
            b.subscribe(2, other_tenant)
            await asyncio.sleep(0.5)                       # relays subscribed
            await asyncio.to_thread(a.publish, {"event_id": 99, "severity": "HIGH"}, 1)
            got_remote = await asyncio.wait_for(remote.get(), 5)
            got_own = await asyncio.wait_for(own.get(), 5)
            await asyncio.sleep(0.5)
            return got_remote, got_own, own.qsize(), other_tenant.qsize()

        got_remote, got_own, own_left, other_left = asyncio.run(run())
        assert got_remote == {"event_id": 99, "severity": "HIGH"} and got_own == got_remote
        assert own_left == 0                               # no duplicate through the relay
        assert other_left == 0                             # tenant isolation across replicas
        assert STATS["relayed_in"] >= relayed + 1
    finally:
        a.stop_relay()
        b.stop_relay()


@needs_redis
@pytest.mark.redis
def test_ingest_limit_is_shared_across_replicas_end_to_end(redis_on, client, token_a, monkeypatch):
    """The real ingest path: hits counted on 'another replica' consume this replica's budget."""
    from app.core import rate_limit

    settings = get_settings()
    monkeypatch.setattr(settings, "ingestion_rate_limit_per_minute_ip", 4)
    name = _name()
    monkeypatch.setattr(rate_limit, "ingestion_limiter", SharedLimiter(name))
    from app.api.ingestion import router as ingest_router

    monkeypatch.setattr(ingest_router, "ingestion_limiter", SharedLimiter(name))
    assert client.get(f"/t/{token_a.token_value}").status_code == 204       # this replica: 1 of 4
    keys = [k for k in shared_state.client().scan_iter(f"hs:rl:{name}:*:k:*")]
    assert len(keys) == 1
    ingest_key = keys[0].split(":k:", 1)[1]
    other_replica = SharedLimiter(name)
    for _ in range(3):                                                       # other replica: 2-4 of 4
        assert other_replica.check_and_increment(ingest_key, 4, 10_000)[0]
    assert client.get(f"/t/{token_a.token_value}").status_code == 429       # shared budget exhausted


@needs_redis
@pytest.mark.redis
def test_shared_limit_slides_across_a_window_boundary(redis_on):
    """Two replicas, burst straddling a boundary: no double budget in the Redis path either."""
    name = _name()
    base = (int(time.time()) // 60) * 60 + 600          # a future window nobody else touches
    now = [base + 59.8]
    a, b = SharedLimiter(name, wall_clock=lambda: now[0]), SharedLimiter(name, wall_clock=lambda: now[0])
    assert a.check_and_increment("ip:1", 2, 1000)[0] and b.check_and_increment("ip:1", 2, 1000)[0]
    now[0] = base + 60.4
    assert not a.check_and_increment("ip:1", 2, 1000)[0]
    now[0] = base + 60 + 45                               # a quarter of the old window still overlaps
    assert b.check_and_increment("ip:1", 2, 1000)[0]
    now[0] = base + 180
    assert a.check_and_increment("ip:1", 2, 1000)[0] and b.check_and_increment("ip:1", 2, 1000)[0]
