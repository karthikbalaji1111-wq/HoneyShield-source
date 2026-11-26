"""Streams end at JWT expiry and on role change; connections are capped."""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.models.enums import Role
from app.services import event_broadcaster as eb
from tests.conftest import make_token


def _ws_closed_code(client, token: str) -> int:
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as ws:
            ws.send_json({"type": "auth", "token": token})
            assert ws.receive_json() == {"type": "auth_success"}
            ws.receive_text()
    assert exc_info.type.__name__ == "WebSocketDisconnect"
    return exc_info.value.code, exc_info.value.reason


def test_websocket_closes_when_the_jwt_expires(client, admin_a):
    token = create_access_token(subject=str(admin_a.id), expires_delta=timedelta(seconds=2),
                                token_version=admin_a.token_version)
    code, reason = _ws_closed_code(client, token)
    assert code == 1008 and reason == "Token expired"


def test_websocket_closes_when_the_role_changes(client, admin_a, db_session: Session, monkeypatch):
    import app.api.v1.events_stream as es_mod
    monkeypatch.setattr(es_mod, "REVALIDATION_INTERVAL_SECONDS", 0.05)
    token = make_token(admin_a)
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as ws:
            ws.send_json({"type": "auth", "token": token})
            assert ws.receive_json() == {"type": "auth_success"}
            admin_a.role = Role.TENANT_USER
            db_session.commit()
            ws.receive_text()
    assert exc_info.value.code == 1008


def test_sse_stream_ends_at_jwt_expiry(admin_a):
    """Drive the SSE generator directly: it must stop by itself once exp passes."""
    from app.api.v1 import events_stream as es

    ctx = es.StreamAuthContext(user_id=admin_a.id, tenant_id=admin_a.tenant_id, role="TENANT_ADMIN",
                               token_version=0, is_active=True, expires_at=__import__("time").time() + 0.3)

    class FakeRequest:
        async def is_disconnected(self):
            return False

    async def collect():
        resp = await es.sse_stream(FakeRequest(), ctx)
        chunks = []
        async for chunk in resp.body_iterator:
            chunks.append(chunk)
        return chunks

    chunks = asyncio.run(asyncio.wait_for(collect(), timeout=5))
    assert any("Token expired" in c for c in chunks)


def test_connection_caps_are_enforced(monkeypatch):
    b = eb.EventBroadcaster()
    monkeypatch.setattr(b, "MAX_SUBSCRIBERS_PER_TENANT", 2)
    monkeypatch.setattr(b, "MAX_SUBSCRIBERS", 3)
    before = eb.STATS["rejected_subscriptions"]
    q = lambda: asyncio.Queue(maxsize=4)  # noqa: E731
    b.subscribe(1, q())
    b.subscribe(1, q())
    with pytest.raises(eb.SubscriptionLimitError):
        b.subscribe(1, q())              # per-tenant cap
    b.subscribe(2, q())
    with pytest.raises(eb.SubscriptionLimitError):
        b.subscribe(3, q())              # global cap
    assert eb.STATS["rejected_subscriptions"] == before + 2


def test_websocket_over_cap_is_refused_with_try_again_later(client, admin_a, monkeypatch):
    monkeypatch.setattr(eb.EventBroadcaster, "MAX_SUBSCRIBERS_PER_TENANT", 0)
    with pytest.raises(Exception) as exc_info:
        with client.websocket_connect("/api/v1/events/stream/ws") as ws:
            ws.send_json({"type": "auth", "token": make_token(admin_a)})
            ws.receive_json()
            ws.receive_text()
    assert exc_info.value.code == 1013


def test_sse_over_cap_returns_429(client, admin_a, monkeypatch):
    monkeypatch.setattr(eb.EventBroadcaster, "MAX_SUBSCRIBERS_PER_TENANT", 0)
    resp = client.get("/api/v1/events/stream/sse", headers={"Authorization": f"Bearer {make_token(admin_a)}"})
    assert resp.status_code == 429 and resp.headers["Retry-After"] == "30"


def test_dropped_events_are_counted():
    q: asyncio.Queue = asyncio.Queue(maxsize=1)
    before = eb.STATS["dropped_events"]
    eb._safe_put(q, {"n": 1}, 1)
    eb._safe_put(q, {"n": 2}, 1)
    assert eb.STATS["dropped_events"] == before + 1 and q.get_nowait() == {"n": 2}
