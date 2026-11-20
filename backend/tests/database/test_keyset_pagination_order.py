"""Keyset pagination must return every event exactly once, even when trigger times are not in id order.

Customer-hook reports carry the customer's asserted time, so a later-recorded event (higher id)
can have an earlier triggered_at. The list is ordered by (triggered_at, id); the cursor must
follow the same order or pages silently skip events (and the CSV export loses rows).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import event as sa_event

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from tests.conftest import auth_headers


def _events(db_session, token, offsets_minutes):
    base = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    rows = []
    for i, off in enumerate(offsets_minutes):
        ev = DetectionEvent(honey_token_id=token.id, ip_address=f"198.51.100.{i + 1}", request_path="/t/x",
                            http_method="GET", severity=EventSeverity.HIGH, source=EventSource.PUBLIC_INGEST,
                            triggered_at=base + timedelta(minutes=off))
        db_session.add(ev)
        db_session.flush()
        rows.append(ev)
    db_session.commit()
    return rows


def test_cursor_pages_return_every_event_once(client, db_session, admin_a, token_a):
    # ids increase, trigger times jump around (a late report of an early event, ties included)
    rows = _events(db_session, token_a, [50, 10, 40, 40, 5, 60, 20, 40])
    seen, cursor = [], None
    for _ in range(20):
        params = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = client.get("/api/v1/detection-events", params=params, headers=auth_headers(admin_a)).json()
        if not page:
            break
        seen += [e["id"] for e in page]
        cursor = page[-1]["id"]
    assert sorted(seen) == sorted(r.id for r in rows) and len(seen) == len(set(seen))
    expected = [r.id for r in sorted(rows, key=lambda r: (r.triggered_at, r.id), reverse=True)]
    assert seen == expected


def test_csv_export_contains_every_event(client, db_session, admin_a, token_a, monkeypatch):
    from app.api.v1 import detection_events as api
    rows = _events(db_session, token_a, [30, 1, 25, 2, 20, 3])
    # force tiny pages so the export walks the cursor
    original = api.DetectionEventService.list_recent_events
    monkeypatch.setattr(api.DetectionEventService, "list_recent_events",
                        lambda self, limit=1000, cursor=None, **kw: original(self, limit=2, cursor=cursor, **kw))
    r = client.get("/api/v1/detection-events/export", headers=auth_headers(admin_a))
    assert r.headers["x-export-rows"] == str(len(rows))


def test_listing_does_not_query_per_event(client, db_session, engine, user_a, token_a):
    _events(db_session, token_a, list(range(40)))
    statements = []
    listener = lambda *a, **k: statements.append(a[2])
    sa_event.listen(engine, "before_cursor_execute", listener)
    try:
        r = client.get("/api/v1/detection-events?limit=40", headers=auth_headers(user_a))   # viewer: masking
        r2 = client.get("/api/v1/detection-events/export", headers=auth_headers(user_a))
    finally:
        sa_event.remove(engine, "before_cursor_execute", listener)
    assert r.status_code == 200 and len(r.json()) == 40 and r2.status_code == 200
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) < 30, f"{len(selects)} SELECTs for 40 events (N+1)"
