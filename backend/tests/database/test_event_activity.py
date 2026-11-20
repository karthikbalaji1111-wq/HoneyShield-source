"""Daily activity series for the console overview: correct buckets, tenant scope, bounds."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from tests.conftest import auth_headers


def _event(db_session, token, when, severity=EventSeverity.HIGH):
    db_session.add(DetectionEvent(honey_token_id=token.id, ip_address="198.51.100.7", request_path="/t/x",
                                  http_method="GET", severity=severity, source=EventSource.PUBLIC_INGEST,
                                  triggered_at=when))


def _noon(days_ago: int) -> datetime:
    d = datetime.now(timezone.utc).date() - timedelta(days=days_ago)
    return datetime(d.year, d.month, d.day, 12, tzinfo=timezone.utc)


def test_activity_counts_each_day_and_severity_and_fills_gaps(client, db_session, admin_a, token_a):
    _event(db_session, token_a, _noon(0), EventSeverity.CRITICAL)
    _event(db_session, token_a, _noon(0), EventSeverity.HIGH)
    _event(db_session, token_a, _noon(2), EventSeverity.LOW)
    _event(db_session, token_a, _noon(20), EventSeverity.HIGH)      # outside a 7-day window
    db_session.commit()
    r = client.get("/api/v1/detection-events/activity?days=7", headers=auth_headers(admin_a))
    assert r.status_code == 200
    days = r.json()
    assert len(days) == 7
    assert days[-1]["date"] == datetime.now(timezone.utc).date().isoformat()   # today last
    assert [d["date"] for d in days] == sorted(d["date"] for d in days)          # oldest first
    by_date = {d["date"]: d for d in days}
    today = by_date[_noon(0).date().isoformat()]
    assert today["total"] == 2 and today["by_severity"]["CRITICAL"] == 1 and today["by_severity"]["HIGH"] == 1
    assert by_date[_noon(2).date().isoformat()]["by_severity"]["LOW"] == 1
    assert by_date[_noon(1).date().isoformat()]["total"] == 0                     # empty day present
    assert sum(d["total"] for d in days) == 3
    assert set(today["by_severity"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_activity_is_tenant_scoped(client, db_session, admin_a, admin_b, token_a, token_b):
    for _ in range(4):
        _event(db_session, token_a, _noon(0))
    _event(db_session, token_b, _noon(0))
    db_session.commit()
    a = client.get("/api/v1/detection-events/activity", headers=auth_headers(admin_a)).json()
    b = client.get("/api/v1/detection-events/activity", headers=auth_headers(admin_b)).json()
    assert sum(d["total"] for d in a) == 4
    assert sum(d["total"] for d in b) == 1
    assert len(a) == 14     # default window


def test_activity_window_is_bounded_and_requires_auth(client, admin_a):
    h = auth_headers(admin_a)
    assert client.get("/api/v1/detection-events/activity?days=0", headers=h).status_code == 422
    assert client.get("/api/v1/detection-events/activity?days=91", headers=h).status_code == 422
    assert client.get("/api/v1/detection-events/activity?days=90", headers=h).status_code == 200
    assert client.get("/api/v1/detection-events/activity").status_code == 401


def test_activity_timeout_is_a_clear_503(client, admin_a, monkeypatch):
    from sqlalchemy.exc import OperationalError

    from app.repositories.detection_event import DetectionEventRepository

    def boom(self, **kw):
        raise OperationalError("SELECT ...", {}, Exception("canceling statement due to statement timeout"))
    monkeypatch.setattr(DetectionEventRepository, "daily_activity", boom)
    r = client.get("/api/v1/detection-events/activity", headers=auth_headers(admin_a))
    assert r.status_code == 503
