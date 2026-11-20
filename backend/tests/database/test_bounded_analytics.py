"""Analytics stay bounded at any data size and say so; tenant_id is set by the database."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app.core.config import get_settings
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from tests.conftest import auth_headers


def _events(db_session, token, n, ip_fmt="198.51.100.{i}"):
    now = datetime.now(timezone.utc)
    for i in range(n):
        db_session.add(DetectionEvent(honey_token_id=token.id, ip_address=ip_fmt.format(i=i % 200), request_path="/t/x",
                                      http_method="GET", severity=EventSeverity.HIGH, source=EventSource.PUBLIC_INGEST,
                                      triggered_at=now - timedelta(minutes=i)))
    db_session.commit()


def test_tenant_id_is_set_by_the_database_on_every_insert_path(client, db_session, token_a, tenant_a):
    _events(db_session, token_a, 3)                                       # direct ORM insert
    assert client.get(f"/t/{token_a.token_value}").status_code == 204       # application path
    db_session.execute(text("INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, "
                            "severity, source, triggered_at) VALUES (:t, '1.2.3.4', '/x', 'GET', 'LOW', "
                            "'PUBLIC_INGEST', CURRENT_TIMESTAMP)"), {"t": token_a.id})   # raw SQL
    db_session.commit()
    db_session.expire_all()
    rows = db_session.query(DetectionEvent.tenant_id).all()
    assert len(rows) == 5 and {r[0] for r in rows} == {tenant_a.id}


def test_summary_and_top_attackers_report_sampling(client, db_session, admin_a, token_a, monkeypatch):
    _events(db_session, token_a, 30)
    h = auth_headers(admin_a)
    r = client.get("/api/v1/threats/summary", headers=h)
    assert r.status_code == 200 and r.json()["sampled"] is False and r.json()["total_events"] == 30
    r = client.get("/api/v1/threats/top-attackers", headers=h)
    assert r.status_code == 200 and r.headers["x-analytics-sampled"] == "false"
    monkeypatch.setattr(get_settings(), "analytics_sample_events", 10)
    r = client.get("/api/v1/threats/summary", headers=h)
    assert r.json()["sampled"] is True and r.json()["total_events"] == 10
    r = client.get("/api/v1/threats/top-attackers", headers=h)
    assert r.headers["x-analytics-sampled"] == "true"
    assert sum(p["total_events"] for p in r.json()) <= 10


def test_analytics_are_tenant_scoped(client, db_session, admin_a, admin_b, token_a, token_b):
    _events(db_session, token_a, 12, ip_fmt="10.0.0.{i}")
    _events(db_session, token_b, 5, ip_fmt="10.9.9.{i}")
    a = client.get("/api/v1/threats/top-attackers", headers=auth_headers(admin_a)).json()
    b = client.get("/api/v1/threats/top-attackers", headers=auth_headers(admin_b)).json()
    assert {p["ip_address"] for p in a}.isdisjoint({p["ip_address"] for p in b})
    assert client.get("/api/v1/threats/summary", headers=auth_headers(admin_b)).json()["total_events"] == 5


def test_analytics_timeout_is_a_clear_503(client, admin_a, monkeypatch):
    from sqlalchemy.exc import OperationalError

    from app.repositories.detection_event import DetectionEventRepository

    def boom(self, **kw):
        raise OperationalError("SELECT ...", {}, Exception("canceling statement due to statement timeout"))
    monkeypatch.setattr(DetectionEventRepository, "rank_ip_activity", boom)
    r = client.get("/api/v1/threats/top-attackers", headers=auth_headers(admin_a))
    assert r.status_code == 503 and "shorter window" in r.text
