"""Regression tests for HONEY-009: top-attackers ranked only the first N IPs in lexical order."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from app.repositories.detection_event import DetectionEventRepository
from app.services.threat_intelligence import ThreatIntelligenceService
from tests.conftest import auth_headers


def _add(db_session, token_id: int, ip: str, n: int) -> None:
    now = datetime.now(timezone.utc)
    for _ in range(n):
        db_session.add(DetectionEvent(source=EventSource.PUBLIC_INGEST, honey_token_id=token_id, ip_address=ip, request_path="/t/x",
                                      http_method="GET", severity=EventSeverity.MEDIUM, triggered_at=now))


def test_top_attacker_survives_candidate_limit(client, db_session, system_admin, token_a):
    for i in range(120):                      # 120 one-hit IPs that sort lexically first
        _add(db_session, token_a.id, f"10.0.0.{i}", 1)
    _add(db_session, token_a.id, "99.99.99.99", 30)   # heaviest attacker, sorts last
    db_session.flush()

    resp = client.get("/api/v1/threats/top-attackers?limit=100", headers=auth_headers(system_admin))
    assert resp.status_code == 200
    ips = [p["ip_address"] for p in resp.json()]
    assert ips[0] == "99.99.99.99"


def test_sql_ranking_matches_python_score(db_session, system_admin, token_a):
    _add(db_session, token_a.id, "1.1.1.1", 2)
    _add(db_session, token_a.id, "2.2.2.2", 7)
    _add(db_session, token_a.id, "3.3.3.3", 40)       # caps must apply identically in SQL and Python
    db_session.flush()

    service = ThreatIntelligenceService(db_session, DetectionEventRepository(db_session), current_user=system_admin)
    ranked = DetectionEventRepository(db_session).aggregate_by_ip(rank_by_threat=service._score_weights())
    python_scores = [service._build_ip_profile(a).threat_score for a in ranked]
    assert python_scores == sorted(python_scores, reverse=True)
    assert [a.ip_address for a in ranked] == ["3.3.3.3", "2.2.2.2", "1.1.1.1"]
