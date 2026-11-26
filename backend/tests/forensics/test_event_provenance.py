"""Every detection event records where it came from; manual evidence is attributed and audited."""
from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError, StatementError

from app.core.auth_exceptions import UnauthorizedError
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from app.repositories.detection_event import DetectionEventRepository
from app.repositories.honey_token import HoneyTokenRepository
from app.services.detection_event import DetectionEventService
from tests.conftest import auth_headers

MANUAL_PAYLOAD = {"ip_address": "8.8.8.8", "request_path": "/t/fake", "http_method": "GET", "severity": "CRITICAL", "reason": "Analyst reproduction for regression test"}


def test_public_hit_is_labelled_public_ingest(client, db_session, token_a):
    client.get(f"/t/{token_a.token_value}")
    event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).one()
    assert event.source == EventSource.PUBLIC_INGEST
    assert event.created_by_user_id is None


def test_manual_event_is_labelled_attributed_and_audited(client, db_session, admin_a, token_a):
    resp = client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **MANUAL_PAYLOAD},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["source"] == "MANUAL"
    assert body["created_by_user_id"] == admin_a.id

    event = db_session.get(DetectionEvent, body["id"])
    assert event.source == EventSource.MANUAL and event.created_by_user_id == admin_a.id

    audit = db_session.query(AuditLog).filter_by(event_type="DETECTION_EVENT_MANUALLY_RECORDED").one()
    assert audit.actor_user_id == admin_a.id
    assert audit.target_id == str(event.id)
    assert audit.tenant_id == token_a.project.tenant_id
    assert audit.event_metadata["asserted_ip_address"] == "8.8.8.8"


def test_listing_exposes_source_so_manual_events_can_be_told_apart(client, admin_a, token_a):
    client.get(f"/t/{token_a.token_value}")
    client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **MANUAL_PAYLOAD},
                headers=auth_headers(admin_a))
    resp = client.get("/api/v1/detection-events", headers=auth_headers(admin_a))
    assert sorted(e["source"] for e in resp.json()) == ["MANUAL", "PUBLIC_INGEST"]


def test_manual_entry_without_a_user_is_refused(db_session, token_a):
    service = DetectionEventService(session=db_session, event_repo=DetectionEventRepository(db_session),
                                    token_repo=HoneyTokenRepository(db_session))
    with pytest.raises(UnauthorizedError):
        service.record_event(token_value=token_a.token_value, ip_address="1.1.1.1", request_path="/x",
                             http_method="GET", severity=EventSeverity.LOW)
    assert db_session.query(DetectionEvent).count() == 0


def test_database_rejects_manual_event_without_creator(db_session, token_a):
    db_session.add(DetectionEvent(source=EventSource.MANUAL, honey_token_id=token_a.id, ip_address="1.1.1.1",
                                  request_path="/x", http_method="GET", severity=EventSeverity.LOW))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_database_rejects_event_without_source(db_session, token_a):
    db_session.add(DetectionEvent(honey_token_id=token_a.id, ip_address="1.1.1.1",
                                  request_path="/x", http_method="GET", severity=EventSeverity.LOW))
    with pytest.raises(IntegrityError):
        db_session.flush()


def test_unknown_source_value_is_rejected(db_session, token_a):
    db_session.add(DetectionEvent(source="FORGED", honey_token_id=token_a.id, ip_address="1.1.1.1",
                                  request_path="/x", http_method="GET", severity=EventSeverity.LOW))
    with pytest.raises((StatementError, LookupError, ValueError)):
        db_session.flush()


def test_manual_event_requires_a_reason(client, admin_a, token_a):
    payload = {k: v for k, v in MANUAL_PAYLOAD.items() if k != "reason"}
    resp = client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **payload},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 422
    resp = client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **payload,
                       "reason": "   short  "}, headers=auth_headers(admin_a))
    assert resp.status_code == 422


def test_manual_event_reason_is_kept_in_the_audit_record(client, db_session, admin_a, token_a):
    client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **MANUAL_PAYLOAD},
                headers=auth_headers(admin_a))
    audit = db_session.query(AuditLog).filter_by(event_type="DETECTION_EVENT_MANUALLY_RECORDED").one()
    assert audit.event_metadata["reason"] == MANUAL_PAYLOAD["reason"]


def test_tenant_user_cannot_enter_manual_events(client, user_a, token_a):
    resp = client.post("/api/v1/detection-events", json={"token_value": token_a.token_value, **MANUAL_PAYLOAD},
                       headers=auth_headers(user_a))
    assert resp.status_code == 403
