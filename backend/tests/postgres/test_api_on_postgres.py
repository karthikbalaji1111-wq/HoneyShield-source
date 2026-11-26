"""End-to-end API behaviour on real PostgreSQL, connected as the least-privilege runtime role.

Exercises the same code paths as production: the real migrated schema (CHECK constraints,
triggers, JSONB, FKs) and the runtime grants. If the application needed a privilege the
runtime role does not have, these tests fail.
"""
from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.security import get_password_hash
from app.db.session import get_db
from app.main import app
from app.models.enums import Role
from app.models.project import Project
from app.models.tenant import Tenant
from app.models.user import User
from tests.conftest import auth_headers

pytestmark = pytest.mark.postgres
INGEST_BASE = "https://ingest.honeyshield.test"


@pytest.fixture()
def pg_client(app_engine, monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", INGEST_BASE)
    factory = sessionmaker(bind=app_engine, autoflush=False, expire_on_commit=False)

    def _get_db():
        s = factory()
        try:
            yield s
        finally:
            s.rollback()
            s.close()

    app.dependency_overrides[get_db] = _get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def seeded(app_engine):
    suffix = secrets.token_hex(3)
    with Session(app_engine, expire_on_commit=False) as s:
        tenant = Tenant(name=f"PG {suffix}", slug=f"pg-{suffix}", is_active=True)
        s.add(tenant)
        s.flush()
        admin = User(email=f"admin-{suffix}@pg.test", hashed_password=get_password_hash("pw-not-used"),
                     role=Role.TENANT_ADMIN, is_active=True, tenant_id=tenant.id)
        project = Project(tenant_id=tenant.id, name="PG", domain=f"{suffix}.pg.example", is_active=True)
        s.add_all([admin, project])
        s.commit()
        return tenant, admin, project


def _generate(client, admin, project, token_type):
    resp = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate",
                       json={"token_type": token_type}, headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _event_rows(app_engine, token_value):
    with app_engine.connect() as c:
        return c.execute(text(
            "SELECT e.source, e.severity, e.created_by_user_id FROM detection_events e "
            "JOIN honey_tokens t ON t.id = e.honey_token_id WHERE t.token_value = :v"), {"v": token_value}).all()


@pytest.mark.parametrize("token_type,key,method,expected_status,severity", [
    ("URL", "url", "GET", 204, "HIGH"),
    ("LINK", "url", "GET", 204, "MEDIUM"),
    ("PIXEL", "pixel_url", "GET", 200, "HIGH"),
])
def test_generated_artifact_records_event_on_postgres(pg_client, app_engine, seeded, token_type, key, method,
                                                      expected_status, severity):
    _, admin, project = seeded
    data = _generate(pg_client, admin, project, token_type)
    url = data["metadata"][key]
    assert url.startswith(INGEST_BASE + "/")
    assert pg_client.request(method, url[len(INGEST_BASE):]).status_code == expected_status
    assert _event_rows(app_engine, data["token_value"]) == [("PUBLIC_INGEST", severity, None)]


def test_manual_event_is_attributed_and_audited_on_postgres(pg_client, app_engine, seeded):
    tenant, admin, project = seeded
    data = _generate(pg_client, admin, project, "URL")
    resp = pg_client.post("/api/v1/detection-events", headers=auth_headers(admin), json={
        "token_value": data["token_value"], "ip_address": "198.51.100.7", "request_path": "/manual",
        "http_method": "GET", "severity": "LOW", "reason": "Analyst reproduction of a reported click"})
    assert resp.status_code == 201, resp.text
    assert _event_rows(app_engine, data["token_value"]) == [("MANUAL", "LOW", admin.id)]
    with app_engine.connect() as c:
        n = c.execute(text("SELECT count(*) FROM audit_logs WHERE event_type = 'DETECTION_EVENT_MANUALLY_RECORDED' "
                           "AND tenant_id = :t"), {"t": tenant.id}).scalar_one()
    assert n == 1


def test_token_lifecycle_and_listing_on_postgres(pg_client, seeded):
    _, admin, project = seeded
    data = _generate(pg_client, admin, project, "URL")
    pg_client.get(data["metadata"]["url"][len(INGEST_BASE):])
    resp = pg_client.get("/api/v1/detection-events", headers=auth_headers(admin))
    assert resp.status_code == 200
    assert any(e["source"] == "PUBLIC_INGEST" for e in resp.json())
    top = pg_client.get("/api/v1/threats/top-attackers", headers=auth_headers(admin))
    assert top.status_code == 200, top.text


def test_readiness_on_postgres_as_runtime_role(pg_client, monkeypatch):
    from app.db import runtime_guard
    runtime_guard.reset()
    monkeypatch.setattr(get_settings(), "enforce_db_least_privilege", True)
    resp = pg_client.get("/api/v1/ready")
    assert resp.status_code == 200, resp.text


SIGNING_KEY = "pg-integration-master-key-0123456789abcdef"


def _signed_post(client, cred, body: dict):
    import json, time
    from app.core import integration_auth
    raw = json.dumps(body).encode()
    ts = str(int(time.time()))
    return client.post("/integrations/v1/events", content=raw, headers={
        "X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts,
        "X-HS-Signature": integration_auth.sign(cred["secret"], "POST", "/integrations/v1/events", ts, raw)})


def test_customer_hook_report_on_postgres(pg_client, app_engine, seeded, monkeypatch):
    from datetime import datetime, timezone
    monkeypatch.setattr(get_settings(), "integration_signing_key", SIGNING_KEY)
    _, admin, project = seeded
    cred = pg_client.post(f"/api/v1/projects/{project.domain}/integrations", json={"label": "pg"},
                          headers=auth_headers(admin)).json()
    token = _generate(pg_client, admin, project, "API_KEY")
    body = {"decoy_id": token["decoy_id"], "idempotency_key": "pg-" + secrets.token_hex(10),
            "observed_at": datetime.now(timezone.utc).isoformat(), "source_ip": "203.0.113.200"}
    assert _signed_post(pg_client, cred, body).status_code == 202
    assert _signed_post(pg_client, cred, body).status_code == 202
    assert _event_rows(app_engine, token["token_value"]) == [("CUSTOMER_HOOK", "CRITICAL", None)]


def test_concurrent_duplicate_reports_store_exactly_one_event(app_engine, seeded, monkeypatch):
    """Races past the pre-check must be resolved by the unique (integration, idempotency_key)."""
    import threading
    from datetime import datetime, timezone
    from app.models.honey_token import HoneyToken
    from app.models.integration import IntegrationCredential
    from app.repositories.detection_event import DetectionEventRepository
    from app.repositories.honey_token import HoneyTokenRepository
    from app.schemas.integration import IntegrationReport
    from app.services.detection_event import DetectionEventService
    from app.services.integration import IntegrationReportService

    _, _, project = seeded
    with Session(app_engine, expire_on_commit=False) as s:
        cred = IntegrationCredential(project_id=project.id, label="race")
        tok = HoneyToken(project_id=project.id, token_type="API_KEY", token_value="race-" + secrets.token_hex(12))
        s.add_all([cred, tok])
        s.commit()
        cred_id, tok_id = cred.id, tok.id

    report = IntegrationReport(decoy_id=tok.decoy_id, idempotency_key="race-" + secrets.token_hex(10),
                               observed_at=datetime.now(timezone.utc), source_ip="203.0.113.201")
    workers, barrier, results = 8, threading.Barrier(8), []

    def worker():
        with Session(app_engine) as s:
            c, t = s.get(IntegrationCredential, cred_id), s.get(HoneyToken, tok_id)
            events = DetectionEventService(s, DetectionEventRepository(s), HoneyTokenRepository(s))
            svc = IntegrationReportService(s)
            original = s.scalar
            def delayed_scalar(*a, **k):  # widen the race window after the duplicate pre-check
                out = original(*a, **k)
                barrier.wait(timeout=10)
                return out
            s.scalar = delayed_scalar
            results.append(svc.record(c, t, report, events) is not None)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert results.count(True) == 1 and len(results) == workers
    with app_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM detection_events WHERE honey_token_id = :t"),
                         {"t": tok_id}).scalar_one() == 1


def test_concurrent_workers_never_claim_the_same_delivery(app_engine, seeded, monkeypatch):
    """FOR UPDATE SKIP LOCKED: two workers claiming at once get disjoint sets."""
    import threading
    from datetime import datetime, timezone
    from app.models.alerting import AlertDestination, OutboxEvent, OutboxStatus
    from app.models.detection_event import DetectionEvent
    from app.models.enums import EventSource
    from app.models.honey_token import HoneyToken
    from app.services import alerting

    tenant, _, project = seeded
    with Session(app_engine, expire_on_commit=False) as s:
        dest = AlertDestination(tenant_id=tenant.id, url="https://hooks.example.com/x")
        tok = HoneyToken(project_id=project.id, token_type="URL", token_value="claim-" + secrets.token_hex(8))
        s.add_all([dest, tok])
        s.flush()
        for _ in range(40):
            ev = DetectionEvent(source=EventSource.PUBLIC_INGEST, honey_token_id=tok.id, ip_address="203.0.113.1",
                                request_path="/t/x", http_method="GET", severity="HIGH")
            s.add(ev)
            s.flush()
            s.add(OutboxEvent(tenant_id=tenant.id, detection_event_id=ev.id, destination_id=dest.id,
                              status=OutboxStatus.PENDING, next_attempt_at=datetime.now(timezone.utc)))
        s.commit()

    claimed: list[list[int]] = []
    barrier = threading.Barrier(4)

    def worker():
        with Session(app_engine) as s:
            barrier.wait(timeout=10)
            claimed.append(alerting.claim_due(s, 15))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    flat = [i for batch in claimed for i in batch]
    assert len(flat) == len(set(flat)) == 40


def test_concurrent_ingestion_produces_a_gapless_verified_chain(pg_client, app_engine, seeded):
    """The tenant head row lock serialises appends: 40 concurrent hits -> seq 1..40, verified."""
    import threading
    from app.services import evidence

    tenant, admin, project = seeded
    token = _generate(pg_client, admin, project, "URL")
    path = token["metadata"]["url"][len(INGEST_BASE):]
    barrier = threading.Barrier(8)
    codes = []

    def burst():
        barrier.wait(timeout=10)
        for _ in range(5):
            codes.append(pg_client.get(path).status_code)

    threads = [threading.Thread(target=burst) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert codes.count(204) == 40
    with Session(app_engine) as s:
        result = evidence.verify_tenant(s, tenant.id)
    assert result.ok, result.failures
    assert result.links_checked == 40 and result.head_seq == 40 and result.unchained_events == 0


def test_authorization_denial_does_not_commit_the_callers_pending_work(app_engine, seeded):
    """The denial audit is written in its own transaction."""
    from app.core.auth_exceptions import ForbiddenError
    from app.services.base import BaseService

    tenant, admin, _ = seeded
    slug = "pending-" + secrets.token_hex(4)
    with Session(app_engine) as s:
        caller_admin = s.get(User, admin.id)
        s.add(Tenant(name="Pending", slug=slug, is_active=True))
        s.flush()
        with pytest.raises(ForbiddenError):
            BaseService(s, current_user=caller_admin)._authorize_tenant_access(tenant.id + 10_000)
        s.rollback()
    with app_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM tenants WHERE slug = :s"), {"s": slug}).scalar_one() == 0
        assert c.execute(text("SELECT count(*) FROM audit_logs WHERE event_type = 'TENANT_ACCESS_DENIED' "
                              "AND actor_user_id = :u"), {"u": admin.id}).scalar_one() >= 1
