"""Retention on real PostgreSQL: only the schema owner, only inside a purge transaction, only DELETE."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.privileges import inspect_current_role
from app.models.detection_event import DetectionEvent
from app.services import audit_chain, evidence, retention

pytestmark = pytest.mark.postgres
KEY = "retention-pg-archive-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)


def _chained_events(app_engine, n: int) -> int:
    """Insert n events through the runtime role and chain them like the application does."""
    with Session(bind=app_engine) as s:
        s.execute(text("INSERT INTO tenants(name, slug, is_active) VALUES ('R', 'r-' || md5(random()::text), true)"))
        tid = s.execute(text("SELECT max(id) FROM tenants")).scalar_one()
        s.execute(text("INSERT INTO projects(tenant_id, name, domain, is_active) "
                       "VALUES (:t, 'P', md5(random()::text) || '.example', true)"), {"t": tid})
        pid = s.execute(text("SELECT max(id) FROM projects")).scalar_one()
        s.execute(text("INSERT INTO honey_tokens(project_id, token_type, token_value, is_active) "
                       "VALUES (:p, 'URL', md5(random()::text), true)"), {"p": pid})
        tok = s.execute(text("SELECT max(id) FROM honey_tokens")).scalar_one()
        for i in range(n):
            eid = s.execute(text(
                "INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source) "
                "VALUES (:t, :ip, '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"),
                {"t": tok, "ip": f"203.0.113.{i + 1}"}).scalar_one()
            evidence.append(s, s.get(DetectionEvent, eid), tid)
            s.commit()
        return tid


def _denied(engine, sql: str, guc: bool) -> str:
    with engine.connect() as conn:
        with pytest.raises((ProgrammingError, DBAPIError)) as exc:
            with conn.begin():
                if guc:
                    conn.execute(text("SET LOCAL honeyshield.retention_purge = 'on'"))
                conn.execute(text(sql))
    return str(exc.value.orig)


def test_runtime_role_cannot_delete_even_with_the_purge_flag(app_engine):
    _chained_events(app_engine, 1)
    for sql in ("DELETE FROM detection_events", "DELETE FROM evidence_chain", "DELETE FROM audit_logs",
                "DELETE FROM audit_chain", "DELETE FROM evidence_chain_anchors",
                "INSERT INTO evidence_chain_anchors VALUES (1, 1, repeat('a', 64), 1, now())"):
        assert "permission denied" in _denied(app_engine, sql, guc=True), sql


def test_owner_cannot_delete_without_the_flag_or_update_with_it(owner_engine, app_engine):
    _chained_events(app_engine, 1)
    assert "immutable" in _denied(owner_engine, "DELETE FROM evidence_chain", guc=False)
    assert "immutable" in _denied(owner_engine, "DELETE FROM detection_events", guc=False)
    assert "immutable" in _denied(owner_engine, "UPDATE detection_events SET ip_address = '10.0.0.1'", guc=True)
    assert "immutable" in _denied(owner_engine, "TRUNCATE audit_logs CASCADE", guc=True)


def test_owner_purge_archives_deletes_and_runtime_still_verifies(owner_engine, app_engine, tmp_path):
    tid = _chained_events(app_engine, 4)
    sink = evidence.WriteOnceDirectory(tmp_path)
    future_cutoff = datetime.now(timezone.utc) + timedelta(minutes=1)   # every link counts as old
    with Session(bind=owner_engine) as owner:
        res = retention.purge_tenant_events(owner, tid, future_cutoff, sink, batch=3)
    assert res.refused is None and res.purged == 4 and len(res.archives) == 2
    for path in sorted(tmp_path.glob("archive-evidence-*.jsonl")):
        retention.verify_archive(path.read_bytes())
    with Session(bind=app_engine) as app:
        r = evidence.verify_tenant(app, tid)
        assert r.ok and r.links_checked == 0 and r.head_seq == 4, r.failures
        assert app.execute(text("SELECT count(*) FROM evidence_chain WHERE tenant_id = :t"), {"t": tid}).scalar_one() == 0
        # The flag does not leak out of the purge transaction.
        assert (app.execute(text("SELECT current_setting('honeyshield.retention_purge', true)")).scalar() or "") != "on"
    with app_engine.connect() as conn:
        assert inspect_current_role(conn).ok


def test_owner_purges_the_audit_log_and_runtime_verifies(owner_engine, app_engine, tmp_path):
    with app_engine.begin() as conn:
        for i in range(3):
            conn.execute(text("INSERT INTO audit_logs(event_type, severity, message, actor_source) "
                              "VALUES ('PG_RETENTION', 'INFO', :m, 'SYSTEM')"), {"m": f"r{i}"})
    with Session(bind=app_engine) as app:
        audit_chain.seal(app)
    sink = evidence.WriteOnceDirectory(tmp_path)
    with Session(bind=owner_engine) as owner:
        res = retention.purge_audit_log(owner, datetime.now(timezone.utc) + timedelta(minutes=1), sink)
    assert res.refused is None and res.purged >= 3
    with Session(bind=app_engine) as app:
        audit_chain.seal(app)
        r = audit_chain.verify(app)
        assert r.ok, r.failures
