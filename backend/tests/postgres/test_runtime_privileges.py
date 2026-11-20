"""HONEY-002 acceptance: the runtime role cannot rewrite, delete or unprotect evidence.

Every statement here runs on a real PostgreSQL connection authenticated as the role
under test. ORM hooks are not involved.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.db import runtime_guard
from app.db.privileges import UnclassifiedTableError, grant_statements, inspect_current_role

pytestmark = pytest.mark.postgres


def _seed(conn) -> int:
    conn.execute(text("INSERT INTO tenants(name, slug, is_active) VALUES ('T', 't-' || md5(random()::text), true)"))
    tid = conn.execute(text("SELECT max(id) FROM tenants")).scalar_one()
    conn.execute(text("INSERT INTO projects(tenant_id, name, domain, is_active) VALUES (:t, 'P', md5(random()::text) || '.example', true)"), {"t": tid})
    pid = conn.execute(text("SELECT max(id) FROM projects")).scalar_one()
    conn.execute(text("INSERT INTO honey_tokens(project_id, token_type, token_value, is_active) VALUES (:p, 'URL', md5(random()::text), true)"), {"p": pid})
    return conn.execute(text("SELECT max(id) FROM honey_tokens")).scalar_one()


def _insert_event(conn, token_id: int) -> int:
    return conn.execute(text(
        "INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source) "
        "VALUES (:t, '203.0.113.9', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"), {"t": token_id}).scalar_one()


def _denied(engine, sql: str, params: dict | None = None) -> str:
    with engine.connect() as conn:
        with pytest.raises((ProgrammingError, DBAPIError)) as exc:
            conn.execute(text(sql), params or {})
            conn.commit()
        conn.rollback()
    return str(exc.value.orig) if getattr(exc.value, "orig", None) else str(exc.value)


@pytest.fixture()
def event_id(app_engine) -> int:
    with app_engine.begin() as conn:
        return _insert_event(conn, _seed(conn))


def test_runtime_can_insert_and_read_evidence(app_engine, event_id):
    with app_engine.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM detection_events WHERE id = :i"), {"i": event_id}).scalar_one() == 1
        conn.execute(text("INSERT INTO audit_logs(event_type, severity, message, target_entity, target_id, metadata) "
                          "VALUES ('PG_TEST', 'INFO', 'pg test', 'test', '1', '{}'::jsonb)"))


@pytest.mark.parametrize("sql", [
    "UPDATE detection_events SET severity = 'LOW' WHERE id = :i",
    "DELETE FROM detection_events WHERE id = :i",
    "TRUNCATE detection_events",
    "UPDATE audit_logs SET event_type = 'X'",
    "DELETE FROM audit_logs",
    "TRUNCATE audit_logs",
])
def test_runtime_cannot_rewrite_or_delete_evidence(app_engine, event_id, sql):
    msg = _denied(app_engine, sql, {"i": event_id} if ":i" in sql else None)
    assert "permission denied" in msg


@pytest.mark.parametrize("sql", [
    "ALTER TABLE detection_events DISABLE TRIGGER ALL",
    "ALTER TABLE audit_logs DISABLE TRIGGER USER",
    "DROP TRIGGER IF EXISTS trg_detection_events_immutable ON detection_events",
    "ALTER TABLE detection_events DROP COLUMN source",
    "DROP TABLE detection_events",
    "CREATE TABLE shadow_events (id int)",
    "CREATE OR REPLACE FUNCTION prevent_forensic_modification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
    "SET session_replication_role = replica",
])
def test_runtime_cannot_change_schema_or_disable_protection(app_engine, sql):
    msg = _denied(app_engine, sql)
    assert "must be owner" in msg or "permission denied" in msg


def test_runtime_can_maintain_mutable_state(app_engine):
    with app_engine.begin() as conn:
        tok = _seed(conn)
        conn.execute(text("UPDATE honey_tokens SET is_active = false WHERE id = :t"), {"t": tok})


def test_evidence_is_immutable_even_for_the_owner_while_triggers_exist(owner_engine, event_id):
    msg = _denied(owner_engine, "UPDATE detection_events SET severity = 'LOW' WHERE id = :i", {"i": event_id})
    assert "immutable" in msg


def test_privilege_inspection_passes_for_runtime_and_fails_for_owner(app_engine, owner_engine):
    with app_engine.connect() as conn:
        report = inspect_current_role(conn)
    assert report.ok, report.violations
    with owner_engine.connect() as conn:
        owner_report = inspect_current_role(conn)
    assert not owner_report.ok
    assert any("owns tables" in v for v in owner_report.violations)


def test_startup_guard_accepts_runtime_and_refuses_owner(app_engine, owner_engine):
    runtime_guard.reset()
    assert runtime_guard.ensure_least_privilege(app_engine) is True
    runtime_guard.reset()
    with pytest.raises(runtime_guard.PrivilegedRuntimeRoleError):
        runtime_guard.ensure_least_privilege(owner_engine)
    runtime_guard.reset()


def test_grant_refuses_unclassified_tables(owner_engine, pg):
    with owner_engine.connect() as conn:
        conn.execute(text("CREATE TABLE stray_unclassified (id int)"))
        with pytest.raises(UnclassifiedTableError):
            grant_statements(conn, pg.app)
        conn.rollback()


def test_runtime_has_no_access_to_an_ungranted_table(owner_engine, app_engine):
    with owner_engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS stray_ungranted (id int)"))
    try:
        assert "permission denied" in _denied(app_engine, "SELECT * FROM stray_ungranted")
    finally:
        with owner_engine.begin() as conn:
            conn.execute(text("DROP TABLE stray_ungranted"))


@pytest.mark.parametrize("sql", [
    "UPDATE evidence_chain SET record_hash = 'x'",
    "DELETE FROM evidence_chain",
    "TRUNCATE evidence_chain",
    "ALTER TABLE evidence_chain DISABLE TRIGGER ALL",
])
def test_runtime_cannot_rewrite_the_evidence_chain(app_engine, sql):
    msg = _denied(app_engine, sql)
    assert "permission denied" in msg or "must be owner" in msg


def test_owner_cannot_rewrite_chain_links_while_triggers_exist(owner_engine, event_id):
    with owner_engine.begin() as conn:
        tenant_id = conn.execute(text(
            "SELECT p.tenant_id FROM detection_events e JOIN honey_tokens t ON t.id = e.honey_token_id "
            "JOIN projects p ON p.id = t.project_id WHERE e.id = :i"), {"i": event_id}).scalar_one()
        link_id = conn.execute(text(
            "INSERT INTO evidence_chain(tenant_id, seq, detection_event_id, prev_hash, record_hash) "
            "VALUES (:t, 1000000 + :i, :i, repeat('0', 64), repeat('a', 64)) RETURNING id"),
            {"t": tenant_id, "i": event_id}).scalar_one()
    msg = _denied(owner_engine, "UPDATE evidence_chain SET record_hash = repeat('b', 64) WHERE id = :l", {"l": link_id})
    assert "immutable" in msg


@pytest.mark.parametrize("sql", [
    "UPDATE audit_chain SET record_hash = 'x'",
    "DELETE FROM audit_chain",
    "TRUNCATE audit_chain",
    "ALTER TABLE audit_chain DISABLE TRIGGER ALL",
    "UPDATE audit_logs SET message = 'x'",
    "DELETE FROM audit_logs",
])
def test_runtime_cannot_rewrite_the_audit_log_or_its_chain(app_engine, sql):
    msg = _denied(app_engine, sql)
    assert "permission denied" in msg or "must be owner" in msg


def test_runtime_seals_and_verifies_the_audit_chain(app_engine):
    """The checkpointer runs as the runtime role: sealing must work with its grants alone."""
    from sqlalchemy.orm import Session

    from app.services import audit_chain

    with app_engine.begin() as conn:
        for i in range(3):
            conn.execute(text("INSERT INTO audit_logs(event_type, severity, message, actor_source, metadata) "
                              "VALUES ('PG_SEAL_TEST', 'INFO', :m, 'SYSTEM', CAST(:md AS jsonb))"),
                         {"m": f"record {i}", "md": '{"b": 2, "a": [1, "x"], "f": 1.5}'})
    with Session(bind=app_engine) as s:
        assert audit_chain.seal(s) >= 3
        assert audit_chain.seal(s) == 0
        r = audit_chain.verify(s)
        assert r.ok and r.unsealed_records == 0 and r.links_checked >= 3, r.failures


def test_owner_cannot_rewrite_audit_chain_links_while_triggers_exist(owner_engine, app_engine):
    from sqlalchemy.orm import Session

    from app.services import audit_chain

    with app_engine.begin() as conn:
        conn.execute(text("INSERT INTO audit_logs(event_type, severity, message, actor_source) "
                          "VALUES ('PG_SEAL_TEST', 'INFO', 'owner test', 'SYSTEM')"))
    with Session(bind=app_engine) as s:
        audit_chain.seal(s)
    msg = _denied(owner_engine, "UPDATE audit_chain SET record_hash = repeat('b', 64)")
    assert "immutable" in msg
