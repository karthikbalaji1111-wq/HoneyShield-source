"""Migration 20261122_01 on real PostgreSQL: CLOUD_AUDIT is a valid source, one event per CloudTrail id."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

pytestmark = pytest.mark.postgres


def _token(conn, token_type="AWS_KEY"):
    conn.execute(text("INSERT INTO tenants(name, slug, is_active) VALUES ('C', 'c-' || md5(random()::text), true)"))
    tid = conn.execute(text("SELECT max(id) FROM tenants")).scalar_one()
    conn.execute(text("INSERT INTO projects(tenant_id, name, domain, is_active) VALUES (:t, 'P', md5(random()::text) || '.ex', true)"),
                 {"t": tid})
    pid = conn.execute(text("SELECT max(id) FROM projects")).scalar_one()
    return conn.execute(text("INSERT INTO honey_tokens(project_id, token_type, token_value, is_active) "
                             "VALUES (:p, :k, md5(random()::text), true) RETURNING id"), {"p": pid, "k": token_type}).scalar_one()


def _event(conn, token_id, source, key):
    conn.execute(text("""INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity,
                         source, idempotency_key, triggered_at)
                         VALUES (:t, '203.0.113.7', 'sts.amazonaws.com/GetCallerIdentity', 'AWS', 'CRITICAL', :s, :k, now())"""),
                 {"t": token_id, "s": source, "k": key})


def test_cloud_audit_events_are_accepted_once_per_cloudtrail_id(app_engine):
    event_id = str(uuid.uuid4())
    with app_engine.begin() as conn:
        tok = _token(conn)
        _event(conn, tok, "CLOUD_AUDIT", event_id)
    with pytest.raises(IntegrityError, match="uq_detection_events_cloud_event"):
        with app_engine.begin() as conn:
            _event(conn, tok, "CLOUD_AUDIT", event_id)
    with app_engine.begin() as conn:
        # The same key under another source is a different event (the indexes are per source).
        _event(conn, tok, "PUBLIC_INGEST", event_id)


def test_unknown_sources_are_still_refused(app_engine):
    with pytest.raises(IntegrityError, match="valid_event_source"):
        with app_engine.begin() as conn:
            _event(conn, _token(conn), "SOMETHING_ELSE", None)


def test_dns_aws_key_and_document_decoys_need_no_schema_change(app_engine):
    with app_engine.begin() as conn:
        assert _token(conn, "DNS") and _token(conn, "AWS_KEY") and _token(conn, "DOCUMENT")
