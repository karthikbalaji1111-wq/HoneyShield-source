"""Trigger-maintained tenant event totals: exact under every insert/delete path; not editable by the app."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.repositories.detection_event import DetectionEventRepository
from app.services import evidence, retention

pytestmark = pytest.mark.postgres


def _tenant_with_tokens(conn, n_tokens=3):
    conn.execute(text("INSERT INTO tenants(name, slug, is_active) VALUES ('C', 'c-' || md5(random()::text), true)"))
    tid = conn.execute(text("SELECT max(id) FROM tenants")).scalar_one()
    conn.execute(text("INSERT INTO projects(tenant_id, name, domain, is_active) VALUES (:t, 'P', md5(random()::text) || '.ex', true)"), {"t": tid})
    pid = conn.execute(text("SELECT max(id) FROM projects")).scalar_one()
    toks = []
    for _ in range(n_tokens):
        toks.append(conn.execute(text("INSERT INTO honey_tokens(project_id, token_type, token_value, is_active) "
                                      "VALUES (:p, 'URL', md5(random()::text), true) RETURNING id"), {"p": pid}).scalar_one())
    return tid, toks


def _insert(conn, token_ids, n, when="now()"):
    conn.execute(text(f"""INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source, triggered_at)
        SELECT (:toks)[1 + (g % cardinality(:toks))], '203.0.113.1', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST', {when}
        FROM generate_series(1, :n) g"""), {"toks": token_ids, "n": n})


def _total(conn, tid):
    return conn.execute(text("SELECT coalesce((SELECT total FROM tenant_event_counts WHERE tenant_id = :t), 0)"), {"t": tid}).scalar_one()


def _exact(conn, tid):
    return conn.execute(text("SELECT count(*) FROM detection_events e JOIN honey_tokens t ON t.id = e.honey_token_id "
                             "JOIN projects p ON p.id = t.project_id WHERE p.tenant_id = :t"), {"t": tid}).scalar_one()


def _daily(conn, tid):
    rows = conn.execute(text("SELECT day, severity, total FROM tenant_daily_event_counts WHERE tenant_id = :t AND total <> 0"),
                        {"t": tid}).all()
    return {(d, s): n for d, s, n in rows}


def _daily_exact(conn, tid):
    rows = conn.execute(text("SELECT (triggered_at AT TIME ZONE 'UTC')::date, severity, count(*) FROM detection_events "
                             "WHERE tenant_id = :t GROUP BY 1, 2"), {"t": tid}).all()
    return {(d, s): n for d, s, n in rows}


def test_daily_totals_are_exact_for_inserts_across_days_and_severities(app_engine):
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        _insert(conn, toks, 30)
        _insert(conn, toks, 12, "now() - interval '3 days'")
        conn.execute(text("""INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source, triggered_at)
            SELECT :t, '203.0.113.2', '/t/y', 'GET', (ARRAY['LOW','MEDIUM','CRITICAL'])[1 + g % 3], 'PUBLIC_INGEST', now() - make_interval(days => g % 5)
            FROM generate_series(1, 45) g"""), {"t": toks[0]})
    with app_engine.connect() as conn:
        daily = _daily(conn, tid)
        assert daily == _daily_exact(conn, tid)
        assert sum(daily.values()) == 87 == _total(conn, tid)


def test_runtime_role_cannot_edit_the_daily_totals(app_engine):
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        _insert(conn, toks, 1)
    for sql in ("UPDATE tenant_daily_event_counts SET total = 0", "DELETE FROM tenant_daily_event_counts",
                "INSERT INTO tenant_daily_event_counts VALUES (999999, current_date, 'HIGH', 1)"):
        with app_engine.connect() as conn:
            with pytest.raises((ProgrammingError, DBAPIError)) as exc:
                with conn.begin():
                    conn.execute(text(sql))
            assert "permission denied" in str(exc.value.orig)


def test_counts_follow_single_and_bulk_inserts_by_the_runtime_role(app_engine):
    with app_engine.begin() as conn:
        a, toks_a = _tenant_with_tokens(conn)
        b, toks_b = _tenant_with_tokens(conn)
        _insert(conn, toks_a, 1)
        _insert(conn, toks_a, 250)                 # one statement, many rows
        _insert(conn, toks_b, 7, "now() - interval '3 days'")
    with app_engine.connect() as conn:
        assert (_total(conn, a), _total(conn, b)) == (251, 7)
        assert (_exact(conn, a), _exact(conn, b)) == (251, 7)


def test_statistics_use_the_counters_and_stay_exact(app_engine):
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        _insert(conn, toks, 40)
        _insert(conn, toks, 5, "now() - interval '2 days'")
    with Session(bind=app_engine) as s:
        total, today = DetectionEventRepository(s).count_summary(tenant_id=tid)
        assert (total, today) == (45, 40)
        g_total, _ = DetectionEventRepository(s).count_summary(tenant_id=None)
        exact_all = s.execute(text("SELECT count(*) FROM detection_events")).scalar_one()
        assert g_total == exact_all


def test_runtime_role_cannot_edit_the_counters(app_engine):
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        _insert(conn, toks, 2)
    for sql in ("UPDATE tenant_event_counts SET total = 0", "DELETE FROM tenant_event_counts",
                "INSERT INTO tenant_event_counts VALUES (999999, 1)"):
        with app_engine.connect() as conn:
            with pytest.raises((ProgrammingError, DBAPIError)) as exc:
                with conn.begin():
                    conn.execute(text(sql))
            assert "permission denied" in str(exc.value.orig)


def test_retention_purge_decrements_the_counters(owner_engine, app_engine, tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", "count-test-archive-key-0123456789abcdef")
    from app.models.detection_event import DetectionEvent
    with Session(bind=app_engine) as s:
        s.execute(text("INSERT INTO tenants(name, slug, is_active) VALUES ('R', 'r-' || md5(random()::text), true)"))
        tid = s.execute(text("SELECT max(id) FROM tenants")).scalar_one()
        s.execute(text("INSERT INTO projects(tenant_id, name, domain, is_active) VALUES (:t, 'P', md5(random()::text) || '.ex', true)"), {"t": tid})
        pid = s.execute(text("SELECT max(id) FROM projects")).scalar_one()
        tok = s.execute(text("INSERT INTO honey_tokens(project_id, token_type, token_value, is_active) "
                             "VALUES (:p, 'URL', md5(random()::text), true) RETURNING id"), {"p": pid}).scalar_one()
        for i in range(6):
            eid = s.execute(text("INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source) "
                                 "VALUES (:t, '198.51.100.9', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"), {"t": tok}).scalar_one()
            evidence.append(s, s.get(DetectionEvent, eid), tid)
            s.commit()
    with app_engine.connect() as conn:
        assert _total(conn, tid) == 6
    with Session(bind=owner_engine) as owner:
        res = retention.purge_tenant_events(owner, tid, datetime.now(timezone.utc) + timedelta(minutes=1),
                                            evidence.WriteOnceDirectory(tmp_path), batch=4)
    assert res.purged == 6
    with app_engine.connect() as conn:
        assert _total(conn, tid) == 0 == _exact(conn, tid)
        assert _daily(conn, tid) == {}


def test_tenant_id_is_derived_by_the_database_and_cannot_be_forged_or_changed(app_engine):
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        other, _ = _tenant_with_tokens(conn)
        eid = conn.execute(text(
            "INSERT INTO detection_events(honey_token_id, tenant_id, ip_address, request_path, http_method, severity, source) "
            "VALUES (:t, :forged, '203.0.113.7', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"),
            {"t": toks[0], "forged": other}).scalar_one()
        assert conn.execute(text("SELECT tenant_id FROM detection_events WHERE id = :i"), {"i": eid}).scalar_one() == tid
    with app_engine.connect() as conn:
        with pytest.raises((ProgrammingError, DBAPIError)):
            with conn.begin():
                conn.execute(text("UPDATE detection_events SET tenant_id = :o WHERE id = :i"), {"o": other, "i": eid})


def test_immutability_allows_only_the_correct_tenant_fill(owner_engine, app_engine):
    """The single exception: fill a NULL tenant_id with the derived tenant, nothing else changed."""
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        other, _ = _tenant_with_tokens(conn)
        eid = conn.execute(text(
            "INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source) "
            "VALUES (:t, '203.0.113.8', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"), {"t": toks[0]}).scalar_one()

    def owner_update(sql, **p):
        with owner_engine.connect() as conn:
            with conn.begin():
                conn.execute(text(sql), {"i": eid, **p})

    # simulate a legacy row: the owner may not even blank it
    with pytest.raises((ProgrammingError, DBAPIError)):
        owner_update("UPDATE detection_events SET tenant_id = NULL WHERE id = :i")
    # a populated tenant can never be changed, even to another real tenant
    with pytest.raises((ProgrammingError, DBAPIError)):
        owner_update("UPDATE detection_events SET tenant_id = :o WHERE id = :i", o=other)
    # evidence fields stay immutable
    with pytest.raises((ProgrammingError, DBAPIError)):
        owner_update("UPDATE detection_events SET ip_address = '10.0.0.1' WHERE id = :i")
    # the runtime role has no UPDATE privilege at all
    with app_engine.connect() as conn:
        with pytest.raises((ProgrammingError, DBAPIError)) as exc:
            with conn.begin():
                conn.execute(text("UPDATE detection_events SET tenant_id = tenant_id WHERE id = :i"), {"i": eid})
        assert "permission denied" in str(exc.value.orig)


def test_fill_exception_accepts_only_the_derived_tenant(owner_engine):
    """Exercise the fill path on a legacy-style NULL row (created with the BEFORE trigger off)."""
    with owner_engine.connect() as conn:
        with conn.begin():
            tid, toks = _tenant_with_tokens(conn)
            other, _ = _tenant_with_tokens(conn)
            conn.execute(text("ALTER TABLE detection_events DISABLE TRIGGER trg_detection_events_tenant"))
            eid = conn.execute(text(
                "INSERT INTO detection_events(honey_token_id, ip_address, request_path, http_method, severity, source) "
                "VALUES (:t, '203.0.113.9', '/t/x', 'GET', 'HIGH', 'PUBLIC_INGEST') RETURNING id"), {"t": toks[0]}).scalar_one()
            conn.execute(text("ALTER TABLE detection_events ENABLE TRIGGER trg_detection_events_tenant"))
        with pytest.raises((ProgrammingError, DBAPIError)):
            with conn.begin():
                conn.execute(text("UPDATE detection_events SET tenant_id = :o WHERE id = :i"), {"o": other, "i": eid})
        with pytest.raises((ProgrammingError, DBAPIError)):
            with conn.begin():
                conn.execute(text("UPDATE detection_events SET tenant_id = :t, user_agent = 'x' WHERE id = :i"),
                             {"t": tid, "i": eid})
        with conn.begin():
            conn.execute(text("UPDATE detection_events SET tenant_id = :t WHERE id = :i"), {"t": tid, "i": eid})
        assert conn.execute(text("SELECT tenant_id FROM detection_events WHERE id = :i"), {"i": eid}).scalar_one() == tid


def test_daily_activity_buckets_by_utc_day_on_postgres(app_engine):
    """The console's activity chart: UTC-day buckets, tenant-scoped, on the real dialect."""
    with app_engine.begin() as conn:
        tid, toks = _tenant_with_tokens(conn)
        other, other_toks = _tenant_with_tokens(conn)
        # 23:30 and 00:30 UTC fall on different UTC days whatever the session time zone is.
        conn.execute(text("SET LOCAL TIME ZONE 'Asia/Kolkata'"))
        _insert(conn, toks, 3, "date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' - interval '30 minutes'")
        _insert(conn, toks, 2, "date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' + interval '30 minutes'")
        _insert(conn, other_toks, 7, "now()")
    since = datetime.now(timezone.utc) - timedelta(days=3)
    with Session(bind=app_engine) as s:
        rows = DetectionEventRepository(s).daily_activity(tenant_id=tid, since=since)
    today = datetime.now(timezone.utc).date()
    got = {(d, sev): n for d, sev, n in rows}
    assert got == {((today - timedelta(days=1)).isoformat(), "HIGH"): 3, (today.isoformat(), "HIGH"): 2}
