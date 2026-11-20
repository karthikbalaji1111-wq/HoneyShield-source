"""Retention: archive-then-purge keeps both chains verifiable and never purges a broken chain.

SQLite has no triggers, so "old" rows are simulated with Core SQL. The PostgreSQL behaviour
(trigger exemption only for the owner, inside the purge transaction) is in
tests/postgres/test_retention_pg.py.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.core.config import Settings, get_settings
from app.models.alerting import OutboxEvent
from app.models.audit_chain import AuditChainAnchor, AuditChainLink
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.evidence import EvidenceChainAnchor, EvidenceChainLink
from app.services import audit_chain, evidence, retention
from tests.conftest import auth_headers

KEY = "retention-archive-key-for-tests-0123456789ab"
OLD = datetime.now(timezone.utc) - timedelta(days=400)
OLD_SQL = OLD.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")  # raw SQL on SQLite: string form


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)


@pytest.fixture()
def sink(tmp_path):
    return evidence.WriteOnceDirectory(tmp_path)


def _hits(client, token, n):
    for i in range(n):
        assert client.get(f"/t/{token.token_value}", headers={"User-Agent": f"ua-{i}"}).status_code == 204


def _age_links(db_session, tenant_id, seqs):
    for seq in seqs:
        db_session.execute(text("UPDATE evidence_chain SET created_at = :t WHERE tenant_id = :tid AND seq = :s"),
                           {"t": OLD_SQL, "tid": tenant_id, "s": seq})
    db_session.commit()


def _cutoff():
    return datetime.now(timezone.utc) - timedelta(days=365)


def _verify(db_session, tenant_id, cps=None):
    db_session.expire_all()
    return evidence.verify_tenant(db_session, tenant_id, cps)


def test_old_prefix_is_archived_purged_and_the_chain_still_verifies(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 5)
    _age_links(db_session, tenant_a.id, [1, 2, 3])
    head_before = _verify(db_session, tenant_a.id)
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    assert (res.purged, res.through_seq, res.refused) == (3, 3, None)
    db_session.expire_all()
    assert db_session.query(EvidenceChainLink).filter_by(tenant_id=tenant_a.id).count() == 2
    anchor = db_session.get(EvidenceChainAnchor, tenant_a.id)
    assert (anchor.purged_through_seq, anchor.events_purged) == (3, 3)
    after = _verify(db_session, tenant_a.id)
    assert after.ok and after.head_seq == head_before.head_seq and after.links_checked == 2
    # New evidence keeps chaining from the unchanged head.
    _hits(client, token_a, 1)
    assert _verify(db_session, tenant_a.id).ok
    # The archive re-verifies offline and ends at the anchor.
    (archive,) = sink.root.glob("archive-evidence-*.jsonl")
    header = retention.verify_archive(archive.read_bytes())
    assert (header["from_seq"], header["through_seq"], header["records"]) == (1, 3, 3)
    assert header["prev_hash"] == evidence.GENESIS and header["through_hash"] == anchor.anchor_hash
    audit = db_session.query(AuditLog).filter_by(event_type="RETENTION_PURGE").one()
    assert audit.event_metadata["archive"] == archive.name and audit.tenant_id == tenant_a.id


def test_only_a_contiguous_prefix_is_purged(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 3)
    _age_links(db_session, tenant_a.id, [1, 3])                  # seq 2 is recent
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    assert (res.purged, res.through_seq) == (1, 1)
    assert _verify(db_session, tenant_a.id).ok


def test_second_purge_continues_from_the_anchor(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 4)
    _age_links(db_session, tenant_a.id, [1, 2])
    retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    _age_links(db_session, tenant_a.id, [3])
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    assert (res.purged, res.through_seq) == (1, 3)
    archives = sorted(sink.root.glob("archive-evidence-*.jsonl"))
    headers = [retention.verify_archive(a.read_bytes()) for a in archives]
    assert headers[1]["prev_hash"] == headers[0]["through_hash"]   # archives chain together
    assert _verify(db_session, tenant_a.id).ok


def test_batches_are_separate_archives(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 5)
    _age_links(db_session, tenant_a.id, [1, 2, 3, 4, 5])
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink, batch=2)
    assert res.purged == 5 and len(res.archives) == 3
    assert _verify(db_session, tenant_a.id).ok


def test_tampered_chain_is_never_purged(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 3)
    _age_links(db_session, tenant_a.id, [1, 2, 3])
    db_session.execute(text("UPDATE detection_events SET ip_address = '10.6.6.6' WHERE id = "
                            "(SELECT detection_event_id FROM evidence_chain WHERE seq = 2 AND tenant_id = :t)"),
                       {"t": tenant_a.id})
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    assert res.refused and "does not verify" in res.refused and res.purged == 0
    db_session.expire_all()
    assert db_session.query(EvidenceChainLink).filter_by(tenant_id=tenant_a.id).count() == 3
    assert not list(sink.root.glob("archive-*"))


def test_outbox_rows_of_purged_events_go_too(client, db_session, admin_a, token_a, tenant_a, sink, monkeypatch):
    from app.services.alerting import webhook

    monkeypatch.setattr(webhook, "default_resolver", lambda h, p: ["93.184.216.34"])
    assert client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/x", "min_severity": "LOW"},
                       headers=auth_headers(admin_a)).status_code == 201
    _hits(client, token_a, 2)
    assert db_session.query(OutboxEvent).count() == 2
    _age_links(db_session, tenant_a.id, [1])
    retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    db_session.expire_all()
    assert db_session.query(OutboxEvent).count() == 1


def test_dry_run_changes_nothing(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 2)
    _age_links(db_session, tenant_a.id, [1, 2])
    res = retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink, dry_run=True)
    assert res.dry_run and res.purged == 2 and not res.archives
    db_session.expire_all()
    assert db_session.query(DetectionEvent).count() == 2 and not list(sink.root.iterdir())


def test_checkpoints_taken_before_a_purge_still_verify(client, db_session, token_a, tenant_a, sink, tmp_path):
    _hits(client, token_a, 4)
    cps = evidence.make_checkpoints(db_session)                    # head at seq 4
    _age_links(db_session, tenant_a.id, [1, 2])
    retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    early = [{**cp, "seq": 1} for cp in cps if cp.get("tenant_id") == tenant_a.id]  # purged range: skipped
    assert _verify(db_session, tenant_a.id, cps).ok
    assert _verify(db_session, tenant_a.id, early).ok


def test_tampered_archive_is_detected(client, db_session, token_a, tenant_a, sink):
    _hits(client, token_a, 2)
    _age_links(db_session, tenant_a.id, [1, 2])
    retention.purge_tenant_events(db_session, tenant_a.id, _cutoff(), sink)
    (archive,) = sink.root.glob("archive-evidence-*.jsonl")
    data = archive.read_bytes()
    with pytest.raises(ValueError, match="signature"):
        retention.verify_archive(data.replace(b"ua-0", b"ua-X"))
    lines = data.split(b"\n")
    rec = json.loads(lines[1])
    rec["canonical"]["ip_address"] = "10.0.0.1"
    forged = b"\n".join([lines[0], json.dumps(rec, sort_keys=True).encode(), *lines[2:-2]]) + b"\n"
    resigned = retention.build_archive(json.loads(lines[0]) | {}, [json.loads(x) for x in forged.split(b"\n")[1:-1]])
    with pytest.raises(ValueError, match="chain broken"):
        retention.verify_archive(resigned)


# --------------------------------------------------------------------------- audit log

def _audit_rows(db_session, n):
    db_session.add_all([AuditLog(event_type="TEST_EVENT", severity="INFO", message=f"r{i}", actor_source="SYSTEM")
                        for i in range(n)])
    db_session.commit()


def test_audit_log_prefix_is_archived_and_purged(db_session, sink):
    _audit_rows(db_session, 4)
    audit_chain.seal(db_session)
    total = db_session.query(AuditChainLink).count()
    db_session.execute(text("UPDATE audit_chain SET created_at = :t WHERE seq <= :s"), {"t": OLD_SQL, "s": total - 1})
    db_session.commit()
    res = retention.purge_audit_log(db_session, _cutoff(), sink)
    assert (res.purged, res.through_seq, res.refused) == (total - 1, total - 1, None)
    db_session.expire_all()
    anchor = db_session.get(AuditChainAnchor, 1)
    assert anchor.purged_through_seq == total - 1
    audit_chain.seal(db_session)                                  # the RETENTION_PURGE record itself
    r = audit_chain.verify(db_session)
    assert r.ok and r.links_checked == 2, r.failures
    (archive,) = sink.root.glob("archive-audit-*.jsonl")
    assert retention.verify_archive(archive.read_bytes())["records"] == total - 1


def test_tampered_audit_chain_is_never_purged(db_session, sink):
    _audit_rows(db_session, 3)
    audit_chain.seal(db_session)
    db_session.execute(text("UPDATE audit_chain SET created_at = :t"), {"t": OLD_SQL})
    db_session.execute(text("UPDATE audit_logs SET message = 'edited' WHERE id = (SELECT min(audit_log_id) FROM audit_chain)"))
    db_session.commit()
    res = retention.purge_audit_log(db_session, _cutoff(), sink)
    assert res.refused and res.purged == 0


# --------------------------------------------------------------------------- guards

def test_short_retention_is_refused():
    with pytest.raises(retention.RetentionRefused):
        retention.cutoff_for(7)
    with pytest.raises(ValueError, match="at least 30"):
        Settings(jwt_secret_key="x" * 40, event_retention_days=7)
    assert Settings(jwt_secret_key="x" * 40, event_retention_days=0, audit_retention_days=365).audit_retention_days == 365
