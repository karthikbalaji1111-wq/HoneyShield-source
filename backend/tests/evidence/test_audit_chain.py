"""Tamper-evident audit log chain: sealing, verification, checkpoints and the API.

Tampering is simulated with Core SQL, which bypasses the ORM immutability hook (SQLite has no
triggers). On PostgreSQL the runtime role cannot UPDATE/DELETE audit_logs or audit_chain at all;
these tests prove that a party who can (a superuser, a tampered backup) is still detected.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.models.audit_chain import AuditChainHead, AuditChainLink
from app.models.audit_log import AuditLog
from app.services import audit_chain, evidence
from tests.conftest import auth_headers

KEY = "audit-checkpoint-key-for-tests-0123456789"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)


def _records(db_session, n, **extra):
    rows = [AuditLog(event_type="TEST_EVENT", severity="INFO", message=f"record {i}", actor_source="SYSTEM",
                     event_metadata={"i": i, "nested": {"k": "v"}}, **extra) for i in range(n)]
    db_session.add_all(rows)
    db_session.commit()
    return rows


def _verify(db_session, checkpoints=None):
    db_session.expire_all()
    return audit_chain.verify(db_session, checkpoints)


def test_seal_chains_every_record_in_id_order_and_is_idempotent(db_session):
    rows = _records(db_session, 4)
    assert audit_chain.seal(db_session) >= 4
    assert audit_chain.seal(db_session) == 0
    links = db_session.query(AuditChainLink).order_by(AuditChainLink.seq).all()
    assert [l.seq for l in links] == list(range(1, len(links) + 1))
    assert links[0].prev_hash == audit_chain.GENESIS
    assert all(b.prev_hash == a.record_hash for a, b in zip(links, links[1:]))
    by_record = [l.audit_log_id for l in links]
    assert by_record == sorted(by_record) and {r.id for r in rows} <= set(by_record)
    head = db_session.get(AuditChainHead, 1)
    assert (head.seq, head.head_hash) == (links[-1].seq, links[-1].record_hash)
    r = _verify(db_session)
    assert r.ok and r.links_checked == len(links) and r.unsealed_records == 0


def test_seal_appends_after_existing_links(db_session):
    _records(db_session, 2)
    audit_chain.seal(db_session)
    first_head = db_session.get(AuditChainHead, 1).seq
    _records(db_session, 3)
    assert audit_chain.seal(db_session) == 3
    assert db_session.get(AuditChainHead, 1).seq == first_head + 3
    assert _verify(db_session).ok


def test_small_batches_produce_the_same_chain(db_session):
    _records(db_session, 7)
    assert audit_chain.seal(db_session, batch=2) >= 7
    assert _verify(db_session).ok


def test_modified_record_is_detected(db_session):
    rows = _records(db_session, 3)
    audit_chain.seal(db_session)
    db_session.execute(text("UPDATE audit_logs SET message = 'nothing happened' WHERE id = :i"), {"i": rows[1].id})
    r = _verify(db_session)
    assert not r.ok
    assert any(f["kind"] == "record_modified" and f["audit_log_id"] == rows[1].id for f in r.failures)


def test_modified_metadata_is_detected(db_session):
    rows = _records(db_session, 2)
    audit_chain.seal(db_session)
    db_session.execute(text("UPDATE audit_logs SET metadata = '{\"i\": 99}' WHERE id = :i"), {"i": rows[0].id})
    assert {f["kind"] for f in _verify(db_session).failures} == {"record_modified"}


def test_deleted_record_and_link_are_detected(db_session):
    rows = _records(db_session, 3)
    audit_chain.seal(db_session)
    db_session.execute(text("DELETE FROM audit_chain WHERE audit_log_id = :i"), {"i": rows[1].id})
    db_session.execute(text("DELETE FROM audit_logs WHERE id = :i"), {"i": rows[1].id})
    kinds = {f["kind"] for f in _verify(db_session).failures}
    assert {"sequence_gap", "broken_link"} <= kinds


def test_truncated_tail_is_detected_by_head(db_session):
    _records(db_session, 3)
    audit_chain.seal(db_session)
    top = db_session.get(AuditChainHead, 1).seq
    db_session.execute(text("DELETE FROM audit_chain WHERE seq = :s"), {"s": top})
    assert "head_mismatch" in {f["kind"] for f in _verify(db_session).failures}


def test_recent_unsealed_records_are_reported_but_not_failures(db_session):
    _records(db_session, 2)
    audit_chain.seal(db_session)
    _records(db_session, 2)
    r = _verify(db_session)
    assert r.ok and r.unsealed_records == 2


def test_records_left_unsealed_past_the_tolerance_fail(db_session):
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    _records(db_session, 1)
    audit_chain.seal(db_session)
    # A record that existed long before the last seal but is not in the chain: inserted behind
    # the application's back, or its link was removed.
    _records(db_session, 1, created_at=old)
    r = _verify(db_session)
    assert not r.ok and any(f["kind"] == "unsealed_records" for f in r.failures)


def test_full_rewrite_is_caught_only_by_an_external_checkpoint(db_session, tmp_path):
    rows = _records(db_session, 3)
    audit_chain.seal(db_session)
    sink = evidence.WriteOnceDirectory(tmp_path)
    evidence.publish_checkpoints(db_session, sink)
    checkpoints = sink.checkpoints()
    audit_cps = [cp for cp in checkpoints if cp.get("chain") == "audit"]
    assert len(audit_cps) == 1 and evidence.checkpoint_is_authentic(audit_cps[0])

    # A database administrator edits a record and recomputes the whole chain and head.
    db_session.execute(text("UPDATE audit_logs SET message = 'rewritten' WHERE id = :i"), {"i": rows[0].id})
    db_session.expire_all()
    links = db_session.query(AuditChainLink).order_by(AuditChainLink.seq).all()
    prev = audit_chain.GENESIS
    for link in links:
        row = db_session.get(AuditLog, link.audit_log_id)
        new = audit_chain.link_hash(prev, audit_chain.canonical_record(row, link.seq))
        db_session.execute(text("UPDATE audit_chain SET prev_hash = :p, record_hash = :h WHERE id = :i"),
                           {"p": prev, "h": new, "i": link.id})
        prev = new
    db_session.execute(text("UPDATE audit_chain_head SET head_hash = :h WHERE id = 1"), {"h": prev})

    assert _verify(db_session).ok                               # internally consistent...
    r = _verify(db_session, checkpoints)                        # ...but not with the exported head
    assert not r.ok and r.failures[0]["kind"] == "checkpoint_mismatch"


def test_audit_checkpoint_signature_covers_the_chain_name(db_session):
    _records(db_session, 1)
    audit_chain.seal(db_session)
    cp = [c for c in evidence.make_checkpoints(db_session) if c.get("chain") == "audit"][0]
    assert evidence.checkpoint_is_authentic(cp)
    assert not evidence.checkpoint_is_authentic({**cp, "head_hash": "f" * 64})
    forged = {k: v for k, v in cp.items() if k != "chain"}
    assert not evidence.checkpoint_is_authentic(forged)


def test_evidence_verification_ignores_audit_checkpoints(client, db_session, token_a, tenant_a):
    assert client.get(f"/t/{token_a.token_value}").status_code == 204
    audit_chain.seal(db_session)
    cps = evidence.make_checkpoints(db_session)
    assert any(cp.get("chain") == "audit" for cp in cps)
    db_session.expire_all()
    assert evidence.verify_tenant(db_session, tenant_a.id, cps).ok


def test_worker_checkpoint_seals_then_verify_passes(db_session, tmp_path, monkeypatch, capsys):
    from app.workers import evidence as worker

    _records(db_session, 2)
    monkeypatch.setattr(worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    assert worker.main(["checkpoint", "--out", str(tmp_path)]) == 0
    assert worker.main(["verify", "--checkpoints", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "audit log: OK" in out and "unsealed=0" in out


def test_verify_endpoint_is_system_admin_only(client, db_session, system_admin, admin_a, user_a):
    _records(db_session, 2)
    audit_chain.seal(db_session)
    r = client.get("/api/v1/audit-logs/verify", headers=auth_headers(system_admin))
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["chain"] == "audit"
    assert client.get("/api/v1/audit-logs/verify", headers=auth_headers(admin_a)).status_code == 403
    assert client.get("/api/v1/audit-logs/verify", headers=auth_headers(user_a)).status_code == 403
    assert client.get("/api/v1/audit-logs/verify").status_code == 401


def test_checkpoint_of_an_empty_chain_verifies(db_session):
    audit_chain.seal(db_session)  # creates the head even with nothing to seal
    head = db_session.get(AuditChainHead, 1)
    cps = [c for c in evidence.make_checkpoints(db_session) if c.get("chain") == "audit"]
    if head.seq == 0:
        assert cps[0]["seq"] == 0 and cps[0]["head_hash"] == audit_chain.GENESIS
    assert _verify(db_session, cps).ok
    forged = [{**cps[0], "seq": 0, "head_hash": "f" * 64}]
    assert not _verify(db_session, forged).ok
