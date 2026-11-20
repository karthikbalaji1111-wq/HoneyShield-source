"""Phase 9: tamper-evident evidence chain, checkpoints and write-once export.

Tampering is simulated with Core SQL, which bypasses the ORM immutability hook (SQLite has no
triggers). On PostgreSQL the runtime role cannot do any of this at all; these tests prove that
a party who CAN (a superuser, a restored tampered backup) is still detected.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.models.evidence import EvidenceChainHead, EvidenceChainLink
from app.services import evidence
from tests.conftest import auth_headers

KEY = "evidence-checkpoint-key-for-tests-0123456789"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)


def _hits(client, token, n):
    for i in range(n):
        assert client.get(f"/t/{token.token_value}", headers={"User-Agent": f"ua-{i}"}).status_code == 204


def _verify(db_session, tenant, checkpoints=None):
    db_session.expire_all()
    return evidence.verify_tenant(db_session, tenant.id, checkpoints)


def test_every_event_path_is_chained_in_order(client, db_session, admin_a, token_a, tenant_a):
    _hits(client, token_a, 3)
    client.post("/api/v1/detection-events", headers=auth_headers(admin_a), json={
        "token_value": token_a.token_value, "ip_address": "198.51.100.1", "request_path": "/m",
        "http_method": "GET", "severity": "LOW", "reason": "Analyst reproduction of a report"})
    links = db_session.query(EvidenceChainLink).filter_by(tenant_id=tenant_a.id).order_by(EvidenceChainLink.seq).all()
    assert [l.seq for l in links] == [1, 2, 3, 4]
    assert links[0].prev_hash == evidence.GENESIS
    assert all(b.prev_hash == a.record_hash for a, b in zip(links, links[1:]))
    head = db_session.get(EvidenceChainHead, tenant_a.id)
    assert (head.seq, head.head_hash) == (4, links[-1].record_hash)
    r = _verify(db_session, tenant_a)
    assert r.ok and r.links_checked == 4 and r.unchained_events == 0


def test_tenants_have_independent_chains(client, db_session, token_a, token_b, tenant_a, tenant_b):
    _hits(client, token_a, 2)
    _hits(client, token_b, 1)
    assert _verify(db_session, tenant_a).head_seq == 2
    assert _verify(db_session, tenant_b).head_seq == 1


def test_modified_event_is_detected(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 3)
    db_session.execute(text("UPDATE detection_events SET ip_address = '10.9.9.9' WHERE id = "
                            "(SELECT detection_event_id FROM evidence_chain WHERE seq = 2 AND tenant_id = :t)"),
                       {"t": tenant_a.id})
    r = _verify(db_session, tenant_a)
    assert not r.ok and r.failures[0]["kind"] == "event_modified" and r.failures[0]["seq"] == 2


def test_reordered_links_are_detected(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 3)
    db_session.execute(text("UPDATE evidence_chain SET seq = 99 WHERE seq = 1 AND tenant_id = :t"), {"t": tenant_a.id})
    db_session.execute(text("UPDATE evidence_chain SET seq = 1 WHERE seq = 3 AND tenant_id = :t"), {"t": tenant_a.id})
    db_session.execute(text("UPDATE evidence_chain SET seq = 3 WHERE seq = 99 AND tenant_id = :t"), {"t": tenant_a.id})
    kinds = {f["kind"] for f in _verify(db_session, tenant_a).failures}
    assert "broken_link" in kinds


def test_removed_link_is_detected(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 3)
    db_session.execute(text("DELETE FROM evidence_chain WHERE seq = 2 AND tenant_id = :t"), {"t": tenant_a.id})
    kinds = {f["kind"] for f in _verify(db_session, tenant_a).failures}
    assert {"sequence_gap", "broken_link", "unchained_after_chain_start"} <= kinds


def test_event_inserted_behind_the_applications_back_is_detected(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 2)
    db_session.execute(text(
        "INSERT INTO detection_events(source, honey_token_id, ip_address, request_path, http_method, severity, "
        "triggered_at, created_at) VALUES ('PUBLIC_INGEST', :t, '1.2.3.4', '/t/x', 'GET', 'HIGH', "
        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"), {"t": token_a.id})
    r = _verify(db_session, tenant_a)
    assert not r.ok and r.unchained_events == 1
    assert r.failures[0]["kind"] == "unchained_after_chain_start"


def test_truncated_tail_is_detected_by_head(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 3)
    db_session.execute(text("DELETE FROM evidence_chain WHERE seq = 3 AND tenant_id = :t"), {"t": tenant_a.id})
    kinds = {f["kind"] for f in _verify(db_session, tenant_a).failures}
    assert "head_mismatch" in kinds


def test_full_chain_rewrite_is_caught_only_by_an_external_checkpoint(client, db_session, token_a, tenant_a, tmp_path):
    _hits(client, token_a, 3)
    sink = evidence.WriteOnceDirectory(tmp_path)
    evidence.publish_checkpoints(db_session, sink)
    checkpoints = sink.checkpoints()
    assert all(evidence.checkpoint_is_authentic(cp) for cp in checkpoints)

    # An attacker with full DB control edits an event AND recomputes every link and the head.
    db_session.execute(text("UPDATE detection_events SET ip_address = '10.0.0.66' WHERE id = "
                            "(SELECT detection_event_id FROM evidence_chain WHERE seq = 1 AND tenant_id = :t)"),
                       {"t": tenant_a.id})
    db_session.expire_all()
    prev = evidence.GENESIS
    for link in db_session.query(EvidenceChainLink).filter_by(tenant_id=tenant_a.id).order_by(EvidenceChainLink.seq):
        from app.models.detection_event import DetectionEvent
        ev = db_session.get(DetectionEvent, link.detection_event_id)
        new = evidence.link_hash(prev, evidence.canonical_event(ev, tenant_a.id, link.seq))
        db_session.execute(text("UPDATE evidence_chain SET prev_hash = :p, record_hash = :r WHERE id = :i"),
                           {"p": prev, "r": new, "i": link.id})
        prev = new
    db_session.execute(text("UPDATE evidence_chain_heads SET head_hash = :h WHERE tenant_id = :t"),
                       {"h": prev, "t": tenant_a.id})

    assert _verify(db_session, tenant_a).ok                       # internally consistent again...
    r = _verify(db_session, tenant_a, checkpoints)                # ...but not with the exported head
    assert not r.ok and r.failures[0]["kind"] == "checkpoint_mismatch"


def test_forged_checkpoint_signature_is_rejected(client, db_session, token_a, tmp_path):
    _hits(client, token_a, 1)
    cp = evidence.make_checkpoints(db_session)[0]
    assert evidence.checkpoint_is_authentic(cp)
    assert not evidence.checkpoint_is_authentic({**cp, "head_hash": "f" * 64})


def test_write_once_sink_refuses_overwrite(tmp_path):
    sink = evidence.WriteOnceDirectory(tmp_path)
    sink.put("checkpoint-x.json", b"[]")
    with pytest.raises(FileExistsError):
        sink.put("checkpoint-x.json", b"[]")


def test_export_is_reverifiable_offline(client, db_session, token_a, tenant_a):
    _hits(client, token_a, 3)
    records = list(evidence.export_since(db_session, tenant_a.id, 0))
    prev = evidence.GENESIS
    for rec in records:
        canonical = json.dumps(rec["canonical"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert rec["prev_hash"] == prev and evidence.link_hash(prev, canonical) == rec["record_hash"]
        prev = rec["record_hash"]
    assert token_a.token_value in json.dumps(records)  # the raw path is evidence; export is operator-only


def test_verify_endpoint_is_tenant_scoped(client, db_session, admin_a, admin_b, user_a, system_admin, token_a,
                                          tenant_a):
    _hits(client, token_a, 2)
    a = client.get("/api/v1/evidence/verify", headers=auth_headers(admin_a)).json()
    assert a["ok"] and a["links_checked"] == 2 and a["tenant_id"] == tenant_a.id
    b = client.get("/api/v1/evidence/verify", headers=auth_headers(admin_b)).json()
    assert b["links_checked"] == 0
    assert client.get("/api/v1/evidence/verify", headers=auth_headers(user_a)).status_code == 403
    assert client.get("/api/v1/evidence/verify", headers=auth_headers(system_admin)).status_code == 422
    s = client.get(f"/api/v1/evidence/verify?tenant_slug={tenant_a.slug}", headers=auth_headers(system_admin))
    assert s.json()["links_checked"] == 2
