"""Decoy hits captured at the edge during a backend outage are recovered exactly once.

The edge spools a hit the backend could not record; the replay worker posts it to the internal
endpoint, signed. These tests cover the endpoint (authentication, original time, no duplicates,
per-source cap, evidence chain) and the live path's use of the edge request id.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.core.replay_signing import replay_key, sign
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSource

URL = "/internal/v1/ingest-replay"
SIGNING_KEY = "test-integration-signing-key-0123456789abcdef"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", SIGNING_KEY)


def _hit(token_value, *, kind="t", seconds_ago=120, ip="203.0.113.50", rid=None, ua="curl/8.7.1"):
    return {"request_id": rid or uuid.uuid4().hex, "time": time.time() - seconds_ago, "remote_addr": ip,
            "method": "GET", "uri": f"/{kind}/{token_value}{'.gif' if kind == 'px' else ''}", "user_agent": ua}


def _post(client, entries, *, key=SIGNING_KEY, stamp=None, host="backend:8000"):
    body = json.dumps({"entries": entries}).encode()
    stamp = stamp or str(int(time.time()))
    return client.post(URL, content=body, headers={
        "Content-Type": "application/json", "Host": host, "X-HS-Timestamp": stamp,
        "X-HS-Signature": sign(replay_key(key), stamp, body)})


def _events(db_session, token):
    db_session.expire_all()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).order_by(DetectionEvent.id).all()


def test_signature_is_required(client, token_a):
    entries = [_hit(token_a.token_value)]
    assert _post(client, entries, key="some-other-key-entirely-0123456789").status_code == 401
    assert _post(client, entries, stamp=str(int(time.time()) - 3600)).status_code == 401
    body = json.dumps({"entries": entries}).encode()
    assert client.post(URL, content=body, headers={"Host": "backend:8000"}).status_code == 401


def test_replayed_hit_keeps_the_time_the_edge_saw_it(client, db_session, token_a):
    hit = _hit(token_a.token_value, seconds_ago=600)
    r = _post(client, [hit])
    assert r.status_code == 200 and r.json()["recorded"] == 1
    [event] = _events(db_session, token_a)
    seen = event.triggered_at if event.triggered_at.tzinfo else event.triggered_at.replace(tzinfo=timezone.utc)
    assert abs((seen - datetime.fromtimestamp(hit["time"], tz=timezone.utc)).total_seconds()) < 1
    assert event.source == EventSource.PUBLIC_INGEST and event.idempotency_key == hit["request_id"]
    assert event.ip_address == "203.0.113.50" and event.user_agent == "curl/8.7.1"
    audit = db_session.query(AuditLog).filter_by(event_type="DETECTION_EVENTS_RECOVERED").one()
    assert audit.event_metadata["recorded"] == 1


def test_the_same_hit_is_never_stored_twice(client, db_session, token_a):
    hits = [_hit(token_a.token_value), _hit(token_a.token_value, kind="px")]
    assert _post(client, hits).json()["recorded"] == 2
    again = _post(client, hits).json()
    assert again["recorded"] == 0 and again["duplicates"] == 2
    assert len(_events(db_session, token_a)) == 2


def test_a_hit_the_backend_stored_before_failing_is_not_replayed_twice(client, db_session, token_a):
    rid = uuid.uuid4().hex
    live = client.get(f"/t/{token_a.token_value}", headers={"X-Request-ID": rid})   # testclient is a trusted proxy
    assert live.status_code == 204
    replay = _post(client, [_hit(token_a.token_value, rid=rid, ip="testclient")]).json()
    assert replay["duplicates"] == 1 and replay["recorded"] == 0
    assert len(_events(db_session, token_a)) == 1


def test_untrusted_callers_cannot_plant_request_ids(client, db_session, token_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxies", ["10.255.255.1"])
    rid = uuid.uuid4().hex
    client.get(f"/t/{token_a.token_value}", headers={"X-Request-ID": rid})
    [event] = _events(db_session, token_a)
    assert event.idempotency_key is None              # the later replay of the real edge id is not blocked


def test_non_decoys_old_and_malformed_entries_are_not_recorded(client, db_session, token_a):
    entries = [_hit("not-a-real-decoy-value"), _hit(token_a.token_value, seconds_ago=40 * 86400),
               {**_hit(token_a.token_value), "uri": "/api/v1/users"}, _hit(token_a.token_value, ip="not-an-ip")]
    r = _post(client, entries).json()
    assert r["recorded"] == 0 and r["not_a_decoy"] == 2 and r["rejected"] == 2
    assert _events(db_session, token_a) == []


def test_the_per_source_cap_applies_to_replays(client, db_session, token_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "ingestion_rate_limit_per_minute_token", 3)
    now = time.time()
    minute_start = now - (now % 60) - 120             # all in one whole minute, two minutes ago
    entries = [{**_hit(token_a.token_value), "time": minute_start + i} for i in range(5)]
    r = _post(client, entries).json()
    assert r["recorded"] == 3 and r["suppressed"] == 2
    assert db_session.query(AuditLog).filter_by(event_type="DETECTION_HITS_SUPPRESSED").count() == 1


def test_recovered_events_extend_the_evidence_chain(client, db_session, token_a, project_a):
    from app.services import evidence
    client.get(f"/t/{token_a.token_value}")
    _post(client, [_hit(token_a.token_value, seconds_ago=30), _hit(token_a.token_value, kind="px", seconds_ago=20)])
    result = evidence.verify_tenant(db_session, project_a.tenant_id)
    assert result.ok and result.links_checked == 3, result.failures


@pytest.mark.parametrize("host", ["app.example.test", "ingest.example.test"])
def test_never_served_on_a_public_host_name(client, token_a, monkeypatch, host):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", "https://ingest.example.test")
    monkeypatch.setattr(get_settings(), "control_plane_hostnames", ["app.example.test"])
    assert _post(client, [_hit(token_a.token_value)], host=host).status_code == 404
    assert _post(client, [_hit(token_a.token_value)], host="backend:8000").status_code == 200


NGINX_EMPTY_GIF = bytes.fromhex("47494638396101000100800100000000ffffff21f9040100000100"
                                "2c00000000010001000002024c01003b")


def test_pixel_response_is_identical_whether_or_not_the_backend_is_up(client, token_a):
    """During an outage the edge answers pixel hits with nginx's empty_gif; the backend must return the
    very same bytes, or the response would reveal that the backend is down."""
    from pathlib import Path
    template = (Path(__file__).resolve().parents[3] / "proxy/templates/default.conf.template").read_text()
    assert "empty_gif;" in template and "@hs_capture_gif" in template
    r = client.get(f"/px/{token_a.token_value}.gif")
    assert r.status_code == 200 and r.headers["content-type"] == "image/gif" and r.content == NGINX_EMPTY_GIF
