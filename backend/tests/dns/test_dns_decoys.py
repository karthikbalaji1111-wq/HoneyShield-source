"""DNS decoys end to end in the backend: generation, the signed listener endpoint, evidence.

The listener forwards names that look like decoys; the backend decides: the name must be inside
DNS_TOKEN_ZONE and its label must belong to a DNS decoy. Events keep the time the listener saw
the query, are stored once per listener request id and carry only DNS context.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest

from app.core.config import get_settings
from app.core.replay_signing import dns_hits_key, replay_key, sign
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from app.services.system_status import get_status
from tests.conftest import auth_headers

URL = "/internal/v1/dns-hits"
KEY = "test-integration-signing-key-0123456789abcdef"
ZONE = "dns.example.net"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)
    monkeypatch.setattr(get_settings(), "dns_token_zone", ZONE)


def _generate(client, admin, project, **params):
    r = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate",
                    json={"token_type": "DNS", **({"generator_params": params} if params else {})},
                    headers=auth_headers(admin))
    assert r.status_code in (200, 201), r.text
    return r.json()


def _hit(qname, *, resolver="192.0.2.53", seconds_ago=30, rid=None, qtype="A", ecs=None):
    return {"request_id": rid or uuid.uuid4().hex, "time": time.time() - seconds_ago, "resolver": resolver,
            "transport": "udp", "qname": qname, "qtype": qtype, "ecs": ecs}


def _post(client, entries, *, key=None, stamp=None):
    body = json.dumps({"entries": entries}).encode()
    stamp = stamp or str(int(time.time()))
    return client.post(URL, content=body, headers={
        "Content-Type": "application/json", "Host": "backend:8000", "X-HS-Timestamp": stamp,
        "X-HS-Signature": sign(key or dns_hits_key(KEY), stamp, body)})


def _events(db_session, token_id):
    db_session.expire_all()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token_id).all()


def test_generated_dns_decoy_is_a_hostname_in_the_zone(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a)
    meta = token["metadata"]
    assert token["token_type"] == "DNS" and meta["hostname"] == f"{token['token_value']}.{ZONE}"
    assert meta["zone"] == ZONE and meta["detection"]["status"] == "PUBLIC_INGEST"


def test_dns_decoys_cannot_be_generated_without_a_zone(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "dns_token_zone", None)
    r = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate", json={"token_type": "DNS"},
                    headers=auth_headers(admin_a))
    assert r.status_code in (400, 422) and "DNS_TOKEN_ZONE" in r.text


def test_a_lookup_becomes_a_public_event_with_dns_context(client, db_session, admin_a, project_a):
    token = _generate(client, admin_a, project_a)
    hit = _hit(f"laptop-7.{token['token_value']}.{ZONE}", qtype="TXT", ecs="198.51.100.0/24", seconds_ago=90)
    r = _post(client, [hit])
    assert r.status_code == 200 and r.json()["recorded"] == 1
    [event] = _events(db_session, token["id"])
    assert event.source == EventSource.PUBLIC_INGEST and event.severity == EventSeverity.HIGH
    assert event.ip_address == "192.0.2.53" and event.http_method == "TXT"
    assert event.request_path == hit["qname"] and event.idempotency_key == hit["request_id"]
    assert event.headers == {"dns-query-type": "TXT", "dns-transport": "udp", "dns-client-subnet": "198.51.100.0/24"}
    assert abs(event.triggered_at.timestamp() - hit["time"]) < 1 if event.triggered_at.tzinfo else True


def test_the_same_query_is_stored_once(client, db_session, admin_a, project_a):
    token = _generate(client, admin_a, project_a)
    hits = [_hit(f"{token['token_value']}.{ZONE}")]
    assert _post(client, hits).json()["recorded"] == 1
    assert _post(client, hits).json()["duplicates"] == 1
    assert len(_events(db_session, token["id"])) == 1


def test_only_dns_decoys_in_the_zone_count(client, db_session, admin_a, project_a, token_a):
    token = _generate(client, admin_a, project_a)
    result = _post(client, [
        _hit(f"{token['token_value']}.other.example"),          # outside the zone
        _hit(f"{token_a.token_value}.{ZONE}"),                  # a URL decoy's value is not a DNS label
        _hit(f"{'b' * 26}.{ZONE}"),                             # well-formed but unknown
    ]).json()
    assert result["not_a_decoy"] == 3 and result["recorded"] == 0
    assert _events(db_session, token["id"]) == []


def test_signature_and_configuration_are_required(client, admin_a, project_a, monkeypatch):
    entries = [_hit(f"{'c' * 26}.{ZONE}")]
    assert _post(client, entries, key=replay_key(KEY)).status_code == 401        # a replay key is not enough
    assert _post(client, entries, stamp=str(int(time.time()) - 3600)).status_code == 401
    monkeypatch.setattr(get_settings(), "dns_token_zone", None)
    assert _post(client, entries).status_code == 503


def test_internal_endpoint_is_refused_on_public_hosts(client):
    body = json.dumps({"entries": []}).encode()
    stamp = str(int(time.time()))
    for host in ("ingest.example.com", "app.example.com"):
        r = client.post(URL, content=body, headers={"Host": host, "X-HS-Timestamp": stamp,
                                                    "X-HS-Signature": sign(dns_hits_key(KEY), stamp, body)})
        assert r.status_code in (200, 404)      # host separation applies once hostnames are configured


def test_empty_batch_is_the_listener_heartbeat(client, db_session):
    assert _post(client, []).status_code == 200
    db_session.expire_all()
    row = get_status(db_session, "dns_listener")
    assert row is not None and row.value["zone"] == ZONE


def test_old_and_future_hits_are_rejected(client, admin_a, project_a):
    token = _generate(client, admin_a, project_a)
    name = f"{token['token_value']}.{ZONE}"
    result = _post(client, [_hit(name, seconds_ago=40 * 86400), _hit(name, seconds_ago=-3600)]).json()
    assert result["rejected"] == 2


def test_viewers_never_see_the_hostname(client, admin_a, user_a, project_a):
    token = _generate(client, admin_a, project_a)
    r = client.get("/api/v1/honey-tokens", params={"project_domain": project_a.domain}, headers=auth_headers(user_a))
    [view] = [t for t in r.json() if t["id"] == token["id"]]
    assert token["token_value"] not in json.dumps(view) and view["metadata"]["zone"] == ZONE


def test_http_hits_cannot_forge_dns_context(client, db_session, token_a):
    client.get(f"/t/{token_a.token_value}", headers={"dns-client-subnet": "10.0.0.0/8", "aws-region": "x"})
    [event] = _events(db_session, token_a.id)
    assert "dns-client-subnet" not in (event.headers or {}) and "aws-region" not in (event.headers or {})
