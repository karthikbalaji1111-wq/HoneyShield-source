"""Operator-chosen decoy URL paths (DECOY_*_PATH) and the operator-host address allowlist."""
from __future__ import annotations

import json
import time
import uuid

import pytest

from app.core import decoy_paths
from app.core.config import Settings, get_settings
from app.core.replay_signing import replay_key, sign
from app.models.detection_event import DetectionEvent
from tests.conftest import auth_headers

SIGNING_KEY = "test-integration-signing-key-0123456789abcdef"


@pytest.fixture()
def custom(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "decoy_link_path", "static/v2")
    monkeypatch.setattr(s, "decoy_pixel_path", "assets/img")
    monkeypatch.setattr(s, "decoy_collect_path", "api-telemetry")
    monkeypatch.setattr(s, "integration_signing_key", SIGNING_KEY)
    return s


def _events(db_session, token):
    db_session.expire_all()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).order_by(DetectionEvent.id).all()


# ------------------------------------------------------------------------------------- validation
@pytest.mark.parametrize("link,pixel,collect,legacy,ok", [
    ("t", "px", "collect", True, True),
    ("static/v2", "assets/img", "api-telemetry", True, True),
    ("static", "static/img", "c", True, False),          # one contains another
    ("px", "img", "c", True, False),                    # clashes with legacy /px/
    ("px", "img", "c", False, True),                    # ...fine once legacy paths are off
    ("Static", "img", "c", True, False),                # upper case
    ("static/../x", "img", "c", True, False),           # traversal characters
    ("api/x", "img", "c", True, False),                 # reserved first segment
    ("a/b/c/d", "img", "c", True, False),               # too many segments
    ("img", "img", "c", True, False),                   # duplicate
    ("static.v2", "img", "c", True, False),             # dots are not allowed (nginx regex safety)
])
def test_path_validation(link, pixel, collect, legacy, ok):
    if ok:
        decoy_paths.validate(link, pixel, collect, legacy)
    else:
        with pytest.raises(ValueError):
            decoy_paths.validate(link, pixel, collect, legacy)


def test_settings_reject_bad_paths(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 40)
    with pytest.raises(ValueError):
        Settings(decoy_link_path="static", decoy_pixel_path="static/img")
    s = Settings(decoy_link_path="/Static/V2/", decoy_pixel_path="assets/img")
    assert s.decoy_link_path == "static/v2"


def test_token_from_path(custom):
    assert decoy_paths.token_from_path(custom, "/static/v2/abc") == "abc"
    assert decoy_paths.token_from_path(custom, "/assets/img/abc.gif?x=1") == "abc"
    assert decoy_paths.token_from_path(custom, "/assets/img/abc") is None
    assert decoy_paths.token_from_path(custom, "/t/legacy") == "legacy"
    assert decoy_paths.token_from_path(custom, "/px/legacy.gif") == "legacy"
    assert decoy_paths.token_from_path(custom, "/static/v2/a/b") is None
    assert decoy_paths.token_from_path(custom, "/elsewhere/abc") is None


# ------------------------------------------------------------------------------------- serving
def test_custom_paths_record_hits_and_keep_the_requested_path(client, db_session, custom, token_a):
    db_session.commit()
    assert client.get(f"/static/v2/{token_a.token_value}").status_code == 204
    r = client.get(f"/assets/img/{token_a.token_value}.gif")
    assert r.status_code == 200 and r.headers["content-type"] == "image/gif"
    assert client.post(f"/api-telemetry/{token_a.token_value}").status_code == 204
    paths = [e.request_path for e in _events(db_session, token_a)]
    assert paths == [f"/static/v2/{token_a.token_value}", f"/assets/img/{token_a.token_value}.gif",
                     f"/api-telemetry/{token_a.token_value}"]
    # Decoys made before the change keep working while legacy paths are on.
    assert client.get(f"/t/{token_a.token_value}").status_code == 204
    assert len(_events(db_session, token_a)) == 4


def test_legacy_paths_can_be_switched_off(client, db_session, custom, token_a, monkeypatch):
    monkeypatch.setattr(custom, "decoy_legacy_paths", False)
    db_session.commit()
    assert client.get(f"/t/{token_a.token_value}").status_code == 404
    assert client.get(f"/px/{token_a.token_value}.gif").status_code == 404
    assert client.post(f"/collect/{token_a.token_value}").status_code == 404
    assert _events(db_session, token_a) == []
    assert client.get(f"/static/v2/{token_a.token_value}").status_code == 204
    assert len(_events(db_session, token_a)) == 1


def test_generated_decoys_use_the_custom_paths(client, db_session, custom, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(custom, "public_ingest_base_url", "https://cdn.example.test")
    db_session.commit()
    h = auth_headers(admin_a)
    link = client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "URL"},
                       headers=h).json()
    assert link["metadata"]["url"].startswith("https://cdn.example.test/static/v2/")
    pixel = client.post("/api/v1/honey-tokens", json={"project_domain": project_a.domain, "token_type": "PIXEL"},
                        headers=h).json()
    assert pixel["metadata"]["pixel_url"].startswith("https://cdn.example.test/assets/img/")
    assert "/t/" not in json.dumps(link["metadata"]) and "/px/" not in json.dumps(pixel["metadata"])
    # The generated URL actually reports.
    path = link["metadata"]["url"].removeprefix("https://cdn.example.test")
    assert client.get(path).status_code == 204


def test_host_separation_with_custom_paths(client, db_session, custom, token_a, monkeypatch):
    monkeypatch.setattr(custom, "public_ingest_base_url", "https://cdn.example.test")
    monkeypatch.setattr(custom, "control_plane_hostnames", ["app.example.test"])
    db_session.commit()
    ingest, control = {"Host": "cdn.example.test"}, {"Host": "app.example.test"}
    assert client.get(f"/static/v2/{token_a.token_value}", headers=ingest).status_code == 204
    assert client.get(f"/static/v2/{token_a.token_value}", headers=control).status_code == 404
    assert client.get("/api/v1/health", headers=ingest).status_code == 404


def test_replay_understands_custom_paths(client, db_session, custom, token_a):
    db_session.commit()
    entries = [{"request_id": uuid.uuid4().hex, "time": time.time() - 60, "remote_addr": "203.0.113.9",
                "method": "GET", "uri": f"/assets/img/{token_a.token_value}.gif", "user_agent": "x"}]
    body = json.dumps({"entries": entries}).encode()
    stamp = str(int(time.time()))
    r = client.post("/internal/v1/ingest-replay", content=body, headers={
        "Content-Type": "application/json", "Host": "backend:8000", "X-HS-Timestamp": stamp,
        "X-HS-Signature": sign(replay_key(SIGNING_KEY), stamp, body)})
    assert r.status_code == 200 and r.json()["recorded"] == 1


# ------------------------------------------------------------------------------------- allowlist
@pytest.fixture()
def allowlist(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "control_plane_allowed_cidrs", "198.51.100.0/24, 2001:db8::/32")
    return s


def test_operator_routes_need_an_allowed_address(client, db_session, allowlist, admin_a, token_a):
    db_session.commit()
    h = auth_headers(admin_a)
    # The test client's peer is a trusted proxy, so X-Forwarded-For is the visitor's address.
    assert client.get("/api/v1/projects", headers={**h, "X-Forwarded-For": "198.51.100.7"}).status_code == 200
    assert client.get("/api/v1/projects", headers={**h, "X-Forwarded-For": "2001:db8::5"}).status_code == 200
    r = client.get("/api/v1/projects", headers={**h, "X-Forwarded-For": "203.0.113.4"})
    assert r.status_code == 403
    r = client.post("/auth/login", json={"email": admin_a.email, "password": "password"},
                    headers={"X-Forwarded-For": "203.0.113.4"})
    assert r.status_code == 403
    # Decoys and health probes are never restricted.
    assert client.get(f"/t/{token_a.token_value}", headers={"X-Forwarded-For": "203.0.113.4"}).status_code == 204
    assert client.get("/health", headers={"X-Forwarded-For": "203.0.113.4"}).status_code == 200


def test_allowlist_validation(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 40)
    with pytest.raises(ValueError):
        Settings(control_plane_allowed_cidrs="198.51.100.0/24, not-an-ip")
    assert len(Settings(control_plane_allowed_cidrs="10.0.0.0/8 192.0.2.1").control_plane_networks) == 2
