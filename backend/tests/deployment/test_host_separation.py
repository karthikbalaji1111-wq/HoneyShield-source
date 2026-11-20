"""Ingest host vs control-plane host separation (application layer)."""
from __future__ import annotations

import pytest

from app.core.config import get_settings
from tests.conftest import auth_headers

INGEST = "ingest.honeyshield.test"
CONTROL = "app.honeyshield.test"


@pytest.fixture(autouse=True)
def separated(monkeypatch):
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", f"https://{INGEST}")
    monkeypatch.setattr(get_settings(), "control_plane_hostnames", [CONTROL])


@pytest.mark.parametrize("path", [
    "/api/v1/tenants", "/api/v1/health", "/api/v1/ready", "/health", "/ready", "/", "/docs", "/redoc",
    "/openapi.json", "/api/v1/events/stream/sse", "/auth/login", "/api/v1/detection-events",
])
def test_ingest_host_exposes_no_control_plane_route(client, path):
    resp = client.get(path, headers={"Host": INGEST})
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


def test_ingest_host_serves_ingest_routes(client, db_session, token_a):
    assert client.get(f"/t/{token_a.token_value}", headers={"Host": INGEST}).status_code == 204
    assert client.get(f"/px/{token_a.token_value}.gif", headers={"Host": f"{INGEST}:443"}).status_code == 200


def test_control_plane_host_does_not_serve_ingest_routes(client, db_session, token_a, admin_a):
    assert client.get(f"/t/{token_a.token_value}", headers={"Host": CONTROL}).status_code == 404
    assert client.post("/integrations/v1/events", headers={"Host": CONTROL}).status_code == 404
    resp = client.get("/api/v1/detection-events", headers={"Host": CONTROL, **auth_headers(admin_a)})
    assert resp.status_code == 200 and resp.json() == []   # the /t/ hit above was never recorded


def test_unknown_host_is_refused(client):
    assert client.get("/api/v1/health", headers={"Host": "evil.example"}).status_code == 404


def test_ingest_host_websocket_is_refused(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/v1/events/stream/ws", headers={"Host": INGEST}) as ws:
            ws.receive_text()


def test_separation_is_off_without_configuration(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "control_plane_hostnames", [])
    assert client.get("/api/v1/health", headers={"Host": INGEST}).status_code == 200


def test_metrics_can_be_scraped_per_pod_by_ip_with_the_token(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "metrics_token", "metrics-token-for-tests-0123456789")
    auth = {"Authorization": "Bearer metrics-token-for-tests-0123456789"}
    for host in ("10.42.0.17:8000", "[fd00::17]:8000"):
        assert client.get("/metrics", headers={"Host": host, **auth}).status_code == 200
        assert client.get("/metrics", headers={"Host": host}).status_code == 404        # token still required
        assert client.get("/api/v1/health", headers={"Host": host}).status_code == 404  # only /metrics
    assert client.get("/metrics", headers={"Host": INGEST, **auth}).status_code == 404   # never on the ingest host
    assert client.get("/metrics", headers={"Host": "unknown.example", **auth}).status_code == 404
