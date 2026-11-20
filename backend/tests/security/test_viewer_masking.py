"""HONEY-015: TENANT_USER viewers never see live honey-token values."""
from __future__ import annotations

from app.core.redaction import mask
from tests.conftest import auth_headers, make_token


def test_tenant_user_sees_masked_tokens_and_artifacts(client, admin_a, user_a, project_a):
    gen = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate", json={"token_type": "URL"},
                      headers=auth_headers(admin_a)).json()
    value = gen["token_value"]
    admin_view = client.get("/api/v1/honey-tokens", headers=auth_headers(admin_a)).json()
    assert value in [t["token_value"] for t in admin_view]

    resp = client.get("/api/v1/honey-tokens", headers=auth_headers(user_a))
    assert resp.status_code == 200
    assert value not in resp.text
    entry = [t for t in resp.json() if t["decoy_id"] == gen["decoy_id"]][0]
    assert entry["token_value"] == mask(value) and mask(value) in entry["metadata"]["url"]


def test_tenant_user_sees_masked_request_paths(client, admin_a, user_a, token_a):
    client.get(f"/t/{token_a.token_value}")
    assert token_a.token_value in client.get("/api/v1/detection-events", headers=auth_headers(admin_a)).text
    resp = client.get("/api/v1/detection-events", headers=auth_headers(user_a))
    assert resp.status_code == 200 and len(resp.json()) == 1
    assert token_a.token_value not in resp.text
    assert resp.json()[0]["request_path"] == f"/t/{mask(token_a.token_value)}"


def test_live_stream_never_carries_the_token_value(client, user_a, token_a):
    with client.websocket_connect("/api/v1/events/stream/ws") as ws:
        ws.send_json({"type": "auth", "token": make_token(user_a)})
        assert ws.receive_json() == {"type": "auth_success"}
        client.get(f"/t/{token_a.token_value}")
        event = ws.receive_json()
    assert token_a.token_value not in str(event)
    assert event["request_path"] == "/t/{token}" and event["decoy_id"] == token_a.decoy_id
