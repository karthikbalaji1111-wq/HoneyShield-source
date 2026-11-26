"""/metrics exists only with a token, requires it, and leaks no secrets."""
from __future__ import annotations

from app.core import metrics
from app.core.config import get_settings

TOKEN = "metrics-scrape-token-0123456789"


def test_metrics_absent_without_configuration(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "metrics_token", None)
    assert client.get("/metrics").status_code == 404


def test_metrics_require_the_token(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "metrics_token", TOKEN)
    assert client.get("/metrics").status_code == 404
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404


def test_metrics_report_ingestion_and_outbox_without_secrets(client, token_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "metrics_token", TOKEN)
    metrics.reset()
    client.get(f"/t/{token_a.token_value}")
    client.get("/t/not-a-token-value")
    body = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).text
    assert 'honeyshield_ingest_requests_total{outcome="valid_recorded"} 1' in body
    assert 'honeyshield_ingest_requests_total{outcome="invalid_token"} 1' in body
    assert "honeyshield_database_up 1" in body
    assert "honeyshield_stream_subscribers" in body
    assert token_a.token_value not in body and "not-a-token-value" not in body


def test_unsafe_inbound_request_ids_are_replaced(client):
    ok = client.get("/health", headers={"X-Request-ID": "0123456789abcdef0123456789abcdef"})
    assert ok.headers["X-Request-ID"] == "0123456789abcdef0123456789abcdef"
    for bad in ("short", "x" * 200, "id with spaces", 'inj"ection{}'):
        resp = client.get("/health", headers={"X-Request-ID": bad})
        assert resp.headers["X-Request-ID"] != bad and len(resp.headers["X-Request-ID"]) == 36
