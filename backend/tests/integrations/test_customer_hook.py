"""CUSTOMER_HOOK integration: API_KEY and FORM_FIELD detection end to end.

The customer side is the shipped reference client (integrations/python/honeyshield_hook.py),
talking to the real ingest routes through a transport bound to the test app.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core import integration_auth
from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSource
from app.models.honey_token import HoneyToken
from tests.conftest import auth_headers

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "integrations" / "python"))
from honeyshield_hook import HoneyShieldHook  # noqa: E402

INGEST = "https://ingest.honeyshield.test"
SIGNING_KEY = "integration-master-key-for-tests-0123456789abcdef"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", SIGNING_KEY)
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", INGEST)


def _transport(client):
    def send(method, url, headers, body, timeout):
        assert url.startswith(INGEST)
        resp = client.request(method, url[len(INGEST):], headers=headers, content=body)
        return resp.status_code, resp.content
    return send


def _create_integration(client, admin, project):
    resp = client.post(f"/api/v1/projects/{project.domain}/integrations", json={"label": "auth-mw"},
                       headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _generate(client, admin, project, token_type):
    resp = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate",
                       json={"token_type": token_type}, headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _hook(client, cred, **kw):
    hook = HoneyShieldHook(INGEST, cred["integration_id"], cred["secret"], transport=_transport(client),
                           sleep=lambda s: None, **kw)
    assert hook.refresh_manifest()
    return hook


def _hook_events(db_session, token_value):
    db_session.expire_all()
    token = db_session.query(HoneyToken).filter_by(token_value=token_value).one()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).all()


def _signed(client, cred, body: dict | bytes, path="/integrations/v1/events", method="POST", ts=None,
            secret=None, extra_headers=None):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    ts = str(int(ts if ts is not None else time.time()))
    sig = integration_auth.sign(secret or cred["secret"], method, path, ts, raw)
    headers = {"X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts, "X-HS-Signature": sig,
               "Content-Type": "application/json", **(extra_headers or {})}
    return client.request(method, path, headers=headers, content=raw)


def _report(decoy_id, **overrides):
    body = {"decoy_id": decoy_id, "idempotency_key": "idem-" + "a" * 20,
            "observed_at": datetime.now(timezone.utc).isoformat(), "source_ip": "203.0.113.50",
            "http_method": "GET", "request_path": "/v1/orders"}
    body.update(overrides)
    return body


# --------------------------------------------------------------------------- API_KEY

def test_api_key_use_is_reported_without_sending_the_key(client, db_session, admin_a, project_a, caplog):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    hook = _hook(client, cred)
    caplog.set_level(logging.DEBUG)

    assert hook.check_api_key("some-real-customer-key", source_ip="198.51.100.1") is False
    assert hook.check_api_key(token["token_value"], source_ip="203.0.113.9", http_method="GET",
                              request_path="/v1/orders?api_key=" + token["token_value"]) is True
    assert hook.drain() == 1 and hook.stats["sent"] == 1

    events = _hook_events(db_session, token["token_value"])
    assert len(events) == 1
    ev = events[0]
    assert ev.source == EventSource.CUSTOMER_HOOK
    assert ev.ip_address == "203.0.113.9"
    assert ev.request_path == "/v1/orders"           # query string (which held the key) dropped
    assert ev.severity.value == "CRITICAL"
    assert ev.integration_credential_id is not None and ev.idempotency_key
    # The key never reaches HoneyShield's logs or the event.
    assert token["token_value"] not in caplog.text
    assert token["token_value"] not in json.dumps({"p": ev.request_path, "h": ev.headers, "u": ev.user_agent})


def test_manifest_exposes_hashes_not_keys(client, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    _generate(client, admin_a, project_a, "URL")
    resp = _signed(client, cred, b"", path="/integrations/v1/manifest", method="GET")
    assert resp.status_code == 200
    decoys = resp.json()["decoys"]
    assert [d["token_type"] for d in decoys] == ["API_KEY"]   # URL tokens are not hook-reportable
    assert decoys[0]["sha256"] == integration_auth.sha256_hex(token["token_value"])
    assert token["token_value"] not in resp.text


# --------------------------------------------------------------------------- FORM_FIELD

def test_form_field_honeypot_end_to_end(client, db_session, admin_a, project_a):
    """Follow the delivered artifact: render the snippet, a bot fills it, the hook reports it."""
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "FORM_FIELD")
    html = token["metadata"]["html_snippet"]
    field = re.search(r'name="([^"]+)"', html).group(1)
    assert re.search(r'value="([^"]*)"', html).group(1) == ""
    hook = _hook(client, cred)

    human = {"email": "a@b.c", field: ""}
    assert hook.check_form(human, source_ip="198.51.100.2", request_path="/signup") is False
    bot = {"email": "spam@x.y", field: "http://spam.example"}
    assert hook.check_form(bot, source_ip="203.0.113.77", request_path="/signup") is True
    hook.drain()

    events = _hook_events(db_session, token["token_value"])
    assert len(events) == 1
    assert events[0].source == EventSource.CUSTOMER_HOOK
    assert events[0].ip_address == "203.0.113.77" and events[0].http_method == "POST"
    assert events[0].severity.value == "MEDIUM"


# --------------------------------------------------------------------------- authentication

@pytest.mark.parametrize("mutate", ["bad_signature", "wrong_secret", "stale", "future", "missing", "unknown_id"])
def test_invalid_authentication_is_rejected_and_stores_nothing(client, db_session, admin_a, project_a, mutate):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    body = _report(token["decoy_id"])
    if mutate == "bad_signature":
        resp = _signed(client, cred, body, extra_headers={"X-HS-Signature": "v1=" + "0" * 64})
    elif mutate == "wrong_secret":
        resp = _signed(client, cred, body, secret="f" * 64)
    elif mutate == "stale":
        resp = _signed(client, cred, body, ts=time.time() - 3600)
    elif mutate == "future":
        resp = _signed(client, cred, body, ts=time.time() + 3600)
    elif mutate == "missing":
        resp = client.post("/integrations/v1/events", json=body)
    else:
        resp = _signed(client, {**cred, "integration_id": "hsi_" + "0" * 24}, body)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Integration authentication failed"}
    assert _hook_events(db_session, token["token_value"]) == []


def test_body_tampering_breaks_the_signature(client, db_session, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    raw = json.dumps(_report(token["decoy_id"])).encode()
    ts = str(int(time.time()))
    sig = integration_auth.sign(cred["secret"], "POST", "/integrations/v1/events", ts, raw)
    tampered = raw.replace(b"203.0.113.50", b"203.0.113.51")
    resp = client.post("/integrations/v1/events", content=tampered, headers={
        "X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts, "X-HS-Signature": sig})
    assert resp.status_code == 401


def test_revoked_credential_is_rejected(client, db_session, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    r = client.post(f"/api/v1/projects/{project_a.domain}/integrations/{cred['integration_id']}/revoke",
                    headers=auth_headers(admin_a))
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert _signed(client, cred, _report(token["decoy_id"])).status_code == 401
    assert _hook_events(db_session, token["token_value"]) == []
    assert db_session.query(AuditLog).filter_by(event_type="INTEGRATION_CREDENTIAL_REVOKED").count() == 1


def test_inactive_tenant_cannot_report(client, db_session, admin_a, project_a, tenant_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    tenant_a.is_active = False
    db_session.flush()
    assert _signed(client, cred, _report(token["decoy_id"])).status_code == 401


def test_repeated_auth_failures_from_one_ip_are_throttled(client, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    codes = [_signed(client, cred, {}, secret="0" * 64).status_code for _ in range(32)]
    assert codes[:30] == [401] * 30 and codes[-1] == 429


# --------------------------------------------------------------------------- idempotency / replay

def test_duplicate_and_replayed_reports_store_one_event(client, db_session, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    body = _report(token["decoy_id"])
    raw = json.dumps(body).encode()
    ts = str(int(time.time()))
    headers = {"X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts,
               "X-HS-Signature": integration_auth.sign(cred["secret"], "POST", "/integrations/v1/events", ts, raw)}
    for _ in range(3):  # exact replay of a captured request inside the timestamp window
        assert client.post("/integrations/v1/events", content=raw, headers=headers).status_code == 202
    assert _signed(client, cred, body).status_code == 202   # fresh signature, same idempotency key
    assert len(_hook_events(db_session, token["token_value"])) == 1


# --------------------------------------------------------------------------- no oracle / isolation

def test_unknown_and_foreign_decoys_get_the_same_response(client, db_session, admin_a, admin_b, project_a,
                                                          project_b):
    cred_a = _create_integration(client, admin_a, project_a)
    own = _generate(client, admin_a, project_a, "API_KEY")
    foreign = _generate(client, admin_b, project_b, "API_KEY")
    url_token = _generate(client, admin_a, project_a, "URL")
    r_own = _signed(client, cred_a, _report(own["decoy_id"], idempotency_key="k" * 20))
    r_foreign = _signed(client, cred_a, _report(foreign["decoy_id"], idempotency_key="j" * 20))
    r_unknown = _signed(client, cred_a, _report("dcy_" + "0" * 24, idempotency_key="m" * 20))
    r_url = _signed(client, cred_a, _report(url_token["decoy_id"], idempotency_key="n" * 20))
    assert {r.status_code for r in (r_own, r_foreign, r_unknown, r_url)} == {202}
    assert r_own.json() == r_foreign.json() == r_unknown.json() == r_url.json()
    assert len(_hook_events(db_session, own["token_value"])) == 1
    assert _hook_events(db_session, foreign["token_value"]) == []
    assert _hook_events(db_session, url_token["token_value"]) == []


# --------------------------------------------------------------------------- sanitisation

@pytest.mark.parametrize("override", [
    {"headers": {"Authorization": "Bearer sk_live_abc"}},
    {"headers": {"X-Api-Key": "whatever"}},
    {"headers": {"Cookie": "session=1"}},
    {"api_key": "sk_live_abc"},
    {"presented_key": "x"},
    {"http_method": "TRACE"},
    {"observed_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
    {"observed_at": "2026-11-13T10:00:00"},
    {"source_ip": "not-an-ip"},
    {"idempotency_key": "short"},
    {"decoy_id": "sk_live_" + "a" * 24},
])
def test_unsafe_or_malformed_reports_are_rejected(client, db_session, admin_a, project_a, override, caplog):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    caplog.set_level(logging.DEBUG)
    resp = _signed(client, cred, {**_report(token["decoy_id"]), **override})
    assert resp.status_code == 422
    assert resp.json() == {"detail": "Report validation failed"}
    assert "sk_live_abc" not in resp.text and "sk_live_abc" not in caplog.text
    assert _hook_events(db_session, token["token_value"]) == []


def test_report_containing_the_decoy_key_is_rejected_and_audited(client, db_session, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    token = _generate(client, admin_a, project_a, "API_KEY")
    resp = _signed(client, cred, _report(token["decoy_id"], user_agent="client " + token["token_value"]))
    assert resp.status_code == 422
    assert _hook_events(db_session, token["token_value"]) == []
    audit = db_session.query(AuditLog).filter_by(event_type="INTEGRATION_REPORT_REJECTED_SECRET").one()
    assert token["token_value"] not in json.dumps(audit.event_metadata) + audit.message


def test_oversized_report_is_rejected(client, admin_a, project_a):
    cred = _create_integration(client, admin_a, project_a)
    assert _signed(client, cred, b"{" + b" " * 20000 + b"}").status_code == 413


# --------------------------------------------------------------------------- credential lifecycle

def test_secret_is_shown_once_and_only_admins_manage_credentials(client, admin_a, user_a, admin_b, project_a):
    cred = _create_integration(client, admin_a, project_a)
    assert len(cred["secret"]) == 64 and cred["integration_id"].startswith("hsi_")
    listing = client.get(f"/api/v1/projects/{project_a.domain}/integrations", headers=auth_headers(admin_a))
    assert listing.status_code == 200
    assert cred["secret"] not in listing.text and "secret" not in listing.json()[0]
    assert client.post(f"/api/v1/projects/{project_a.domain}/integrations", json={},
                       headers=auth_headers(user_a)).status_code == 403
    assert client.get(f"/api/v1/projects/{project_a.domain}/integrations",
                      headers=auth_headers(admin_b)).status_code == 404


def test_integrations_are_disabled_without_a_signing_key(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", None)
    resp = client.post(f"/api/v1/projects/{project_a.domain}/integrations", json={},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 503
    assert client.post("/integrations/v1/events", content=b"{}", headers={
        "X-HS-Integration": "hsi_x", "X-HS-Timestamp": str(int(time.time())), "X-HS-Signature": "v1=0"}
    ).status_code == 503


def test_secret_is_never_stored(client, db_session, admin_a, project_a):
    from app.models.integration import IntegrationCredential
    cred = _create_integration(client, admin_a, project_a)
    row = db_session.query(IntegrationCredential).filter_by(public_id=cred["integration_id"]).one()
    assert cred["secret"] not in json.dumps({c.name: str(getattr(row, c.key, "")) for c in row.__table__.columns})


# --------------------------------------------------------------------------- reference client behaviour

def test_reference_client_never_blocks_or_raises_on_transport_failure():
    calls = []

    def broken(method, url, headers, body, timeout):
        calls.append(method)
        raise OSError("network down")

    hook = HoneyShieldHook(INGEST, "hsi_x", "s", transport=broken, max_attempts=3, sleep=lambda s: None)
    hook._key_hashes = {integration_auth.sha256_hex("decoy-key"): "dcy_" + "1" * 24}
    started = time.perf_counter()
    assert hook.check_api_key("decoy-key", source_ip="203.0.113.1") is True
    assert time.perf_counter() - started < 0.05      # enqueue only, no network in the request path
    hook.drain()
    assert calls == ["POST", "POST", "POST"]          # bounded tries per round...
    assert len(hook._queue) == 1 and hook.stats["deferred"] == 1   # ...and the report is kept, not dropped


def test_reference_client_keeps_reports_through_an_outage_and_sends_them_once():
    """An outage delays reports; it does not lose them. Every retry has the same idempotency key."""
    sent, up = [], {"ok": False}

    def flaky(method, url, headers, body, timeout):
        if not up["ok"]:
            raise OSError("HoneyShield unreachable")
        sent.append(json.loads(body))
        return 202, b""

    hook = HoneyShieldHook(INGEST, "hsi_x", "s", transport=flaky, sleep=lambda s: None)
    hook._key_hashes = {integration_auth.sha256_hex("decoy-key"): "dcy_" + "4" * 24}
    for i in range(3):
        hook.check_api_key("decoy-key", source_ip=f"203.0.113.{i}")
    for _ in range(5):                                # many rounds while it is down
        hook.drain()
    assert sent == [] and len(hook._queue) == 3
    keys_before = [r["idempotency_key"] for r in hook._queue]
    up["ok"] = True
    assert hook.drain() == 3 and len(hook._queue) == 0
    assert [r["idempotency_key"] for r in sent] == keys_before and hook.stats["sent"] == 3


def test_reference_client_spool_survives_a_restart(tmp_path):
    spool = tmp_path / "honeyshield-hook.jsonl"
    down = lambda *a: (_ for _ in ()).throw(OSError("down"))  # noqa: E731
    hook = HoneyShieldHook(INGEST, "hsi_x", "s", transport=down, sleep=lambda s: None, spool_path=str(spool))
    hook._form_fields = {"website": "dcy_" + "5" * 24}
    hook.check_form({"website": "bot"}, source_ip="203.0.113.9")
    hook.stop()                                       # application shuts down while HoneyShield is unreachable
    assert len(spool.read_text().splitlines()) == 1
    received = []
    restarted = HoneyShieldHook(INGEST, "hsi_x", "s", spool_path=str(spool), sleep=lambda s: None,
                                transport=lambda m, u, h, b, t: (received.append(json.loads(b)) or (202, b"")) if m == "POST" else (200, b'{"decoys": []}'))
    restarted._load_spool()
    assert restarted.drain() == 1 and received[0]["decoy_id"] == "dcy_" + "5" * 24
    assert spool.read_text() == ""


def test_reference_client_queue_is_bounded():
    hook = HoneyShieldHook(INGEST, "hsi_x", "s", transport=lambda *a: (202, b""), queue_size=5)
    hook._form_fields = {"website": "dcy_" + "2" * 24}
    for i in range(20):
        hook.check_form({"website": "x"}, source_ip=f"203.0.113.{i}")
    assert len(hook._queue) == 5 and hook.stats["dropped_queue_full"] == 15


def test_reference_client_does_not_retry_rejections():
    calls = []

    def reject(method, url, headers, body, timeout):
        calls.append(1)
        return 422, b""

    hook = HoneyShieldHook(INGEST, "hsi_x", "s", transport=reject, sleep=lambda s: None)
    hook._key_hashes = {integration_auth.sha256_hex("k"): "dcy_" + "3" * 24}
    hook.check_api_key("k", source_ip="203.0.113.1")
    hook.drain()
    assert calls == [1] and hook.stats["rejected"] == 1


def test_public_and_manual_events_are_unaffected_and_filterable(client, db_session, admin_a, project_a, token_a):
    cred = _create_integration(client, admin_a, project_a)
    key = _generate(client, admin_a, project_a, "API_KEY")
    client.get(f"/t/{token_a.token_value}")
    hook = _hook(client, cred)
    hook.check_api_key(key["token_value"], source_ip="203.0.113.5")
    hook.drain()
    sources = sorted(e.source.value for e in db_session.query(DetectionEvent).all())
    assert sources == ["CUSTOMER_HOOK", "PUBLIC_INGEST"]
