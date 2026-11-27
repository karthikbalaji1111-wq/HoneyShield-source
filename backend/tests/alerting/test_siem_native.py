"""Native SIEM delivery: Splunk HTTP Event Collector and Microsoft Sentinel (Logs Ingestion API)."""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.models.alerting import OutboxEvent, OutboxStatus
from app.services import alerting
from app.services.alerting import siem, webhook
from tests.conftest import auth_headers

KEY = "alerting-master-key-for-tests-0123456789abcdef"
PUBLIC = ["93.184.216.34"]
HEC = "0f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8"
CLIENT = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRET = "s3cr~et.Value_with-chars@and:colons"
DCR = "dcr-" + "0123456789abcdef" * 2
HOST = "honeyshield-alerts-ab12.westeurope-1.ingest.monitor.azure.com"
SENTINEL = (f"sentinel://{CLIENT}:{urllib.parse.quote(SECRET, safe='')}@{HOST}/{DCR}/Custom-HoneyShield"
            f"?tenant={TENANT}")
TEMPLATE = Path(__file__).resolve().parents[3] / "deploy" / "sentinel" / "honeyshield-sentinel.json"


class Recorder:
    def __init__(self, *codes):
        self.codes, self.calls = list(codes), []

    def __call__(self, target, headers, body, timeout):
        self.calls.append((target, headers, body))
        return self.codes.pop(0) if len(self.codes) > 1 else self.codes[0]


class TokenServer:
    """Stands in for login.microsoftonline.com."""

    def __init__(self, status=200, payload=None):
        self.status = status
        self.payload = payload if payload is not None else {"access_token": "eyJ.token", "expires_in": 3599}
        self.calls = []

    def __call__(self, target, headers, body, timeout):
        self.calls.append((target, headers, body))
        return self.status, json.dumps(self.payload).encode()


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: PUBLIC)
    siem.TOKENS._tokens.clear()


def _dest(client, admin, **kw):
    r = client.post("/api/v1/alert-destinations", json=kw, headers=auth_headers(admin))
    assert r.status_code == 201, r.text
    return r.json()


def _due(db_session):
    for row in db_session.query(OutboxEvent).filter(OutboxEvent.status == OutboxStatus.PENDING):
        row.next_attempt_at = row.created_at
    db_session.commit()


# ----------------------------------------------------------------------------------- Splunk

@pytest.mark.parametrize("url", [
    f"https://{HEC}@splunk.example.com", f"splunk://not-a-guid@splunk.example.com",
    f"splunk://{HEC}:x@splunk.example.com", f"splunk://{HEC}@splunk.example.com:9997",
    f"splunk://{HEC}@splunk.example.com/services/collector", f"splunk://{HEC}@splunk.example.com?index=Bad Index",
    f"splunk://{HEC}@splunk.example.com?sourcetype=x", f"splunk://{HEC}@localhost", f"splunk://{HEC}@",
])
def test_invalid_splunk_urls_are_refused(url):
    with pytest.raises(webhook.UnsafeWebhookURL):
        siem.parse_splunk(url)


def test_splunk_url_defaults():
    t = siem.parse_splunk(f"splunk://{HEC}@HEC.Example.com?index=security")
    assert (t.host, t.port, t.token, t.index) == ("hec.example.com", 8088, HEC, "security")
    assert t.endpoint == "https://hec.example.com:8088/services/collector/event"
    assert siem.parse_splunk(f"splunk://{HEC}@http-inputs-acme.splunkcloud.com:443").port == 443


def test_detection_reaches_splunk(client, db_session, admin_a, token_a):
    dest = _dest(client, admin_a, format="SPLUNK_HEC", url=f"splunk://{HEC}@hec.example.com?index=security")
    assert dest["signing_secret"] is None
    assert dest["url"] == f"splunk://****{HEC[-4:]}@hec.example.com?index=security"
    listed = client.get("/api/v1/alert-destinations", headers=auth_headers(admin_a)).json()
    assert HEC not in json.dumps(listed)

    client.get(f"/t/{token_a.token_value}")
    sender = Recorder(200)
    assert alerting.run_once(db_session, sender=sender) == {"DELIVERED": 1}
    target, headers, body = sender.calls[0]
    assert (target.scheme, target.host, target.port, target.path) == (
        "https", "hec.example.com", 8088, "/services/collector/event")
    assert target.addresses == tuple(PUBLIC)
    assert headers["Authorization"] == f"Splunk {HEC}"
    assert headers["X-Splunk-Request-Channel"] == siem.splunk_channel(dest["destination_id"])
    event = json.loads(body)
    assert event["sourcetype"] == "honeyshield:detection" and event["source"] == "honeyshield"
    assert event["index"] == "security" and isinstance(event["time"], float)
    assert event["event"]["token_type"] == "URL" and event["event"]["severity"] == "HIGH"
    assert [t["id"] for t in event["event"]["attack"]] == ["T1595.003", "T1213"]
    assert "triggered_ms" not in event["event"] and token_a.token_value not in body.decode()


@pytest.mark.parametrize("code,status", [(403, "DEAD"), (400, "DEAD"), (503, "PENDING"), (429, "PENDING")])
def test_splunk_answers(client, db_session, admin_a, token_a, code, status):
    _dest(client, admin_a, format="SPLUNK_HEC", url=f"splunk://{HEC}@hec.example.com")
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder(code)) == {status: 1}


# --------------------------------------------------------------------------------- Sentinel

def test_sentinel_url_parses_and_decodes_the_secret():
    t = siem.parse_sentinel(SENTINEL)
    assert (t.client_id, t.client_secret, t.host, t.dcr, t.stream, t.tenant) == (
        CLIENT, SECRET, HOST, DCR, "Custom-HoneyShield", TENANT)
    assert t.endpoint == (f"https://{HOST}/dataCollectionRules/{DCR}/streams/Custom-HoneyShield"
                          "?api-version=2023-01-01")
    assert t.token_endpoint == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert siem.parse_sentinel(SENTINEL.replace(TENANT, "Contoso.onmicrosoft.com")).tenant == "contoso.onmicrosoft.com"


@pytest.mark.parametrize("mutate", [
    lambda u: u.replace("sentinel://", "https://"),
    lambda u: u.replace(HOST, "evil.example.com"),
    lambda u: u.replace(HOST, "x.ingest.monitor.azure.com.evil.com"),
    lambda u: u.replace(DCR, "dcr-xyz"),
    lambda u: u.replace("Custom-HoneyShield", "HoneyShield"),
    lambda u: u.replace(f"?tenant={TENANT}", ""),
    lambda u: u.replace(f"tenant={TENANT}", f"tenant={TENANT}&x=1"),
    lambda u: u.replace(CLIENT, "not-a-guid"),
    lambda u: u.replace(HOST, HOST + ":8443"),
    lambda u: u.replace(f":{urllib.parse.quote(SECRET, safe='')}@", "@"),
])
def test_invalid_sentinel_urls_are_refused(mutate):
    with pytest.raises(webhook.UnsafeWebhookURL):
        siem.parse_sentinel(mutate(SENTINEL))


def test_detection_reaches_sentinel(client, db_session, admin_a, token_a):
    dest = _dest(client, admin_a, format="SENTINEL", url=SENTINEL)
    assert SECRET not in json.dumps(dest) and urllib.parse.quote(SECRET, safe="") not in json.dumps(dest)
    assert dest["url"] == f"sentinel://{CLIENT}:****@{HOST}/{DCR}/Custom-HoneyShield?tenant={TENANT}"

    client.get(f"/t/{token_a.token_value}")
    login, sender = TokenServer(), Recorder(204)
    assert alerting.run_once(db_session, sender=sender, requester=login) == {"DELIVERED": 1}

    [(ltarget, lheaders, lbody)] = login.calls
    assert (ltarget.host, ltarget.path) == ("login.microsoftonline.com", f"/{TENANT}/oauth2/v2.0/token")
    form = urllib.parse.parse_qs(lbody.decode())
    assert form == {"client_id": [CLIENT], "client_secret": [SECRET], "grant_type": ["client_credentials"],
                    "scope": ["https://monitor.azure.com//.default"]}

    target, headers, body = sender.calls[0]
    assert (target.host, target.port) == (HOST, 443)
    assert target.path == f"/dataCollectionRules/{DCR}/streams/Custom-HoneyShield?api-version=2023-01-01"
    assert headers["Authorization"] == "Bearer eyJ.token"
    [record] = json.loads(body)
    assert record["Severity"] == "HIGH" and record["TokenType"] == "URL"
    assert record["AttackTechniques"] == "T1595.003,T1213" and record["TimeGenerated"]
    assert SECRET not in body.decode()

    # The token is reused for the next alert.
    client.get(f"/t/{token_a.token_value}?again=1")
    alerting.run_once(db_session, sender=Recorder(204), requester=login)
    assert len(login.calls) == 1


def test_sentinel_record_matches_the_template():
    template = json.loads(TEMPLATE.read_text())
    resources = {r["type"]: r for r in template["resources"]}
    stream = resources["Microsoft.Insights/dataCollectionRules"]["properties"]["streamDeclarations"]["Custom-HoneyShield"]
    table = resources["Microsoft.OperationalInsights/workspaces/tables"]["properties"]["schema"]["columns"]
    record = siem.sentinel_record({"attack": []})
    assert [c["name"] for c in stream["columns"]] == list(record) == [c["name"] for c in table]


def test_bad_sentinel_credentials_are_permanent(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="SENTINEL", url=SENTINEL)
    client.get(f"/t/{token_a.token_value}")
    login = TokenServer(401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"})
    sender = Recorder(204)
    assert alerting.run_once(db_session, sender=sender, requester=login) == {"DEAD": 1}
    assert sender.calls == []
    row = db_session.query(OutboxEvent).one()
    assert "invalid_client" in row.last_error and SECRET not in row.last_error


def test_entra_outage_is_retried(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="SENTINEL", url=SENTINEL)
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder(204), requester=TokenServer(503, {})) == {"PENDING": 1}


def test_missing_role_is_retried_and_a_rejected_token_is_dropped(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="SENTINEL", url=SENTINEL)
    client.get(f"/t/{token_a.token_value}")
    login = TokenServer()
    # 403 while the role assignment propagates, then 401 (token revoked), then accepted.
    assert alerting.run_once(db_session, sender=Recorder(403), requester=login) == {"PENDING": 1}
    _due(db_session)
    assert alerting.run_once(db_session, sender=Recorder(401), requester=login) == {"PENDING": 1}
    _due(db_session)
    assert alerting.run_once(db_session, sender=Recorder(204), requester=login) == {"DELIVERED": 1}
    assert len(login.calls) == 2  # fetched again after the 401


def test_sentinel_payload_errors_are_permanent(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="SENTINEL", url=SENTINEL)
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder(400), requester=TokenServer()) == {"DEAD": 1}


def test_test_alert_reaches_both(client, db_session, admin_a):
    for kw in ({"format": "SPLUNK_HEC", "url": f"splunk://{HEC}@hec.example.com"},
               {"format": "SENTINEL", "url": SENTINEL}):
        dest = _dest(client, admin_a, **kw)
        r = client.post(f"/api/v1/alert-destinations/{dest['destination_id']}/test", headers=auth_headers(admin_a))
        assert r.status_code == 202, r.text
    sender = Recorder(200)
    assert alerting.run_once(db_session, sender=sender, requester=TokenServer()) == {"DELIVERED": 2}
    bodies = [json.loads(c[2]) for c in sender.calls]
    assert any(isinstance(b, dict) and b["event"]["source"] == "TEST" for b in bodies)
    assert any(isinstance(b, list) and b[0]["DetectionSource"] == "TEST" for b in bodies)


def test_private_ingestion_hosts_are_refused(client, admin_a, monkeypatch):
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: ["10.0.0.5"])
    r = client.post("/api/v1/alert-destinations", json={"format": "SPLUNK_HEC", "url": f"splunk://{HEC}@hec.example.com"},
                    headers=auth_headers(admin_a))
    assert r.status_code == 422
