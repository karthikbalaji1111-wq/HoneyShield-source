"""MITRE ATT&CK labels on events and alerts, and PagerDuty (Events API v2) delivery."""
from __future__ import annotations

import json

import pytest

from app.core import attack
from app.core.config import get_settings
from app.models.alerting import OutboxStatus
from app.models.enums import HoneyTokenType
from app.services import alerting
from app.services.alerting import channels, pagerduty, webhook
from tests.conftest import auth_headers

KEY = "alerting-master-key-for-tests-0123456789abcdef"
PUBLIC = ["93.184.216.34"]
PD_KEY = "R0utingKey0123456789abcdefABCDEF"


class Recorder:
    def __init__(self, code):
        self.code, self.calls = code, []

    def __call__(self, target, headers, body, timeout):
        self.calls.append((target, headers, body))
        return self.code


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)
    looked_up: list[str] = []
    monkeypatch.setattr(webhook, "default_resolver", lambda host, port: looked_up.append(host) or PUBLIC)
    return looked_up


def _dest(client, admin, **kw):
    r = client.post("/api/v1/alert-destinations", json={"url": "https://hooks.example.com/hs", **kw},
                    headers=auth_headers(admin))
    assert r.status_code == 201, r.text
    return r.json()


# ----------------------------------------------------------------------------- ATT&CK

def test_every_decoy_type_has_a_mapping_of_known_techniques():
    assert set(attack.BY_DECOY_TYPE) == {t.value for t in HoneyTokenType}
    for ids in attack.BY_DECOY_TYPE.values():
        assert all(i in attack.TECHNIQUES for i in ids)
    [t] = [x for x in attack.techniques_for("AWS_KEY") if x["id"] == "T1078.004"]
    assert t == {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",
                 "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                 "url": "https://attack.mitre.org/techniques/T1078/004/"}
    assert attack.techniques_for("FORM_FIELD") == [] and attack.techniques_for(None) == []


def test_events_carry_attack_techniques(client, admin_a, user_a, token_a):
    client.get(f"/t/{token_a.token_value}")
    for viewer in (admin_a, user_a):
        [event] = client.get("/api/v1/detection-events", headers=auth_headers(viewer)).json()
        assert [t["id"] for t in event["attack"]] == ["T1595.003", "T1213"]


def test_webhook_slack_email_and_cef_alerts_name_the_techniques(client, db_session, admin_a, token_a):
    _dest(client, admin_a)
    _dest(client, admin_a, format="SLACK", url="https://hooks.example.com/slack")
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder(204)
    alerting.run_once(db_session, sender=sender)
    bodies = [json.loads(c[2]) for c in sender.calls]
    [envelope] = [b for b in bodies if "data" in b]
    assert envelope["data"]["attack"] == [{"id": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
                                          {"id": "T1213", "name": "Data from Information Repositories"}]
    [slack] = [b for b in bodies if "text" in b]
    assert slack["text"].endswith("ATT&CK: T1595.003, T1213.")

    data = envelope["data"] | {"triggered_ms": 1}
    assert "cs6Label=attackTechniques cs6=T1595.003,T1213" in channels.cef_message(data)
    assert "ATT&CK:          T1595.003 Active Scanning: Wordlist Scanning, T1213 " in channels.email_body(data)
    # A type with no technique sends no empty CEF field.
    assert "cs6" not in channels.cef_message(data | {"attack": []})


# ----------------------------------------------------------------------------- PagerDuty

@pytest.mark.parametrize("url", [
    "https://events.pagerduty.com/v2/enqueue",
    "pagerduty://short",
    f"pagerduty://{PD_KEY}/extra",
    f"pagerduty://{PD_KEY}?x=1",
    f"pagerduty://user@{PD_KEY}",
    "pagerduty://bad-key-with-dashes-0123456789",
    "pagerduty+us://" + PD_KEY,
])
def test_invalid_pagerduty_urls_are_refused(url):
    with pytest.raises(webhook.UnsafeWebhookURL):
        pagerduty.parse_url(url)


def test_pagerduty_url_keeps_the_key_case_and_picks_the_region():
    assert pagerduty.parse_url(f"pagerduty://{PD_KEY}") == pagerduty.PagerDutyTarget(
        "https://events.pagerduty.com/v2/enqueue", PD_KEY)
    assert pagerduty.parse_url(f"PagerDuty+EU://{PD_KEY}").endpoint == "https://events.eu.pagerduty.com/v2/enqueue"


def test_creating_a_pagerduty_destination_never_resolves_the_key(client, admin_a, configured):
    dest = _dest(client, admin_a, format="PAGERDUTY", url=f"pagerduty://{PD_KEY}")
    assert dest["signing_secret"] is None
    assert PD_KEY.lower() not in [h.lower() for h in configured]
    assert "events.pagerduty.com" in configured


def test_a_detection_pages_through_the_events_api(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="PAGERDUTY", url=f"pagerduty://{PD_KEY}")
    client.get(f"/t/{token_a.token_value}")
    sender = Recorder(202)
    assert alerting.run_once(db_session, sender=sender) == {"DELIVERED": 1}
    target, headers, body = sender.calls[0]
    assert (target.scheme, target.host, target.path) == ("https", "events.pagerduty.com", "/v2/enqueue")
    assert target.addresses == tuple(PUBLIC)
    event = json.loads(body)
    assert event["routing_key"] == PD_KEY and event["event_action"] == "trigger"
    assert event["dedup_key"].startswith("honeyshield-") and event["dedup_key"] != "honeyshield-None"
    p = event["payload"]
    assert p["severity"] == "error" and p["source"] == "alpha.example.com" and p["component"] == "URL"
    assert p["class"] == "honeytoken" and "URL decoy 'Alpha token'" in p["summary"]
    assert p["custom_details"]["attack"].startswith("T1595.003 Active Scanning")
    assert token_a.token_value not in body.decode()


def test_pagerduty_rejection_is_permanent_and_rate_limits_retry(client, db_session, admin_a, token_a):
    _dest(client, admin_a, format="PAGERDUTY", url=f"pagerduty://{PD_KEY}")
    client.get(f"/t/{token_a.token_value}")
    assert alerting.run_once(db_session, sender=Recorder(429)) == {"PENDING": 1}
    from app.models.alerting import OutboxEvent
    row = db_session.query(OutboxEvent).one()
    row.next_attempt_at = row.created_at
    db_session.commit()
    assert alerting.run_once(db_session, sender=Recorder(400)) == {"DEAD": 1}
    db_session.expire_all()
    assert db_session.query(OutboxEvent).one().status == OutboxStatus.DEAD


def test_pagerduty_test_alert_is_informational(client, db_session, admin_a):
    dest = _dest(client, admin_a, format="PAGERDUTY", url=f"pagerduty+eu://{PD_KEY}")
    r = client.post(f"/api/v1/alert-destinations/{dest['destination_id']}/test", headers=auth_headers(admin_a))
    assert r.status_code == 202
    sender = Recorder(202)
    alerting.run_once(db_session, sender=sender)
    target, _, body = sender.calls[0]
    event = json.loads(body)
    assert target.host == "events.eu.pagerduty.com"
    assert event["payload"]["severity"] == "info" and "test alert" in event["payload"]["summary"]
    assert event["dedup_key"] == f"honeyshield-test-{r.json()['delivery_id']}"
