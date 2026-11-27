"""Active Directory decoy accounts: generation, setup scripts, the DC manifest and directory reports.

The PowerShell collector itself is exercised at the end when ``pwsh`` is available (it is on the CI
runners): its signing and its report format must be exactly what the server accepts.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core import integration_auth
from app.core.config import get_settings
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSource
from app.models.honey_token import HoneyToken
from app.models.integration import IntegrationCredential
from app.schemas.integration import DirectoryReport
from app.services.bait_files import AD_SCRIPTS
from tests.conftest import auth_headers

INGEST = "https://ingest.honeyshield.test"
SIGNING_KEY = "integration-master-key-for-tests-0123456789abcdef"
COLLECTOR = AD_SCRIPTS / "HoneyShield-DCCollector.ps1"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", SIGNING_KEY)
    monkeypatch.setattr(get_settings(), "public_ingest_base_url", INGEST)


def _integration(client, admin, project):
    resp = client.post(f"/api/v1/projects/{project.domain}/integrations", json={"label": "dc01"},
                       headers=auth_headers(admin))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _generate(client, admin, project, token_type="AD_ACCOUNT", **params):
    resp = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate",
                       json={"token_type": token_type, "generator_params": params or None},
                       headers=auth_headers(admin))
    return resp


def _decoy(client, admin, project, **params):
    resp = _generate(client, admin, project, **params)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _signed(client, cred, body, path="/integrations/v1/directory-events", method="POST"):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    ts = str(int(time.time()))
    headers = {"X-HS-Integration": cred["integration_id"], "X-HS-Timestamp": ts,
               "X-HS-Signature": integration_auth.sign(cred["secret"], method, path, ts, raw),
               "Content-Type": "application/json"}
    return client.request(method, path, headers=headers, content=raw)


def _report(decoy, **overrides):
    body = {"decoy_id": decoy["decoy_id"], "idempotency_key": "ad_" + "1" * 40,
            "observed_at": datetime.now(timezone.utc).isoformat(), "windows_event_id": 4769,
            "succeeded": True, "domain_controller": "DC01.corp.example.com",
            "target_name": decoy["metadata"]["account_name"], "source_ip": "::ffff:10.20.4.31",
            "actor": "jsmith@CORP.EXAMPLE.COM", "status": "0x0", "ticket_encryption": "0x17", "record_id": 912345}
    body.update(overrides)
    return body


def _events(db_session, decoy):
    db_session.expire_all()
    token = db_session.query(HoneyToken).filter_by(decoy_id=decoy["decoy_id"]).one()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token.id).order_by(DetectionEvent.id).all()


def _download(client, admin, decoy, kind):
    return client.get(f"/api/v1/honey-tokens/{decoy['decoy_id']}/files/{kind}", headers=auth_headers(admin))


# --------------------------------------------------------------------------- generation

def test_generated_decoy_is_an_ordinary_looking_account(client, admin_a, project_a):
    decoy = _decoy(client, admin_a, project_a)
    meta = decoy["metadata"]
    assert decoy["token_type"] == "AD_ACCOUNT"
    assert decoy["token_value"].startswith("ad-") and len(decoy["token_value"]) == 35
    assert meta["account_name"] and meta["account_name"] not in decoy["token_value"]
    assert meta["audit_reads"] is False and meta["admin_count"] is True
    assert meta["detection"]["docs"] == "docs/active-directory-decoys.md"
    assert decoy["files"] == ["setup-script", "dc-collector"]


def test_chosen_name_spn_and_read_auditing(client, admin_a, project_a):
    decoy = _decoy(client, admin_a, project_a, account_name="svc_backup_legacy", spn="HTTP/backup02",
                   audit_reads=True, description="Legacy backup service")
    meta = decoy["metadata"]
    assert (meta["account_name"], meta["spn"], meta["audit_reads"]) == ("svc_backup_legacy", "HTTP/backup02", True)
    no_spn = _decoy(client, admin_a, project_a, account_name="adm_old", spn=False)
    assert no_spn["metadata"]["spn"] is None


@pytest.mark.parametrize("params", [
    {"account_name": "has space"}, {"account_name": "a" * 21}, {"account_name": "x'; Remove-ADUser"},
    {"spn": "HTTP/host(1)"}, {"description": "Line\nbreak"}, {"description": "quote ' inside"},
])
def test_unsafe_parameters_are_refused(client, admin_a, project_a, params):
    assert _generate(client, admin_a, project_a, **params).status_code == 422


def test_names_are_unique_per_project(client, admin_a, admin_b, project_a, project_b):
    _decoy(client, admin_a, project_a, account_name="svc_veeam")
    resp = _generate(client, admin_a, project_a, account_name="SVC_VEEAM")
    assert resp.status_code == 422 and "account name" in resp.text
    _decoy(client, admin_b, project_b, account_name="svc_veeam")  # another customer may use it too
    # Generated names never collide, even after every built-in name is used.
    names = {_decoy(client, admin_a, project_a)["metadata"]["account_name"].lower() for _ in range(10)}
    assert len(names) == 10 and "svc_veeam" not in names


def test_refused_where_integrations_are_not_configured(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", None)
    resp = _generate(client, admin_a, project_a)
    assert resp.status_code == 422 and "INTEGRATION_SIGNING_KEY" in resp.text
    types = client.get("/api/v1/honey-tokens/types", headers=auth_headers(admin_a)).json()["types"]
    assert types["AD_ACCOUNT"] is False


def test_rotation_keeps_the_account(client, db_session, admin_a, project_a):
    decoy = _decoy(client, admin_a, project_a, account_name="svc_reporting", spn=False)
    resp = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": decoy["token_value"]},
                       headers=auth_headers(admin_a))
    assert resp.status_code == 200, resp.text
    new = resp.json()
    assert new["decoy_id"] != decoy["decoy_id"]
    assert new["metadata"]["account_name"] == "svc_reporting" and new["metadata"]["spn"] is None


# --------------------------------------------------------------------------- scripts

def test_setup_script_carries_the_decoy(client, db_session, admin_a, project_a):
    decoy = _decoy(client, admin_a, project_a, account_name="svc_sqlbackup", spn="MSSQLSvc/sqlbak01:1433",
                   audit_reads=True)
    resp = _download(client, admin_a, decoy, "setup-script")
    assert resp.status_code == 200
    assert 'filename="New-HoneyShieldDecoy-svc_sqlbackup.ps1"' in resp.headers["content-disposition"]
    text = resp.content.decode("ascii")
    assert "{{" not in text and "\r\n" in text and "\n" not in text.replace("\r\n", "")
    assert "$AccountName   = 'svc_sqlbackup'" in text
    assert "$SpnTemplate   = 'MSSQLSvc/sqlbak01:1433'" in text
    assert "$AuditReads    = $true" in text and "$SetAdminCount = $true" in text
    assert decoy["decoy_id"] in text
    # Nothing secret is in it: the password is generated on the domain controller.
    assert decoy["token_value"] not in text


def test_collector_points_at_this_installation(client, admin_a, project_a):
    decoy = _decoy(client, admin_a, project_a)
    resp = _download(client, admin_a, decoy, "dc-collector")
    assert resp.status_code == 200
    text = resp.content.decode("ascii")
    assert f"[string]$BaseUrl = '{INGEST}'" in text and "{{" not in text


# --------------------------------------------------------------------------- manifest

def test_directory_manifest_lists_accounts_once(client, db_session, admin_a, project_a):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="svc_ansible", audit_reads=True)
    _generate(client, admin_a, project_a, token_type="API_KEY")
    rotated = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": decoy["token_value"]},
                          headers=auth_headers(admin_a)).json()

    resp = _signed(client, cred, b"", path="/integrations/v1/directory-manifest", method="GET")
    assert resp.status_code == 200
    decoys = resp.json()["decoys"]
    assert decoys == [{"decoy_id": rotated["decoy_id"], "account_name": "svc_ansible", "spn": rotated["metadata"]["spn"],
                       "audit_reads": True, "is_active": True}]
    assert decoy["token_value"] not in resp.text and rotated["token_value"] not in resp.text
    db_session.expire_all()
    assert db_session.query(IntegrationCredential).filter_by(public_id=cred["integration_id"]).one().last_used_at

    # The HTTP middleware manifest does not list directory decoys.
    plain = _signed(client, cred, b"", path="/integrations/v1/manifest", method="GET").json()["decoys"]
    assert all(d["token_type"] != "AD_ACCOUNT" for d in plain)


def test_manifest_needs_a_signature(client):
    assert client.get("/integrations/v1/directory-manifest").status_code == 401


# --------------------------------------------------------------------------- reports

def test_kerberoasting_is_recorded_as_critical(client, db_session, admin_a, project_a):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="svc_sqlbackup")
    assert _signed(client, cred, _report(decoy)).status_code == 202

    [event] = _events(db_session, decoy)
    assert event.source == EventSource.CUSTOMER_HOOK
    assert (event.request_path, event.http_method, event.severity.value) == ("ad/service-ticket", "AD", "CRITICAL")
    assert event.ip_address == "10.20.4.31"
    assert event.headers == {"ad-event-id": "4769", "ad-domain-controller": "DC01.corp.example.com",
                             "ad-target": "svc_sqlbackup", "ad-actor": "jsmith@CORP.EXAMPLE.COM",
                             "ad-status": "0x0", "ad-ticket-encryption": "0x17", "ad-record-id": "912345"}

    [view] = client.get("/api/v1/detection-events", headers=auth_headers(admin_a)).json()
    assert [t["id"] for t in view["attack"]] == ["T1558.003"]


@pytest.mark.parametrize("event_id,succeeded,kind,severity,technique", [
    (4771, False, "ad/preauth-failure", "CRITICAL", "T1110"),
    (4625, False, "ad/logon-failure", "CRITICAL", "T1110"),
    (4768, False, "ad/tgt-failure", "CRITICAL", "T1110"),
    (4768, True, "ad/tgt-issued", "CRITICAL", "T1078.002"),
    (4776, False, "ad/ntlm-failure", "CRITICAL", "T1110"),
    (4624, True, "ad/logon-success", "CRITICAL", "T1078.002"),
    (4662, True, "ad/object-read", "HIGH", "T1087.002"),
])
def test_event_kinds(client, db_session, admin_a, project_a, event_id, succeeded, kind, severity, technique):
    from app.core.attack import technique_ids

    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="it_admin_temp")
    body = _report(decoy, windows_event_id=event_id, succeeded=succeeded, target_name="CORP\\IT_ADMIN_TEMP",
                   ticket_encryption=None, actor=None, status="0xC000006A", logon_type=3)
    assert _signed(client, cred, body).status_code == 202
    [event] = _events(db_session, decoy)
    assert (event.request_path, event.severity.value) == (kind, severity)
    assert technique_ids("AD_ACCOUNT", event.request_path) == [technique]
    assert event.headers["ad-status"] == "0xc000006a" and event.headers["ad-logon-type"] == "3"


def test_events_without_an_address(client, db_session, admin_a, project_a):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="adm_helpdesk")
    body = _report(decoy, windows_event_id=4776, succeeded=False, source_ip=None, workstation="WKS-0193")
    del body["source_ip"]
    assert _signed(client, cred, body).status_code == 202
    [event] = _events(db_session, decoy)
    assert event.ip_address == "0.0.0.0" and event.headers["ad-workstation"] == "WKS-0193"


def test_resent_events_are_stored_once(client, db_session, admin_a, project_a):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a)
    for _ in range(3):
        assert _signed(client, cred, _report(decoy)).status_code == 202
    assert len(_events(db_session, decoy)) == 1


def test_event_for_another_account_is_rejected(client, db_session, admin_a, project_a):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="svc_veeam")
    assert _signed(client, cred, _report(decoy, target_name="administrator")).status_code == 422
    assert _events(db_session, decoy) == []


def test_reports_only_reach_own_directory_decoys(client, db_session, admin_a, admin_b, project_a, project_b):
    cred_a = _integration(client, admin_a, project_a)
    other = _decoy(client, admin_b, project_b, account_name="svc_veeam")
    assert _signed(client, cred_a, _report(other)).status_code == 202          # no oracle
    assert _events(db_session, other) == []

    api_key = _generate(client, admin_a, project_a, token_type="API_KEY").json()
    body = _report({"decoy_id": api_key["decoy_id"], "metadata": {"account_name": "svc_veeam"}})
    assert _signed(client, cred_a, body).status_code == 202
    assert _events(db_session, api_key) == []

    # And an AD decoy cannot be reported as an HTTP hit.
    own = _decoy(client, admin_a, project_a, account_name="svc_veeam")
    http = {"decoy_id": own["decoy_id"], "idempotency_key": "idem-" + "b" * 20,
            "observed_at": datetime.now(timezone.utc).isoformat(), "source_ip": "203.0.113.5"}
    assert _signed(client, cred_a, http, path="/integrations/v1/events").status_code == 202
    assert _events(db_session, own) == []


@pytest.mark.parametrize("override", [
    {"windows_event_id": 4720}, {"domain_controller": "dc01; rm"}, {"target_name": "svc\x00x"},
    {"status": "error"}, {"logon_type": 99}, {"observed_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()},
    {"password": "Summer2026!"}, {"source_ip": "not-an-ip"},
])
def test_malformed_reports_are_rejected(client, db_session, admin_a, project_a, override):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a)
    resp = _signed(client, cred, _report(decoy, **override))
    assert resp.status_code == 422 and resp.json() == {"detail": "Report validation failed"}
    assert _events(db_session, decoy) == []


def test_alert_payload_names_the_technique_of_the_event(client, db_session, admin_a, project_a):
    from app.services.alerting import event_data

    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a)
    _signed(client, cred, _report(decoy, windows_event_id=4771, succeeded=False))
    [event] = _events(db_session, decoy)
    data = event_data(event, delivery_id=1)
    assert data["token_type"] == "AD_ACCOUNT" and data["request_path"] == "ad/preauth-failure"
    assert data["attack"] == [{"id": "T1110", "name": "Brute Force"}]


# --------------------------------------------------------------------------- the collector itself

PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")


def _pwsh(script: str, tmp_path: Path) -> str:
    out = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                         text=True, timeout=120, cwd=tmp_path)
    assert out.returncode == 0, out.stderr + out.stdout
    return out.stdout.strip()


@needs_pwsh
def test_scripts_parse(client, admin_a, project_a, tmp_path):
    decoy = _decoy(client, admin_a, project_a, audit_reads=True)
    for kind, name in (("setup-script", "setup.ps1"), ("dc-collector", "collector.ps1")):
        (tmp_path / name).write_bytes(_download(client, admin_a, decoy, kind).content)
    out = _pwsh("$e = $null; foreach ($f in 'setup.ps1','collector.ps1') { "
                "[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f), [ref]$null, [ref]$e); "
                "if ($e) { $e | ForEach-Object { \"$f $($_.Extent.StartLineNumber): $($_.Message)\" } } }; 'parsed'", tmp_path)
    assert out == "parsed"


@needs_pwsh
def test_collector_signs_and_reports_what_the_server_accepts(client, db_session, admin_a, project_a, tmp_path):
    cred = _integration(client, admin_a, project_a)
    decoy = _decoy(client, admin_a, project_a, account_name="svc_sqlbackup", audit_reads=True)
    path = "/integrations/v1/directory-events"
    when = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    script = f"""
        . '{COLLECTOR}' -StateDir '{tmp_path}'
        $data = @{{ TargetUserName = 'jsmith@CORP.EXAMPLE.COM'; ServiceName = 'SVC_SQLBACKUP'; IpAddress = '::ffff:10.20.4.31';
                   Status = '0x0'; TicketEncryptionType = '0x17'; ServiceSid = 'S-1-5-21-1-2-3-1105' }}
        $report = ConvertTo-HsDirectoryReport -DecoyId '{decoy["decoy_id"]}' -AccountName 'svc_sqlbackup' -EventId 4769 `
            -Keywords ([long]-9214364837600034816) -RecordId 4242 -MachineName 'DC01.corp.example.com' `
            -TimeCreated ([datetime]::Parse('{when.isoformat()}').ToUniversalTime()) -Data $data
        $body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $report -Compress -Depth 4))
        $ts = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $sig = New-HsSignature '{cred["secret"]}' 'POST' '{path}' $ts $body
        $xpath = Get-HsXPath 'svc_sqlbackup' 'b0e1f6a2-1111-2222-3333-444455556666' 10 20
        ConvertTo-Json -Compress -InputObject @{{ body = [Convert]::ToBase64String($body); ts = $ts; sig = $sig; xpath = $xpath }}
    """
    out = json.loads(_pwsh(script, tmp_path).splitlines()[-1])
    import base64
    raw = base64.b64decode(out["body"])
    assert out["sig"] == integration_auth.sign(cred["secret"], "POST", path, out["ts"], raw)
    report = DirectoryReport.model_validate_json(raw)
    assert (report.windows_event_id, report.succeeded, report.target_name) == (4769, True, "SVC_SQLBACKUP")
    assert report.observed_at == when and report.source_ip == "10.20.4.31"

    resp = client.post(path, content=raw, headers={"X-HS-Integration": cred["integration_id"],
                                                   "X-HS-Timestamp": out["ts"], "X-HS-Signature": out["sig"],
                                                   "Content-Type": "application/json"})
    assert resp.status_code == 202
    [event] = _events(db_session, decoy)
    assert event.request_path == "ad/service-ticket" and event.headers["ad-actor"] == "jsmith@CORP.EXAMPLE.COM"

    xpath = out["xpath"]
    assert "EventRecordID > 10 and EventRecordID <= 20" in xpath
    for name in ("svc_sqlbackup", "SVC_SQLBACKUP"):
        assert f"Data[@Name='TargetUserName']='{name}'" in xpath and f"Data[@Name='ServiceName']='{name}'" in xpath
    assert "Data[@Name='ObjectName']='%{b0e1f6a2-1111-2222-3333-444455556666}'" in xpath
