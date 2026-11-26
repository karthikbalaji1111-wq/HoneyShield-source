"""Cloud canaries: real (fake-AWS) keys that can do nothing, and every use of them recorded.

Covers the lifecycle the worker owns: provisioning (deny-all user + key, recovery from a crash,
never touching someone else's user), detection from CloudTrail (provenance, context, duplicates,
regional failures, non-IP sources) and clean-up when the decoy is revoked.
"""
from __future__ import annotations

import json

import pytest

from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.enums import EventSeverity, EventSource
from app.models.honey_token import HoneyToken
from app.services import aws_canary
from app.services.aws_canary import AwsClient, AwsError, CanaryManager
from app.workers.cloud_canary import run_cycle
from tests.cloud.fake_aws import FakeAws
from tests.conftest import auth_headers


@pytest.fixture()
def aws(monkeypatch):
    fake = FakeAws()
    s = get_settings()
    for name, value in (("aws_canary_enabled", True), ("aws_canary_regions", "us-east-1,eu-west-1"),
                        ("aws_canary_iam_path", "/svc/"), ("aws_canary_endpoint_url", fake.url),
                        ("aws_canary_permissions_boundary", "arn:aws:iam::123456789012:policy/hs-canary-boundary")):
        monkeypatch.setattr(s, name, value)
    monkeypatch.setattr(aws_canary, "LOOKUP_INTERVAL", 0)
    yield fake
    fake.close()


@pytest.fixture()
def manager(db_session, aws):
    m = CanaryManager(db_session, get_settings(), AwsClient("AKIDTEST", "secret", aws.url))
    m.identify()
    return m


def _generate(client, admin, project):
    r = client.post(f"/api/v1/projects/{project.domain}/honey-tokens/generate", json={"token_type": "AWS_KEY"},
                    headers=auth_headers(admin))
    assert r.status_code == 201, r.text
    return r.json()


def _token(db_session, token_id) -> HoneyToken:
    db_session.expire_all()
    return db_session.get(HoneyToken, token_id)


def _events(db_session, token_id):
    db_session.expire_all()
    return db_session.query(DetectionEvent).filter_by(honey_token_id=token_id).order_by(DetectionEvent.id).all()


# ----------------------------------------------------------------------------------- provisioning
def test_generation_waits_for_the_worker(client, admin_a, project_a, aws):
    token = _generate(client, admin_a, project_a)
    assert token["token_type"] == "AWS_KEY" and token["metadata"]["status"] == "provisioning"
    assert token["metadata"]["iam_user"] == token["token_value"] and aws.users == {}


def test_aws_keys_need_the_worker_configured(client, admin_a, project_a, monkeypatch):
    monkeypatch.setattr(get_settings(), "aws_canary_enabled", False)
    r = client.post(f"/api/v1/projects/{project_a.domain}/honey-tokens/generate", json={"token_type": "AWS_KEY"},
                    headers=auth_headers(admin_a))
    assert r.status_code in (400, 422) and "AWS_CANARY_ENABLED" in r.text


def test_provisioning_creates_a_deny_all_user_and_one_key(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    assert manager.reconcile()["provisioned"] == 1
    token = _token(db_session, created["id"])
    meta = token.token_metadata
    user = aws.users[token.token_value]
    assert user["path"] == "/svc/" and user["tags"] == {"honeyshield-decoy": token.decoy_id}
    assert user["boundary"] == "arn:aws:iam::123456789012:policy/hs-canary-boundary"
    assert user["policies"]["deny-all"]["Statement"] == [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    assert meta["status"] == "active" and user["keys"] == [meta["access_key_id"]]
    assert meta["secret_access_key"].startswith("s3cr3t") and meta["account_id"] == aws.account
    assert meta["iam_arn"] == f"arn:aws:iam::{aws.account}:user/svc/{token.token_value}"
    assert db_session.query(AuditLog).filter_by(event_type="CLOUD_CANARY_PROVISIONED", target_id=token.id).count() == 1
    assert manager.reconcile() == {"provisioned": 0, "deleted": 0, "failed": 0, "retry": 0}


def test_viewers_never_see_the_key(client, db_session, admin_a, user_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    meta = _token(db_session, created["id"]).token_metadata
    r = client.get("/api/v1/honey-tokens", params={"project_domain": project_a.domain}, headers=auth_headers(user_a))
    text = json.dumps(r.json())
    assert meta["access_key_id"] not in text and meta["secret_access_key"] not in text
    r = client.get("/api/v1/honey-tokens", params={"project_domain": project_a.domain}, headers=auth_headers(admin_a))
    assert meta["secret_access_key"] in json.dumps(r.json())


def test_a_crashed_attempt_is_finished_without_a_second_key(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    token = _token(db_session, created["id"])
    # A previous run created the user and a key, then died before saving anything.
    aws.users[token.token_value] = {"path": "/svc/", "tags": {"honeyshield-decoy": token.decoy_id},
                                    "policies": {}, "keys": ["AKIAORPHANED00000"]}
    manager.reconcile()
    meta = _token(db_session, created["id"]).token_metadata
    assert meta["status"] == "active" and aws.users[token.token_value]["keys"] == [meta["access_key_id"]]


def test_someone_elses_user_is_never_touched(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    token = _token(db_session, created["id"])
    aws.users[token.token_value] = {"path": "/svc/", "tags": {"team": "data"}, "policies": {}, "keys": ["AKIAREAL"]}
    assert manager.reconcile()["failed"] == 1
    meta = _token(db_session, created["id"]).token_metadata
    assert meta["status"] == "failed" and "NameInUse" in meta["last_error"] and not meta.get("user_created")
    assert aws.users[token.token_value]["keys"] == ["AKIAREAL"]
    assert db_session.query(AuditLog).filter_by(event_type="CLOUD_CANARY_FAILED").count() == 1


def test_throttling_is_retried_and_a_refusal_fails(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    aws.fail["CreateUser"] = (400, "Throttling")
    assert manager.reconcile()["retry"] == 1
    assert _token(db_session, created["id"]).token_metadata["status"] == "provisioning"
    aws.fail["CreateUser"] = (403, "AccessDenied")
    assert manager.reconcile()["failed"] == 1
    assert _token(db_session, created["id"]).token_metadata["status"] == "failed"


# ----------------------------------------------------------------------------------- detection
def test_key_use_becomes_a_critical_cloud_audit_event(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    key_id = _token(db_session, created["id"]).token_metadata["access_key_id"]
    event_id = aws.add_event("us-east-1", key_id)
    aws.add_event("eu-west-1", key_id, name="ListBuckets", source="s3.amazonaws.com", ip="198.51.100.9",
                  agent="Boto3/1.35.0")
    result = manager.poll()
    assert result["recorded"] == 2 and result["region_errors"] == {}
    first, second = _events(db_session, created["id"])
    assert first.source == EventSource.CLOUD_AUDIT and first.severity == EventSeverity.CRITICAL
    assert first.ip_address == "203.0.113.77" and first.user_agent == "aws-cli/2.17.0"
    assert first.request_path == "sts.amazonaws.com/GetCallerIdentity" and first.http_method == "AWS"
    assert first.idempotency_key == event_id
    assert first.headers["aws-region"] == "us-east-1" and first.headers["aws-error-code"] == "AccessDenied"
    assert second.headers["aws-region"] == "eu-west-1" and second.request_path == "s3.amazonaws.com/ListBuckets"


def test_overlapping_polls_store_each_event_once(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    key_id = _token(db_session, created["id"]).token_metadata["access_key_id"]
    aws.add_event("us-east-1", key_id)
    assert manager.poll()["recorded"] == 1
    again = manager.poll()
    assert again["recorded"] == 0 and again["duplicates"] == 1
    assert len(_events(db_session, created["id"])) == 1


def test_a_failing_region_does_not_stop_the_others(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    key_id = _token(db_session, created["id"]).token_metadata["access_key_id"]
    aws.region_fail["eu-west-1"] = (400, "UnrecognizedClientException")
    aws.add_event("us-east-1", key_id)
    result = manager.poll()
    assert result["recorded"] == 1 and result["region_errors"] == {"eu-west-1": "UnrecognizedClientException"}


def test_a_source_that_is_not_an_address_is_kept_as_context(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    key_id = _token(db_session, created["id"]).token_metadata["access_key_id"]
    aws.add_event("us-east-1", key_id, ip="lambda.amazonaws.com")
    manager.poll()
    [event] = _events(db_session, created["id"])
    assert event.ip_address == "0.0.0.0" and event.headers["aws-source-address"] == "lambda.amazonaws.com"


def test_many_events_are_read_across_pages(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    key_id = _token(db_session, created["id"]).token_metadata["access_key_id"]
    for i in range(120):
        aws.add_event("us-east-1", key_id, ip=f"203.0.113.{i % 100 + 1}")
    assert manager.poll()["recorded"] == 120


# ----------------------------------------------------------------------------------- clean-up
def test_revoking_deletes_the_aws_user(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    name = created["token_value"]
    r = client.post("/api/v1/honey-tokens/revoke", json={"token_value": name}, headers=auth_headers(admin_a))
    assert r.status_code in (200, 204), r.text
    assert manager.reconcile()["deleted"] == 1
    meta = _token(db_session, created["id"]).token_metadata
    assert name not in aws.users and meta["status"] == "deleted" and meta["secret_access_key"] is None
    assert db_session.query(AuditLog).filter_by(event_type="CLOUD_CANARY_DELETED").count() == 1


def test_rotation_replaces_the_key(client, db_session, admin_a, project_a, aws, manager):
    created = _generate(client, admin_a, project_a)
    manager.reconcile()
    r = client.post("/api/v1/honey-tokens/rotate", json={"old_token_value": created["token_value"]},
                    headers=auth_headers(admin_a))
    assert r.status_code in (200, 201), r.text
    new = r.json()
    run_cycle(manager, poll_due=False)
    assert created["token_value"] not in aws.users and new["token_value"] in aws.users
    assert _token(db_session, new["id"]).token_metadata["status"] == "active"


def test_run_cycle_polls_only_when_due(manager):
    assert "poll" not in run_cycle(manager, poll_due=False)
    assert run_cycle(manager, poll_due=True)["poll"]["events"] == 0


def test_errors_from_aws_are_classified():
    assert AwsError("Throttling").transient and AwsError("x", status=503).transient
    assert not AwsError("AccessDenied", status=403).transient
