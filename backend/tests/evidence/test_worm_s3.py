"""WORM shipping of checkpoints to S3 Object Lock.

* SigV4 is checked against AWS's published example request.
* A local fake S3 records exactly what is sent (lock headers, Content-MD5, If-None-Match).
* With HS_TEST_S3_ENDPOINT (+ HS_TEST_S3_ACCESS_KEY / HS_TEST_S3_SECRET_KEY) the tests also run
  against a real Object Lock store (MinIO): locked versions cannot be deleted or replaced.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import Settings, get_settings
from app.services import audit_chain, evidence, worm

KEY = "worm-checkpoint-key-for-tests-0123456789abcdef"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setattr(get_settings(), "integration_signing_key", KEY)


# --------------------------------------------------------------------------- SigV4

def test_sigv4_matches_the_aws_documented_example():
    """AWS S3 API reference, 'Signature Calculations for the Authorization Header', GET Object."""
    headers = worm.sigv4_headers(
        "GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {"Range": "bytes=0-9"}, worm.EMPTY_SHA256,
        "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        now=datetime(2013, 5, 24, tzinfo=timezone.utc))
    assert headers["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_sigv4_matches_the_aws_documented_list_example():
    """Same reference, GET Bucket (List Objects) with query parameters."""
    headers = worm.sigv4_headers(
        "GET", "examplebucket.s3.amazonaws.com", "/", {"max-keys": "2", "prefix": "J"}, {}, worm.EMPTY_SHA256,
        "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        now=datetime(2013, 5, 24, tzinfo=timezone.utc))
    assert headers["Authorization"].endswith(
        "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")


# ------------------------------------------------------------------- settings

def test_s3_settings_are_validated():
    base = dict(jwt_secret_key="x" * 40)
    with pytest.raises(ValueError, match="EVIDENCE_S3_ENDPOINT"):
        Settings(**base, evidence_s3_bucket="b")
    full = dict(evidence_s3_bucket="b", evidence_s3_endpoint="https://s3.eu-west-1.amazonaws.com",
                evidence_s3_access_key_id="AKIA", evidence_s3_secret_access_key="s")
    assert Settings(**base, **full).evidence_s3_lock_mode == "COMPLIANCE"
    with pytest.raises(ValueError, match="PREFIX"):
        Settings(**base, **full, evidence_s3_prefix="/abs/")
    with pytest.raises(ValueError):
        Settings(**base, **full, evidence_s3_lock_mode="NONE")


# ------------------------------------------------------------------- fake S3

class _FakeS3(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        srv = self.server
        srv.requests.append(("PUT", self.path, dict(self.headers), body))
        if self.path in srv.objects and self.headers.get("If-None-Match") == "*":
            self.send_response(412)
            self.end_headers()
            return
        if srv.fail_next:
            srv.fail_next -= 1
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"<Error><Code>SlowDown</Code></Error>")
            return
        srv.objects[self.path] = body
        self.send_response(200)
        self.send_header("x-amz-version-id", "v" + str(len(srv.objects)))
        self.end_headers()

    def do_GET(self):
        srv = self.server
        srv.requests.append(("GET", self.path, dict(self.headers), b""))
        if "list-type=2" in self.path:
            keys = "".join(f"<Contents><Key>{k.split('/', 2)[2]}</Key></Contents>" for k in sorted(srv.objects))
            body = (f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{keys}'
                    "<IsTruncated>false</IsTruncated></ListBucketResult>").encode()
        elif self.path in srv.objects:
            body = srv.objects[self.path]
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def fake_s3():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeS3)
    srv.requests, srv.objects, srv.fail_next = [], {}, 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg = worm.S3Config(endpoint=f"http://127.0.0.1:{srv.server_address[1]}", bucket="hs-evidence",
                        region="eu-west-1", access_key_id="AKIATEST", secret_access_key="secret",
                        retention_days=30)
    yield srv, worm.S3ObjectLockSink(cfg)
    srv.shutdown()
    srv.server_close()


def test_put_sends_object_lock_headers(fake_s3):
    srv, sink = fake_s3
    now = datetime(2026, 11, 17, 9, 0, tzinfo=timezone.utc)
    data = b'[{"seq": 1}]'
    assert sink.put("checkpoint-1.json", data, now=now) == "v1"
    method, path, headers, body = srv.requests[-1]
    h = {k.lower(): v for k, v in headers.items()}
    assert (method, path, body) == ("PUT", "/hs-evidence/checkpoints/checkpoint-1.json", data)
    assert h["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert h["x-amz-object-lock-retain-until-date"] == "2026-12-17T09:00:00Z"
    assert h["content-md5"] == base64.b64encode(hashlib.md5(data).digest()).decode()
    assert h["if-none-match"] == "*"
    assert h["x-amz-content-sha256"] == hashlib.sha256(data).hexdigest()
    assert h["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIATEST/20")
    assert "/eu-west-1/s3/aws4_request" in h["authorization"]
    signed = h["authorization"].split("SignedHeaders=")[1].split(",")[0].split(";")
    assert {"content-md5", "if-none-match", "x-amz-object-lock-mode",
            "x-amz-object-lock-retain-until-date", "host"} <= set(signed)


def test_existing_name_is_never_replaced(fake_s3):
    _, sink = fake_s3
    sink.put("checkpoint-1.json", b"[]")
    with pytest.raises(worm.ObjectExistsError):
        sink.put("checkpoint-1.json", b'[{"forged": true}]')


def test_invalid_object_names_are_refused(fake_s3):
    _, sink = fake_s3
    for name in ("../x.json", "a/b.json", ".hidden"):
        with pytest.raises(worm.WormError):
            sink.put(name, b"[]")


def test_sync_uploads_only_missing_files_and_retries_failures(fake_s3, tmp_path):
    srv, sink = fake_s3
    for i in range(3):
        (tmp_path / f"checkpoint-{i}.json").write_text("[]")
    (tmp_path / "unrelated.txt").write_text("x")
    srv.fail_next = 1
    with pytest.raises(worm.WormError, match="503 SlowDown"):
        worm.sync_directory(tmp_path, sink)
    assert worm.sync_directory(tmp_path, sink) == ["checkpoint-0.json", "checkpoint-1.json", "checkpoint-2.json"]
    assert worm.sync_directory(tmp_path, sink) == []
    assert sink.list_names() == ["checkpoint-0.json", "checkpoint-1.json", "checkpoint-2.json"]


def _configure(monkeypatch, cfg: worm.S3Config):
    s = get_settings()
    for attr, value in (("evidence_s3_endpoint", cfg.endpoint), ("evidence_s3_bucket", cfg.bucket),
                        ("evidence_s3_region", cfg.region), ("evidence_s3_access_key_id", cfg.access_key_id),
                        ("evidence_s3_secret_access_key", cfg.secret_access_key),
                        ("evidence_s3_prefix", cfg.prefix), ("evidence_s3_retention_days", cfg.retention_days)):
        monkeypatch.setattr(s, attr, value)


def _worker(db_session, monkeypatch):
    from app.workers import evidence as worker

    monkeypatch.setattr(worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    return worker


def test_checkpoint_ships_and_verify_reads_back_from_s3(client, db_session, token_a, fake_s3, tmp_path,
                                                         monkeypatch, capsys):
    srv, sink = fake_s3
    _configure(monkeypatch, sink.cfg)
    worker = _worker(db_session, monkeypatch)
    assert client.get(f"/t/{token_a.token_value}").status_code == 204
    assert worker.main(["checkpoint", "--out", str(tmp_path)]) == 0
    assert len(sink.list_names()) == 1
    assert worker.main(["verify", "--checkpoints", "s3"]) == 0
    out = capsys.readouterr().out
    assert "Shipped 1 checkpoint file(s)" in out and "Loaded" in out and "audit log: OK" in out


def test_checkpoint_fails_loudly_when_shipping_fails(db_session, fake_s3, tmp_path, monkeypatch, capsys):
    srv, sink = fake_s3
    _configure(monkeypatch, sink.cfg)
    worker = _worker(db_session, monkeypatch)
    status = tmp_path / "status" / "ok"
    status.parent.mkdir()
    monkeypatch.setenv(worker.STATUS_FILE_ENV, str(status))
    out_dir = tmp_path / "cps"
    srv.fail_next = 5
    assert worker.main(["checkpoint", "--out", str(out_dir)]) == worker.SHIP_FAILED   # loop keeps going
    assert "FAIL: shipping checkpoints" in capsys.readouterr().err
    assert list(out_dir.glob("checkpoint-*.json")) and not status.exists()   # kept locally; not healthy
    srv.fail_next = 0
    assert worker.main(["checkpoint", "--out", str(out_dir)]) == 0
    assert len(sink.list_names()) == 2 and status.exists()   # the missed file was uploaded too


def test_ship_requires_configuration(db_session, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(get_settings(), "evidence_s3_bucket", None)
    worker = _worker(db_session, monkeypatch)
    assert worker.main(["ship", "--out", str(tmp_path)]) == 1
    assert worker.main(["verify", "--checkpoints", "s3"]) == 1


# ------------------------------------------------------------- real Object Lock store

S3_ENDPOINT = os.environ.get("HS_TEST_S3_ENDPOINT")


@pytest.fixture()
def real_sink():
    if not S3_ENDPOINT:
        pytest.skip("HS_TEST_S3_ENDPOINT not set (real Object Lock store)")
    cfg = worm.S3Config(endpoint=S3_ENDPOINT, bucket=f"hs-test-{secrets.token_hex(4)}", region="us-east-1",
                        access_key_id=os.environ["HS_TEST_S3_ACCESS_KEY"],
                        secret_access_key=os.environ["HS_TEST_S3_SECRET_KEY"], retention_days=1)
    sink = worm.S3ObjectLockSink(cfg)
    status, _, body = sink._request("PUT", None, headers={"x-amz-bucket-object-lock-enabled": "true"})
    assert status == 200, body
    return sink


@pytest.mark.s3
def test_real_store_locks_each_checkpoint(real_sink):
    version = real_sink.put("checkpoint-a.json", b'[{"seq": 1}]')
    assert version
    ret = real_sink.retention("checkpoint-a.json")
    assert ret["mode"] == "COMPLIANCE"
    until = datetime.fromisoformat(ret["retain_until"].replace("Z", "+00:00"))
    assert timedelta(hours=23) < until - datetime.now(timezone.utc) <= timedelta(days=1, minutes=5)
    assert real_sink.get("checkpoint-a.json") == b'[{"seq": 1}]'


@pytest.mark.s3
def test_real_store_refuses_replacement_and_deletion(real_sink):
    version = real_sink.put("checkpoint-b.json", b"[]")
    with pytest.raises(worm.ObjectExistsError):
        real_sink.put("checkpoint-b.json", b'[{"forged": true}]')
    status, _, body = real_sink._request("DELETE", real_sink.cfg.prefix + "checkpoint-b.json",
                                         query={"versionId": version})
    assert status in (400, 403), (status, body)
    assert real_sink.get("checkpoint-b.json") == b"[]"


@pytest.mark.s3
def test_real_store_round_trip_through_the_worker(client, db_session, token_a, real_sink, tmp_path,
                                                  monkeypatch, capsys):
    _configure(monkeypatch, real_sink.cfg)
    worker = _worker(db_session, monkeypatch)
    assert client.get(f"/t/{token_a.token_value}").status_code == 204
    assert worker.main(["checkpoint", "--out", str(tmp_path)]) == 0
    assert worker.main(["verify", "--checkpoints", "s3"]) == 0
    cps = real_sink.checkpoints()
    assert cps and all(evidence.checkpoint_is_authentic(cp) for cp in cps)
    assert any(cp.get("chain") == audit_chain.CHAIN_NAME for cp in cps)
    assert json.loads(real_sink.get(real_sink.list_names()[0]))
