"""Backup encryption (age v1 format) and backup bookkeeping without a database.

The end-to-end backup -> off-site -> download -> decrypt -> restore test runs against real
PostgreSQL and S3 in tests/postgres/test_backup_pg.py.
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from app.core import agecrypt
from app.core.config import Settings
from app.workers import backup

AGE = shutil.which("age")
needs_age = pytest.mark.skipif(AGE is None, reason="the reference age binary is not installed")


def _roundtrip(data: bytes, recipients: list[str]) -> bytes:
    out = io.BytesIO()
    assert agecrypt.encrypt_stream(io.BytesIO(data), out, recipients) == len(data)
    return out.getvalue()


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 3 * 65536, 250_000])
def test_encrypt_decrypt_roundtrip(size):
    ident, rcpt = agecrypt.generate_identity()
    data = os.urandom(size)
    back = io.BytesIO()
    agecrypt.decrypt_stream(io.BytesIO(_roundtrip(data, [rcpt])), back, agecrypt.identities_from_text(ident))
    assert back.getvalue() == data


def test_several_recipients_and_wrong_identity():
    (i1, r1), (i2, r2), (i3, _) = (agecrypt.generate_identity() for _ in range(3))
    enc = _roundtrip(b"secret dump", [r1, r2])
    for ident in (i1, i2):
        out = io.BytesIO()
        agecrypt.decrypt_stream(io.BytesIO(enc), out, agecrypt.identities_from_text(ident))
        assert out.getvalue() == b"secret dump"
    with pytest.raises(agecrypt.AgeError, match="no identity"):
        agecrypt.decrypt_stream(io.BytesIO(enc), io.BytesIO(), agecrypt.identities_from_text(i3))


@pytest.mark.parametrize("where", ["header", "payload", "truncate", "append"])
def test_tampering_is_detected(where):
    ident, rcpt = agecrypt.generate_identity()
    enc = bytearray(_roundtrip(os.urandom(100_000), [rcpt]))
    if where == "header":
        enc[30] ^= 1
    elif where == "payload":
        enc[-100] ^= 1
    elif where == "truncate":
        del enc[-65536:]
    else:
        enc += b"x" * 40
    with pytest.raises(agecrypt.AgeError):
        agecrypt.decrypt_stream(io.BytesIO(bytes(enc)), io.BytesIO(), agecrypt.identities_from_text(ident))


def test_keys_and_bech32():
    ident, rcpt = agecrypt.generate_identity()
    assert ident.startswith("AGE-SECRET-KEY-1") and rcpt.startswith("age1")
    assert agecrypt.recipient_of(agecrypt.parse_identity(ident)) == rcpt
    with pytest.raises(agecrypt.AgeError):
        agecrypt.parse_recipient(rcpt[:-1] + ("q" if rcpt[-1] != "q" else "p"))  # checksum
    with pytest.raises(agecrypt.AgeError):
        agecrypt.parse_recipient(ident)
    with pytest.raises(ValueError, match="BACKUP_AGE_RECIPIENTS"):
        Settings(jwt_secret_key="x" * 40, backup_age_recipients="age1notakey")
    with pytest.raises(ValueError, match="never leave the server unencrypted"):
        Settings(jwt_secret_key="x" * 40, backup_s3_bucket="b", backup_s3_endpoint="https://s3.example",
                 backup_s3_access_key_id="a", backup_s3_secret_access_key="s")


@needs_age
@pytest.mark.parametrize("size", [0, 70_000])
def test_interoperates_with_the_reference_age_tool(tmp_path, size):
    ident, rcpt = agecrypt.generate_identity()
    (tmp_path / "key.txt").write_text(ident + "\n")
    data = os.urandom(size)
    (tmp_path / "ours.age").write_bytes(_roundtrip(data, [rcpt]))
    got = subprocess.run([AGE, "-d", "-i", str(tmp_path / "key.txt"), str(tmp_path / "ours.age")],
                         capture_output=True, check=True)
    assert got.stdout == data
    theirs = subprocess.run([AGE, "-r", rcpt], input=data, capture_output=True, check=True).stdout
    out = io.BytesIO()
    agecrypt.decrypt_stream(io.BytesIO(theirs), out, agecrypt.identities_from_text(ident))
    assert out.getvalue() == data


class FakeStore:
    def __init__(self, names):
        self.objects = {f"p/{n}": b"x" for n in names}
        self.fail = set()

    def list(self, prefix):
        from app.services.s3_store import S3Object
        return [S3Object(k, 1, "") for k in sorted(self.objects) if k.startswith(prefix)]

    def delete(self, key):
        if key in self.fail:
            raise RuntimeError("AccessDenied (object lock)")
        del self.objects[key]


def test_remote_retention_keeps_the_newest_seven(monkeypatch):
    now = datetime(2026, 11, 20, 3, 0, tzinfo=timezone.utc)
    names = [backup.backup_name(now - timedelta(days=d)) for d in range(60)]
    s = Settings(jwt_secret_key="x" * 40, backup_keep_days=30, backup_s3_prefix="p/")
    store = FakeStore(names + ["unrelated.txt"])
    removed, errors = backup.prune_remote(s, store, now)
    left = backup.remote_backups(s, store)
    assert len(left) == 31 and not errors  # days 0..30 kept
    assert "p/unrelated.txt" in store.objects
    # Very short retention still keeps seven.
    s2 = Settings(jwt_secret_key="x" * 40, backup_keep_days=1, backup_s3_prefix="p/")
    backup.prune_remote(s2, store, now)
    assert len(backup.remote_backups(s2, store)) == 7
    # A store that refuses deletes (Object Lock) is reported, not fatal.
    store = FakeStore(names)
    store.fail = {f"p/{names[-1]}"}
    _, errors = backup.prune_remote(s, store, now)
    assert errors and "object lock" in errors[0]


def test_local_retention(tmp_path):
    s = Settings(jwt_secret_key="x" * 40, backup_dir=str(tmp_path), backup_keep_local=2)
    now = datetime(2026, 11, 20, tzinfo=timezone.utc)
    for d in range(5):
        (tmp_path / backup.backup_name(now - timedelta(days=d))).write_bytes(b"x")
    (tmp_path / "notes.txt").write_text("keep me")
    assert len(backup.prune_local(s)) == 3
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [backup.backup_name(now - timedelta(days=1)), backup.backup_name(now), "notes.txt"])


def test_schedule(monkeypatch):
    s = Settings(jwt_secret_key="x" * 40, backup_interval_hours=24)
    now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)
    assert backup.due({}, s, now)
    assert not backup.due({"last_success_at": (now - timedelta(hours=2)).isoformat()}, s, now)
    assert backup.due({"last_success_at": (now - timedelta(hours=25)).isoformat()}, s, now)
    # After a failure, retry in 30 minutes, not in a tight loop.
    failed = {"state": "error", "last_attempt_at": (now - timedelta(minutes=5)).isoformat()}
    assert not backup.due(failed, s, now)
    failed["last_attempt_at"] = (now - timedelta(minutes=31)).isoformat()
    assert backup.due(failed, s, now)


def test_not_configured_is_reported(db_session, monkeypatch):
    s = Settings(jwt_secret_key="x" * 40)
    state = backup.run_once(db_session, s)
    assert state["state"] == "not_configured"


def test_keygen_prints_a_usable_identity(capsys):
    assert backup.main(["keygen"]) == 0
    out = capsys.readouterr().out
    ident = [l for l in out.splitlines() if l.startswith("AGE-SECRET-KEY-1")][0]
    rcpt = [l for l in out.splitlines() if "public key" in l][0].split(": ")[1]
    assert agecrypt.recipient_of(agecrypt.parse_identity(ident)) == rcpt
