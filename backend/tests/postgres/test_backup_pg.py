"""End-to-end backup on real PostgreSQL and real S3: dump -> encrypt -> upload -> download -> decrypt ->
restore into an empty database, row counts compared. Needs pg_dump/pg_restore and HS_TEST_S3_*.
"""
from __future__ import annotations

import os
import secrets
import shutil
import subprocess

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core import agecrypt
from app.core.config import get_settings
from app.services import worm
from app.services.s3_store import S3Store, S3StoreConfig
from app.workers import backup

S3_ENDPOINT = os.environ.get("HS_TEST_S3_ENDPOINT")


@pytest.fixture()
def bucket():
    if not S3_ENDPOINT:
        pytest.skip("HS_TEST_S3_ENDPOINT not set")
    name = f"hs-backup-{secrets.token_hex(4)}"
    sink = worm.S3ObjectLockSink(worm.S3Config(S3_ENDPOINT, name, "us-east-1", os.environ["HS_TEST_S3_ACCESS_KEY"],
                                               os.environ["HS_TEST_S3_SECRET_KEY"]))
    status, _, body = sink._request("PUT", None)
    assert status == 200, body
    return name


@pytest.fixture()
def configured(monkeypatch, pg, bucket, tmp_path):
    for tool in ("pg_dump", "pg_restore"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not installed")
    ident, rcpt = agecrypt.generate_identity()
    key = tmp_path / "backup-key.txt"
    key.write_text(f"# test\n{ident}\n")
    s = get_settings()
    for name, value in {
        "database_url": pg.app_url, "backup_age_recipients": rcpt, "backup_dir": str(tmp_path / "backups"),
        "backup_s3_endpoint": S3_ENDPOINT, "backup_s3_bucket": bucket, "backup_s3_region": "us-east-1",
        "backup_s3_access_key_id": os.environ["HS_TEST_S3_ACCESS_KEY"],
        "backup_s3_secret_access_key": os.environ["HS_TEST_S3_SECRET_KEY"], "backup_identity_file": str(key),
    }.items():
        monkeypatch.setattr(s, name, value)
    return s, key


def _seed(owner_engine):
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO tenants (name, slug, is_active, created_at, updated_at) "
                       "VALUES ('Backup Co', :slug, true, now(), now())"), {"slug": f"backup-{secrets.token_hex(3)}"})
        return c.execute(text("SELECT count(*) FROM tenants")).scalar_one()


def test_backup_is_offsite_encrypted_verified_and_restorable(configured, pg, owner_engine, app_engine, tmp_path):
    settings, key = configured
    tenants = _seed(owner_engine)
    with Session(app_engine) as session:
        state = backup.run_once(session, settings)
    assert state["state"] == "ok", state
    assert state["offsite"] is True and state["last_verified_at"] and not state.get("verify_error")
    store = S3Store(S3StoreConfig(S3_ENDPOINT, settings.backup_s3_bucket, "us-east-1",
                                  os.environ["HS_TEST_S3_ACCESS_KEY"], os.environ["HS_TEST_S3_SECRET_KEY"]))
    names = backup.remote_backups(settings, store)
    assert names == [state["file"]]

    # What is stored off-site is ciphertext: no table names, no tenant names.
    enc = tmp_path / "copy.age"
    store.get_to_file(settings.backup_s3_prefix + names[0], enc)
    raw = enc.read_bytes()
    assert raw.startswith(b"age-encryption.org/v1\n") and b"tenants" not in raw and b"Backup Co" not in raw

    # The documented restore path: fetch + decrypt, then pg_restore into an empty database.
    dump = tmp_path / "restore.dump"
    assert backup.main(["fetch", "latest", "--identity", str(key), "--out", str(dump)]) == 0
    restored_db = f"{pg.db}_restore"
    admin = create_engine(pg.admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{restored_db}"'))
    try:
        target = make_url(pg.admin_url).set(database=restored_db)
        env = {**os.environ, "PGPASSWORD": target.password or ""}
        proc = subprocess.run(["pg_restore", "--no-owner", "--no-privileges", "--exit-on-error", "-h", target.host,
                               "-p", str(target.port or 5432), "-U", target.username, "-d", restored_db, str(dump)],
                              env=env, capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr[-2000:]
        eng = create_engine(target.set(drivername="postgresql+psycopg2").render_as_string(hide_password=False))
        with eng.connect() as c:
            assert c.execute(text("SELECT count(*) FROM tenants")).scalar_one() == tenants
            assert c.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        eng.dispose()
    finally:
        with admin.connect() as c:
            c.execute(text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :d"),
                      {"d": restored_db})
            c.execute(text(f'DROP DATABASE IF EXISTS "{restored_db}"'))
        admin.dispose()


def test_a_modified_offsite_copy_fails_verification(configured, app_engine, tmp_path):
    settings, _ = configured
    with Session(app_engine) as session:
        state = backup.run_once(session, settings)
    assert state["state"] == "ok"
    store = backup.store(settings)
    bad = tmp_path / "bad.age"
    store.get_to_file(settings.backup_s3_prefix + state["file"], bad)
    data = bytearray(bad.read_bytes())
    data[-50] ^= 1
    bad.write_bytes(bytes(data))
    store.put_file(settings.backup_s3_prefix + state["file"], bad)
    with pytest.raises(backup.BackupError, match="differs from what was uploaded"):
        backup.verify_copy(settings, store, state["file"], state["sha256"])
    with pytest.raises(agecrypt.AgeError):
        backup.verify_copy(settings, store, state["file"], None)


def test_failures_are_reported_not_hidden(configured, app_engine, monkeypatch):
    settings, _ = configured
    monkeypatch.setattr(settings, "database_url", settings.database_url.replace("@", "x@", 1))  # wrong user
    with Session(app_engine) as session:
        state = backup.run_once(session, settings)
    assert state["state"] == "error" and "pg_dump failed" in state["last_error"]
    assert not list((__import__("pathlib").Path(settings.backup_dir)).glob(".work-*"))  # no plaintext left
