"""Encrypted, off-site database backups: ``python -m app.workers.backup [loop|run|keygen|list|fetch]``.

Without backups, losing the one server loses every record and all evidence. This worker:

1. dumps the database with ``pg_dump`` (custom format) as the runtime role, which can read every
   table but change nothing it should not;
2. checks the dump is a readable archive (``pg_restore --list``) before keeping it;
3. encrypts it to the operator's age public key(s) (app/core/agecrypt.py) and deletes the plain dump
   at once. The server cannot read its own backups unless BACKUP_IDENTITY_FILE is mounted;
4. uploads it to any S3-compatible bucket (BACKUP_S3_*), then confirms the stored size;
5. keeps BACKUP_KEEP_LOCAL copies here and deletes off-site copies older than BACKUP_KEEP_DAYS,
   always keeping the newest seven;
6. with BACKUP_IDENTITY_FILE, every BACKUP_VERIFY_EVERY_DAYS downloads the newest off-site copy,
   decrypts it and checks it is a readable dump: the only real proof a backup can be restored;
7. reports to system_status (key ``backup``), which the watchdog turns into notices.

Restoring: ``fetch latest --identity key.txt --out restore.dump`` (or ``age -d -i key.txt``) and then
scripts/restore_postgres.sh (docs/backup-and-restore.md).
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import signal
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core import agecrypt
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

logger = logging.getLogger("honeyshield.backup")
NAME_RE = re.compile(r"^honeyshield-(\d{8}T\d{6}Z)\.dump\.age$")
STATUS_KEY = "backup"
KEEP_AT_LEAST = 7
RETRY_AFTER_FAILURE = timedelta(minutes=30)


class BackupError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value)) if value else None
    except ValueError:
        return None
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def backup_name(at: datetime) -> str:
    return f"honeyshield-{at.strftime('%Y%m%dT%H%M%SZ')}.dump.age"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def store(settings: Settings):
    from app.services.s3_store import S3Store, S3StoreConfig

    if not settings.backup_s3_bucket:
        return None
    return S3Store(S3StoreConfig(settings.backup_s3_endpoint, settings.backup_s3_bucket, settings.backup_s3_region,
                                 settings.backup_s3_access_key_id, settings.backup_s3_secret_access_key,
                                 ca_file=settings.backup_s3_ca_file))


def _connection(settings: Settings) -> dict[str, str]:
    from sqlalchemy.engine import make_url

    url = make_url(settings.sqlalchemy_database_uri)
    return {"host": url.host or "localhost", "port": str(url.port or 5432), "user": url.username or "",
            "password": url.password or "", "dbname": url.database or ""}


def _run(cmd: list[str], env: dict[str, str], timeout: float = 6 * 3600) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, env=env, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise BackupError(f"{cmd[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackupError(f"{Path(cmd[0]).name} timed out") from exc


def _stderr(proc: subprocess.CompletedProcess) -> str:
    text = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
    return (text[-1] if text else f"exit {proc.returncode}")[:300]


def dump_database(settings: Settings, out: Path) -> None:
    c = _connection(settings)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PGPASSWORD": c["password"],
           "PGCONNECT_TIMEOUT": "15", "LC_ALL": "C.UTF-8"}
    proc = _run([settings.backup_pg_dump, "--format=custom", "--compress=6", "--no-password",
                 "-h", c["host"], "-p", c["port"], "-U", c["user"], "-d", c["dbname"], "-f", str(out)], env)
    if proc.returncode != 0:
        raise BackupError(f"pg_dump failed: {_stderr(proc)}")


def check_archive(settings: Settings, path: Path) -> int:
    """Number of entries in the dump's table of contents (0 or an error means unusable)."""
    proc = _run([settings.backup_pg_restore, "--list", str(path)],
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"}, timeout=3600)
    if proc.returncode != 0:
        raise BackupError(f"the dump is not a readable archive: {_stderr(proc)}")
    entries = sum(1 for line in proc.stdout.decode("utf-8", "replace").splitlines()
                  if line.strip() and not line.startswith(";"))
    if entries == 0:
        raise BackupError("the dump is empty")
    return entries


def _secure_file(path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


def make_backup(settings: Settings, at: datetime | None = None) -> dict[str, Any]:
    """Dump, check and encrypt one backup into BACKUP_DIR; returns its details."""
    at = at or _now()
    directory = Path(settings.backup_dir)
    directory.mkdir(parents=True, exist_ok=True)
    name = backup_name(at)
    plain = directory / f".work-{name}.dump"
    part = directory / f".{name}.part"
    final = directory / name
    try:
        for p in (plain, part):
            if p.exists():
                p.unlink()
        _secure_file(plain)
        dump_database(settings, plain)
        entries = check_archive(settings, plain)
        _secure_file(part)
        with open(plain, "rb") as src, open(part, "wb") as dst:
            size_plain = agecrypt.encrypt_stream(src, dst, settings.backup_recipient_list)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(part, final)
    finally:
        for p in (plain, part):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
    return {"file": name, "size": final.stat().st_size, "sha256": _sha256(final), "dump_bytes": size_plain,
            "entries": entries, "path": str(final)}


def prune_local(settings: Settings) -> list[str]:
    files = sorted(p for p in Path(settings.backup_dir).glob("honeyshield-*.dump.age") if NAME_RE.match(p.name))
    removed = []
    for p in files[:-settings.backup_keep_local] if len(files) > settings.backup_keep_local else []:
        p.unlink()
        removed.append(p.name)
    return removed


def remote_backups(settings: Settings, s3) -> list[str]:
    prefix = settings.backup_s3_prefix
    names = [o.key[len(prefix):] for o in s3.list(prefix)]
    return sorted(n for n in names if NAME_RE.match(n))


def prune_remote(settings: Settings, s3, now: datetime | None = None) -> tuple[list[str], list[str]]:
    """Delete off-site copies older than BACKUP_KEEP_DAYS, never the newest seven."""
    now = now or _now()
    names = remote_backups(settings, s3)
    cutoff = now - timedelta(days=settings.backup_keep_days)
    removed, errors = [], []
    for name in names[:-KEEP_AT_LEAST] if len(names) > KEEP_AT_LEAST else []:
        stamp = datetime.strptime(NAME_RE.match(name).group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        if stamp >= cutoff:
            continue
        try:
            s3.delete(settings.backup_s3_prefix + name)
            removed.append(name)
        except Exception as exc:  # e.g. Object Lock retention: keeping it is the safe outcome
            errors.append(f"{name}: {exc}")
    return removed, errors


def verify_copy(settings: Settings, s3, name: str, expected_sha256: str | None) -> dict[str, Any]:
    """Download (or read locally), decrypt and check one backup. Needs BACKUP_IDENTITY_FILE."""
    identities = agecrypt.identities_from_text(Path(settings.backup_identity_file).read_text())
    directory = Path(settings.backup_dir)
    enc = directory / f".verify-{name}"
    plain = directory / f".verify-{name}.dump"
    try:
        for p in (enc, plain):
            if p.exists():
                p.unlink()
        if s3 is not None:
            s3.get_to_file(settings.backup_s3_prefix + name, enc)
        else:
            enc.write_bytes((directory / name).read_bytes())
        digest = _sha256(enc)
        if expected_sha256 and digest != expected_sha256:
            raise BackupError(f"{name}: the stored copy differs from what was uploaded")
        _secure_file(plain)
        with open(enc, "rb") as src, open(plain, "wb") as dst:
            agecrypt.decrypt_stream(src, dst, identities)
        entries = check_archive(settings, plain)
        return {"file": name, "entries": entries, "sha256": digest}
    finally:
        for p in (enc, plain):
            try:
                p.unlink()
            except FileNotFoundError:
                pass


def run_once(session, settings: Settings | None = None, *, now: datetime | None = None) -> dict[str, Any]:
    """One backup cycle; records the outcome in system_status and returns it."""
    from app.services.system_status import get_status, put_status

    settings = settings or get_settings()
    now = now or _now()
    row = get_status(session, STATUS_KEY)
    prev = dict(row.value) if row else {}
    session.rollback()
    if not settings.backup_age_recipients:
        state = {"state": "not_configured", "last_attempt_at": now.isoformat()}
        put_status(session, STATUS_KEY, state)
        return state
    s3 = store(settings)
    state = {**prev, "state": "ok", "last_attempt_at": now.isoformat(), "offsite": s3 is not None,
             "location": (f"s3://{settings.backup_s3_bucket}/{settings.backup_s3_prefix}" if s3
                          else settings.backup_dir)}
    try:
        info = make_backup(settings, now)
        if s3 is not None:
            key = settings.backup_s3_prefix + info["file"]
            s3.put_file(key, info["path"], "application/octet-stream")
            stored = s3.head(key)
            if stored != info["size"]:
                raise BackupError(f"uploaded size {stored} differs from {info['size']}")
        prune_local(settings)
        warnings = []
        if s3 is not None:
            _, errors = prune_remote(settings, s3, now)
            warnings += [f"could not delete old copy {e}" for e in errors[:3]]
        state.update({"last_success_at": now.isoformat(), "file": info["file"], "size": info["size"],
                      "sha256": info["sha256"], "entries": info["entries"], "last_error": None,
                      "warnings": warnings or None})
        logger.info("Backup %s written (%d bytes encrypted, %d archive entries)%s", info["file"], info["size"],
                    info["entries"], f", uploaded to {state['location']}" if s3 else ", kept on this server only")
        if settings.backup_identity_file:
            last = _parse_time(prev.get("last_verified_at"))
            if last is None or now - last >= timedelta(days=settings.backup_verify_every_days):
                try:
                    verify_copy(settings, s3, info["file"], info["sha256"])
                    state.update({"last_verified_at": now.isoformat(), "verified_file": info["file"],
                                  "verify_error": None})
                    logger.info("Backup %s verified: downloaded, decrypted and readable", info["file"])
                except Exception as exc:
                    state["verify_error"] = f"{type(exc).__name__}: {exc}"[:300]
                    logger.error("Backup verification failed: %s", state["verify_error"])
    except Exception as exc:
        state.update({"state": "error", "last_error": f"{type(exc).__name__}: {exc}"[:300]})
        logger.error("Backup failed: %s", state["last_error"])
    if state.get("verify_error") and state["state"] == "ok":
        state["state"] = "error"
        state["last_error"] = "restore check failed: " + state["verify_error"]
        state["last_success_at"] = prev.get("last_success_at")
    put_status(session, STATUS_KEY, state)
    return state


def due(prev: dict[str, Any], settings: Settings, now: datetime) -> bool:
    last_ok = _parse_time(prev.get("last_success_at"))
    last_try = _parse_time(prev.get("last_attempt_at"))
    if last_try and prev.get("state") == "error" and now - last_try < RETRY_AFTER_FAILURE:
        return False
    return last_ok is None or now - last_ok >= timedelta(hours=settings.backup_interval_hours)


_stop = threading.Event()


def _handle(signum, _frame) -> None:
    _stop.set()


def _loop(settings: Settings) -> int:
    from app.db.session import SessionLocal
    from app.services.system_status import get_status

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    logger.info("Backup worker started (every %sh, %s)", settings.backup_interval_hours,
                f"off-site to s3://{settings.backup_s3_bucket}" if settings.backup_s3_bucket else "local only")
    while not _stop.is_set():
        session = SessionLocal()
        try:
            row = get_status(session, STATUS_KEY)
            prev = dict(row.value) if row else {}
            session.rollback()
            if not settings.backup_age_recipients or due(prev, settings, _now()):
                run_once(session, settings)
        except Exception:
            logger.exception("Backup cycle failed")
        finally:
            session.close()
        try:
            # Liveness marker on the container's private tmpfs.
            Path("/tmp/backup.alive").touch()  # nosec B108
        except OSError:
            pass
        _stop.wait(300)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.workers.backup")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("loop", help="Run on schedule (default).")
    sub.add_parser("run", help="Make one backup now.")
    sub.add_parser("keygen", help="Print a new age identity (keep it OFF the server) and its public key.")
    sub.add_parser("list", help="List local and off-site backups.")
    f = sub.add_parser("fetch", help="Download and decrypt a backup into a pg_restore-ready dump.")
    f.add_argument("name", help="Backup file name, or 'latest'")
    f.add_argument("--identity", required=True, help="age identity file (AGE-SECRET-KEY-1...)")
    f.add_argument("--out", required=True, help="Where to write the decrypted dump")
    args = parser.parse_args(argv)
    if args.cmd == "keygen":  # needs no configuration (the installer runs it with no network)
        identity, recipient = agecrypt.generate_identity()
        print(f"# HoneyShield backup key, created {_now().strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"# public key: {recipient}")
        print(identity)
        return 0
    settings = get_settings()
    configure_logging(settings.log_level)
    if args.cmd == "list":
        local = sorted(p.name for p in Path(settings.backup_dir).glob("honeyshield-*.dump.age"))
        print("On this server:" if local else "On this server: none")
        for n in local:
            print(f"  {n}")
        s3 = store(settings)
        if s3:
            names = remote_backups(settings, s3)
            print(f"Off-site (s3://{settings.backup_s3_bucket}/{settings.backup_s3_prefix}): {len(names)}")
            for n in names:
                print(f"  {n}")
        return 0
    if args.cmd == "fetch":
        s3 = store(settings)
        names = remote_backups(settings, s3) if s3 else sorted(
            p.name for p in Path(settings.backup_dir).glob("honeyshield-*.dump.age"))
        name = names[-1] if args.name == "latest" and names else args.name
        if not NAME_RE.match(name or ""):
            print("FAIL: no such backup", file=sys.stderr)
            return 1
        identities = agecrypt.identities_from_text(Path(args.identity).read_text())
        enc = Path(args.out + ".age")
        if s3:
            s3.get_to_file(settings.backup_s3_prefix + name, enc)
        else:
            enc.write_bytes((Path(settings.backup_dir) / name).read_bytes())
        try:
            with open(enc, "rb") as src, open(args.out, "wb") as dst:
                agecrypt.decrypt_stream(src, dst, identities)
        finally:
            enc.unlink()
        print(f"Decrypted {name} to {args.out}; restore it with scripts/restore_postgres.sh")
        return 0

    if args.cmd == "run":
        from app.db.session import SessionLocal
        session = SessionLocal()
        try:
            state = run_once(session, settings)
        finally:
            session.close()
        print(f"{state['state']}: {state.get('file') or state.get('last_error') or ''}")
        return 0 if state["state"] == "ok" else 1
    return _loop(settings)


if __name__ == "__main__":
    raise SystemExit(main())
