"""Evidence integrity operations.

    python -m app.workers.evidence verify [--checkpoints DIR]   # exit 1 on any failure
    python -m app.workers.evidence checkpoint --out DIR          # signed heads, write-once file
    python -m app.workers.evidence export --tenant ID --after SEQ --out FILE.jsonl
    python -m app.workers.evidence seal-audit                    # chain new audit records
    python -m app.workers.evidence ship --out DIR                # upload unshipped files to S3

With EVIDENCE_S3_BUCKET set, ``checkpoint`` also uploads every local checkpoint file not yet in
the Object Lock bucket (so a failed upload is retried next run) and exits 3 if that upload failed
(the checkpoint itself was written; the container loop keeps going). After a fully successful
cycle it touches $HS_CHECKPOINT_STATUS_FILE, which the container health check watches.
``verify --checkpoints s3`` reads the checkpoints back from the bucket.

``checkpoint`` seals the audit log first, so its signed file covers both chains.

Run ``checkpoint`` on a schedule (e.g. every 15 minutes) and ship DIR to object storage with
retention lock. ``verify --checkpoints`` then detects a chain rewritten after any checkpoint.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.tenant import Tenant
from app.services import audit_chain, evidence


def _sink():
    from app.core.config import get_settings
    from app.services import worm

    cfg = worm.S3Config.from_settings(get_settings())
    return worm.S3ObjectLockSink(cfg) if cfg else None


SHIP_FAILED = 3  # checkpoint written locally, upload failed: the loop keeps running and retries
STATUS_FILE_ENV = "HS_CHECKPOINT_STATUS_FILE"


def _mark_ok() -> None:
    """Touch the status file the container health check watches (a full cycle succeeded)."""
    path = os.environ.get(STATUS_FILE_ENV)
    if path:
        with open(path, "a"):
            os.utime(path, None)


def _record_cycle(session, rc: int, path) -> None:
    """Report the cycle to system_status for the watchdog (never fails the checkpoint itself)."""
    from datetime import datetime, timezone

    from app.services.system_status import put_status
    try:
        put_status(session, "checkpoint", {
            "ok": rc == 0,
            "at": datetime.now(timezone.utc).isoformat(),
            "file": os.path.basename(str(path)) if path else None,
            "error": None if rc == 0 else "checkpoint written locally but the S3 Object Lock upload failed",
        })
    except Exception as exc:  # status is advisory
        session.rollback()
        print(f"WARN: could not record checkpoint status: {type(exc).__name__}", file=sys.stderr)


def _ship(local_dir: str, required: bool = False) -> int:
    from app.services import worm

    sink = _sink()
    if sink is None:
        if required:
            print("FAIL: EVIDENCE_S3_BUCKET is not configured", file=sys.stderr)
            return 1
        return 0
    try:
        uploaded = worm.sync_directory(local_dir, sink)
    except (worm.WormError, OSError) as exc:
        print(f"FAIL: shipping checkpoints to s3://{sink.cfg.bucket}: {exc}", file=sys.stderr)
        return SHIP_FAILED
    print(f"Shipped {len(uploaded)} checkpoint file(s) to s3://{sink.cfg.bucket}/{sink.cfg.prefix} "
          f"({sink.cfg.lock_mode}, {sink.cfg.retention_days} days)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.workers.evidence")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--checkpoints", help="Directory of exported checkpoint files, or 's3' for the Object Lock bucket")
    c = sub.add_parser("checkpoint")
    c.add_argument("--out", required=True)
    e = sub.add_parser("export")
    e.add_argument("--tenant", type=int, required=True)
    e.add_argument("--after", type=int, default=0)
    e.add_argument("--out", required=True)
    sub.add_parser("seal-audit")
    sh = sub.add_parser("ship")
    sh.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    session = SessionLocal()
    try:
        if args.cmd == "seal-audit":
            print(f"Sealed {audit_chain.seal(session)} audit record(s)")
            return 0
        if args.cmd == "checkpoint":
            sealed = audit_chain.seal(session)
            path = evidence.publish_checkpoints(session, evidence.WriteOnceDirectory(args.out))
            print(f"Sealed {sealed} audit record(s); wrote {path}")
            rc = _ship(args.out)
            if rc == 0:
                _mark_ok()
            _record_cycle(session, rc, path)
            return rc
        if args.cmd == "ship":
            return _ship(args.out, required=True)
        if args.cmd == "export":
            # The export holds attacker IPs and request details: only its owner may read it.
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            n = 0
            with os.fdopen(fd, "w") as fh:
                for rec in evidence.export_since(session, args.tenant, args.after):
                    fh.write(json.dumps(rec, sort_keys=True) + "\n")
                    n += 1
            print(f"Exported {n} chained events to {args.out}")
            return 0
        checkpoints = []
        if args.checkpoints == "s3":
            sink = _sink()
            if sink is None:
                print("FAIL: EVIDENCE_S3_BUCKET is not configured", file=sys.stderr)
                return 1
            checkpoints = sink.checkpoints()
            print(f"Loaded {len(checkpoints)} checkpoint entries from s3://{sink.cfg.bucket}/{sink.cfg.prefix}")
        elif args.checkpoints:
            checkpoints = evidence.WriteOnceDirectory(args.checkpoints).checkpoints()
        if checkpoints:
            forged = [cp for cp in checkpoints if not evidence.checkpoint_is_authentic(cp)]
            if forged:
                print(f"FAIL: {len(forged)} checkpoint(s) have invalid signatures", file=sys.stderr)
                return 1
        ok = True
        for tenant_id in session.scalars(select(Tenant.id).order_by(Tenant.id)):
            r = evidence.verify_tenant(session, tenant_id, checkpoints)
            status = "OK" if r.ok else "FAIL"
            print(f"tenant {tenant_id}: {status} links={r.links_checked} head_seq={r.head_seq} "
                  f"unchained={r.unchained_events} failures={json.dumps(r.failures)}")
            ok = ok and r.ok
        a = audit_chain.verify(session, checkpoints)
        print(f"audit log: {'OK' if a.ok else 'FAIL'} links={a.links_checked} head_seq={a.head_seq} "
              f"unsealed={a.unsealed_records} failures={json.dumps(a.failures)}")
        return 0 if ok and a.ok else 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
