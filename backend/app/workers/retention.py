"""Retention maintenance job: archive old evidence write-once, then purge it.

    python -m app.workers.retention [--dry-run] [--events-days N] [--audit-days N]

Runs as the SCHEMA OWNER (MIGRATION_DATABASE_URL / POSTGRES_MIGRATION_USER): the immutability
trigger lets only the table owner delete, and only inside this job's transactions. Defaults come
from EVENT_RETENTION_DAYS / AUDIT_RETENTION_DAYS (0 = keep forever). Archives go to the S3
Object Lock bucket when EVIDENCE_S3_BUCKET is set, else to RETENTION_ARCHIVE_DIR (write-once
files). Exit status 1 if any chain did not verify (nothing of that chain is purged).
"""
from __future__ import annotations

import argparse
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.tenant import Tenant
from app.services import evidence, retention, worm


def _sink(settings):
    cfg = worm.S3Config.from_settings(settings)
    if cfg is not None:
        cfg.prefix = "archives/"  # next to checkpoints/, same Object Lock bucket and retention
        return worm.S3ObjectLockSink(cfg), f"s3://{cfg.bucket}/{cfg.prefix}"
    return evidence.WriteOnceDirectory(settings.retention_archive_dir), settings.retention_archive_dir


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(prog="python -m app.workers.retention")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--events-days", type=int, default=settings.event_retention_days)
    parser.add_argument("--audit-days", type=int, default=settings.audit_retention_days)
    parser.add_argument("--batch", type=int, default=5000)
    args = parser.parse_args(argv)
    if not args.events_days and not args.audit_days:
        print("Retention disabled (EVENT_RETENTION_DAYS and AUDIT_RETENTION_DAYS are 0); nothing to do.")
        return 0
    sink, where = _sink(settings)
    engine = create_engine(settings.migration_database_uri)
    ok = True
    with Session(bind=engine) as session:
        results = []
        if args.events_days:
            cutoff = retention.cutoff_for(args.events_days)
            for tenant_id in list(session.scalars(select(Tenant.id).order_by(Tenant.id))):
                results.append(retention.purge_tenant_events(session, tenant_id, cutoff, sink, batch=args.batch,
                                                             dry_run=args.dry_run))
        if args.audit_days:
            results.append(retention.purge_audit_log(session, retention.cutoff_for(args.audit_days), sink,
                                                     batch=args.batch, dry_run=args.dry_run))
    for r in results:
        if r.refused:
            ok = False
            print(f"REFUSED {r.scope}: {r.refused}", file=sys.stderr)
        elif r.purged:
            verb = "would purge (first batch)" if r.dry_run else "purged"
            print(f"{r.scope}: {verb} {r.purged} record(s) through seq {r.through_seq}"
                  + ("" if r.dry_run else f"; archives in {where}: {', '.join(r.archives)}"))
        else:
            print(f"{r.scope}: nothing older than the cutoff")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
