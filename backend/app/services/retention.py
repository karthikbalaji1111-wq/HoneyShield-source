"""Retention: archive old evidence write-once, then purge it, keeping the chains verifiable.

Order of operations, per tenant (and for the audit log), each batch in ONE transaction:
1. verify the chain; a chain that does not verify is never purged (that would destroy the
   evidence of tampering) - the run reports it and exits non-zero;
2. choose a chain PREFIX: links appended before the cutoff (link insertion time is monotonic in
   the sequence because appends hold the head lock), at most ``batch`` per transaction;
3. write a signed JSON-lines archive of those links and their canonical records to the
   write-once sink (S3 Object Lock when configured, else the local archive directory) - the
   purge only happens after the archive write succeeded;
4. ``SET LOCAL honeyshield.retention_purge = 'on'`` and delete (as the schema owner: the only
   role the trigger exempts, and only for DELETE);
5. move the anchor to the last purged link, so verification continues from its hash;
6. audit ``RETENTION_PURGE`` with counts and the archive name.

Archives re-verify offline: every line carries prev_hash/record_hash and the canonical record,
the first line names the range and anchor hashes, and the last line is an HMAC over the rest.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.orm import Session

from app.models.alerting import OutboxEvent
from app.models.audit_chain import AuditChainAnchor, AuditChainLink
from app.models.audit_log import AuditLog
from app.models.detection_event import DetectionEvent
from app.models.evidence import EvidenceChainAnchor, EvidenceChainLink
from app.models.honey_token import HoneyToken
from app.models.project import Project
from app.services import audit_chain, evidence

MIN_RETENTION_DAYS = 30
ARCHIVE_VERSION = 1


class RetentionRefused(RuntimeError):
    pass


@dataclass
class PurgeResult:
    scope: str
    purged: int = 0
    through_seq: int = 0
    archives: list[str] = field(default_factory=list)
    refused: str | None = None
    dry_run: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _signing_key() -> bytes:
    from app.core.config import get_settings

    key = get_settings().integration_signing_key
    if not key:
        raise RetentionRefused("INTEGRATION_SIGNING_KEY is required to sign archives")
    return key.encode()


def build_archive(header: dict[str, Any], records: list[dict[str, Any]]) -> bytes:
    lines = [json.dumps({"kind": "honeyshield-archive", "version": ARCHIVE_VERSION, **header}, sort_keys=True)]
    lines += [json.dumps(r, sort_keys=True, default=str) for r in records]
    body = ("\n".join(lines) + "\n").encode()
    mac = hmac.new(_signing_key(), b"honeyshield-archive-v1|" + hashlib.sha256(body).digest(), hashlib.sha256)
    return body + (json.dumps({"kind": "signature", "hmac_sha256": mac.hexdigest()}) + "\n").encode()


def verify_archive(data: bytes) -> dict[str, Any]:
    """Check signature and chain continuity of an archive offline. Returns its header."""
    body, _, last = data.rstrip(b"\n").rpartition(b"\n")
    sig = json.loads(last)
    expected = hmac.new(_signing_key(), b"honeyshield-archive-v1|" + hashlib.sha256(body + b"\n").digest(),
                        hashlib.sha256).hexdigest()
    if sig.get("kind") != "signature" or not hmac.compare_digest(sig.get("hmac_sha256", ""), expected):
        raise ValueError("archive signature invalid")
    lines = [json.loads(x) for x in body.split(b"\n")]
    header, records = lines[0], lines[1:]
    prev = header["prev_hash"]
    for rec in records:
        if rec.get("unchained"):
            continue
        canonical = json.dumps(rec["canonical"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if rec["prev_hash"] != prev or evidence.link_hash(prev, canonical) != rec["record_hash"]:
            raise ValueError(f"archive chain broken at seq {rec.get('seq')}")
        prev = rec["record_hash"]
    if prev != header["through_hash"]:
        raise ValueError("archive does not end at its declared hash")
    return header


def _enable_purge(session: Session) -> None:
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SET LOCAL honeyshield.retention_purge = 'on'"))


def _audit(session: Session, message: str, tenant_id: int | None, metadata: dict[str, Any]) -> None:
    session.execute(insert(AuditLog).values(
        event_type="RETENTION_PURGE", severity="WARNING", message=message, actor_source="retention_job",
        tenant_id=tenant_id, event_metadata=metadata, created_at=_now()))


def _stamp() -> str:
    return _now().strftime("%Y%m%dT%H%M%S%fZ")


# --------------------------------------------------------------------------- evidence

def _tenant_event_ids(tenant_id: int):
    return (select(DetectionEvent.id).join(HoneyToken, HoneyToken.id == DetectionEvent.honey_token_id)
            .join(Project, Project.id == HoneyToken.project_id).where(Project.tenant_id == tenant_id))


def purge_tenant_events(session: Session, tenant_id: int, cutoff: datetime, sink, *, batch: int = 5000,
                        dry_run: bool = False) -> PurgeResult:
    res = PurgeResult(scope=f"tenant {tenant_id}", dry_run=dry_run)
    check = evidence.verify_tenant(session, tenant_id)
    if not check.ok:
        res.refused = f"evidence chain does not verify ({check.failures[0]['kind']}); nothing purged"
        session.rollback()
        return res
    while True:
        anchor = session.get(EvidenceChainAnchor, tenant_id, populate_existing=True)
        start = anchor.purged_through_seq if anchor else 0
        first_new = session.scalar(select(func.min(EvidenceChainLink.seq)).where(
            EvidenceChainLink.tenant_id == tenant_id, EvidenceChainLink.seq > start,
            EvidenceChainLink.created_at >= cutoff))
        last = session.scalar(select(func.max(EvidenceChainLink.seq)).where(EvidenceChainLink.tenant_id == tenant_id)) or 0
        through = min((first_new - 1) if first_new else last, start + batch)
        legacy_ids = list(session.scalars(
            _tenant_event_ids(tenant_id).where(
                DetectionEvent.triggered_at < cutoff,
                ~DetectionEvent.id.in_(select(EvidenceChainLink.detection_event_id)))
            .order_by(DetectionEvent.id).limit(batch)))
        if through <= start and not legacy_ids:
            session.rollback()
            break
        links = session.execute(
            select(EvidenceChainLink, DetectionEvent)
            .join(DetectionEvent, DetectionEvent.id == EvidenceChainLink.detection_event_id)
            .where(EvidenceChainLink.tenant_id == tenant_id, EvidenceChainLink.seq > start,
                   EvidenceChainLink.seq <= through)
            .order_by(EvidenceChainLink.seq)).all()
        records = [{"seq": l.seq, "prev_hash": l.prev_hash, "record_hash": l.record_hash,
                    "canonical": json.loads(evidence.canonical_event(e, tenant_id, l.seq))} for l, e in links]
        legacy = session.scalars(select(DetectionEvent).where(DetectionEvent.id.in_(legacy_ids))).all()
        records += [{"unchained": True, "canonical": json.loads(evidence.canonical_event(e, tenant_id, 0))}
                    for e in legacy]
        prev_hash = anchor.anchor_hash if anchor else evidence.GENESIS
        through_hash = links[-1][0].record_hash if links else prev_hash
        count = len(records)
        if dry_run:  # report the first batch only: without purging, the next batch cannot be chosen
            res.purged, res.through_seq = count, through
            session.rollback()
            break
        name = f"archive-evidence-t{tenant_id}-{start + 1:010d}-{through:010d}-{_stamp()}.jsonl"
        sink.put(name, build_archive({"chain": "evidence", "tenant_id": tenant_id, "from_seq": start + 1,
                                      "through_seq": through, "prev_hash": prev_hash, "through_hash": through_hash,
                                      "cutoff": cutoff.isoformat(), "records": count}, records))
        event_ids = [e.id for _, e in links] + legacy_ids
        _enable_purge(session)
        session.execute(delete(OutboxEvent).where(OutboxEvent.detection_event_id.in_(event_ids)))
        session.execute(delete(EvidenceChainLink).where(EvidenceChainLink.tenant_id == tenant_id,
                                                        EvidenceChainLink.seq > start,
                                                        EvidenceChainLink.seq <= through))
        session.execute(delete(DetectionEvent).where(DetectionEvent.id.in_(event_ids)))
        if links:
            if anchor is None:
                session.execute(insert(EvidenceChainAnchor).values(
                    tenant_id=tenant_id, purged_through_seq=through, anchor_hash=through_hash,
                    events_purged=count, purged_at=_now()))
            else:
                session.execute(update(EvidenceChainAnchor).where(EvidenceChainAnchor.tenant_id == tenant_id).values(
                    purged_through_seq=through, anchor_hash=through_hash,
                    events_purged=EvidenceChainAnchor.events_purged + count, purged_at=_now()))
        _audit(session, f"Retention purged {count} detection event(s) of tenant {tenant_id} through chain "
                        f"seq {through}", tenant_id,
               {"archive": name, "events": count, "from_seq": start + 1, "through_seq": through,
                "cutoff": cutoff.isoformat()})
        session.commit()
        res.purged += count
        res.through_seq = through
        res.archives.append(name)
    return res


# --------------------------------------------------------------------------- audit log

def purge_audit_log(session: Session, cutoff: datetime, sink, *, batch: int = 5000,
                    dry_run: bool = False) -> PurgeResult:
    res = PurgeResult(scope="audit log", dry_run=dry_run)
    if not dry_run:
        audit_chain.seal(session)
    check = audit_chain.verify(session)
    if not check.ok:
        res.refused = f"audit chain does not verify ({check.failures[0]['kind']}); nothing purged"
        session.rollback()
        return res
    while True:
        anchor = session.get(AuditChainAnchor, 1, populate_existing=True)
        start = anchor.purged_through_seq if anchor else 0
        first_new = session.scalar(select(func.min(AuditChainLink.seq)).where(
            AuditChainLink.seq > start, AuditChainLink.created_at >= cutoff))
        last = session.scalar(select(func.max(AuditChainLink.seq))) or 0
        through = min((first_new - 1) if first_new else last, start + batch)
        if through <= start:
            session.rollback()
            break
        rows = session.execute(
            select(AuditChainLink, AuditLog).join(AuditLog, AuditLog.id == AuditChainLink.audit_log_id)
            .where(AuditChainLink.seq > start, AuditChainLink.seq <= through).order_by(AuditChainLink.seq)).all()
        if dry_run:
            res.purged, res.through_seq = len(rows), through
            session.rollback()
            break
        records = [{"seq": l.seq, "prev_hash": l.prev_hash, "record_hash": l.record_hash,
                    "canonical": json.loads(audit_chain.canonical_record(r, l.seq))} for l, r in rows]
        prev_hash = anchor.anchor_hash if anchor else audit_chain.GENESIS
        through_hash = rows[-1][0].record_hash
        name = f"archive-audit-{start + 1:010d}-{through:010d}-{_stamp()}.jsonl"
        sink.put(name, build_archive({"chain": "audit", "tenant_id": None, "from_seq": start + 1,
                                      "through_seq": through, "prev_hash": prev_hash, "through_hash": through_hash,
                                      "cutoff": cutoff.isoformat(), "records": len(records)}, records))
        ids = [r.id for _, r in rows]
        _enable_purge(session)
        session.execute(delete(AuditChainLink).where(AuditChainLink.seq > start, AuditChainLink.seq <= through))
        session.execute(delete(AuditLog).where(AuditLog.id.in_(ids)))
        if anchor is None:
            session.execute(insert(AuditChainAnchor).values(id=1, purged_through_seq=through, anchor_hash=through_hash,
                                                            records_purged=len(ids), purged_at=_now()))
        else:
            session.execute(update(AuditChainAnchor).where(AuditChainAnchor.id == 1).values(
                purged_through_seq=through, anchor_hash=through_hash,
                records_purged=AuditChainAnchor.records_purged + len(ids), purged_at=_now()))
        _audit(session, f"Retention purged {len(ids)} audit record(s) through chain seq {through}", None,
               {"archive": name, "records": len(ids), "from_seq": start + 1, "through_seq": through,
                "cutoff": cutoff.isoformat()})
        session.commit()
        res.purged += len(ids)
        res.through_seq = through
        res.archives.append(name)
    return res


def cutoff_for(days: int, now: datetime | None = None) -> datetime:
    if days < MIN_RETENTION_DAYS:
        raise RetentionRefused(f"Retention below {MIN_RETENTION_DAYS} days is refused")
    return (now or _now()) - timedelta(days=days)
