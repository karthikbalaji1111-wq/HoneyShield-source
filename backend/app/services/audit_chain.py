"""Tamper-evident audit log: a hash chain sealed over committed audit records.

Why sealing is asynchronous
* Audit records are written from many places, some in a second session while the caller's
  transaction is still open (``record_independently``). A synchronous global chain lock there
  would let one request wait on a lock its own outer transaction holds, which PostgreSQL cannot
  detect as a deadlock. So records are written exactly as before and a sealer appends them to
  the chain afterwards (the checkpointer runs it before every checkpoint).
* Audit records are immutable from the moment they commit (trigger + INSERT/SELECT grants), so
  the unsealed window only matters against a database superuser; it is a few minutes at most
  and the verifier reports records left unsealed past it.

What the chain detects (with ``verify``)
* a sealed record modified or deleted, links removed, reordered or altered, a head that does
  not match the chain, and - given exported checkpoints - a chain rewritten after a checkpoint.
It cannot tell a record forged by a database superuser before sealing from a genuine one.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_chain import AuditChainAnchor, AuditChainHead, AuditChainLink
from app.models.audit_log import AuditLog

GENESIS = "0" * 64
CANONICAL_VERSION = 1
CHAIN_NAME = "audit"
# Records still unsealed this long after the last seal are reported as a failure.
UNSEALED_TOLERANCE = timedelta(minutes=10)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_record(row: AuditLog, seq: int) -> str:
    doc: dict[str, Any] = {
        "v": CANONICAL_VERSION,
        "seq": seq,
        "audit_log_id": row.id,
        "event_type": row.event_type,
        "severity": row.severity,
        "message": row.message,
        "actor_source": row.actor_source,
        "actor_user_id": row.actor_user_id,
        "target_entity": row.target_entity,
        "target_id": row.target_id,
        "tenant_id": row.tenant_id,
        "project_id": row.project_id,
        "metadata": row.event_metadata,
        "created_at": _iso(row.created_at),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def link_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256(prev_hash.encode() + b"\n" + canonical.encode()).hexdigest()


def _lock_head(session: Session) -> AuditChainHead:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    session.execute(insert(AuditChainHead).values(id=1, seq=0, head_hash=GENESIS)
                    .on_conflict_do_nothing(index_elements=["id"]))
    return session.scalars(select(AuditChainHead).where(AuditChainHead.id == 1)
                           .with_for_update().execution_options(populate_existing=True)).one()


def unsealed_query():
    return select(AuditLog).where(~select(AuditChainLink.id)
                                  .where(AuditChainLink.audit_log_id == AuditLog.id).exists())


def seal(session: Session, batch: int = 1000, max_batches: int | None = None) -> int:
    """Append every committed, unsealed audit record to the chain (oldest id first).

    Commits after each batch. Safe to run concurrently: the head row lock serialises sealers
    and ``audit_log_id`` is unique. Returns the number of records sealed.
    """
    sealed = 0
    batches = 0
    while max_batches is None or batches < max_batches:
        head = _lock_head(session)
        rows = list(session.scalars(unsealed_query().order_by(AuditLog.id).limit(batch)))
        if not rows:
            session.commit()
            break
        seq, prev = head.seq, head.head_hash
        for row in rows:
            seq += 1
            record = link_hash(prev, canonical_record(row, seq))
            session.add(AuditChainLink(seq=seq, audit_log_id=row.id, prev_hash=prev, record_hash=record))
            prev = record
        head.seq, head.head_hash = seq, prev
        head.updated_at = datetime.now(timezone.utc)
        session.commit()
        sealed += len(rows)
        batches += 1
        if len(rows) < batch:
            break
    return sealed


@dataclass
class AuditVerification:
    chain: str = CHAIN_NAME
    ok: bool = True
    links_checked: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    unsealed_records: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)

    def fail(self, kind: str, **detail: Any) -> None:
        self.ok = False
        if len(self.failures) < 50:
            self.failures.append({"kind": kind, **detail})


def verify(session: Session, checkpoints: list[dict] | None = None, batch: int = 1000) -> AuditVerification:
    result = AuditVerification()
    wanted = {cp["seq"]: cp["head_hash"] for cp in checkpoints or [] if cp.get("chain") == CHAIN_NAME}
    expected_prev, expected_seq, last_seq = GENESIS, 1, 0
    seen: dict[int, str] = {0: GENESIS}  # a checkpoint of the empty chain records the genesis hash
    anchor = session.get(AuditChainAnchor, 1)
    if anchor is not None:  # records up to the anchor were archived and purged (retention)
        expected_prev, expected_seq, last_seq = anchor.anchor_hash, anchor.purged_through_seq + 1, anchor.purged_through_seq
        seen = {anchor.purged_through_seq: anchor.anchor_hash}
        wanted = {k: v for k, v in wanted.items() if k >= anchor.purged_through_seq}
    while True:
        rows = session.execute(
            select(AuditChainLink, AuditLog)
            .join(AuditLog, AuditLog.id == AuditChainLink.audit_log_id, isouter=True)
            .where(AuditChainLink.seq > last_seq)
            .order_by(AuditChainLink.seq).limit(batch)
        ).all()
        if not rows:
            break
        for link, row in rows:
            last_seq = link.seq
            if link.seq != expected_seq:
                result.fail("sequence_gap", expected_seq=expected_seq, found_seq=link.seq)
            if link.prev_hash != expected_prev:
                result.fail("broken_link", seq=link.seq)
            if row is None:
                result.fail("record_missing", seq=link.seq, audit_log_id=link.audit_log_id)
            elif link_hash(link.prev_hash, canonical_record(row, link.seq)) != link.record_hash:
                result.fail("record_modified", seq=link.seq, audit_log_id=row.id)
            if link.seq in wanted:
                seen[link.seq] = link.record_hash
            expected_prev, expected_seq = link.record_hash, link.seq + 1
            result.links_checked += 1
    result.head_seq, result.head_hash = expected_seq - 1, expected_prev

    head = session.get(AuditChainHead, 1)
    if head is not None and (head.seq, head.head_hash) != (result.head_seq, result.head_hash):
        result.fail("head_mismatch", head_seq=head.seq, chain_seq=result.head_seq)

    result.unsealed_records = session.scalar(
        select(func.count()).select_from(unsealed_query().subquery())) or 0
    if head is not None and result.unsealed_records:
        last_seal = head.updated_at if head.updated_at.tzinfo else head.updated_at.replace(tzinfo=timezone.utc)
        cutoff = last_seal - UNSEALED_TOLERANCE
        stale = session.scalar(select(func.count()).select_from(
            unsealed_query().where(AuditLog.created_at < cutoff).subquery())) or 0
        if stale:
            result.fail("unsealed_records", count=stale)

    for seq, expected in sorted(wanted.items()):
        if seq > result.head_seq:
            result.fail("checkpoint_ahead_of_chain", checkpoint_seq=seq, chain_seq=result.head_seq)
        elif seen.get(seq) != expected:
            result.fail("checkpoint_mismatch", checkpoint_seq=seq)
    return result


def head_checkpoint(session: Session) -> dict[str, Any] | None:
    head = session.get(AuditChainHead, 1)
    if head is None:
        return None
    return {"chain": CHAIN_NAME, "tenant_id": None, "seq": head.seq, "head_hash": head.head_hash}


def result_dict(result: AuditVerification) -> dict[str, Any]:
    return asdict(result)
