"""Evidence integrity: hash chain, verification, signed checkpoints and WORM export.

Threat model (docs/evidence-integrity.md)
* The runtime role cannot UPDATE/DELETE/TRUNCATE evidence (grants) and triggers block the
  owner too; the chain additionally makes any change by a party who bypasses both (a DB
  superuser, a restored tampered backup, direct storage edits) DETECTABLE.
* A party with full DB control can recompute the whole chain. Signed checkpoints exported to
  write-once storage outside the database are what detect that: a rewritten chain no longer
  matches an exported (seq, head_hash).
* Events recorded before the chain existed are reported as ``unchained``; they cannot be
  retro-actively protected.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.detection_event import DetectionEvent
from app.models.evidence import EvidenceChainAnchor, EvidenceChainHead, EvidenceChainLink
from app.models.honey_token import HoneyToken
from app.models.project import Project

GENESIS = "0" * 64
CANONICAL_VERSION = 1


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_event(event: DetectionEvent, tenant_id: int, seq: int) -> str:
    """Stable serialisation: sorted keys, no whitespace, UTC microsecond timestamps."""
    doc: dict[str, Any] = {
        "v": CANONICAL_VERSION,
        "tenant_id": tenant_id,
        "seq": seq,
        "event_id": event.id,
        "honey_token_id": event.honey_token_id,
        "source": event.source.value if hasattr(event.source, "value") else str(event.source),
        "severity": event.severity.value if hasattr(event.severity, "value") else str(event.severity),
        "ip_address": event.ip_address,
        "request_path": event.request_path,
        "http_method": event.http_method,
        "user_agent": event.user_agent,
        "headers": {str(k): str(v) for k, v in (event.headers or {}).items()},
        "triggered_at": _iso(event.triggered_at),
        "created_by_user_id": event.created_by_user_id,
        "integration_credential_id": event.integration_credential_id,
        "idempotency_key": event.idempotency_key,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def link_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256(prev_hash.encode() + b"\n" + canonical.encode()).hexdigest()


def _lock_head(session: Session, tenant_id: int) -> EvidenceChainHead:
    """Row-lock the tenant's head (creating it on the tenant's first event)."""
    locked = select(EvidenceChainHead).where(EvidenceChainHead.tenant_id == tenant_id) \
        .with_for_update().execution_options(populate_existing=True)
    head = session.scalars(locked).one_or_none()
    if head is not None:  # steady state: one statement
        return head
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    session.execute(insert(EvidenceChainHead).values(tenant_id=tenant_id, seq=0, head_hash=GENESIS)
                    .on_conflict_do_nothing(index_elements=["tenant_id"]))
    return session.scalars(locked).one()


def append(session: Session, event: DetectionEvent, tenant_id: int) -> EvidenceChainLink:
    """Append a link for a flushed event inside its transaction (holds the tenant head lock)."""
    head = _lock_head(session, tenant_id)
    seq = head.seq + 1
    record = link_hash(head.head_hash, canonical_event(event, tenant_id, seq))
    link = EvidenceChainLink(tenant_id=tenant_id, seq=seq, detection_event_id=event.id,
                             prev_hash=head.head_hash, record_hash=record)
    session.add(link)
    head.seq, head.head_hash = seq, record
    session.flush()
    return link


@dataclass
class VerificationResult:
    tenant_id: int
    ok: bool = True
    links_checked: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    unchained_events: int = 0
    failures: list[dict[str, Any]] = field(default_factory=list)

    def fail(self, kind: str, **detail: Any) -> None:
        self.ok = False
        if len(self.failures) < 50:
            self.failures.append({"kind": kind, **detail})


def verify_tenant(session: Session, tenant_id: int, checkpoints: list[dict] | None = None,
                  batch: int = 1000) -> VerificationResult:
    """Recompute the tenant's chain from the stored events.

    Detects: modified event fields, modified/reordered/removed links, gaps, a head that does
    not match the last link, events with no link (missing from chain) and, given exported
    checkpoints, a chain rewritten after the checkpoint was taken.
    """
    result = VerificationResult(tenant_id=tenant_id)
    expected_prev, expected_seq, last_id = GENESIS, 1, 0
    by_seq: dict[int, str] = {}
    anchor = session.get(EvidenceChainAnchor, tenant_id)
    if anchor is not None:  # links up to the anchor were archived and purged (retention)
        expected_prev, expected_seq, last_id = anchor.anchor_hash, anchor.purged_through_seq + 1, anchor.purged_through_seq
        by_seq[anchor.purged_through_seq] = anchor.anchor_hash
    while True:
        rows = session.execute(
            select(EvidenceChainLink, DetectionEvent)
            .join(DetectionEvent, DetectionEvent.id == EvidenceChainLink.detection_event_id, isouter=True)
            .where(EvidenceChainLink.tenant_id == tenant_id, EvidenceChainLink.seq > last_id)
            .order_by(EvidenceChainLink.seq).limit(batch)
        ).all()
        if not rows:
            break
        for link, event in rows:
            last_id = link.seq
            if link.seq != expected_seq:
                result.fail("sequence_gap", expected_seq=expected_seq, found_seq=link.seq)
                expected_seq = link.seq
            if link.prev_hash != expected_prev:
                result.fail("broken_link", seq=link.seq)
            if event is None:
                result.fail("event_missing", seq=link.seq, event_id=link.detection_event_id)
            else:
                recomputed = link_hash(link.prev_hash, canonical_event(event, tenant_id, link.seq))
                if recomputed != link.record_hash:
                    result.fail("event_modified", seq=link.seq, event_id=event.id)
            by_seq[link.seq] = link.record_hash
            expected_prev, expected_seq = link.record_hash, link.seq + 1
            result.links_checked += 1
    result.head_seq = expected_seq - 1
    result.head_hash = expected_prev

    head = session.get(EvidenceChainHead, tenant_id)
    if head is not None and (head.seq, head.head_hash) != (result.head_seq, result.head_hash):
        result.fail("head_mismatch", head_seq=head.seq, chain_seq=result.head_seq)

    tenant_events = (select(func.count(DetectionEvent.id))
                     .join(HoneyToken, HoneyToken.id == DetectionEvent.honey_token_id)
                     .join(Project, Project.id == HoneyToken.project_id)
                     .where(Project.tenant_id == tenant_id))
    total = session.scalar(tenant_events) or 0
    chained_existing = session.scalar(
        select(func.count(EvidenceChainLink.id))
        .join(DetectionEvent, DetectionEvent.id == EvidenceChainLink.detection_event_id)
        .where(EvidenceChainLink.tenant_id == tenant_id)) or 0
    result.unchained_events = max(0, total - chained_existing)
    first_link_event = session.scalar(select(func.min(EvidenceChainLink.detection_event_id))
                                      .where(EvidenceChainLink.tenant_id == tenant_id))
    if first_link_event is not None:
        # Any event newer than the first chained one must be chained: a gap means an event was
        # inserted while bypassing the application (or its link was removed).
        stray = session.scalar(
            tenant_events.where(DetectionEvent.id > first_link_event,
                                ~DetectionEvent.id.in_(select(EvidenceChainLink.detection_event_id))))
        if stray:
            result.fail("unchained_after_chain_start", count=stray)

    for cp in checkpoints or []:
        if cp.get("chain") or cp.get("tenant_id") != tenant_id:
            continue
        seq = cp["seq"]
        if anchor is not None and seq < anchor.purged_through_seq:
            continue  # purged range: verified against this checkpoint when it was archived
        if seq > result.head_seq:
            result.fail("checkpoint_ahead_of_chain", checkpoint_seq=seq, chain_seq=result.head_seq)
        elif by_seq.get(seq) != cp["head_hash"]:
            result.fail("checkpoint_mismatch", checkpoint_seq=seq)
    return result


# ------------------------------------------------------------------ checkpoints / export

def _checkpoint_key() -> str:
    from app.core.config import get_settings
    from app.core.exceptions import ServiceNotConfiguredError

    key = get_settings().integration_signing_key
    if not key:
        raise ServiceNotConfiguredError("INTEGRATION_SIGNING_KEY is required to sign checkpoints")
    return key


def sign_checkpoint(cp: dict[str, Any], key: str) -> str:
    fields = ("tenant_id", "seq", "head_hash", "created_at") + (("chain",) if "chain" in cp else ())
    body = json.dumps({k: cp[k] for k in fields}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), b"honeyshield-checkpoint-v1|" + body, hashlib.sha256).hexdigest()


def make_checkpoints(session: Session) -> list[dict[str, Any]]:
    key = _checkpoint_key()
    now = _iso(datetime.now(timezone.utc))
    out = []
    for head in session.scalars(select(EvidenceChainHead).order_by(EvidenceChainHead.tenant_id)):
        cp = {"tenant_id": head.tenant_id, "seq": head.seq, "head_hash": head.head_hash, "created_at": now}
        cp["signature"] = sign_checkpoint(cp, key)
        out.append(cp)
    from app.services import audit_chain

    audit_cp = audit_chain.head_checkpoint(session)
    if audit_cp is not None:
        audit_cp["created_at"] = now
        audit_cp["signature"] = sign_checkpoint(audit_cp, key)
        out.append(audit_cp)
    return out


def checkpoint_is_authentic(cp: dict[str, Any]) -> bool:
    return hmac.compare_digest(sign_checkpoint(cp, _checkpoint_key()), str(cp.get("signature", "")))


class WriteOnceDirectory:
    """Local write-once sink: files are created with O_EXCL and made read-only.

    Stands in for object storage with retention lock (e.g. S3 Object Lock in compliance mode),
    which is what production should use: a local directory is only as safe as the host.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, name: str, data: bytes) -> Path:
        path = self.root / name
        # Read-only, and only for the checkpointer's own user (root can always read it).
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        return path

    def checkpoints(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.root.glob("checkpoint-*.json")):
            out.extend(json.loads(p.read_text()))
        return out


def export_since(session: Session, tenant_id: int, after_seq: int) -> Iterator[dict[str, Any]]:
    """Events with their chain links, for append-only external archives (JSON lines)."""
    rows = session.execute(
        select(EvidenceChainLink, DetectionEvent)
        .join(DetectionEvent, DetectionEvent.id == EvidenceChainLink.detection_event_id)
        .where(EvidenceChainLink.tenant_id == tenant_id, EvidenceChainLink.seq > after_seq)
        .order_by(EvidenceChainLink.seq))
    for link, event in rows:
        yield {"seq": link.seq, "prev_hash": link.prev_hash, "record_hash": link.record_hash,
               "canonical": json.loads(canonical_event(event, tenant_id, link.seq))}


def publish_checkpoints(session: Session, sink: WriteOnceDirectory) -> Path:
    cps = make_checkpoints(session)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return sink.put(f"checkpoint-{stamp}.json", json.dumps(cps, sort_keys=True, indent=1).encode())


def result_dict(result: VerificationResult) -> dict[str, Any]:
    return asdict(result)
