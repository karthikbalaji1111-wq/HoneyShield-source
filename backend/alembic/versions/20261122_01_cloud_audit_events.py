"""Cloud canary events: a CLOUD_AUDIT provenance and one event per CloudTrail event id.

Revision ID: 20261122_01
Revises: 20261119_03
Create Date: 2026-11-22 09:00:00.000000+00:00

Uses of a cloud canary key are read from AWS CloudTrail, so they are neither observed by HoneyShield
(PUBLIC_INGEST) nor reported by a customer (CUSTOMER_HOOK): they get their own source. The worker
reads every window more than once (CloudTrail delivers late), so the CloudTrail event id is stored as
the idempotency key and a partial unique index keeps it to one event.

DNS and AWS key decoys need no schema change: honey_tokens.token_type is a plain string column.

Online on PostgreSQL: the constraint is re-added NOT VALID then validated (no long lock), the index is
built CONCURRENTLY outside a transaction.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "20261122_01"
down_revision: Union[str, None] = "20261119_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CONSTRAINT = "ck_detection_events_valid_event_source"
OLD = "('PUBLIC_INGEST', 'MANUAL', 'CUSTOMER_HOOK', 'LEGACY_UNVERIFIED')"
NEW = "('PUBLIC_INGEST', 'MANUAL', 'CUSTOMER_HOOK', 'CLOUD_AUDIT', 'LEGACY_UNVERIFIED')"
INDEX = "uq_detection_events_cloud_event"
WHERE = "source = 'CLOUD_AUDIT' AND idempotency_key IS NOT NULL"


def _set_sources(values: str) -> None:
    op.execute(f"ALTER TABLE detection_events DROP CONSTRAINT IF EXISTS {CONSTRAINT}")
    op.execute(f"ALTER TABLE detection_events ADD CONSTRAINT {CONSTRAINT} CHECK (source IN {values}) NOT VALID")
    op.execute(f"ALTER TABLE detection_events VALIDATE CONSTRAINT {CONSTRAINT}")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        _set_sources(NEW)
        with op.get_context().autocommit_block():
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}")
            op.execute(f"CREATE UNIQUE INDEX CONCURRENTLY {INDEX} ON detection_events (idempotency_key) WHERE {WHERE}")
    else:
        # SQLite development databases carry no source constraint (see 20261113_01).
        op.execute(f"CREATE UNIQUE INDEX {INDEX} ON detection_events (idempotency_key) WHERE {WHERE}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}")
        # Fails, as it should, while CLOUD_AUDIT events exist: evidence is never rewritten.
        _set_sources(OLD)
    else:
        op.execute(f"DROP INDEX IF EXISTS {INDEX}")
