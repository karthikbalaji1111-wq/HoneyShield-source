"""One public detection event per edge request (no duplicates when edge-captured hits are replayed).

Revision ID: 20261119_01
Revises: 20261118_03
Create Date: 2026-11-19 09:00:00.000000+00:00

Public hits now store the edge's request id in ``idempotency_key``. A hit the edge captured while the
backend was unavailable is replayed later with the same id; this partial unique index makes the
second insert fail, so a hit that the backend had in fact stored before it failed is never counted
twice. Existing rows have no id (NULL) and are unaffected.

Online: built CONCURRENTLY outside a transaction on PostgreSQL, so inserts are never blocked.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "20261119_01"
down_revision: Union[str, None] = "20261118_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEX = "uq_detection_events_public_request"
WHERE = "source = 'PUBLIC_INGEST' AND idempotency_key IS NOT NULL"


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            # A failed earlier attempt can leave an INVALID index behind; start clean.
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}")
            op.execute(f"CREATE UNIQUE INDEX CONCURRENTLY {INDEX} ON detection_events (idempotency_key) WHERE {WHERE}")
    else:
        op.execute(f"CREATE UNIQUE INDEX {INDEX} ON detection_events (idempotency_key) WHERE {WHERE}")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX}")
    else:
        op.execute(f"DROP INDEX IF EXISTS {INDEX}")
