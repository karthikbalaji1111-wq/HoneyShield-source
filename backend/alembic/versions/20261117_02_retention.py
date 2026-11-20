"""Retention: archive-then-purge of old evidence with chain anchors.

Revision ID: 20261117_02
Revises: 20261117_01
Create Date: 2026-11-17 12:00:00.000000+00:00

* prevent_forensic_modification() keeps refusing every UPDATE and TRUNCATE. DELETE is allowed
  only when BOTH hold: the transaction set ``honeyshield.retention_purge = 'on'`` (SET LOCAL by
  app.services.retention) AND the deleting role owns the table. The runtime role has no DELETE
  privilege on these tables at all, so this changes nothing for the API.
* evidence_chain_anchors / audit_chain_anchor record where each purged chain now starts
  (sequence and hash of the last purged link), so verification continues from the anchor.
  Runtime: SELECT only.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261117_02"
down_revision: Union[str, None] = "20261117_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_GUARDED = """
CREATE OR REPLACE FUNCTION prevent_forensic_modification()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('honeyshield.retention_purge', true) = 'on'
       AND current_user = (SELECT tableowner FROM pg_tables
                           WHERE schemaname = TG_TABLE_SCHEMA AND tablename = TG_TABLE_NAME) THEN
        RETURN OLD;  -- audited retention purge by the schema owner (app.services.retention)
    END IF;
    RAISE EXCEPTION 'Forensic records are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;
"""

_ORIGINAL = """
CREATE OR REPLACE FUNCTION prevent_forensic_modification()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Forensic records are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;
"""


def upgrade() -> None:
    op.create_table(
        "evidence_chain_anchors",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("purged_through_seq", sa.Integer(), nullable=False),
        sa.Column("anchor_hash", sa.String(length=64), nullable=False),
        sa.Column("events_purged", sa.BigInteger(), nullable=False),
        sa.Column("purged_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_evidence_chain_anchors_tenant_id_tenants")),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_evidence_chain_anchors")),
    )
    op.create_table(
        "audit_chain_anchor",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("purged_through_seq", sa.Integer(), nullable=False),
        sa.Column("anchor_hash", sa.String(length=64), nullable=False),
        sa.Column("records_purged", sa.BigInteger(), nullable=False),
        sa.Column("purged_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_audit_chain_anchor_single_row")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_chain_anchor")),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_GUARDED)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_ORIGINAL)
    op.drop_table("audit_chain_anchor")
    op.drop_table("evidence_chain_anchors")
