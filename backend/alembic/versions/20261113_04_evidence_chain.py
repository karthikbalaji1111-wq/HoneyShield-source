"""Tamper-evident evidence chain.

Revision ID: 20261113_04
Revises: 20261113_03
Create Date: 2026-11-13 21:00:00.000000+00:00

evidence_chain is append-only (same immutability trigger as detection_events; runtime grants
SELECT/INSERT only). evidence_chain_heads is a small mutable table holding each tenant's
current head; it is row-locked during appends so links are strictly ordered per tenant.
Existing events are NOT back-filled: they are reported as unchained by the verifier.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_04"
down_revision: Union[str, None] = "20261113_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "evidence_chain",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("detection_event_id", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_evidence_chain_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["detection_event_id"], ["detection_events.id"],
                                name=op.f("fk_evidence_chain_detection_event_id_detection_events")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_chain")),
        sa.UniqueConstraint("tenant_id", "seq", name=op.f("uq_evidence_chain_tenant_id")),
        sa.UniqueConstraint("detection_event_id", name=op.f("uq_evidence_chain_detection_event_id")),
    )
    op.create_index(op.f("ix_evidence_chain_tenant_id"), "evidence_chain", ["tenant_id"])
    op.create_table(
        "evidence_chain_heads",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_evidence_chain_heads_tenant_id_tenants")),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_evidence_chain_heads")),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE TRIGGER trg_evidence_chain_immutable BEFORE UPDATE OR DELETE ON evidence_chain "
                   "FOR EACH ROW EXECUTE FUNCTION prevent_forensic_modification()")
        op.execute("CREATE TRIGGER trg_evidence_chain_no_truncate BEFORE TRUNCATE ON evidence_chain "
                   "FOR EACH STATEMENT EXECUTE FUNCTION prevent_forensic_modification()")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_evidence_chain_no_truncate ON evidence_chain")
        op.execute("DROP TRIGGER IF EXISTS trg_evidence_chain_immutable ON evidence_chain")
    op.drop_table("evidence_chain_heads")
    op.drop_index(op.f("ix_evidence_chain_tenant_id"), table_name="evidence_chain")
    op.drop_table("evidence_chain")
