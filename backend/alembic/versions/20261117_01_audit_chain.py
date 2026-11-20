"""Tamper-evident audit log chain.

Revision ID: 20261117_01
Revises: 20261116_01
Create Date: 2026-11-17 09:00:00.000000+00:00

audit_chain is append-only (same immutability trigger as audit_logs; runtime grants
SELECT/INSERT only). audit_chain_head is a single mutable row holding the head; it is
row-locked while the sealer appends. Existing audit records are sealed by the first run of
the sealer (they were already immutable).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261117_01"
down_revision: Union[str, None] = "20261116_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_chain",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("audit_log_id", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"],
                                name=op.f("fk_audit_chain_audit_log_id_audit_logs")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_chain")),
        sa.UniqueConstraint("seq", name=op.f("uq_audit_chain_seq")),
        sa.UniqueConstraint("audit_log_id", name=op.f("uq_audit_chain_audit_log_id")),
    )
    op.create_table(
        "audit_chain_head",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("head_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_audit_chain_head_single_row")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_chain_head")),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE TRIGGER trg_audit_chain_immutable BEFORE UPDATE OR DELETE ON audit_chain "
                   "FOR EACH ROW EXECUTE FUNCTION prevent_forensic_modification()")
        op.execute("CREATE TRIGGER trg_audit_chain_no_truncate BEFORE TRUNCATE ON audit_chain "
                   "FOR EACH STATEMENT EXECUTE FUNCTION prevent_forensic_modification()")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_audit_chain_no_truncate ON audit_chain")
        op.execute("DROP TRIGGER IF EXISTS trg_audit_chain_immutable ON audit_chain")
    op.drop_table("audit_chain_head")
    op.drop_table("audit_chain")
