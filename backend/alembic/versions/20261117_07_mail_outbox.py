"""Account mail queue sent by the worker (the API has no internet egress).

Revision ID: 20261117_07
Revises: 20261117_06
Create Date: 2026-11-18 00:30:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261117_07"
down_revision: Union[str, None] = "20261117_06"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mail_outbox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("console_base", sa.String(length=300), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("kind IN ('password_reset')", name=op.f("ck_mail_outbox_kind_valid")),
        sa.CheckConstraint("status IN ('PENDING', 'SENT', 'FAILED', 'EXPIRED')", name=op.f("ck_mail_outbox_status_valid")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_mail_outbox_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mail_outbox")),
    )
    op.create_index("ix_mail_outbox_status_next_attempt_at", "mail_outbox", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_mail_outbox_status_next_attempt_at", table_name="mail_outbox")
    op.drop_table("mail_outbox")
