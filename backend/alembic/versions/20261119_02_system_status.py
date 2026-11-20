"""Operational status rows for the watchdog, the self-test probe, backups and the checkpointer.

Revision ID: 20261119_02
Revises: 20261119_01
Create Date: 2026-11-19 18:00:00.000000+00:00

A new, empty table: no existing data is touched and nothing is locked.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261119_02"
down_revision: Union[str, None] = "20261119_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_status",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_system_status")),
    )


def downgrade() -> None:
    op.drop_table("system_status")
