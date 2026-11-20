"""Test alert deliveries: outbox rows without a detection event.

Revision ID: 20261117_05
Revises: 20261117_04
Create Date: 2026-11-17 19:00:00.000000+00:00

A test delivery is an outbox row with is_test = true and no detection event, so testing a
destination never creates fake evidence. A CHECK keeps every non-test row tied to an event.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261117_05"
down_revision: Union[str, None] = "20261117_04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("outbox_events") as batch:
        batch.add_column(sa.Column("is_test", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.alter_column("detection_event_id", existing_type=sa.Integer(), nullable=True)
        batch.create_check_constraint("event_or_test", "is_test OR detection_event_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DELETE FROM outbox_events WHERE is_test")
    with op.batch_alter_table("outbox_events") as batch:
        batch.drop_constraint(op.f("ck_outbox_events_event_or_test"), type_="check")
        batch.alter_column("detection_event_id", existing_type=sa.Integer(), nullable=False)
        batch.drop_column("is_test")
