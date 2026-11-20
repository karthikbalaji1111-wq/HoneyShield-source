"""Composite (triggered_at, id) index for event listing and keyset pagination.

Revision ID: 20261117_06
Revises: 20261117_05
Create Date: 2026-11-17 23:00:00.000000+00:00

Listing orders by (triggered_at DESC, id DESC) and the cursor now continues after the anchor
event's (triggered_at, id). The composite index serves both; it replaces the single-column
triggered_at index (anything that used that one can use the composite's leading column).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "20261117_06"
down_revision: Union[str, None] = "20261117_05"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_detection_events_triggered_at_id", "detection_events", ["triggered_at", "id"])
    op.drop_index("ix_detection_events_triggered_at", table_name="detection_events")


def downgrade() -> None:
    op.create_index("ix_detection_events_triggered_at", "detection_events", ["triggered_at"])
    op.drop_index("ix_detection_events_triggered_at_id", table_name="detection_events")
