"""Durable alerting: alert_destinations and the outbox_events transactional outbox.

Revision ID: 20261113_03
Revises: 20261113_02
Create Date: 2026-11-13 18:00:00.000000+00:00

New tables only; nothing touches evidence rows. outbox_events references detection_events
without ON DELETE (evidence is never deleted, so the reference cannot dangle).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_03"
down_revision: Union[str, None] = "20261113_02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "alert_destinations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=40), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("min_severity", sa.String(length=50), nullable=False),
        sa.Column("key_salt", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_alert_destinations_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], name=op.f("fk_alert_destinations_project_id_projects")),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"],
                                name=op.f("fk_alert_destinations_created_by_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_destinations")),
        sa.UniqueConstraint("public_id", name=op.f("uq_alert_destinations_public_id")),
    )
    op.create_index(op.f("ix_alert_destinations_tenant_id"), "alert_destinations", ["tenant_id"])

    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("detection_event_id", sa.Integer(), nullable=False),
        sa.Column("destination_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_outbox_events_tenant_id_tenants")),
        sa.ForeignKeyConstraint(["detection_event_id"], ["detection_events.id"],
                                name=op.f("fk_outbox_events_detection_event_id_detection_events")),
        sa.ForeignKeyConstraint(["destination_id"], ["alert_destinations.id"],
                                name=op.f("fk_outbox_events_destination_id_alert_destinations")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbox_events")),
        sa.UniqueConstraint("detection_event_id", "destination_id", name=op.f("uq_outbox_events_detection_event_id")),
        sa.CheckConstraint("status IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'DEAD')",
                           name=op.f("ck_outbox_events_valid_status")),
    )
    op.create_index(op.f("ix_outbox_events_tenant_id"), "outbox_events", ["tenant_id"])
    op.create_index("ix_outbox_events_status_next_attempt_at", "outbox_events", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_outbox_events_status_next_attempt_at", table_name="outbox_events")
    op.drop_index(op.f("ix_outbox_events_tenant_id"), table_name="outbox_events")
    op.drop_table("outbox_events")
    op.drop_index(op.f("ix_alert_destinations_tenant_id"), table_name="alert_destinations")
    op.drop_table("alert_destinations")
