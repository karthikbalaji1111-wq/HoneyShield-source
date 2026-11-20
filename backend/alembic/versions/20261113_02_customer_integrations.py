"""Customer integrations: credentials, decoy ids and CUSTOMER_HOOK provenance.

Revision ID: 20261113_02
Revises: 20261113_01
Create Date: 2026-11-13 12:00:00.000000+00:00

* integration_credentials: per-project report-only credentials. No secret column: secrets
  are derived from INTEGRATION_SIGNING_KEY and never stored.
* honey_tokens.decoy_id: opaque public identifier; existing tokens are backfilled
  (honey_tokens is mutable state, not evidence, so the UPDATE is permitted).
* detection_events.integration_credential_id / idempotency_key: catalog-only nullable
  column additions (no row rewrite, immutability triggers do not fire), a unique pair for
  idempotent reports, and a CHECK that CUSTOMER_HOOK rows carry both.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_02"
down_revision: Union[str, None] = "20261113_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    is_pg = op.get_bind().dialect.name == "postgresql"

    op.create_table(
        "integration_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=40), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("key_salt", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"],
                                name=op.f("fk_integration_credentials_project_id_projects")),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"],
                                name=op.f("fk_integration_credentials_created_by_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_credentials")),
        sa.UniqueConstraint("public_id", name=op.f("uq_integration_credentials_public_id")),
    )
    op.create_index(op.f("ix_integration_credentials_project_id"), "integration_credentials", ["project_id"])

    op.add_column("honey_tokens", sa.Column("decoy_id", sa.String(length=40), nullable=True))
    if is_pg:
        op.execute("UPDATE honey_tokens SET decoy_id = 'dcy_' || substr(md5(random()::text || id::text || "
                   "clock_timestamp()::text), 1, 24) WHERE decoy_id IS NULL")
        op.alter_column("honey_tokens", "decoy_id", nullable=False, server_default=sa.text(
            "'dcy_' || substr(md5(random()::text || clock_timestamp()::text), 1, 24)"))
        op.create_unique_constraint(op.f("uq_honey_tokens_decoy_id"), "honey_tokens", ["decoy_id"])

    op.add_column("detection_events", sa.Column("integration_credential_id", sa.Integer(), nullable=True))
    op.add_column("detection_events", sa.Column("idempotency_key", sa.String(length=64), nullable=True))
    if is_pg:
        op.create_foreign_key(
            op.f("fk_detection_events_integration_credential_id_integration_credentials"),
            "detection_events", "integration_credentials", ["integration_credential_id"], ["id"],
        )
        op.create_unique_constraint(
            op.f("uq_detection_events_integration_credential_id"), "detection_events",
            ["integration_credential_id", "idempotency_key"],
        )
        op.execute(
            "ALTER TABLE detection_events ADD CONSTRAINT ck_detection_events_hook_event_has_integration "
            "CHECK (source <> 'CUSTOMER_HOOK' OR (integration_credential_id IS NOT NULL "
            "AND idempotency_key IS NOT NULL)) NOT VALID"
        )
        op.execute("ALTER TABLE detection_events VALIDATE CONSTRAINT ck_detection_events_hook_event_has_integration")


def downgrade() -> None:
    is_pg = op.get_bind().dialect.name == "postgresql"
    if is_pg:
        op.drop_constraint(op.f("ck_detection_events_hook_event_has_integration"), "detection_events", type_="check")
        op.drop_constraint(op.f("uq_detection_events_integration_credential_id"), "detection_events", type_="unique")
        op.drop_constraint(op.f("fk_detection_events_integration_credential_id_integration_credentials"),
                           "detection_events", type_="foreignkey")
        op.drop_constraint(op.f("uq_honey_tokens_decoy_id"), "honey_tokens", type_="unique")
    # Column drops are DDL; triggers do not block them. CUSTOMER_HOOK attribution is lost.
    op.drop_column("detection_events", "idempotency_key")
    op.drop_column("detection_events", "integration_credential_id")
    op.drop_column("honey_tokens", "decoy_id")
    op.drop_index(op.f("ix_integration_credentials_project_id"), table_name="integration_credentials")
    op.drop_table("integration_credentials")
