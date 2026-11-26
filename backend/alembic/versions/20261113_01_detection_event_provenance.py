"""Record detection-event provenance.

Revision ID: 20261113_01
Revises: 20261019_01
Create Date: 2026-11-13 00:00:00.000000+00:00

Adds ``detection_events.source`` and ``detection_events.created_by_user_id``.

Forensic-safety notes
- detection_events carries BEFORE UPDATE/DELETE immutability triggers. Nothing here
  updates rows: on PostgreSQL 11+ ``ADD COLUMN ... NOT NULL DEFAULT <constant>`` is a
  catalog-only change, so existing rows read the default without any UPDATE and the
  triggers do not fire.
- Existing rows are labelled LEGACY_UNVERIFIED because their origin (public trigger or
  manual API entry) was never recorded and cannot be reconstructed. They are NOT
  relabelled PUBLIC_INGEST.
- The default is dropped afterwards so every new insert must state its source.
- created_by_user_id has no ON DELETE action: SET NULL would be an UPDATE rejected by
  the immutability trigger.
- Both CHECK constraints are added NOT VALID and then validated, so validation scans
  without blocking writes for the whole scan on large tables.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20261113_01"
down_revision: Union[str, None] = "20261019_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCES = "('PUBLIC_INGEST', 'MANUAL', 'CUSTOMER_HOOK', 'LEGACY_UNVERIFIED')"


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    op.add_column(
        "detection_events",
        sa.Column("source", sa.String(length=32), nullable=False, server_default="LEGACY_UNVERIFIED"),
    )
    op.add_column("detection_events", sa.Column("created_by_user_id", sa.Integer(), nullable=True))

    if is_pg:
        op.alter_column("detection_events", "source", server_default=None)
        op.create_foreign_key(
            op.f("fk_detection_events_created_by_user_id_users"),
            "detection_events", "users", ["created_by_user_id"], ["id"],
        )
        op.execute(
            "ALTER TABLE detection_events ADD CONSTRAINT ck_detection_events_valid_event_source "
            f"CHECK (source IN {_SOURCES}) NOT VALID"
        )
        op.execute(
            "ALTER TABLE detection_events ADD CONSTRAINT ck_detection_events_manual_event_has_creator "
            "CHECK (source <> 'MANUAL' OR created_by_user_id IS NOT NULL) NOT VALID"
        )
        op.execute("ALTER TABLE detection_events VALIDATE CONSTRAINT ck_detection_events_valid_event_source")
        op.execute("ALTER TABLE detection_events VALIDATE CONSTRAINT ck_detection_events_manual_event_has_creator")
    else:
        # SQLite cannot alter defaults or add constraints in place; batch mode would
        # rebuild the table, which the forensic triggers forbid. Development-only path.
        pass

    op.create_index(op.f("ix_detection_events_source"), "detection_events", ["source"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index(op.f("ix_detection_events_source"), table_name="detection_events")
    if bind.dialect.name == "postgresql":
        # op.f() marks these as final names; a plain string would be re-prefixed by the
        # naming convention ("ck_detection_events_ck_detection_events_...") and not match.
        op.drop_constraint(op.f("ck_detection_events_manual_event_has_creator"), "detection_events", type_="check")
        op.drop_constraint(op.f("ck_detection_events_valid_event_source"), "detection_events", type_="check")
        op.drop_constraint(
            op.f("fk_detection_events_created_by_user_id_users"), "detection_events", type_="foreignkey"
        )
    # Dropping columns is DDL, not UPDATE/DELETE, so the immutability triggers do not block it.
    # It does discard provenance permanently; take a backup first.
    op.drop_column("detection_events", "created_by_user_id")
    op.drop_column("detection_events", "source")
