"""Exact per-tenant event totals maintained by the database (O(1) statistics).

Revision ID: 20261118_01
Revises: 20261117_07
Create Date: 2026-11-18 03:00:00.000000+00:00

Counting millions of events on every dashboard load took 6-47 s at 10M events. Statement-level
triggers keep tenant_event_counts exact for every insert and delete, whatever their source
(application, bulk retention purge, direct SQL). The trigger function is SECURITY DEFINER (owned
by the schema owner) so the runtime role can read the totals but never edit them.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261118_01"
down_revision: Union[str, None] = "20261117_07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FUNCTION = """
CREATE OR REPLACE FUNCTION hs_maintain_tenant_event_counts() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO tenant_event_counts AS c (tenant_id, total)
        SELECT p.tenant_id, count(*) FROM new_rows n
          JOIN honey_tokens t ON t.id = n.honey_token_id JOIN projects p ON p.id = t.project_id
         GROUP BY p.tenant_id
        ON CONFLICT (tenant_id) DO UPDATE SET total = c.total + EXCLUDED.total;
    ELSE
        UPDATE tenant_event_counts c SET total = c.total - d.n
          FROM (SELECT p.tenant_id, count(*) AS n FROM old_rows o
                  JOIN honey_tokens t ON t.id = o.honey_token_id JOIN projects p ON p.id = t.project_id
                 GROUP BY p.tenant_id) d
         WHERE c.tenant_id = d.tenant_id;
    END IF;
    RETURN NULL;
END;
$$;
"""


def upgrade() -> None:
    op.create_table(
        "tenant_event_counts",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name=op.f("fk_tenant_event_counts_tenant_id_tenants")),
        sa.PrimaryKeyConstraint("tenant_id", name=op.f("pk_tenant_event_counts")),
    )
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(_FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION hs_maintain_tenant_event_counts() FROM PUBLIC")
    op.execute("CREATE TRIGGER trg_detection_events_count_ins AFTER INSERT ON detection_events "
               "REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION hs_maintain_tenant_event_counts()")
    op.execute("CREATE TRIGGER trg_detection_events_count_del AFTER DELETE ON detection_events "
               "REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION hs_maintain_tenant_event_counts()")
    # Backfill once (same statement as the triggers use).
    op.execute("""
        INSERT INTO tenant_event_counts (tenant_id, total)
        SELECT p.tenant_id, count(*) FROM detection_events e
          JOIN honey_tokens t ON t.id = e.honey_token_id JOIN projects p ON p.id = t.project_id
         GROUP BY p.tenant_id
    """)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_detection_events_count_del ON detection_events")
        op.execute("DROP TRIGGER IF EXISTS trg_detection_events_count_ins ON detection_events")
        op.execute("DROP FUNCTION IF EXISTS hs_maintain_tenant_event_counts()")
    op.drop_table("tenant_event_counts")
