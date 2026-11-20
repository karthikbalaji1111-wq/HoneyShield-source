"""Exact per-tenant, per-UTC-day, per-severity event totals (O(days) activity chart).

Revision ID: 20261118_03
Revises: 20261118_02
Create Date: 2026-11-18 05:00:00.000000+00:00

The console's 14-day activity chart counted events on every load: 0.8 s for a 5M-event tenant and
4.0 s for a system administrator at 10M events. Statement-level triggers (the same design as
tenant_event_counts) keep these totals exact for every insert and delete, whatever the source;
the SECURITY DEFINER function lets the runtime role read them but never edit them.

Online: the triggers are created in one short transaction, then existing events are counted by
ONE INSERT ... SELECT (a single consistent snapshot) in its own transaction, so decoy-hit inserts
are never blocked for the duration of the count. Rows inserted after the triggers exist are counted
by the triggers (the backfill covers id <= the high-water mark taken while trigger creation held
its lock). A retention purge that deletes an old event in the milliseconds between the two
transactions would leave that day one too low; purges only touch events past the retention period
(>= 30 days) and the restore drill checks the totals against the events.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261118_03"
down_revision: Union[str, None] = "20261118_02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FUNCTION = """
CREATE OR REPLACE FUNCTION hs_maintain_tenant_daily_counts() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO tenant_daily_event_counts AS c (tenant_id, day, severity, total)
        SELECT n.tenant_id, (n.triggered_at AT TIME ZONE 'UTC')::date, n.severity, count(*)
          FROM new_rows n WHERE n.tenant_id IS NOT NULL
         GROUP BY 1, 2, 3
        ON CONFLICT (tenant_id, day, severity) DO UPDATE SET total = c.total + EXCLUDED.total;
    ELSE
        UPDATE tenant_daily_event_counts c SET total = c.total - d.n
          FROM (SELECT o.tenant_id, (o.triggered_at AT TIME ZONE 'UTC')::date AS day, o.severity, count(*) AS n
                  FROM old_rows o WHERE o.tenant_id IS NOT NULL GROUP BY 1, 2, 3) d
         WHERE c.tenant_id = d.tenant_id AND c.day = d.day AND c.severity = d.severity;
    END IF;
    RETURN NULL;
END;
$$;
"""


def upgrade() -> None:
    op.create_table(
        "tenant_daily_event_counts",
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"],
                                name=op.f("fk_tenant_daily_event_counts_tenant_id_tenants")),
        sa.PrimaryKeyConstraint("tenant_id", "day", "severity", name=op.f("pk_tenant_daily_event_counts")),
    )
    op.create_index(op.f("ix_tenant_daily_event_counts_day"), "tenant_daily_event_counts", ["day"])
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(_FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION hs_maintain_tenant_daily_counts() FROM PUBLIC")
    op.execute("CREATE TRIGGER trg_detection_events_daily_ins AFTER INSERT ON detection_events "
               "REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION hs_maintain_tenant_daily_counts()")
    op.execute("CREATE TRIGGER trg_detection_events_daily_del AFTER DELETE ON detection_events "
               "REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION hs_maintain_tenant_daily_counts()")
    # CREATE TRIGGER waited for in-flight inserts and blocks new ones until this transaction
    # commits: every row now present is <= the high-water mark; later rows are counted by trigger.
    bind = op.get_bind()
    high_water = bind.execute(sa.text("SELECT coalesce(max(id), 0) FROM detection_events")).scalar_one()
    with op.get_context().autocommit_block():
        bind.execute(sa.text("""
            INSERT INTO tenant_daily_event_counts AS c (tenant_id, day, severity, total)
            SELECT e.tenant_id, (e.triggered_at AT TIME ZONE 'UTC')::date, e.severity, count(*)
              FROM detection_events e
             WHERE e.id <= :hw AND e.tenant_id IS NOT NULL
             GROUP BY 1, 2, 3
            ON CONFLICT (tenant_id, day, severity) DO UPDATE SET total = c.total + EXCLUDED.total"""),
            {"hw": high_water})


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_detection_events_daily_del ON detection_events")
        op.execute("DROP TRIGGER IF EXISTS trg_detection_events_daily_ins ON detection_events")
        op.execute("DROP FUNCTION IF EXISTS hs_maintain_tenant_daily_counts()")
    op.drop_index(op.f("ix_tenant_daily_event_counts_day"), table_name="tenant_daily_event_counts")
    op.drop_table("tenant_daily_event_counts")
