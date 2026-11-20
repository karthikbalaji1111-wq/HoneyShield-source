"""Denormalised detection_events.tenant_id with a (tenant_id, triggered_at, id) index.

Revision ID: 20261118_02
Revises: 20261118_01
Create Date: 2026-11-18 05:00:00.000000+00:00

Tenant-scoped listing, export, statistics and analytics joined events -> decoys -> projects, so
PostgreSQL could not use a time-ordered index (26-80 s for a 5M-event tenant). The column is
filled by a BEFORE INSERT trigger from the decoy's project - authoritative, so it cannot be
spoofed or forgotten by any insert path. It is not part of the evidence hash.

Online: the immutability trigger gains one narrow exception (fill a NULL tenant_id with the value
derived from the decoy, every other field identical), so the backfill needs no table lock. It runs
in fixed primary-key batches of 20,000, each its own short transaction. The index is built
CONCURRENTLY and the foreign key is added NOT VALID then validated. Decoy-hit inserts keep
flowing throughout. VACUUM ANALYZE afterwards.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261118_02"
down_revision: Union[str, None] = "20261118_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FILL = """
CREATE OR REPLACE FUNCTION hs_detection_event_tenant() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.tenant_id := (SELECT p.tenant_id FROM honey_tokens t JOIN projects p ON p.id = t.project_id
                      WHERE t.id = NEW.honey_token_id);
    RETURN NEW;
END;
$$;
"""

# Immutability (as in 20261117_02) plus ONE narrow exception on detection_events: an UPDATE that
# only fills a missing tenant_id with the tenant derived from the decoy (every other field
# identical). The runtime role has no UPDATE privilege at all; this exists so the backfill below
# needs no table lock (DISABLE TRIGGER would block decoy-hit inserts).
_IMMUTABLE_WITH_FILL = """
CREATE OR REPLACE FUNCTION prevent_forensic_modification()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('honeyshield.retention_purge', true) = 'on'
       AND current_user = (SELECT tableowner FROM pg_tables
                           WHERE schemaname = TG_TABLE_SCHEMA AND tablename = TG_TABLE_NAME) THEN
        RETURN OLD;  -- audited retention purge by the schema owner (app.services.retention)
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'detection_events' THEN
        IF OLD.tenant_id IS NULL AND NEW.tenant_id IS NOT NULL
           AND (to_jsonb(OLD) - 'tenant_id') = (to_jsonb(NEW) - 'tenant_id')
           AND NEW.tenant_id = (SELECT p.tenant_id FROM honey_tokens t JOIN projects p ON p.id = t.project_id
                                WHERE t.id = NEW.honey_token_id) THEN
            RETURN NEW;  -- one-time fill of the derived tenant column (migration 20261118_02)
        END IF;
    END IF;
    RAISE EXCEPTION 'Forensic records are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;
"""

_IMMUTABLE_PREVIOUS = """
CREATE OR REPLACE FUNCTION prevent_forensic_modification()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('honeyshield.retention_purge', true) = 'on'
       AND current_user = (SELECT tableowner FROM pg_tables
                           WHERE schemaname = TG_TABLE_SCHEMA AND tablename = TG_TABLE_NAME) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'Forensic records are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;
"""

# Counters can now use the column directly (no join per statement).
_COUNTS = """
CREATE OR REPLACE FUNCTION hs_maintain_tenant_event_counts() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO tenant_event_counts AS c (tenant_id, total)
        SELECT n.tenant_id, count(*) FROM new_rows n WHERE n.tenant_id IS NOT NULL GROUP BY n.tenant_id
        ON CONFLICT (tenant_id) DO UPDATE SET total = c.total + EXCLUDED.total;
    ELSE
        UPDATE tenant_event_counts c SET total = c.total - d.n
          FROM (SELECT o.tenant_id, count(*) AS n FROM old_rows o WHERE o.tenant_id IS NOT NULL
                 GROUP BY o.tenant_id) d
         WHERE c.tenant_id = d.tenant_id;
    END IF;
    RETURN NULL;
END;
$$;
"""


BATCH = 20_000


def upgrade() -> None:
    op.add_column("detection_events", sa.Column("tenant_id", sa.Integer(), nullable=True))
    if op.get_bind().dialect.name != "postgresql":
        op.create_foreign_key(op.f("fk_detection_events_tenant_id_tenants"), "detection_events", "tenants",
                              ["tenant_id"], ["id"])
        op.create_index("ix_detection_events_tenant_id_triggered_at_id", "detection_events",
                        ["tenant_id", "triggered_at", "id"])
        return
    # New rows get tenant_id from now on (committed with the column at the end of this block).
    op.execute(_FILL)
    op.execute("CREATE TRIGGER trg_detection_events_tenant BEFORE INSERT ON detection_events "
               "FOR EACH ROW EXECUTE FUNCTION hs_detection_event_tenant()")
    op.execute(_COUNTS)
    # Online from here: no long lock on detection_events, so decoy hits keep being recorded while
    # this runs (one big UPDATE + CREATE INDEX blocked inserts for ~7 min per 10M events).
    op.execute(_IMMUTABLE_WITH_FILL)
    with op.get_context().autocommit_block():
        bind = op.get_bind()
        lo, hi = bind.execute(sa.text("SELECT min(id), max(id) FROM detection_events")).one()
        if lo is not None:
            # Fixed primary-key ranges: every batch costs the same; row locks only.
            for start in range(lo, hi + 1, BATCH):
                bind.execute(sa.text("""
                    UPDATE detection_events e SET tenant_id = p.tenant_id
                      FROM honey_tokens t JOIN projects p ON p.id = t.project_id
                     WHERE t.id = e.honey_token_id AND e.id >= :a AND e.id < :b AND e.tenant_id IS NULL"""),
                    {"a": start, "b": start + BATCH})
        bind.execute(sa.text("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_detection_events_tenant_id_triggered_at_id "
                             "ON detection_events (tenant_id, triggered_at, id)"))
        bind.execute(sa.text("ALTER TABLE detection_events ADD CONSTRAINT fk_detection_events_tenant_id_tenants "
                             "FOREIGN KEY (tenant_id) REFERENCES tenants (id) NOT VALID"))
        bind.execute(sa.text("ALTER TABLE detection_events VALIDATE CONSTRAINT fk_detection_events_tenant_id_tenants"))


def downgrade() -> None:
    op.drop_index("ix_detection_events_tenant_id_triggered_at_id", table_name="detection_events")
    op.drop_constraint(op.f("fk_detection_events_tenant_id_tenants"), "detection_events", type_="foreignkey")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_IMMUTABLE_PREVIOUS)
        op.execute("DROP TRIGGER IF EXISTS trg_detection_events_tenant ON detection_events")
        op.execute("DROP FUNCTION IF EXISTS hs_detection_event_tenant()")
        op.execute("""
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
$$;""")
    op.drop_column("detection_events", "tenant_id")
