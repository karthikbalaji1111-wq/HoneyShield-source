"""Audit-log foreign keys: ON DELETE SET NULL -> no action.

Revision ID: 20261113_06
Revises: 20261113_05
Create Date: 2026-11-14 00:00:00.000000+00:00

SET NULL is an UPDATE of audit_logs, which the immutability trigger rejects, so a hard DELETE
of a referenced tenant/project/user failed with a misleading trigger error. With no action
the database refuses the delete with a plain foreign-key violation. HoneyShield never hard
deletes these rows (tenants, projects and users are deactivated), so behaviour is unchanged.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "20261113_06"
down_revision: Union[str, None] = "20261113_05"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FKS = (
    ("fk_audit_logs_tenant_id_tenants", "tenant_id", "tenants"),
    ("fk_audit_logs_project_id_projects", "project_id", "projects"),
    ("fk_audit_logs_actor_user_id_users", "actor_user_id", "users"),
)


def _recreate(ondelete: str | None) -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for name, column, table in _FKS:
        op.execute(f"ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS {name}")
        op.create_foreign_key(op.f(name), "audit_logs", table, [column], ["id"], ondelete=ondelete)


def upgrade() -> None:
    _recreate(None)


def downgrade() -> None:
    _recreate("SET NULL")
