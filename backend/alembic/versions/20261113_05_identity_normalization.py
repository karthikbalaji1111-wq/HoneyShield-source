"""Case-insensitive identities and normalised project domains (HONEY-022/024).

Revision ID: 20261113_05
Revises: 20261113_04
Create Date: 2026-11-13 23:00:00.000000+00:00

* users.email is lower-cased and a UNIQUE index on lower(email) is added. If two existing
  accounts differ only by case, the migration STOPS with an explicit error instead of
  silently merging or renaming identities: an operator must decide which account survives.
* projects.domain is lower-cased (with the same stop-on-collision rule per tenant).
users and projects are mutable application state, not evidence, so the UPDATEs are allowed.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261113_05"
down_revision: Union[str, None] = "20261113_04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dupes = bind.execute(sa.text(
        "SELECT lower(email) FROM users GROUP BY lower(email) HAVING count(*) > 1")).scalars().all()
    if dupes:
        raise RuntimeError(
            f"{len(dupes)} email address(es) exist in several letter cases. Resolve them manually "
            "(deactivate or rename the duplicate accounts) before running this migration.")
    domain_dupes = bind.execute(sa.text(
        "SELECT tenant_id, lower(domain) FROM projects GROUP BY tenant_id, lower(domain) HAVING count(*) > 1")).all()
    if domain_dupes:
        raise RuntimeError(f"{len(domain_dupes)} project domain(s) collide case-insensitively within a tenant.")
    op.execute("UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email))")
    op.execute("UPDATE projects SET domain = lower(domain) WHERE domain <> lower(domain)")
    if bind.dialect.name == "postgresql":
        op.execute("CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email))")
        op.execute("ALTER TABLE users ADD CONSTRAINT ck_users_email_lowercase CHECK (email = lower(email))")
        op.execute("ALTER TABLE projects ADD CONSTRAINT ck_projects_domain_lowercase CHECK (domain = lower(domain))")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE projects DROP CONSTRAINT IF EXISTS ck_projects_domain_lowercase")
        op.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS ck_users_email_lowercase")
        op.execute("DROP INDEX IF EXISTS uq_users_email_lower")
    # Lower-casing is not reversed: the original letter case was not identity-significant.
