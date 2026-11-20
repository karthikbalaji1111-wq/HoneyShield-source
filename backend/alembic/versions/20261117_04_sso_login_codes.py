"""One-time SSO login codes.

Revision ID: 20261117_04
Revises: 20261117_03
Create Date: 2026-11-17 17:00:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261117_04"
down_revision: Union[str, None] = "20261117_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sso_login_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("amr", sa.String(length=10), nullable=False),
        sa.Column("auth_time", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_sso_login_codes_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_login_codes")),
        sa.UniqueConstraint("code_hash", name=op.f("uq_sso_login_codes_code_hash")),
    )


def downgrade() -> None:
    op.drop_table("sso_login_codes")
