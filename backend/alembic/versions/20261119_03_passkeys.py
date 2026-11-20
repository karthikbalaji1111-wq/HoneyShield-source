"""Passkeys (WebAuthn) as a phishing-resistant second factor.

Revision ID: 20261119_03
Revises: 20261119_02
Create Date: 2026-11-19 18:30:00.000000+00:00

Two new tables and one new column with a constant default (``users.passkey_enabled``). On
PostgreSQL 11+ adding a column with a constant default is a catalog-only change: no table rewrite
and only a brief lock.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261119_03"
down_revision: Union[str, None] = "20261119_02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.add_column("users", sa.Column("passkey_enabled", sa.Boolean(), nullable=False,
                                     server_default=sa.text("false")))
    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.String(length=1400), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("alg", sa.Integer(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("transports", sa.JSON(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE",
                                name=op.f("fk_passkey_credentials_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_passkey_credentials")),
        sa.UniqueConstraint("credential_id", name=op.f("uq_passkey_credentials_credential_id")),
    )
    op.create_index(op.f("ix_passkey_credentials_user_id"), "passkey_credentials", ["user_id"])
    op.create_table(
        "passkey_challenges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("challenge", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint("purpose IN ('register', 'login')", name=op.f("ck_passkey_challenges_purpose_valid")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE",
                                name=op.f("fk_passkey_challenges_user_id_users")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_passkey_challenges")),
        sa.UniqueConstraint("public_id", name=op.f("uq_passkey_challenges_public_id")),
    )
    op.create_index("ix_passkey_challenges_expires_at", "passkey_challenges", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_passkey_challenges_expires_at", table_name="passkey_challenges")
    op.drop_table("passkey_challenges")
    op.drop_index(op.f("ix_passkey_credentials_user_id"), table_name="passkey_credentials")
    op.drop_table("passkey_credentials")
    op.drop_column("users", "passkey_enabled")
