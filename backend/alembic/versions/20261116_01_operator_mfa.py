"""Operator MFA columns on users.

Revision ID: 20261116_01
Revises: 20261113_06
Create Date: 2026-11-16 00:00:00.000000+00:00

Adds TOTP enrolment state. The TOTP secret itself is never stored (derived from MFA_SECRET_KEY,
the user id and ``mfa_nonce``); recovery codes are stored only as keyed hashes. Existing users
start with MFA disabled; roles in MFA_REQUIRED_ROLES are forced to enrol at their next login.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "20261116_01"
down_revision: Union[str, None] = "20261113_06"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        batch.add_column(sa.Column("mfa_nonce", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("mfa_recovery_hashes", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_check_constraint("mfa_enabled_has_nonce", "(NOT mfa_enabled) OR mfa_nonce IS NOT NULL")


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("mfa_enabled_has_nonce", type_="check")
        batch.drop_column("mfa_enabled_at")
        batch.drop_column("mfa_recovery_hashes")
        batch.drop_column("mfa_last_step")
        batch.drop_column("mfa_nonce")
        batch.drop_column("mfa_enabled")
