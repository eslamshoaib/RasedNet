"""must change password flag

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('must_change_password', sa.Boolean(), nullable=False, server_default=sa.false())
        )
    # Drop the server default now that existing rows are backfilled; the ORM sets the value.
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('must_change_password', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('must_change_password')
