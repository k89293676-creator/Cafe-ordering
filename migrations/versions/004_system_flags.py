"""Add system_flags table for global runtime toggles (maintenance mode, etc.).

Revision ID: 004_system_flags
Revises: 003_scaling_idx
Create Date: 2026-04-23
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "004_system_flags"
down_revision = "003_scaling_idx"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def upgrade() -> None:
    if _has_table("system_flags"):
        return
    op.create_table(
        "system_flags",
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("value", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    if _has_table("system_flags"):
        op.drop_table("system_flags")
