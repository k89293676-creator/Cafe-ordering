"""Add currency field to Owner model.

Revision ID: 008_owner_currency
Revises: 007_webhook_events_cols
Create Date: 2026-07-02

Adds:
  owners.currency   TEXT DEFAULT 'gbp'  -- per-owner currency code (ISO 4217 lower)
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "008_owner_currency"
down_revision = "007_webhook_events_cols"
branch_labels = None
depends_on = None


def _has_column(table: str, col: str) -> bool:
    return col in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("owners", "currency"):
        op.add_column(
            "owners",
            sa.Column(
                "currency",
                sa.String(10),
                nullable=False,
                server_default="gbp",
            ),
        )


def downgrade() -> None:
    if _has_column("owners", "currency"):
        op.drop_column("owners", "currency")
