"""Add scaling indexes for orders / feedback / cafe_tables.

Revision ID: 003_scaling_idx
Revises: 002_ext_idx
Create Date: 2026-04-23

Composite + per-tenant indexes that support the dashboard and per-owner
queries hit on every page load. All operations are idempotent so the
migration is safe to re-run.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "003_scaling_idx"
down_revision = "002_ext_idx"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return sa.inspect(bind).has_table(name)


def _has_index(table: str, name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table(table):
        return False
    return any(ix["name"] == name for ix in insp.get_indexes(table))


def _create_index(name: str, table: str, cols: list[str]) -> None:
    if not _has_table(table):
        return
    if _has_index(table, name):
        return
    op.create_index(name, table, cols)


def _drop_index(name: str, table: str) -> None:
    if not _has_table(table):
        return
    if not _has_index(table, name):
        return
    op.drop_index(name, table_name=table)


def upgrade() -> None:
    # Hot path: superadmin + owner dashboards filter orders by owner, status,
    # and recent created_at. A composite index lets Postgres serve those
    # queries without a sequential scan as the orders table grows.
    _create_index(
        "ix_orders_owner_status_created",
        "orders",
        ["owner_id", "status", "created_at"],
    )

    # Per-owner feedback listings.
    _create_index("ix_feedback_owner", "feedback", ["owner_id"])

    # Per-owner table listings (cached on every order).
    _create_index("ix_cafe_tables_owner", "cafe_tables", ["owner_id"])


def downgrade() -> None:
    _drop_index("ix_cafe_tables_owner", "cafe_tables")
    _drop_index("ix_feedback_owner", "feedback")
    _drop_index("ix_orders_owner_status_created", "orders")
