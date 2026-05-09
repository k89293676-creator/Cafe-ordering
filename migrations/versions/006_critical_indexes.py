"""Add critical missing indexes for query performance — Issue #3.

Revision ID: 006_critical_idx
Revises: 005_refactor_tables
Create Date: 2026-05-09

Indexes that were absent from models and earlier migrations but are hit
on every dashboard load, order-status poll, and customer lookup.
All operations are idempotent — safe to re-run.

Fix applied: _create_index now checks for column existence before attempting
to create an index, preventing PostgreSQL errors when columns don't yet
exist (e.g. webhook_events.status / next_attempt_at added in migration 007).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006_critical_idx"
down_revision = "005_refactor_tables"
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


def _has_columns(table: str, cols: list[str]) -> bool:
    """Return True only when ALL *cols* exist on *table*."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if not insp.has_table(table):
        return False
    existing = {c["name"] for c in insp.get_columns(table)}
    return all(c in existing for c in cols)


def _create_index(name: str, table: str, cols: list[str], unique: bool = False) -> None:
    """Create an index only when the table AND all columns exist."""
    if not _has_table(table):
        return
    if not _has_columns(table, cols):
        # Columns added by a later migration — that migration creates the index.
        return
    if _has_index(table, name):
        return
    op.create_index(name, table, cols, unique=unique)


def _drop_index(name: str, table: str) -> None:
    if not _has_table(table):
        return
    if not _has_index(table, name):
        return
    op.drop_index(name, table_name=table)


def upgrade() -> None:
    # orders.created_at — dashboard "last N orders" sorts by this
    _create_index("ix_orders_created_at", "orders", ["created_at"])

    # orders.status — kitchen view filters by status constantly
    _create_index("ix_orders_status", "orders", ["status"])

    # orders.table_id — customer order lookup by table
    _create_index("ix_orders_table_id", "orders", ["table_id"])

    # orders.customer_email — loyalty / dedup lookups
    _create_index("ix_orders_customer_email", "orders", ["customer_email"])

    # orders (owner_id, created_at) — per-owner time-series analytics
    _create_index("ix_orders_owner_created", "orders", ["owner_id", "created_at"])

    # orders (owner_id, payment_status) — billing reconciliation
    _create_index(
        "ix_orders_owner_payment_status",
        "orders",
        ["owner_id", "payment_status"],
    )

    # online_payments (provider, status) — reconciliation pipeline
    _create_index(
        "ix_online_payments_provider_status",
        "online_payments",
        ["provider", "status"],
    )

    # online_payments.created_at — time-range reconciliation queries
    _create_index("ix_online_payments_created_at", "online_payments", ["created_at"])

    # ingredients (owner_id, menu_item_id) — stock check on every order
    # NOTE: skipped gracefully if ingredients.menu_item_id doesn't exist yet
    _create_index(
        "ix_ingredients_owner_menu_item",
        "ingredients",
        ["owner_id", "menu_item_id"],
    )

    # customers email + phone — dedup on order placement
    _create_index("ix_customers_email", "customers", ["email"])
    _create_index("ix_customers_phone", "customers", ["phone"])

    # audit_log owner_id + created_at — security event timeline
    _create_index("ix_audit_log_owner_created", "audit_log", ["owner_id", "created_at"])

    # webhook_events (status, next_attempt_at) — retry worker hot path.
    # These columns are added in migration 007; _create_index skips safely
    # when they don't exist yet and migration 007 creates the index itself.
    _create_index(
        "ix_webhook_events_status_next",
        "webhook_events",
        ["status", "next_attempt_at"],
    )


def downgrade() -> None:
    for name, table in [
        ("ix_webhook_events_status_next", "webhook_events"),
        ("ix_audit_log_owner_created", "audit_log"),
        ("ix_customers_phone", "customers"),
        ("ix_customers_email", "customers"),
        ("ix_ingredients_owner_menu_item", "ingredients"),
        ("ix_online_payments_created_at", "online_payments"),
        ("ix_online_payments_provider_status", "online_payments"),
        ("ix_orders_owner_payment_status", "orders"),
        ("ix_orders_owner_created", "orders"),
        ("ix_orders_customer_email", "orders"),
        ("ix_orders_table_id", "orders"),
        ("ix_orders_status", "orders"),
        ("ix_orders_created_at", "orders"),
    ]:
        _drop_index(name, table)
