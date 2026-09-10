"""Create tables missing from earlier migrations (idempotent).

Revision ID: 009_missing_tables
Revises: 008_owner_currency
Create Date: 2026-09-10

Covers models that have no migration yet:
  admin_keys            (app.models.auth.AdminKey)
  loyalty_accounts      (app.models.pos.LoyaltyAccount)
  loyalty_transactions  (app.models.pos.LoyaltyTransaction)
  suppliers             (app.models.pos.Supplier)
  purchase_orders       (app.models.pos.PurchaseOrder)
  purchase_order_items  (app.models.pos.PurchaseOrderItem)
  table_calls           (app.models.staff.TableCall — also created by
                         002_ext_idx; guarded so re-running is safe)

Every create is guarded by _has_table() and every index by _has_index(),
so this migration is a no-op on databases where the tables already exist
(e.g. via db.create_all()).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "009_missing_tables"
down_revision = "008_owner_currency"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_index(table: str, name: str) -> bool:
    insp = sa.inspect(op.get_bind())
    if not insp.has_table(table):
        return False
    return any(ix["name"] == name for ix in insp.get_indexes(table))


def _mk_index(name: str, table: str, cols: list[str]) -> None:
    if not _has_index(table, name):
        op.create_index(name, table, cols)


def upgrade() -> None:
    # ── admin_keys ────────────────────────────────────────────────────
    if not _has_table("admin_keys"):
        op.create_table(
            "admin_keys",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      unique=True, nullable=False),
            sa.Column("username", sa.Text, server_default=""),
            sa.Column("key_hash", sa.Text, nullable=False),
            sa.Column("generated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now()),
        )
        _mk_index("ix_admin_keys_owner_id", "admin_keys", ["owner_id"])

    # ── loyalty_accounts ──────────────────────────────────────────────
    if not _has_table("loyalty_accounts"):
        op.create_table(
            "loyalty_accounts",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("customer_phone", sa.Text, nullable=False),
            sa.Column("customer_name", sa.Text, server_default=""),
            sa.Column("customer_email", sa.Text, server_default=""),
            sa.Column("points", sa.Integer, nullable=False, server_default="0"),
            sa.Column("tier", sa.Text, nullable=False, server_default="bronze"),
            sa.Column("total_spent", sa.Numeric(10, 2), server_default="0"),
            sa.Column("visit_count", sa.Integer, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("owner_id", "customer_phone", name="uq_loyalty_owner_phone"),
        )
        _mk_index("ix_loyalty_accounts_owner_id", "loyalty_accounts", ["owner_id"])

    # ── loyalty_transactions ──────────────────────────────────────────
    if not _has_table("loyalty_transactions"):
        op.create_table(
            "loyalty_transactions",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("account_id", sa.Integer,
                      sa.ForeignKey("loyalty_accounts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("order_id", sa.Integer,
                      sa.ForeignKey("orders.id", ondelete="SET NULL"), nullable=True),
            sa.Column("points", sa.Integer, nullable=False),
            sa.Column("type", sa.Text, server_default="earn"),
            sa.Column("reason", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        _mk_index("ix_loyalty_transactions_owner_id", "loyalty_transactions", ["owner_id"])
        _mk_index("ix_loyalty_transactions_account_id", "loyalty_transactions", ["account_id"])

    # ── suppliers ─────────────────────────────────────────────────────
    if not _has_table("suppliers"):
        op.create_table(
            "suppliers",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("name", sa.Text, nullable=False),
            sa.Column("contact", sa.Text, server_default=""),
            sa.Column("phone", sa.Text, server_default=""),
            sa.Column("email", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        _mk_index("ix_suppliers_owner_id", "suppliers", ["owner_id"])

    # ── purchase_orders ───────────────────────────────────────────────
    if not _has_table("purchase_orders"):
        op.create_table(
            "purchase_orders",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("supplier_id", sa.Integer,
                      sa.ForeignKey("suppliers.id", ondelete="SET NULL"), nullable=True),
            sa.Column("supplier_name", sa.Text, server_default=""),
            sa.Column("status", sa.Text, nullable=False, server_default="draft"),
            sa.Column("total_cost", sa.Numeric(10, 2), server_default="0"),
            sa.Column("notes", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        )
        _mk_index("ix_purchase_orders_owner_id", "purchase_orders", ["owner_id"])

    # ── purchase_order_items ──────────────────────────────────────────
    if not _has_table("purchase_order_items"):
        op.create_table(
            "purchase_order_items",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("po_id", sa.Integer,
                      sa.ForeignKey("purchase_orders.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ingredient_id", sa.Integer,
                      sa.ForeignKey("ingredients.id", ondelete="SET NULL"), nullable=True),
            sa.Column("ingredient_name", sa.Text, nullable=False),
            sa.Column("quantity", sa.Numeric(10, 3), nullable=False),
            sa.Column("unit", sa.Text, server_default="unit"),
            sa.Column("unit_cost", sa.Numeric(10, 4), server_default="0"),
            sa.Column("line_total", sa.Numeric(10, 2), server_default="0"),
        )
        _mk_index("ix_purchase_order_items_po_id", "purchase_order_items", ["po_id"])

    # ── table_calls (also created by 002_ext_idx; guard keeps this safe) ──
    if not _has_table("table_calls"):
        op.create_table(
            "table_calls",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"),
                      nullable=True),
            sa.Column("cafe_id", sa.Integer, sa.ForeignKey("cafes.id", ondelete="SET NULL"),
                      nullable=True),
            sa.Column("table_id", sa.Text, nullable=False),
            sa.Column("table_name", sa.Text, server_default=""),
            sa.Column("reason", sa.Text, server_default="service"),
            sa.Column("note", sa.Text, server_default=""),
            sa.Column("status", sa.Text, server_default="open"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by_employee_id", sa.Integer, sa.ForeignKey("employees.id"),
                      nullable=True),
        )
        _mk_index("ix_table_calls_owner", "table_calls", ["owner_id"])
        _mk_index("ix_table_calls_status", "table_calls", ["status"])
        _mk_index("ix_table_calls_table", "table_calls", ["table_id"])
        _mk_index("ix_table_calls_created", "table_calls", ["created_at"])


def downgrade() -> None:
    for tbl in (
        "purchase_order_items",
        "purchase_orders",
        "suppliers",
        "loyalty_transactions",
        "loyalty_accounts",
        "admin_keys",
    ):
        try:
            if _has_table(tbl):
                op.drop_table(tbl)
        except Exception:
            pass
    # table_calls intentionally NOT dropped here — owned by 002_ext_idx.
