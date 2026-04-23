"""Add extension tables (table_calls, employees, order assignments) + indexes.

Revision ID: 002_ext_idx
Revises: 001_saas_upgrade_initial
Create Date: 2026-04-22
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "002_ext_idx"
down_revision = "001_saas_upgrade_initial"
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


def upgrade() -> None:
    # ------------------------------------------------------------------
    # New tables (safe / idempotent)
    # ------------------------------------------------------------------
    if not _has_table("employees"):
        op.create_table(
            "employees",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False),
            sa.Column("cafe_id", sa.Integer, sa.ForeignKey("cafes.id", ondelete="SET NULL"), nullable=True),
            sa.Column("name", sa.Text, nullable=False),
            sa.Column("role", sa.Text, server_default="server"),
            sa.Column("pin_code", sa.Text, server_default=""),
            sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_employees_owner", "employees", ["owner_id"])

    if not _has_table("table_calls"):
        op.create_table(
            "table_calls",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=True),
            sa.Column("cafe_id", sa.Integer, sa.ForeignKey("cafes.id", ondelete="SET NULL"), nullable=True),
            sa.Column("table_id", sa.Text, nullable=False),
            sa.Column("table_name", sa.Text, server_default=""),
            sa.Column("reason", sa.Text, server_default="service"),
            sa.Column("note", sa.Text, server_default=""),
            sa.Column("status", sa.Text, server_default="open"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by_employee_id", sa.Integer, sa.ForeignKey("employees.id"), nullable=True),
        )
        op.create_index("ix_table_calls_owner", "table_calls", ["owner_id"])
        op.create_index("ix_table_calls_status", "table_calls", ["status"])
        op.create_index("ix_table_calls_table", "table_calls", ["table_id"])
        op.create_index("ix_table_calls_created", "table_calls", ["created_at"])

    if not _has_table("order_employee_assignments"):
        op.create_table(
            "order_employee_assignments",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("order_id", sa.Integer, sa.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False),
            sa.Column("employee_id", sa.Integer, sa.ForeignKey("employees.id", ondelete="CASCADE"), nullable=False),
            sa.Column("role", sa.Text, server_default="server"),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("order_id", "employee_id", "role", name="uq_order_employee_role"),
        )
        op.create_index("ix_oea_order", "order_employee_assignments", ["order_id"])
        op.create_index("ix_oea_employee", "order_employee_assignments", ["employee_id"])

    # ------------------------------------------------------------------
    # Performance indexes on existing tables
    # ------------------------------------------------------------------
    if not _has_index("orders", "ix_orders_owner_created"):
        op.create_index("ix_orders_owner_created", "orders", ["owner_id", "created_at"])
    if not _has_index("orders", "ix_orders_status"):
        op.create_index("ix_orders_status", "orders", ["status"])
    if not _has_index("orders", "ix_orders_owner_status"):
        op.create_index("ix_orders_owner_status", "orders", ["owner_id", "status"])
    if not _has_index("orders", "ix_orders_table"):
        op.create_index("ix_orders_table", "orders", ["table_id"])
    if not _has_index("orders", "ix_orders_cafe"):
        op.create_index("ix_orders_cafe", "orders", ["cafe_id"])
    if not _has_index("feedback", "ix_feedback_owner"):
        op.create_index("ix_feedback_owner", "feedback", ["owner_id"])
    if not _has_index("feedback", "ix_feedback_order"):
        op.create_index("ix_feedback_order", "feedback", ["order_id"])
    if not _has_index("ingredients", "ix_ingredients_owner"):
        op.create_index("ix_ingredients_owner", "ingredients", ["owner_id"])
    if not _has_index("cafe_tables", "ix_cafe_tables_owner"):
        op.create_index("ix_cafe_tables_owner", "cafe_tables", ["owner_id"])
    if not _has_index("remember_tokens", "ix_remember_tokens_owner"):
        op.create_index("ix_remember_tokens_owner", "remember_tokens", ["owner_id"])
    if not _has_index("remember_tokens", "ix_remember_tokens_expires"):
        op.create_index("ix_remember_tokens_expires", "remember_tokens", ["expires_at"])


def downgrade() -> None:
    for ix, table in [
        ("ix_orders_owner_created", "orders"),
        ("ix_orders_status", "orders"),
        ("ix_orders_owner_status", "orders"),
        ("ix_orders_table", "orders"),
        ("ix_orders_cafe", "orders"),
        ("ix_feedback_owner", "feedback"),
        ("ix_feedback_order", "feedback"),
        ("ix_ingredients_owner", "ingredients"),
        ("ix_cafe_tables_owner", "cafe_tables"),
        ("ix_remember_tokens_owner", "remember_tokens"),
        ("ix_remember_tokens_expires", "remember_tokens"),
    ]:
        try:
            op.drop_index(ix, table_name=table)
        except Exception:
            pass
    for tbl in ("order_employee_assignments", "table_calls", "employees"):
        try:
            op.drop_table(tbl)
        except Exception:
            pass
