"""Add tables from app/ package refactor: aggregator_credentials, aggregator_orders,
billing_logs, cash_drawer_counts, payment_credentials, webhook_events,
audit_log, owner_invitations, order_employee_assignments.

Revision ID: 005_refactor_tables
Revises: 004_system_flags
Create Date: 2026-05-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "005_refactor_tables"
down_revision = "004_system_flags"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in sa.inspect(bind).get_table_names()


def _has_column(table: str, col: str) -> bool:
    bind = op.get_bind()
    return col in {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    # ── aggregator_credentials ────────────────────────────────────────────
    if not _has_table("aggregator_credentials"):
        op.create_table(
            "aggregator_credentials",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=False),
            sa.Column("platform", sa.Text, nullable=False),
            sa.Column("display_name", sa.Text, server_default=""),
            sa.Column("api_key", sa.Text, server_default=""),
            sa.Column("secret_enc", sa.Text, server_default=""),
            sa.Column("webhook_secret_enc", sa.Text, server_default=""),
            sa.Column("merchant_id", sa.Text, server_default=""),
            sa.Column("mode", sa.Text, server_default="test"),
            sa.Column("is_active", sa.Boolean, server_default="true"),
            sa.Column("auto_accept", sa.Boolean, server_default="false"),
            sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_test_status", sa.Text, server_default=""),
            sa.Column("last_test_message", sa.Text, server_default=""),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("verified_fingerprint", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("owner_id", "platform", name="uq_aggregator_owner_platform"),
        )
        op.create_index("ix_aggregator_credentials_owner_id", "aggregator_credentials", ["owner_id"])

    # ── aggregator_orders ─────────────────────────────────────────────────
    if not _has_table("aggregator_orders"):
        op.create_table(
            "aggregator_orders",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=False),
            sa.Column("platform", sa.Text, nullable=False),
            sa.Column("external_order_id", sa.Text, nullable=False),
            sa.Column("order_id", sa.Integer, sa.ForeignKey("orders.id"), nullable=True),
            sa.Column("customer_name", sa.Text, server_default=""),
            sa.Column("customer_phone", sa.Text, server_default=""),
            sa.Column("items_snapshot", sa.JSON),
            sa.Column("subtotal", sa.Numeric(10, 2), server_default="0"),
            sa.Column("total", sa.Numeric(10, 2), server_default="0"),
            sa.Column("currency", sa.Text, server_default="INR"),
            sa.Column("aggregator_status", sa.Text, server_default="placed"),
            sa.Column("pickup_eta_minutes", sa.Integer, server_default="0"),
            sa.Column("rider_name", sa.Text, server_default=""),
            sa.Column("rider_phone", sa.Text, server_default=""),
            sa.Column("notes", sa.Text, server_default=""),
            sa.Column("raw", sa.JSON),
            sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rejected_reason", sa.Text, server_default=""),
            sa.Column("food_ready_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("platform", "external_order_id", name="uq_aggregator_platform_external"),
        )
        op.create_index("ix_aggregator_orders_owner_id", "aggregator_orders", ["owner_id"])
        op.create_index("ix_aggregator_orders_order_id", "aggregator_orders", ["order_id"])

    # ── billing_logs ──────────────────────────────────────────────────────
    if not _has_table("billing_logs"):
        op.create_table(
            "billing_logs",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=False),
            sa.Column("order_id", sa.Integer, sa.ForeignKey("orders.id"), nullable=True),
            sa.Column("invoice_number", sa.Text, server_default=""),
            sa.Column("action", sa.Text, nullable=False),
            sa.Column("actor_owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=True),
            sa.Column("actor_username", sa.Text, server_default=""),
            sa.Column("amount", sa.Numeric(10, 2), server_default="0"),
            sa.Column("payment_method", sa.Text, server_default=""),
            sa.Column("reason", sa.Text, server_default=""),
            sa.Column("payload", sa.JSON),
            sa.Column("ip", sa.Text, server_default=""),
            sa.Column("request_id", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_billing_logs_owner_id", "billing_logs", ["owner_id"])
        op.create_index("ix_billing_logs_order_id", "billing_logs", ["order_id"])
        op.create_index("ix_billing_logs_created_at", "billing_logs", ["created_at"])

    # ── cash_drawer_counts ────────────────────────────────────────────────
    if not _has_table("cash_drawer_counts"):
        op.create_table(
            "cash_drawer_counts",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False),
            sa.Column("counted_by_owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=True),
            sa.Column("counted_by_username", sa.Text, server_default=""),
            sa.Column("day", sa.Date, nullable=False),
            sa.Column("expected_cash", sa.Numeric(10, 2), server_default="0"),
            sa.Column("counted_cash", sa.Numeric(10, 2), server_default="0"),
            sa.Column("float_left", sa.Numeric(10, 2), server_default="0"),
            sa.Column("variance", sa.Numeric(10, 2), server_default="0"),
            sa.Column("variance_pct", sa.Numeric(6, 2), server_default="0"),
            sa.Column("severity", sa.Text, server_default="ok"),
            sa.Column("notes", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_cash_drawer_counts_owner_id", "cash_drawer_counts", ["owner_id"])
        op.create_index("ix_cash_drawer_counts_day", "cash_drawer_counts", ["day"])

    # ── payment_credentials ───────────────────────────────────────────────
    if not _has_table("payment_credentials"):
        op.create_table(
            "payment_credentials",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.Text, nullable=False),
            sa.Column("display_name", sa.Text, server_default=""),
            sa.Column("public_key", sa.Text, server_default=""),
            sa.Column("secret_key_enc", sa.Text, server_default=""),
            sa.Column("webhook_secret_enc", sa.Text, server_default=""),
            sa.Column("mode", sa.Text, server_default="test"),
            sa.Column("is_active", sa.Boolean, server_default="true"),
            sa.Column("is_default", sa.Boolean, server_default="false"),
            sa.Column("last_tested_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_test_status", sa.Text, server_default=""),
            sa.Column("last_test_message", sa.Text, server_default=""),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("verified_fingerprint", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.UniqueConstraint("owner_id", "provider", name="uq_payment_owner_provider"),
        )
        op.create_index("ix_payment_credentials_owner_id", "payment_credentials", ["owner_id"])

    # ── webhook_events ────────────────────────────────────────────────────
    if not _has_table("webhook_events"):
        op.create_table(
            "webhook_events",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("provider", sa.Text, nullable=False),
            sa.Column("event_id", sa.Text, nullable=False),
            sa.Column("intent_id", sa.Text, server_default=""),
            sa.Column("event_type", sa.Text, server_default=""),
            sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("processed", sa.Boolean, server_default="false"),
            sa.UniqueConstraint("provider", "event_id", name="uq_webhook_provider_event"),
        )
        op.create_index("ix_webhook_events_intent_id", "webhook_events", ["intent_id"])

    # ── audit_log ─────────────────────────────────────────────────────────
    if not _has_table("audit_log"):
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=True),
            sa.Column("actor_type", sa.Text, server_default="system"),
            sa.Column("actor_id", sa.Integer, nullable=True),
            sa.Column("actor_label", sa.Text, server_default=""),
            sa.Column("action", sa.Text, nullable=False),
            sa.Column("target", sa.Text, server_default=""),
            sa.Column("meta", sa.JSON),
            sa.Column("ip", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_audit_log_owner_id", "audit_log", ["owner_id"])
        op.create_index("ix_audit_log_action", "audit_log", ["action"])
        op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])

    # ── owner_invitations ─────────────────────────────────────────────────
    if not _has_table("owner_invitations"):
        op.create_table(
            "owner_invitations",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("token_hash", sa.Text, nullable=False, unique=True),
            sa.Column("email", sa.Text, server_default=""),
            sa.Column("note", sa.Text, server_default=""),
            sa.Column("plan_tier", sa.Text, server_default="free"),
            sa.Column("cafe_id", sa.Integer, sa.ForeignKey("cafes.id"), nullable=True),
            sa.Column("created_by_owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("used_by_owner_id", sa.Integer, sa.ForeignKey("owners.id"), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_owner_invitations_token_hash", "owner_invitations", ["token_hash"])

    # ── order_employee_assignments ────────────────────────────────────────
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
        op.create_index("ix_order_employee_assignments_order_id", "order_employee_assignments", ["order_id"])
        op.create_index("ix_order_employee_assignments_employee_id", "order_employee_assignments", ["employee_id"])

    # ── online_payments (from refactor) ───────────────────────────────────
    if not _has_table("online_payments"):
        op.create_table(
            "online_payments",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False),
            sa.Column("order_id", sa.Integer, sa.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.Text, nullable=False),
            sa.Column("intent_id", sa.Text, nullable=False),
            sa.Column("amount", sa.Numeric(10, 2), server_default="0"),
            sa.Column("currency", sa.Text, server_default="INR"),
            sa.Column("status", sa.Text, server_default="pending"),
            sa.Column("customer_email", sa.Text, server_default=""),
            sa.Column("customer_phone", sa.Text, server_default=""),
            sa.Column("error_message", sa.Text, server_default=""),
            sa.Column("raw", sa.JSON),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_online_payments_owner_id", "online_payments", ["owner_id"])
        op.create_index("ix_online_payments_order_id", "online_payments", ["order_id"])
        op.create_index("ix_online_payments_intent_id", "online_payments", ["intent_id"])

    # ── remember_tokens ───────────────────────────────────────────────────
    if not _has_table("remember_tokens"):
        op.create_table(
            "remember_tokens",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("owner_id", sa.Integer, sa.ForeignKey("owners.id", ondelete="CASCADE")),
            sa.Column("token_hash", sa.Text, unique=True, nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    # ── owner_leads ───────────────────────────────────────────────────────
    if not _has_table("owner_leads"):
        op.create_table(
            "owner_leads",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("contact_name", sa.Text, nullable=False, server_default=""),
            sa.Column("cafe_name", sa.Text, nullable=False, server_default=""),
            sa.Column("email", sa.Text, nullable=False, server_default=""),
            sa.Column("phone", sa.Text, server_default=""),
            sa.Column("city", sa.Text, server_default=""),
            sa.Column("table_count", sa.Integer, server_default="0"),
            sa.Column("message", sa.Text, server_default=""),
            sa.Column("source", sa.Text, server_default="landing"),
            sa.Column("status", sa.Text, nullable=False, server_default="pending"),
            sa.Column("handled_by", sa.Integer, sa.ForeignKey("owners.id"), nullable=True),
            sa.Column("handled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("submitted_ip", sa.Text, server_default=""),
            sa.Column("submitted_ua", sa.Text, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )

    # ── orders: new refactor columns ──────────────────────────────────────
    if _has_table("orders"):
        order_cols = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("orders")}
        _add_if_missing = lambda col, typ, **kw: (  # noqa: E731
            op.add_column("orders", sa.Column(col, typ, **kw))
            if col not in order_cols else None
        )
        _add_if_missing("discount", sa.Numeric(10, 2), server_default="0")
        _add_if_missing("tax", sa.Numeric(10, 2), server_default="0")
        _add_if_missing("service_charge", sa.Numeric(10, 2), server_default="0")
        _add_if_missing("invoice_number", sa.Text, server_default="")
        _add_if_missing("paid_at", sa.DateTime(timezone=True), nullable=True)
        _add_if_missing("settled_by", sa.Integer, nullable=True)
        _add_if_missing("payments_breakdown", sa.JSON)
        _add_if_missing("void_reason", sa.Text, server_default="")
        _add_if_missing("refund_amount", sa.Numeric(10, 2), server_default="0")
        _add_if_missing("refund_reason", sa.Text, server_default="")
        _add_if_missing("modifiers", sa.JSON)
        _add_if_missing("tip", sa.Numeric(10, 2), server_default="0")
        _add_if_missing("cafe_id", sa.Integer, nullable=True)

    # ── owners: new refactor columns ──────────────────────────────────────
    if _has_table("owners"):
        owner_cols = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("owners")}
        _add_o = lambda col, typ, **kw: (  # noqa: E731
            op.add_column("owners", sa.Column(col, typ, **kw))
            if col not in owner_cols else None
        )
        _add_o("plan_tier", sa.Text, server_default="free")
        _add_o("max_tables", sa.Integer, nullable=True)
        _add_o("max_menu_items", sa.Integer, nullable=True)
        _add_o("monthly_order_limit", sa.Integer, nullable=True)
        _add_o("trial_ends_at", sa.DateTime(timezone=True), nullable=True)
        _add_o("notes", sa.Text, server_default="")
        _add_o("cafe_id", sa.Integer, nullable=True)
        _add_o("totp_secret", sa.Text, nullable=True)
        _add_o("totp_enabled", sa.Boolean, server_default="false")
        _add_o("phone", sa.Text, server_default="")
        _add_o("approval_status", sa.Text, nullable=False, server_default="active")
        _add_o("is_superadmin", sa.Boolean, server_default="false")


def downgrade() -> None:
    for tbl in [
        "order_employee_assignments",
        "owner_invitations",
        "audit_log",
        "webhook_events",
        "payment_credentials",
        "cash_drawer_counts",
        "billing_logs",
        "aggregator_orders",
        "aggregator_credentials",
        "online_payments",
        "remember_tokens",
        "owner_leads",
    ]:
        if _has_table(tbl):
            op.drop_table(tbl)
