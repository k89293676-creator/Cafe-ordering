"""Add status, next_attempt_at, and retry columns to webhook_events.

Revision ID: 007_webhook_events_cols
Revises: 006_critical_idx
Create Date: 2026-05-09

The webhook_events table was created in migration 005 with only the minimal
columns needed for payment-provider deduplication. This migration adds the
columns required by the webhook retry worker (lib_webhook_retry):

  status          TEXT DEFAULT 'pending'  — pending / delivered / failed / dead
  attempts        INTEGER DEFAULT 0       — delivery attempt count
  next_attempt_at TIMESTAMP WITH TIME ZONE — when to next retry
  last_error      TEXT DEFAULT ''         — last delivery error message
  payload         JSON                    — serialised event body for replay

After adding the columns, the index that migration 006 skipped (because the
columns did not yet exist) is created here.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "007_webhook_events_cols"
down_revision = "006_critical_idx"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, col: str) -> bool:
    if not _has_table(table):
        return False
    return col in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _has_index(table: str, name: str) -> bool:
    if not _has_table(table):
        return False
    return any(
        ix["name"] == name
        for ix in sa.inspect(op.get_bind()).get_indexes(table)
    )


def upgrade() -> None:
    if not _has_table("webhook_events"):
        return  # should not happen; created in 005

    # ── Add missing retry/status columns ──────────────────────────────────
    if not _has_column("webhook_events", "status"):
        op.add_column(
            "webhook_events",
            sa.Column("status", sa.Text, server_default="pending", nullable=False),
        )
    if not _has_column("webhook_events", "attempts"):
        op.add_column(
            "webhook_events",
            sa.Column("attempts", sa.Integer, server_default="0", nullable=False),
        )
    if not _has_column("webhook_events", "next_attempt_at"):
        op.add_column(
            "webhook_events",
            sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        )
    if not _has_column("webhook_events", "last_error"):
        op.add_column(
            "webhook_events",
            sa.Column("last_error", sa.Text, server_default="", nullable=True),
        )
    if not _has_column("webhook_events", "payload"):
        op.add_column(
            "webhook_events",
            sa.Column("payload", sa.JSON, nullable=True),
        )

    # ── Create the index that migration 006 safely skipped ────────────────
    if not _has_index("webhook_events", "ix_webhook_events_status_next"):
        op.create_index(
            "ix_webhook_events_status_next",
            "webhook_events",
            ["status", "next_attempt_at"],
        )


def downgrade() -> None:
    if _has_index("webhook_events", "ix_webhook_events_status_next"):
        op.drop_index("ix_webhook_events_status_next", table_name="webhook_events")

    for col in ["payload", "last_error", "next_attempt_at", "attempts", "status"]:
        if _has_column("webhook_events", col):
            op.drop_column("webhook_events", col)
