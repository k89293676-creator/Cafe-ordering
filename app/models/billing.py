"""Billing-domain models: BillingLog, CashDrawerCount, PaymentProviderCredential, WebhookEventLog.

Enhancement applied:
  WebhookEventLog — added retry/status columns (status, attempts, next_attempt_at,
  last_error, payload) to match migration 007 and the webhook retry worker schema.
"""
from __future__ import annotations

from app.extensions import db


class BillingLog(db.Model):
    """Append-only audit log for billing actions (settle / void / refund / adjust)."""

    __tablename__ = "billing_logs"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True, index=True)
    invoice_number = db.Column(db.Text, default="")
    action = db.Column(db.Text, nullable=False)
    actor_owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    actor_username = db.Column(db.Text, default="")
    amount = db.Column(db.Numeric(10, 2), default=0)
    payment_method = db.Column(db.Text, default="")
    reason = db.Column(db.Text, default="")
    payload = db.Column(db.JSON, default=dict)
    ip = db.Column(db.Text, default="")
    request_id = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)


class CashDrawerCount(db.Model):
    """Per-shift cash count vs system expectation for reconciliation."""

    __tablename__ = "cash_drawer_counts"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    counted_by_owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    counted_by_username = db.Column(db.Text, default="")
    day = db.Column(db.Date, nullable=False, index=True)
    expected_cash = db.Column(db.Numeric(10, 2), default=0)
    counted_cash = db.Column(db.Numeric(10, 2), default=0)
    float_left = db.Column(db.Numeric(10, 2), default=0)
    variance = db.Column(db.Numeric(10, 2), default=0)
    variance_pct = db.Column(db.Numeric(6, 2), default=0)
    severity = db.Column(db.Text, default="ok")
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)


class PaymentProviderCredential(db.Model):
    """Per-owner encrypted payment-gateway credentials."""

    __tablename__ = "payment_credentials"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = db.Column(db.Text, nullable=False)
    display_name = db.Column(db.Text, default="")
    public_key = db.Column(db.Text, default="")
    secret_key_enc = db.Column(db.Text, default="")
    webhook_secret_enc = db.Column(db.Text, default="")
    mode = db.Column(db.Text, default="test", server_default="test")
    is_active = db.Column(db.Boolean, default=True, server_default="true")
    is_default = db.Column(db.Boolean, default=False, server_default="false")
    last_tested_at = db.Column(db.DateTime(timezone=True))
    last_test_status = db.Column(db.Text, default="")
    last_test_message = db.Column(db.Text, default="")
    verified_at = db.Column(db.DateTime(timezone=True))
    verified_fingerprint = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime(timezone=True),
        server_default=db.func.now(),
        onupdate=db.func.now(),
    )
    __table_args__ = (
        db.UniqueConstraint("owner_id", "provider", name="uq_payment_owner_provider"),
    )


class WebhookEventLog(db.Model):
    """Idempotency and retry table for inbound provider webhooks.

    Columns added in migration 007:
      status          — lifecycle state: pending / delivered / failed / dead
      attempts        — delivery attempt counter
      next_attempt_at — when the retry worker should next attempt delivery
      last_error      — last delivery failure message (for operator visibility)
      payload         — serialised event body for replay without re-fetching
    """

    __tablename__ = "webhook_events"

    # ── Core dedup columns (migration 005) ───────────────────────────────────
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.Text, nullable=False)
    event_id = db.Column(db.Text, nullable=False)
    intent_id = db.Column(db.Text, default="", index=True)
    event_type = db.Column(db.Text, default="")
    received_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    processed = db.Column(db.Boolean, default=False, server_default="false")

    # ── Retry / status columns (migration 007) ───────────────────────────────
    status = db.Column(
        db.Text, default="pending", server_default="pending", nullable=False, index=True
    )
    attempts = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    next_attempt_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    last_error = db.Column(db.Text, default="", nullable=True)
    payload = db.Column(db.JSON, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("provider", "event_id", name="uq_webhook_provider_event"),
    )

    # ── Status constants ──────────────────────────────────────────────────────
    STATUS_PENDING = "pending"
    STATUS_DELIVERED = "delivered"
    STATUS_FAILED = "failed"
    STATUS_DEAD = "dead"

    @property
    def is_retryable(self) -> bool:
        return self.status in (self.STATUS_PENDING, self.STATUS_FAILED, self.STATUS_DEAD)
