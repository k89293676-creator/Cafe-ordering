"""Aggregator-domain models: AggregatorPlatformCredential, AggregatorOrder."""
from __future__ import annotations

from app.extensions import db


class AggregatorPlatformCredential(db.Model):
    """Per-owner Swiggy/Zomato/Uber Eats partner credentials."""

    __tablename__ = "aggregator_credentials"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), index=True, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    display_name = db.Column(db.Text, default="")
    api_key = db.Column(db.Text, default="")
    secret_enc = db.Column(db.Text, default="")
    webhook_secret_enc = db.Column(db.Text, default="")
    merchant_id = db.Column(db.Text, default="")
    mode = db.Column(db.Text, default="test", server_default="test")
    is_active = db.Column(db.Boolean, default=True, server_default="true")
    auto_accept = db.Column(db.Boolean, default=False, server_default="false")
    last_tested_at = db.Column(db.DateTime(timezone=True))
    last_test_status = db.Column(db.Text, default="")
    last_test_message = db.Column(db.Text, default="")
    verified_at = db.Column(db.DateTime(timezone=True))
    verified_fingerprint = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
    __table_args__ = (
        db.UniqueConstraint("owner_id", "platform", name="uq_aggregator_owner_platform"),
    )


class AggregatorOrder(db.Model):
    """Mirror of an aggregator-side order linked to an internal Order row."""

    __tablename__ = "aggregator_orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), index=True, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    external_order_id = db.Column(db.Text, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True, index=True)
    customer_name = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    items_snapshot = db.Column(db.JSON, default=list)
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    currency = db.Column(db.Text, default="INR")
    aggregator_status = db.Column(db.Text, default="placed")
    pickup_eta_minutes = db.Column(db.Integer, default=0)
    rider_name = db.Column(db.Text, default="")
    rider_phone = db.Column(db.Text, default="")
    notes = db.Column(db.Text, default="")
    raw = db.Column(db.JSON, default=dict)
    accepted_at = db.Column(db.DateTime(timezone=True))
    rejected_at = db.Column(db.DateTime(timezone=True))
    rejected_reason = db.Column(db.Text, default="")
    food_ready_at = db.Column(db.DateTime(timezone=True))
    delivered_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
    __table_args__ = (
        db.UniqueConstraint("platform", "external_order_id", name="uq_aggregator_platform_external"),
    )
