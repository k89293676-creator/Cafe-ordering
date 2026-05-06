"""Order-domain models: Order, Feedback, OnlinePayment."""
from __future__ import annotations

from app.extensions import db


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    table_id = db.Column(db.Text)
    table_name = db.Column(db.Text)
    customer_name = db.Column(db.Text, default="Guest")
    customer_email = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    customer_id = db.Column(db.Integer, db.ForeignKey("customers.id"), nullable=True)
    items = db.Column(db.JSON, nullable=False, default=list)
    modifiers = db.Column(db.JSON, default=dict)
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    tip = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    status = db.Column(db.Text, default="pending")
    pickup_code = db.Column(db.Text, default="")
    origin = db.Column(db.Text, default="table")
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    payment_status = db.Column(db.Text, default="unpaid", server_default="unpaid", index=True)
    payment_method = db.Column(db.Text, default="", server_default="")
    discount = db.Column(db.Numeric(10, 2), default=0, server_default="0")
    tax = db.Column(db.Numeric(10, 2), default=0, server_default="0")
    service_charge = db.Column(db.Numeric(10, 2), default=0, server_default="0")
    invoice_number = db.Column(db.Text, default="", server_default="", index=True)
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)
    settled_by = db.Column(db.Integer, nullable=True)
    payments_breakdown = db.Column(db.JSON, default=list)
    void_reason = db.Column(db.Text, default="", server_default="")
    refund_amount = db.Column(db.Numeric(10, 2), default=0, server_default="0")
    refund_reason = db.Column(db.Text, default="", server_default="")


class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True)
    table_id = db.Column(db.Text)
    customer_name = db.Column(db.Text, default="Guest")
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class OnlinePayment(db.Model):
    __tablename__ = "online_payments"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = db.Column(db.Text, nullable=False)
    intent_id = db.Column(db.Text, nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2), default=0)
    currency = db.Column(db.Text, default="INR", server_default="INR")
    status = db.Column(db.Text, default="pending", server_default="pending")
    customer_email = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    error_message = db.Column(db.Text, default="")
    raw = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
