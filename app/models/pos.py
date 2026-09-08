"""POS enhancements: Loyalty, Purchase Orders, KDS meta.
Matches Toast/Square/Lightspeed parity: points/tiers, PO/supplier, station timers.
"""
from __future__ import annotations
from datetime import datetime, timezone
from app.extensions import db

class LoyaltyAccount(db.Model):
    __tablename__ = "loyalty_accounts"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    customer_phone = db.Column(db.Text, nullable=False)
    customer_name = db.Column(db.Text, default="")
    customer_email = db.Column(db.Text, default="")
    points = db.Column(db.Integer, default=0, nullable=False)
    tier = db.Column(db.Text, default="bronze", nullable=False)  # bronze/silver/gold/platinum
    total_spent = db.Column(db.Numeric(10,2), default=0)
    visit_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())
    __table_args__ = (db.UniqueConstraint("owner_id","customer_phone", name="uq_loyalty_owner_phone"),)

    def tier_for_points(self):
        p = self.points or 0
        if p >= 5000: return "platinum"
        if p >= 2000: return "gold"
        if p >= 500: return "silver"
        return "bronze"

class LoyaltyTransaction(db.Model):
    __tablename__ = "loyalty_transactions"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    account_id = db.Column(db.Integer, db.ForeignKey("loyalty_accounts.id", ondelete="CASCADE"), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="SET NULL"), nullable=True)
    points = db.Column(db.Integer, nullable=False)  # +earn / -redeem
    type = db.Column(db.Text, default="earn")  # earn/redeem/adjust/tier_bonus
    reason = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

class Supplier(db.Model):
    __tablename__ = "suppliers"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.Text, nullable=False)
    contact = db.Column(db.Text, default="")
    phone = db.Column(db.Text, default="")
    email = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

class PurchaseOrder(db.Model):
    __tablename__ = "purchase_orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("suppliers.id", ondelete="SET NULL"), nullable=True)
    supplier_name = db.Column(db.Text, default="")
    status = db.Column(db.Text, default="draft", nullable=False)  # draft/ordered/received/cancelled
    total_cost = db.Column(db.Numeric(10,2), default=0)
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    received_at = db.Column(db.DateTime(timezone=True), nullable=True)

class PurchaseOrderItem(db.Model):
    __tablename__ = "purchase_order_items"
    id = db.Column(db.Integer, primary_key=True)
    po_id = db.Column(db.Integer, db.ForeignKey("purchase_orders.id", ondelete="CASCADE"), nullable=False, index=True)
    ingredient_id = db.Column(db.Integer, db.ForeignKey("ingredients.id", ondelete="SET NULL"), nullable=True)
    ingredient_name = db.Column(db.Text, nullable=False)
    quantity = db.Column(db.Numeric(10,3), nullable=False)
    unit = db.Column(db.Text, default="unit")
    unit_cost = db.Column(db.Numeric(10,4), default=0)
    line_total = db.Column(db.Numeric(10,2), default=0)

# KDS extension: add columns to orders via _init_db if missing (see app/utils/db_init.py)
# For now, we store KDS meta in order.notes JSON or via Order.kds_station if column exists
