"""Core domain models: Cafe, Owner, CafeTable, Menu, Ingredient."""
from __future__ import annotations

from app.extensions import db


class Cafe(db.Model):
    __tablename__ = "cafes"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, default="")
    slug = db.Column(db.Text, unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Owner(db.Model):
    __tablename__ = "owners"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    cafe_name = db.Column(db.Text, default="")
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    google_place_id = db.Column(db.Text, default="")
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
    is_superadmin = db.Column(db.Boolean, default=False, nullable=False, server_default="false")
    totp_secret = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, server_default="false")
    phone = db.Column(db.Text, default="")
    approval_status = db.Column(db.Text, default="active", server_default="active", nullable=False)
    plan_tier = db.Column(db.Text, default="free", server_default="free", nullable=False)
    max_tables = db.Column(db.Integer, nullable=True)
    max_menu_items = db.Column(db.Integer, nullable=True)
    monthly_order_limit = db.Column(db.Integer, nullable=True)
    trial_ends_at = db.Column(db.DateTime(timezone=True), nullable=True)
    notes = db.Column(db.Text, default="", server_default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    # Stripe subscription columns (added additively)
    stripe_customer_id = db.Column(db.Text, nullable=True)
    stripe_subscription_id = db.Column(db.Text, nullable=True)
    # Onboarding wizard state
    onboarding_complete = db.Column(db.Boolean, default=False, server_default="false")

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)

    # ── camelCase aliases used by Jinja2 templates ────────────────────────
    @property
    def cafeName(self) -> str:  # noqa: N802
        return self.cafe_name or ""

    @property
    def isSuperadmin(self) -> bool:  # noqa: N802
        return bool(self.is_superadmin)


class CafeTable(db.Model):
    __tablename__ = "cafe_tables"
    id = db.Column(db.Text, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Menu(db.Model):
    __tablename__ = "menus"
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), primary_key=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    data = db.Column(db.JSON, nullable=False, default=lambda: {"categories": []})


class Ingredient(db.Model):
    __tablename__ = "ingredients"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    name = db.Column(db.Text, nullable=False)
    unit = db.Column(db.Text, default="unit")
    stock = db.Column(db.Numeric(10, 3), default=0)
    low_stock_threshold = db.Column(db.Numeric(10, 3), default=5)
    menu_item_id = db.Column(db.Text, nullable=True)
    qty_per_order = db.Column(db.Numeric(10, 3), default=1)
    cost_per_unit = db.Column(db.Numeric(10, 4), default=0, server_default="0")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Settings(db.Model):
    __tablename__ = "settings"
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), primary_key=True)
    logo_url = db.Column(db.Text, default="")
    brand_color = db.Column(db.Text, default="#4f46e5")
    tax_rate_percent = db.Column(db.Numeric(5, 2), default=0, server_default="0")
    tax_label = db.Column(db.Text, default="GST", server_default="GST")
    gstin = db.Column(db.Text, default="", server_default="")
    service_charge_percent = db.Column(db.Numeric(5, 2), default=0, server_default="0")
    invoice_prefix = db.Column(db.Text, default="INV", server_default="INV")
    invoice_seq = db.Column(db.Integer, default=0, server_default="0")
    billing_address = db.Column(db.Text, default="", server_default="")
    billing_phone = db.Column(db.Text, default="", server_default="")
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
