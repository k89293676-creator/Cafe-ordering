"""Auth & tenant management models: RememberToken, OwnerLead, SystemFlag, OwnerLead."""
from __future__ import annotations

from app.extensions import db


class RememberToken(db.Model):
    __tablename__ = "remember_tokens"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"))
    token_hash = db.Column(db.Text, unique=True, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class OwnerLead(db.Model):
    """Pre-account 'request access' submissions from the public landing page."""

    __tablename__ = "owner_leads"
    id = db.Column(db.Integer, primary_key=True)
    contact_name = db.Column(db.Text, nullable=False, default="")
    cafe_name = db.Column(db.Text, nullable=False, default="")
    email = db.Column(db.Text, nullable=False, default="")
    phone = db.Column(db.Text, default="")
    city = db.Column(db.Text, default="")
    table_count = db.Column(db.Integer, default=0)
    message = db.Column(db.Text, default="")
    source = db.Column(db.Text, default="landing")
    status = db.Column(db.Text, default="pending", server_default="pending", nullable=False)
    handled_by = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    handled_at = db.Column(db.DateTime(timezone=True), nullable=True)
    submitted_ip = db.Column(db.Text, default="")
    submitted_ua = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class SystemFlag(db.Model):
    """Global key/value runtime toggles (e.g. maintenance_mode)."""

    __tablename__ = "system_flags"
    key = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now())


class Invitation(db.Model):
    """One-time invite token issued by a superadmin to onboard an owner."""

    __tablename__ = "owner_invitations"
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.Text, unique=True, nullable=False, index=True)
    email = db.Column(db.Text, default="")
    note = db.Column(db.Text, default="")
    plan_tier = db.Column(db.Text, default="free")
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    created_by_owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    used_by_owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)


class AuditLog(db.Model):
    """Tenant-scoped audit trail of important actions."""

    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_type = db.Column(db.Text, default="system")
    actor_id = db.Column(db.Integer, nullable=True)
    actor_label = db.Column(db.Text, default="")
    action = db.Column(db.Text, nullable=False, index=True)
    target = db.Column(db.Text, default="")
    meta = db.Column(db.JSON, default=dict)
    ip = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)
