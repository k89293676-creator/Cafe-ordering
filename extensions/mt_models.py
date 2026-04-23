"""SQLAlchemy models for multi-tenant controls (invitations + audit log).

Lives in the ``extensions`` package so it shares the same ``db`` instance and
gets created via the deferred ``db.create_all()`` call in
:func:`extensions.register_extensions`.
"""
from __future__ import annotations

from app import db


class Invitation(db.Model):
    """A one-time invite token issued by a superadmin to onboard an owner.

    The plaintext token is shown to the issuer once, then only its hash is
    stored.  The token can be redeemed at /owner/signup?invite=<token>.
    """

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
    actor_type = db.Column(db.Text, default="system")  # owner | superadmin | system | customer
    actor_id = db.Column(db.Integer, nullable=True)
    actor_label = db.Column(db.Text, default="")
    action = db.Column(db.Text, nullable=False, index=True)
    target = db.Column(db.Text, default="")
    meta = db.Column(db.JSON, default=dict)
    ip = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)
