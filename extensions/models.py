"""SQLAlchemy models for the new feature blueprints.

These models are appended to the same ``db`` instance defined in ``app.py``
so that they share metadata, sessions and Alembic migrations.
"""
from __future__ import annotations

from app import db


class TableCall(db.Model):
    """A customer-initiated 'At Your Service' / waiter-call event."""

    __tablename__ = "table_calls"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=True, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id", ondelete="SET NULL"), nullable=True, index=True)
    table_id = db.Column(db.Text, nullable=False, index=True)
    table_name = db.Column(db.Text, default="")
    reason = db.Column(db.Text, default="service")  # service | bill | water | help
    note = db.Column(db.Text, default="")
    status = db.Column(db.Text, default="open", index=True)  # open | acknowledged | resolved
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)
    acknowledged_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    resolved_by_employee_id = db.Column(db.Integer, db.ForeignKey("employees.id"), nullable=True)


class Employee(db.Model):
    """Lightweight staff record used for performance reporting."""

    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False, index=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id", ondelete="SET NULL"), nullable=True)
    name = db.Column(db.Text, nullable=False)
    role = db.Column(db.Text, default="server")
    pin_code = db.Column(db.Text, default="")
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class OrderEmployeeAssignment(db.Model):
    """Associates an order with the staff member who handled it."""

    __tablename__ = "order_employee_assignments"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False, index=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("employees.id", ondelete="CASCADE"), nullable=False, index=True)
    role = db.Column(db.Text, default="server")  # server | barista | cashier
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint("order_id", "employee_id", "role", name="uq_order_employee_role"),
    )
