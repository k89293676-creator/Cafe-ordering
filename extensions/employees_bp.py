"""Lightweight employee management + performance reporting."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from flask import Blueprint, abort, jsonify, render_template, request

from app import Order, db, login_required, logged_in_owner_id
from ._helpers import parse_date_range, safe_float
from .models import Employee, OrderEmployeeAssignment

bp = Blueprint("employees", __name__)


# ---------------------------------------------------------------------------
# Owner UI
# ---------------------------------------------------------------------------

@bp.route("/owner/employees")
@login_required
def view():
    return render_template("extensions/employees.html")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def _emp_dict(e: Employee) -> dict:
    return {
        "id": e.id,
        "name": e.name,
        "role": e.role,
        "isActive": bool(e.is_active),
        "createdAt": e.created_at.isoformat() if e.created_at else None,
    }


@bp.route("/api/owner/employees", methods=["GET"])
@login_required
def list_employees():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    emps = Employee.query.filter_by(owner_id=owner_id).order_by(Employee.created_at.desc()).all()
    return jsonify({"employees": [_emp_dict(e) for e in emps]})


@bp.route("/api/owner/employees", methods=["POST"])
@login_required
def create_employee():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    payload = request.get_json(silent=True) or request.form.to_dict()
    name = str(payload.get("name", "")).strip()[:100]
    role = str(payload.get("role", "server")).strip().lower()[:30] or "server"
    if not name:
        abort(400, description="Employee name is required.")
    emp = Employee(owner_id=owner_id, name=name, role=role)
    db.session.add(emp)
    db.session.commit()
    return jsonify({"ok": True, "employee": _emp_dict(emp)}), 201


@bp.route("/api/owner/employees/<int:emp_id>", methods=["DELETE", "POST"])
@login_required
def deactivate_employee(emp_id: int):
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    emp = db.session.get(Employee, emp_id)
    if not emp or emp.owner_id != owner_id:
        abort(404)
    emp.is_active = False
    db.session.commit()
    return jsonify({"ok": True})


@bp.route("/api/owner/orders/<int:order_id>/assign", methods=["POST"])
@login_required
def assign_employee_to_order(order_id: int):
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    order = db.session.get(Order, order_id)
    if not order or order.owner_id != owner_id:
        abort(404)
    payload = request.get_json(silent=True) or request.form.to_dict()
    emp_id = int(payload.get("employee_id") or 0)
    role = str(payload.get("role", "server")).strip().lower()[:30] or "server"
    emp = db.session.get(Employee, emp_id)
    if not emp or emp.owner_id != owner_id:
        abort(404, description="Unknown employee.")
    existing = OrderEmployeeAssignment.query.filter_by(order_id=order_id, employee_id=emp_id, role=role).first()
    if existing:
        return jsonify({"ok": True, "deduped": True})
    assignment = OrderEmployeeAssignment(order_id=order_id, employee_id=emp_id, role=role)
    db.session.add(assignment)
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Performance report
# ---------------------------------------------------------------------------

@bp.route("/api/owner/employees/performance")
@login_required
def performance_report():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"), default_days=30)

    emps = Employee.query.filter_by(owner_id=owner_id).all()
    by_emp = {e.id: {"id": e.id, "name": e.name, "role": e.role, "orders": 0, "revenue": 0.0, "tips": 0.0, "items": 0} for e in emps}

    rows = (
        db.session.query(OrderEmployeeAssignment, Order)
        .join(Order, Order.id == OrderEmployeeAssignment.order_id)
        .filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .all()
    )
    for assn, order in rows:
        if assn.employee_id not in by_emp:
            continue
        rec = by_emp[assn.employee_id]
        rec["orders"] += 1
        rec["revenue"] += safe_float(order.total)
        rec["tips"] += safe_float(order.tip)
        rec["items"] += len(order.items or [])

    out = []
    for rec in by_emp.values():
        avg_ticket = rec["revenue"] / rec["orders"] if rec["orders"] else 0.0
        tip_pct = (rec["tips"] / rec["revenue"] * 100) if rec["revenue"] else 0.0
        out.append({
            **rec,
            "revenue": round(rec["revenue"], 2),
            "tips": round(rec["tips"], 2),
            "avgTicket": round(avg_ticket, 2),
            "tipPct": round(tip_pct, 1),
        })
    out.sort(key=lambda x: -x["revenue"])
    return jsonify({"employees": out, "start": start_dt.isoformat(), "end": end_dt.isoformat()})
