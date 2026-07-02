"""Customer Lifetime Value (LTV) analytics."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from flask import Blueprint, abort, jsonify, render_template, request

from app import Order, login_required, logged_in_owner_id
from ._helpers import parse_date_range, safe_float

bp = Blueprint("ltv", __name__)


@bp.route("/owner/reports/ltv")
@login_required
def view():
    return render_template("extensions/ltv.html")


@bp.route("/api/owner/reports/ltv")
@login_required
def report():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    # LTV is naturally lifetime: default look-back is 365 days, configurable.
    start_dt, end_dt = parse_date_range(
        request.args.get("start"), request.args.get("end"), default_days=365
    )

    rows = (
        Order.query.filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .order_by(Order.created_at.asc())
        .all()
    )

    by_customer: dict[str, dict] = defaultdict(lambda: {
        "key": "",
        "name": "Guest",
        "email": "",
        "phone": "",
        "orders": 0,
        "revenue": 0.0,
        "firstSeen": None,
        "lastSeen": None,
        "tables": set(),
    })

    for o in rows:
        # Customer identity: prefer email, then phone, then name+table fallback.
        email = (o.customer_email or "").strip().lower()
        phone = (o.customer_phone or "").strip()
        name = (o.customer_name or "Guest").strip() or "Guest"
        if email:
            key = f"e:{email}"
        elif phone:
            key = f"p:{phone}"
        else:
            key = f"n:{name.lower()}|t:{o.table_id or ''}"
        rec = by_customer[key]
        rec["key"] = key
        rec["name"] = name
        rec["email"] = email or rec["email"]
        rec["phone"] = phone or rec["phone"]
        rec["orders"] += 1
        rec["revenue"] += safe_float(o.total)
        ts = o.created_at
        if ts:
            if rec["firstSeen"] is None or ts < rec["firstSeen"]:
                rec["firstSeen"] = ts
            if rec["lastSeen"] is None or ts > rec["lastSeen"]:
                rec["lastSeen"] = ts
        if o.table_name:
            rec["tables"].add(o.table_name)

    customers = []
    now = datetime.now(timezone.utc)
    for rec in by_customer.values():
        first = rec["firstSeen"]
        last = rec["lastSeen"]
        days_active = ((last - first).days + 1) if (first and last) else 1
        avg_ticket = rec["revenue"] / rec["orders"] if rec["orders"] else 0.0
        # Simple projection: monthly revenue * 12 over active span.
        monthly_rev = (rec["revenue"] / days_active) * 30 if days_active else 0.0
        projected_ltv = monthly_rev * 12
        customers.append({
            "key": rec["key"],
            "name": rec["name"],
            "email": rec["email"],
            "phone": rec["phone"],
            "orders": rec["orders"],
            "revenue": round(rec["revenue"], 2),
            "avgTicket": round(avg_ticket, 2),
            "firstSeen": first.isoformat() if first else None,
            "lastSeen": last.isoformat() if last else None,
            "daysActive": days_active,
            "projectedLtv": round(projected_ltv, 2),
            "favoriteTables": sorted(rec["tables"])[:3],
            "daysSinceLastVisit": (now - last).days if last else None,
        })

    customers.sort(key=lambda c: -c["revenue"])

    total_revenue = sum(c["revenue"] for c in customers)
    repeat_customers = sum(1 for c in customers if c["orders"] > 1)
    churn_threshold_days = 60
    at_risk = [c for c in customers if c["daysSinceLastVisit"] is not None and c["daysSinceLastVisit"] >= churn_threshold_days and c["orders"] > 1]

    return jsonify({
        "summary": {
            "totalCustomers": len(customers),
            "repeatCustomers": repeat_customers,
            "repeatRate": round((repeat_customers / len(customers) * 100) if customers else 0, 1),
            "totalRevenue": round(total_revenue, 2),
            "avgLtv": round(total_revenue / len(customers), 2) if customers else 0,
            "atRiskCount": len(at_risk),
        },
        "customers": customers[:200],
        "atRisk": at_risk[:50],
    })
