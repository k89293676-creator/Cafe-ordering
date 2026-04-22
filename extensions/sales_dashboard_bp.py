"""Interactive sales dashboard with drill-down JSON endpoints."""
from __future__ import annotations

from collections import defaultdict
from datetime import timezone

from flask import Blueprint, abort, jsonify, render_template, request

from app import Order, db, login_required, logged_in_owner_id
from ._helpers import parse_date_range, safe_float

bp = Blueprint("sales_dashboard", __name__)


@bp.route("/owner/dashboard/sales")
@login_required
def sales_dashboard_view():
    return render_template("extensions/sales_dashboard.html")


@bp.route("/api/owner/sales/summary")
@login_required
def sales_summary():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"))
    rows = (
        Order.query.filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        ).all()
    )
    total_revenue = sum(safe_float(r.total) for r in rows)
    total_orders = len(rows)
    avg_ticket = (total_revenue / total_orders) if total_orders else 0.0
    total_items = sum(len(r.items or []) for r in rows)
    return jsonify({
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "totalRevenue": round(total_revenue, 2),
        "totalOrders": total_orders,
        "avgTicket": round(avg_ticket, 2),
        "totalItems": total_items,
    })


@bp.route("/api/owner/sales/timeseries")
@login_required
def sales_timeseries():
    """Daily revenue timeseries; supports drill-down by day to hour buckets."""
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"))
    granularity = request.args.get("granularity", "day")
    rows = Order.query.filter(
        Order.owner_id == owner_id,
        Order.status == "completed",
        Order.created_at >= start_dt,
        Order.created_at <= end_dt,
    ).all()

    buckets: dict[str, dict[str, float]] = defaultdict(lambda: {"revenue": 0.0, "orders": 0})
    for o in rows:
        dt = o.created_at.astimezone(timezone.utc) if o.created_at else None
        if not dt:
            continue
        key = dt.strftime("%Y-%m-%d") if granularity == "day" else dt.strftime("%Y-%m-%d %H:00")
        buckets[key]["revenue"] += safe_float(o.total)
        buckets[key]["orders"] += 1

    series = sorted(
        [{"bucket": k, "revenue": round(v["revenue"], 2), "orders": v["orders"]}
         for k, v in buckets.items()],
        key=lambda x: x["bucket"],
    )
    return jsonify({"granularity": granularity, "series": series})


@bp.route("/api/owner/sales/by-category")
@login_required
def sales_by_category():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"))
    rows = Order.query.filter(
        Order.owner_id == owner_id,
        Order.status == "completed",
        Order.created_at >= start_dt,
        Order.created_at <= end_dt,
    ).all()
    by_cat: dict[str, dict[str, float]] = defaultdict(lambda: {"revenue": 0.0, "qty": 0})
    for o in rows:
        for it in (o.items or []):
            cat = str(it.get("category") or "Uncategorized")
            qty = int(it.get("qty") or it.get("quantity") or 1)
            line = safe_float(it.get("price")) * qty
            by_cat[cat]["revenue"] += line
            by_cat[cat]["qty"] += qty
    return jsonify({
        "categories": sorted(
            [{"category": c, "revenue": round(v["revenue"], 2), "qty": v["qty"]}
             for c, v in by_cat.items()],
            key=lambda x: -x["revenue"],
        )
    })


@bp.route("/api/owner/sales/top-items")
@login_required
def sales_top_items():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"))
    limit = max(1, min(int(request.args.get("limit", 15)), 100))
    rows = Order.query.filter(
        Order.owner_id == owner_id,
        Order.status == "completed",
        Order.created_at >= start_dt,
        Order.created_at <= end_dt,
    ).all()
    by_item: dict[str, dict[str, float]] = defaultdict(lambda: {"revenue": 0.0, "qty": 0, "name": ""})
    for o in rows:
        for it in (o.items or []):
            key = str(it.get("id") or it.get("name") or "?")
            qty = int(it.get("qty") or it.get("quantity") or 1)
            by_item[key]["name"] = str(it.get("name") or key)
            by_item[key]["qty"] += qty
            by_item[key]["revenue"] += safe_float(it.get("price")) * qty
    items = sorted(by_item.values(), key=lambda x: -x["revenue"])[:limit]
    return jsonify({"items": [
        {"name": x["name"], "qty": x["qty"], "revenue": round(x["revenue"], 2)}
        for x in items
    ]})


@bp.route("/api/owner/sales/orders")
@login_required
def sales_orders_drill():
    """Drill-down: list completed orders inside a specific bucket."""
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"), default_days=1)
    rows = (
        Order.query.filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .order_by(Order.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify({
        "orders": [
            {
                "id": o.id,
                "customerName": o.customer_name,
                "tableName": o.table_name,
                "total": safe_float(o.total),
                "createdAt": o.created_at.isoformat() if o.created_at else None,
            }
            for o in rows
        ]
    })
