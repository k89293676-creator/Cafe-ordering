"""Owner analytics and export routes."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, render_template, request

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.orders import load_orders
from app.services.tables import load_settings
from app.utils.security import login_required

bp = Blueprint("web_analytics", __name__)


@bp.route("/owner/analytics")
@login_required
def owner_analytics():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    from app.models import Order, Feedback
    now = datetime.now(timezone.utc)
    period = request.args.get("period", "30")
    try:
        days = max(1, min(int(period), 365))
    except (ValueError, TypeError):
        days = 30
    cutoff = now - timedelta(days=days)

    orders = Order.query.filter(
        Order.owner_id == owner_id,
        Order.created_at >= cutoff,
        Order.status.notin_(["cancelled", "voided"]),
    ).all()

    total_revenue = float(sum(o.total or 0 for o in orders))
    order_count = len(orders)
    avg_order_value = round(total_revenue / order_count, 2) if order_count else 0.0

    # Revenue by day
    revenue_by_day: dict[str, float] = {}
    for o in orders:
        day = (o.created_at.date() if o.created_at else now.date()).isoformat()
        revenue_by_day[day] = revenue_by_day.get(day, 0.0) + float(o.total or 0)

    # Top items
    item_counts: dict[str, dict] = {}
    for o in orders:
        for item in (o.items or []):
            iid = item.get("id", "")
            if not iid:
                continue
            if iid not in item_counts:
                item_counts[iid] = {"name": item.get("name", iid), "qty": 0, "revenue": 0.0}
            qty = int(item.get("quantity", 1))
            item_counts[iid]["qty"] += qty
            item_counts[iid]["revenue"] += float(item.get("lineTotal", 0))
    top_items = sorted(item_counts.values(), key=lambda x: x["qty"], reverse=True)[:10]

    # Avg feedback
    feedback = Feedback.query.filter(Feedback.owner_id == owner_id, Feedback.created_at >= cutoff).all()
    avg_rating = round(sum(f.rating for f in feedback) / len(feedback), 1) if feedback else 0.0

    settings = load_settings(owner_id)
    return render_template(
        "owner_analytics.html",
        owner=owner,
        settings=settings,
        days=days,
        total_revenue=total_revenue,
        order_count=order_count,
        avg_order_value=avg_order_value,
        revenue_by_day=revenue_by_day,
        top_items=top_items,
        avg_rating=avg_rating,
        feedback_count=len(feedback),
    )


@bp.route("/owner/export/orders.csv")
@login_required
@limiter.limit("10 per hour")
def export_orders_csv():
    owner_id = logged_in_owner_id()
    orders = load_orders(owner_id=owner_id, limit=5000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "createdAt", "status", "tableName", "customerName",
        "customerEmail", "customerPhone", "total", "paymentStatus", "origin",
    ])
    writer.writeheader()
    for o in orders:
        writer.writerow({
            "id": o.get("id"),
            "createdAt": o.get("createdAt", ""),
            "status": o.get("status", ""),
            "tableName": o.get("tableName", ""),
            "customerName": o.get("customerName", ""),
            "customerEmail": o.get("customerEmail", ""),
            "customerPhone": o.get("customerPhone", ""),
            "total": o.get("total", 0),
            "paymentStatus": o.get("paymentStatus", ""),
            "origin": o.get("origin", ""),
        })
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=orders.csv"},
    )
