"""Extra panels for the superadmin dashboard.

Exposes JSON endpoints used by the enhanced dashboard template (top cafes,
growth, churn, system health) and a single HTML page that aggregates them.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, render_template

from app import (
    Cafe,
    Feedback,
    Order,
    Owner,
    db,
    login_required,
    superadmin_required,
)
from ._helpers import safe_float
from .models import TableCall

bp = Blueprint("superadmin_extras", __name__)


@bp.route("/superadmin/insights")
@login_required
@superadmin_required
def insights_view():
    return render_template("extensions/superadmin_panels.html")


@bp.route("/api/superadmin/top-cafes")
@login_required
@superadmin_required
def top_cafes():
    cafes = Cafe.query.all()
    out = []
    for c in cafes:
        owners = Owner.query.filter_by(cafe_id=c.id).all()
        owner_ids = [o.id for o in owners]
        if not owner_ids:
            continue
        revenue_row = (
            db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
            .filter(Order.owner_id.in_(owner_ids), Order.status == "completed")
            .scalar()
        )
        order_count = (
            db.session.query(db.func.count(Order.id))
            .filter(Order.owner_id.in_(owner_ids))
            .scalar()
        )
        feedback_avg = (
            db.session.query(db.func.avg(Feedback.rating))
            .filter(Feedback.owner_id.in_(owner_ids))
            .scalar()
        )
        out.append({
            "cafeId": c.id,
            "name": c.name,
            "isActive": bool(c.is_active),
            "revenue": round(safe_float(revenue_row), 2),
            "orders": int(order_count or 0),
            "ownerCount": len(owners),
            "avgRating": round(float(feedback_avg), 2) if feedback_avg else None,
        })
    out.sort(key=lambda x: -x["revenue"])
    return jsonify({"cafes": out[:25]})


@bp.route("/api/superadmin/growth")
@login_required
@superadmin_required
def growth_metrics():
    """Last 30 days of new owners + completed-order counts per day."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)
    owners = Owner.query.filter(Owner.created_at >= start).all()
    orders = Order.query.filter(Order.created_at >= start).all()

    owner_buckets: dict[str, int] = defaultdict(int)
    order_buckets: dict[str, int] = defaultdict(int)
    revenue_buckets: dict[str, float] = defaultdict(float)
    for o in owners:
        if o.created_at:
            owner_buckets[o.created_at.strftime("%Y-%m-%d")] += 1
    for o in orders:
        if o.created_at:
            day = o.created_at.strftime("%Y-%m-%d")
            order_buckets[day] += 1
            if o.status == "completed":
                revenue_buckets[day] += safe_float(o.total)

    days = []
    cur = start
    while cur <= end:
        key = cur.strftime("%Y-%m-%d")
        days.append({
            "day": key,
            "newOwners": owner_buckets.get(key, 0),
            "orders": order_buckets.get(key, 0),
            "revenue": round(revenue_buckets.get(key, 0.0), 2),
        })
        cur += timedelta(days=1)
    return jsonify({"days": days})


@bp.route("/api/superadmin/health")
@login_required
@superadmin_required
def health_panel():
    open_calls = TableCall.query.filter_by(status="open").count()
    inactive_owners = Owner.query.filter_by(is_active=False).count()
    inactive_cafes = Cafe.query.filter_by(is_active=False).count()
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    orders_24h = Order.query.filter(Order.created_at >= yesterday).count()
    completed_24h = Order.query.filter(
        Order.created_at >= yesterday, Order.status == "completed"
    ).count()
    return jsonify({
        "openTableCalls": open_calls,
        "inactiveOwners": inactive_owners,
        "inactiveCafes": inactive_cafes,
        "orders24h": orders_24h,
        "completed24h": completed_24h,
    })
