"""Real-time dashboard stats endpoint.

Routes
------
GET /api/v1/stats/today   — today's order counts, revenue, pending, avg-order value
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify

from app.extensions import db, limiter
from app.utils.security import login_required
from app.services.auth import logged_in_owner_id

log = logging.getLogger("cafe.api.stats")

bp = Blueprint("api_v1_stats", __name__)


@bp.route("/api/v1/stats/today")
@login_required
@limiter.limit("120 per minute")
def stats_today():
    """Return today's stats.

    Response shape::

        {
            "orders":    int,
            "revenue":   float,
            "pending":   int,
            "avg_order": float | null
        }
    """
    from app.models.orders import Order
    from sqlalchemy import func

    owner_id = logged_in_owner_id()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    _CANCELLED = {"cancelled", "voided"}

    rows = (
        db.session.query(Order.created_at, Order.total, Order.status)
        .filter(Order.owner_id == owner_id, Order.created_at >= today_start)
        .all()
    )

    revenue = 0.0
    orders = 0
    pending = 0
    completed_count = 0

    for created_at, total, status in rows:
        orders += 1
        if status not in _CANCELLED:
            revenue += float(total or 0)
            completed_count += 1
        if status == "pending":
            pending += 1

    avg_order: float | None = round(revenue / completed_count, 2) if completed_count else None

    from app.models.core import Owner
    _owner = db.session.get(Owner, owner_id)
    _currency = (_owner.currency or "gbp").lower() if _owner else "gbp"
    _SYMBOLS = {
        "gbp": "£", "usd": "$", "eur": "€", "inr": "₹",
        "aud": "A$", "cad": "C$", "sgd": "S$", "aed": "د.إ",
        "nzd": "NZ$", "jpy": "¥", "cny": "¥", "krw": "₩",
    }
    _sym = _SYMBOLS.get(_currency, _currency.upper())

    return jsonify(
        orders=orders,
        revenue=round(revenue, 2),
        pending=pending,
        avg_order=avg_order,
        currency=_currency,
        currency_symbol=_sym,
    ), 200
