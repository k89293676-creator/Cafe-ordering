"""Billing summary API endpoint.

Routes
------
GET /api/v1/billing/summary  — today + 7-day billing summary with currency
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify

from app.extensions import db, limiter
from app.models import Order, Owner
from app.utils.security import login_required
from app.services.auth import logged_in_owner_id

log = logging.getLogger("cafe.api.billing_summary")

bp = Blueprint("api_v1_billing_summary", __name__)

_CURRENCY_SYMBOLS = {
    "gbp": "£", "usd": "$", "eur": "€", "inr": "₹",
    "aud": "A$", "cad": "C$", "sgd": "S$", "aed": "د.إ",
    "nzd": "NZ$", "jpy": "¥", "cny": "¥", "krw": "₩",
}


def _owner_currency(owner_id: int) -> tuple[str, str]:
    owner = db.session.get(Owner, owner_id)
    code = (getattr(owner, "currency", None) or "gbp").lower()
    return code, _CURRENCY_SYMBOLS.get(code, code.upper())


@bp.route("/api/v1/billing/summary")
@login_required
@limiter.limit("60 per minute")
def billing_summary():
    """Return today's and 7-day billing summary with currency metadata.

    Response shape::

        {
            "currency":        str,
            "currency_symbol": str,
            "today": {
                "gross_revenue":  float,
                "net_revenue":    float,
                "refunds":        float,
                "orders_paid":    int,
                "average_ticket": float | null,
                "open_tabs":      int,
                "open_value":     float,
                "refund_ratio":   float,
            },
            "week": {
                "gross_revenue": float,
                "net_revenue":   float,
                "refunds":       float,
                "orders_paid":   int,
                "days": [{"date": str, "gross": float, "net": float, "orders": int}]
            },
            "health": {
                "score":  int,
                "alerts": list[str]
            },
            "as_of": str
        }
    """
    owner_id = logged_in_owner_id()
    currency_code, currency_symbol = _owner_currency(owner_id)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    # ── Today ─────────────────────────────────────────────────────────────────
    today_rows = (
        db.session.query(Order.total, Order.refund_amount, Order.payment_status, Order.tip)
        .filter(
            Order.owner_id == owner_id,
            Order.payment_status.in_(("paid", "refunded")),
            Order.paid_at >= today_start,
        )
        .all()
    )
    today_gross = sum(float(r.total or 0) for r in today_rows)
    today_refunds = sum(float(r.refund_amount or 0) for r in today_rows)
    today_net = today_gross - today_refunds
    today_paid = len(today_rows)
    today_avg = round(today_net / today_paid, 2) if today_paid else None
    today_refund_ratio = round(today_refunds / today_gross * 100, 2) if today_gross else 0.0

    open_tabs = (
        Order.query
        .filter(
            Order.owner_id == owner_id,
            Order.payment_status == "unpaid",
            Order.status != "cancelled",
        )
        .count()
    )
    open_value = float(
        db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
        .filter(
            Order.owner_id == owner_id,
            Order.payment_status == "unpaid",
            Order.status != "cancelled",
        )
        .scalar() or 0
    )

    # ── 7-day trend ───────────────────────────────────────────────────────────
    week_rows = (
        db.session.query(
            db.func.date(Order.paid_at).label("d"),
            db.func.coalesce(db.func.sum(Order.total), 0).label("gross"),
            db.func.coalesce(db.func.sum(Order.refund_amount), 0).label("refunds"),
            db.func.count(Order.id).label("cnt"),
        )
        .filter(
            Order.owner_id == owner_id,
            Order.payment_status.in_(("paid", "refunded")),
            Order.paid_at >= week_start,
        )
        .group_by("d")
        .order_by("d")
        .all()
    )
    week_gross = sum(float(r.gross or 0) for r in week_rows)
    week_refunds = sum(float(r.refunds or 0) for r in week_rows)
    week_net = week_gross - week_refunds
    week_paid = sum(int(r.cnt or 0) for r in week_rows)
    days = [
        {
            "date": r.d.isoformat() if hasattr(r.d, "isoformat") else str(r.d),
            "gross": round(float(r.gross or 0), 2),
            "net": round(float(r.gross or 0) - float(r.refunds or 0), 2),
            "orders": int(r.cnt or 0),
        }
        for r in week_rows
    ]

    # ── Health score ──────────────────────────────────────────────────────────
    score = 100
    alerts: list[str] = []

    if today_refund_ratio > 10:
        score -= 20
        alerts.append(f"High refund ratio today: {today_refund_ratio:.1f}%")
    elif today_refund_ratio > 5:
        score -= 10
        alerts.append(f"Elevated refund ratio today: {today_refund_ratio:.1f}%")

    if open_tabs > 20:
        score -= 15
        alerts.append(f"{open_tabs} open tabs — consider settling outstanding bills")
    elif open_tabs > 10:
        score -= 5
        alerts.append(f"{open_tabs} open tabs")

    if today_paid == 0 and now.hour >= 12:
        score -= 10
        alerts.append("No paid orders recorded today — check payment flow")

    score = max(0, min(100, score))

    return jsonify(
        currency=currency_code,
        currency_symbol=currency_symbol,
        today={
            "gross_revenue": round(today_gross, 2),
            "net_revenue": round(today_net, 2),
            "refunds": round(today_refunds, 2),
            "orders_paid": today_paid,
            "average_ticket": today_avg,
            "open_tabs": open_tabs,
            "open_value": round(open_value, 2),
            "refund_ratio": today_refund_ratio,
        },
        week={
            "gross_revenue": round(week_gross, 2),
            "net_revenue": round(week_net, 2),
            "refunds": round(week_refunds, 2),
            "orders_paid": week_paid,
            "days": days,
        },
        health={"score": score, "alerts": alerts},
        as_of=now.isoformat(),
    ), 200
