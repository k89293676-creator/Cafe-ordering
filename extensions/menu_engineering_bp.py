"""Menu Engineering Report — popularity vs. profitability matrix.

Classifies menu items into the classic four quadrants:

* **Star**         — high popularity, high profit margin
* **Plowhorse**    — high popularity, low profit margin
* **Puzzle**       — low popularity, high profit margin
* **Dog**          — low popularity, low profit margin
"""
from __future__ import annotations

from collections import defaultdict

from flask import Blueprint, abort, jsonify, render_template, request

from app import Order, load_menu, login_required, logged_in_owner_id
from ._helpers import parse_date_range, safe_float

bp = Blueprint("menu_engineering", __name__)


@bp.route("/owner/reports/menu-engineering")
@login_required
def view():
    return render_template("extensions/menu_engineering.html")


@bp.route("/api/owner/reports/menu-engineering")
@login_required
def report():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(request.args.get("start"), request.args.get("end"), default_days=30)

    menu = load_menu()
    item_index: dict[str, dict] = {}
    for cat in menu.get("categories", []):
        if cat.get("ownerId") not in (None, owner_id):
            continue
        for it in cat.get("items", []):
            item_index[str(it.get("id"))] = {
                "id": str(it.get("id")),
                "name": it.get("name") or "?",
                "category": cat.get("name") or "Uncategorized",
                "price": safe_float(it.get("price")),
                "cost": safe_float(it.get("cost", 0)),
            }

    rows = Order.query.filter(
        Order.owner_id == owner_id,
        Order.status == "completed",
        Order.created_at >= start_dt,
        Order.created_at <= end_dt,
    ).all()

    sold: dict[str, dict[str, float]] = defaultdict(lambda: {"qty": 0, "revenue": 0.0})
    for o in rows:
        for it in (o.items or []):
            key = str(it.get("id") or it.get("name") or "?")
            qty = int(it.get("qty") or it.get("quantity") or 1)
            sold[key]["qty"] += qty
            sold[key]["revenue"] += safe_float(it.get("price")) * qty

    total_qty = sum(s["qty"] for s in sold.values()) or 1
    pop_threshold = 0.7 * (total_qty / max(len(sold), 1))  # 70% of average qty

    margins: list[float] = []
    enriched = []
    for key, s in sold.items():
        meta = item_index.get(key, {"name": key, "category": "Uncategorized", "price": 0.0, "cost": 0.0})
        unit_price = meta["price"] or (s["revenue"] / s["qty"] if s["qty"] else 0.0)
        unit_cost = meta["cost"] or 0.0
        unit_margin = unit_price - unit_cost
        margin_pct = (unit_margin / unit_price * 100.0) if unit_price else 0.0
        total_profit = unit_margin * s["qty"]
        enriched.append({
            "id": key,
            "name": meta["name"],
            "category": meta["category"],
            "qty": s["qty"],
            "revenue": round(s["revenue"], 2),
            "unitPrice": round(unit_price, 2),
            "unitCost": round(unit_cost, 2),
            "unitMargin": round(unit_margin, 2),
            "marginPct": round(margin_pct, 1),
            "totalProfit": round(total_profit, 2),
        })
        margins.append(margin_pct)

    avg_margin = sum(margins) / len(margins) if margins else 0.0

    for row in enriched:
        popular = row["qty"] >= pop_threshold
        profitable = row["marginPct"] >= avg_margin
        row["quadrant"] = (
            "star" if popular and profitable else
            "plowhorse" if popular and not profitable else
            "puzzle" if not popular and profitable else
            "dog"
        )

    enriched.sort(key=lambda x: -x["totalProfit"])
    return jsonify({
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "popularityThreshold": round(pop_threshold, 2),
        "marginThresholdPct": round(avg_margin, 1),
        "items": enriched,
    })
