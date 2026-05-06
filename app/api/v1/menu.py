"""Menu API — /api/v1/menu."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, jsonify, request

from app.extensions import db, limiter
from app.services.menu import load_menu
from app.services.tables import load_tables
from app.services.orders import compute_order_summary

bp = Blueprint("api_v1_menu", __name__)


@bp.route("/api/v1/menu")
@bp.route("/api/menu")
@limiter.limit("120 per minute")
def menu_api():
    from app.models import Order
    table_id = request.args.get("table_id", "").strip()[:64]
    all_menu = load_menu()

    if table_id:
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")
            filtered = {"categories": [c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id]}
        else:
            filtered = {"categories": []}
    else:
        filtered = {"categories": []}

    popular_ids: set[str] = set()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent_orders = Order.query.filter(
            Order.created_at >= cutoff,
            Order.status.in_(["completed", "preparing", "ready", "pending"]),
        ).all()
        item_counts: dict[str, int] = {}
        for _o in recent_orders:
            for _item in (_o.items or []):
                _iid = _item.get("id", "")
                if _iid:
                    item_counts[_iid] = item_counts.get(_iid, 0) + int(_item.get("quantity", 1))
        popular_ids = {iid for iid, cnt in item_counts.items() if cnt >= 3}
    except Exception:
        popular_ids = set()

    result = copy.deepcopy(filtered)
    for cat in result.get("categories", []):
        for item in cat.get("items", []):
            item["popular"] = item.get("id", "") in popular_ids

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@bp.route("/api/v1/order-preview", methods=["POST"])
@bp.route("/api/order-preview", methods=["POST"])
@limiter.limit("30 per minute")
def order_preview():
    import re
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    owner_menu = None
    if table_id and re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            all_menu = load_menu()
            owner_menu = {"categories": [
                c for c in all_menu.get("categories", []) if c.get("ownerId") == table.get("ownerId")
            ]}
    return compute_order_summary(payload.get("items", []), owner_menu), 200
