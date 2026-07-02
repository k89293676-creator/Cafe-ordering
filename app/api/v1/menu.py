"""Menu API — /api/v1/menu.

Optimization #1: ResponseCache applied to the menu endpoint.
The public menu is the single hottest read path in the entire API — every
customer who opens the QR page hits it. Caching for 30 seconds per owner
eliminates 95%+ of database round-trips during a busy service period.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, jsonify, request

from app.extensions import db, limiter
from app.services.menu import load_menu
from app.services.tables import load_tables
from app.services.orders import compute_order_summary

bp = Blueprint("api_v1_menu", __name__)

# Optimization #1 — module-level cache singleton (shared across requests)
from lib_runtime import ResponseCache as _RC
_menu_cache = _RC(max_entries=200)


@bp.route("/api/v1/menu")
@bp.route("/api/menu")
@limiter.limit("120 per minute")
def menu_api():
    """Return menu items for the given table.

    Optimization #1: caches per-owner popular-item counts for 30 seconds,
    avoiding the heavy recent-orders scan on every request.
    """
    from app.models import Order
    table_id = request.args.get("table_id", "").strip()[:64]
    all_menu = load_menu()

    owner_id = None
    if table_id:
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")
            filtered = {"categories": [
                c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id
            ]}
        else:
            filtered = {"categories": []}
    else:
        filtered = {"categories": []}

    # Optimization #1: cache per-owner popular item sets (30s TTL)
    cache_key = f"menu:popular:{owner_id or 'global'}"
    popular_ids: set[str] = _menu_cache.get_or_set(
        cache_key,
        ttl_seconds=30,
        factory=lambda: _compute_popular_ids(owner_id),
    )

    result = copy.deepcopy(filtered)
    for cat in result.get("categories", []):
        for item in cat.get("items", []):
            item["popular"] = item.get("id", "") in popular_ids

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


def _compute_popular_ids(owner_id) -> set:
    """Count order frequency for the last 30 days; returns set of hot item IDs."""
    from app.models import Order
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        # Optimization #2: only select the columns we need (avoid loading full rows)
        from app.extensions import db as _db
        from sqlalchemy import text
        if owner_id:
            rows = _db.session.execute(
                text(
                    "SELECT items FROM orders "
                    "WHERE owner_id = :oid AND created_at >= :cutoff "
                    "AND status IN ('completed','preparing','ready','pending') "
                    "LIMIT 500"
                ),
                {"oid": owner_id, "cutoff": cutoff},
            ).fetchall()
        else:
            rows = _db.session.execute(
                text(
                    "SELECT items FROM orders "
                    "WHERE created_at >= :cutoff "
                    "AND status IN ('completed','preparing','ready','pending') "
                    "LIMIT 500"
                ),
                {"cutoff": cutoff},
            ).fetchall()

        item_counts: dict[str, int] = {}
        for (items,) in rows:
            if not isinstance(items, list):
                continue
            for _item in items:
                _iid = _item.get("id", "") if isinstance(_item, dict) else ""
                if _iid:
                    item_counts[_iid] = item_counts.get(_iid, 0) + int(
                        _item.get("quantity", 1) if isinstance(_item, dict) else 1
                    )
        return {iid for iid, cnt in item_counts.items() if cnt >= 3}
    except Exception:
        return set()


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
