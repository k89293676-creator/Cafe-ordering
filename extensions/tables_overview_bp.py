"""Tables Overview — at-a-glance view of every table for the owner.

Builds on the existing CafeTable + Order + TableCall data to give the
owner a single live grid showing, for every one of their tables:

    * occupancy state (free / occupied / ready-to-serve / needs-attention)
    * the open order on that table (id, status, total, items, age)
    * any open service calls (count, latest reason, latest age)
    * today's totals on that table (orders, revenue)
    * the timestamp of the last activity (order or call)

Plus per-table actions:

    * ``POST /api/owner/tables/<id>/clear``       — resolve all open calls
    * ``GET  /api/owner/tables/<id>/detail``      — recent orders + calls
    * ``POST /api/owner/tables/<id>/note``        — set a short note shown
                                                    on the card (in-memory,
                                                    per-process, 30 min TTL)

All endpoints are owner-scoped and rely on the indexes added in migration
003 (``ix_orders_owner_status_created`` etc.) so this stays cheap as the
data grows.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from threading import Lock

from flask import Blueprint, abort, jsonify, render_template, request
from sqlalchemy import func

from app import (
    CafeTable,
    Order,
    db,
    login_required,
    logged_in_owner,
    logged_in_owner_id,
    _db_update_order_status,
    _notify_owner,
    _notify_order_status,
)
from .models import TableCall


bp = Blueprint("tables_overview", __name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTIVE_ORDER_STATUSES = ("pending", "confirmed", "preparing", "ready")

# A call older than this with no acknowledgement escalates the table to
# "needs attention" so it visually pops on the grid.
CALL_ESCALATION_SECONDS = 5 * 60

# Per-process notes (ephemeral). We deliberately do NOT persist these:
# they're meant for "Birthday party — go slow" style sticky notes that
# the next shift shouldn't inherit. Cleared after 30 minutes of silence
# or when the table is cleared.
_NOTE_TTL_SECONDS = 30 * 60
_notes_lock = Lock()
_notes: dict[tuple[int, str], tuple[str, float]] = {}

# Owner-toggled "needs cleaning" flag — same ephemeral semantics as notes
# (per-process, auto-clears so the next shift starts fresh). A separate
# concept from customer-initiated service calls so a busser can mark a
# table after a guest leaves without spamming the calls queue.
_CLEANING_TTL_SECONDS = 2 * 60 * 60
_cleaning_lock = Lock()
_cleaning: dict[tuple[int, str], float] = {}


def _is_cleaning(owner_id: int, table_id: str) -> bool:
    with _cleaning_lock:
        ts = _cleaning.get((owner_id, table_id))
        if not ts:
            return False
        if (time.time() - ts) > _CLEANING_TTL_SECONDS:
            _cleaning.pop((owner_id, table_id), None)
            return False
        return True


def _set_cleaning(owner_id: int, table_id: str, on: bool) -> None:
    with _cleaning_lock:
        if on:
            _cleaning[(owner_id, table_id)] = time.time()
        else:
            _cleaning.pop((owner_id, table_id), None)


def _get_note(owner_id: int, table_id: str) -> str:
    with _notes_lock:
        item = _notes.get((owner_id, table_id))
        if not item:
            return ""
        text, ts = item
        if (time.time() - ts) > _NOTE_TTL_SECONDS:
            _notes.pop((owner_id, table_id), None)
            return ""
        return text


def _set_note(owner_id: int, table_id: str, text: str) -> None:
    text = (text or "").strip()[:200]
    with _notes_lock:
        if text:
            _notes[(owner_id, table_id)] = (text, time.time())
        else:
            _notes.pop((owner_id, table_id), None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _age_seconds(dt: datetime | None, now: datetime) -> int:
    if not dt:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return max(0, int((now - dt).total_seconds()))
    except Exception:
        return 0


def _items_count(items) -> int:
    """Best-effort line-item count regardless of the legacy items shape."""
    if not items:
        return 0
    if isinstance(items, list):
        total = 0
        for it in items:
            if isinstance(it, dict):
                try:
                    total += int(it.get("qty") or it.get("quantity") or 1)
                except (TypeError, ValueError):
                    total += 1
            else:
                total += 1
        return total
    return 0


def _classify(open_order, open_calls: list[TableCall], now: datetime,
              cleaning: bool = False) -> str:
    """Single-source-of-truth status badge for a table card."""
    # Any escalated / "bill" call is the loudest signal.
    for c in open_calls:
        if c.reason == "bill":
            return "needs_attention"
        if _age_seconds(c.created_at, now) > CALL_ESCALATION_SECONDS and c.status == "open":
            return "needs_attention"
    if open_order and open_order.status == "ready":
        return "ready_to_serve"
    if open_order or open_calls:
        return "occupied"
    if cleaning:
        return "cleaning"
    return "free"


# ---------------------------------------------------------------------------
# HTML view
# ---------------------------------------------------------------------------

@bp.route("/owner/tables/overview", endpoint="view")
@login_required
def overview_view():
    owner_id = logged_in_owner_id()
    table_count = CafeTable.query.filter_by(owner_id=owner_id).count()
    return render_template(
        "tables_overview.html",
        owner_username=logged_in_owner(),
        table_count=table_count,
    )


# ---------------------------------------------------------------------------
# JSON feed: one round-trip, no N+1
# ---------------------------------------------------------------------------

@bp.route("/api/owner/tables/overview", endpoint="api_overview")
@login_required
def api_overview():
    owner_id = logged_in_owner_id()
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # 1. Owner's tables (single query, indexed by owner_id).
    tables = (CafeTable.query
              .filter(CafeTable.owner_id == owner_id)
              .order_by(CafeTable.created_at.asc())
              .all())

    # 2. Active orders for this owner (uses ix_orders_owner_status_created).
    active_orders = (Order.query
                     .filter(Order.owner_id == owner_id,
                             Order.status.in_(ACTIVE_ORDER_STATUSES))
                     .order_by(Order.created_at.asc())
                     .all())
    orders_by_table: dict[str, Order] = {}
    for o in active_orders:
        # Keep the *oldest* open order per table — that's the one to clear.
        if o.table_id and o.table_id not in orders_by_table:
            orders_by_table[o.table_id] = o

    # 3. Open / acknowledged calls for this owner.
    open_calls = (TableCall.query
                  .filter(TableCall.owner_id == owner_id,
                          TableCall.status.in_(("open", "acknowledged")))
                  .order_by(TableCall.created_at.asc())
                  .all())
    calls_by_table: dict[str, list[TableCall]] = {}
    for c in open_calls:
        calls_by_table.setdefault(c.table_id, []).append(c)

    # 4. Today's totals per table — a single GROUP BY query.
    today_rows = (db.session.query(
                      Order.table_id,
                      func.count(Order.id),
                      func.coalesce(func.sum(Order.total), 0))
                  .filter(Order.owner_id == owner_id,
                          Order.created_at >= today_start,
                          Order.status != "cancelled")
                  .group_by(Order.table_id)
                  .all())
    today_by_table = {tid: (int(cnt), float(rev or 0)) for tid, cnt, rev in today_rows}

    # 5. Last activity timestamp per table — most recent order created_at
    #    among ALL statuses (so completed orders still count) plus most
    #    recent call. Two cheap aggregate queries instead of one per table.
    last_order_rows = (db.session.query(Order.table_id, func.max(Order.created_at))
                       .filter(Order.owner_id == owner_id)
                       .group_by(Order.table_id)
                       .all())
    last_order_by_table = {tid: ts for tid, ts in last_order_rows}

    last_call_rows = (db.session.query(TableCall.table_id, func.max(TableCall.created_at))
                      .filter(TableCall.owner_id == owner_id)
                      .group_by(TableCall.table_id)
                      .all())
    last_call_by_table = {tid: ts for tid, ts in last_call_rows}

    # --- shape payload ---------------------------------------------------
    out = []
    counts = {"free": 0, "occupied": 0, "ready_to_serve": 0, "needs_attention": 0, "cleaning": 0}
    for t in tables:
        order = orders_by_table.get(t.id)
        calls = calls_by_table.get(t.id, [])
        cleaning = _is_cleaning(owner_id, t.id)
        status = _classify(order, calls, now, cleaning=cleaning)
        counts[status] = counts.get(status, 0) + 1

        order_payload = None
        if order:
            order_payload = {
                "id": order.id,
                "status": order.status,
                "total": float(order.total or 0),
                "itemsCount": _items_count(order.items),
                "ageSeconds": _age_seconds(order.created_at, now),
                "customerName": order.customer_name or "",
                "createdAt": _iso(order.created_at),
            }

        latest_call = calls[-1] if calls else None
        calls_payload = {
            "count": len(calls),
            "latestReason": latest_call.reason if latest_call else None,
            "latestAgeSeconds": _age_seconds(latest_call.created_at, now) if latest_call else 0,
            "anyAcknowledged": any(c.status == "acknowledged" for c in calls),
        }

        today_count, today_rev = today_by_table.get(t.id, (0, 0.0))
        last_order_ts = last_order_by_table.get(t.id)
        last_call_ts = last_call_by_table.get(t.id)
        last_activity = max(filter(None, [last_order_ts, last_call_ts]), default=None)
        occupied_since = order.created_at if order else None

        out.append({
            "id": t.id,
            "name": t.name,
            "status": status,
            "openOrder": order_payload,
            "openCalls": calls_payload,
            "today": {"orders": today_count, "revenue": today_rev},
            "lastActivityAt": _iso(last_activity),
            "occupiedSinceSeconds": _age_seconds(occupied_since, now) if occupied_since else 0,
            "note": _get_note(owner_id, t.id),
            "cleaning": cleaning,
        })

    return jsonify({
        "ok": True,
        "fetchedAt": _iso(now),
        "summary": {
            "total": len(out),
            **counts,
        },
        "tables": out,
    })


# ---------------------------------------------------------------------------
# Per-table detail
# ---------------------------------------------------------------------------

@bp.route("/api/owner/tables/<table_id>/detail", endpoint="api_detail")
@login_required
def api_detail(table_id: str):
    owner_id = logged_in_owner_id()
    table = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not table:
        abort(404)
    now = datetime.now(timezone.utc)

    recent_orders = (Order.query
                     .filter(Order.owner_id == owner_id, Order.table_id == table_id)
                     .order_by(Order.created_at.desc())
                     .limit(10)
                     .all())
    recent_calls = (TableCall.query
                    .filter(TableCall.owner_id == owner_id, TableCall.table_id == table_id)
                    .order_by(TableCall.created_at.desc())
                    .limit(10)
                    .all())

    # 7-day rolling stats — single aggregate query.
    week_start = now - timedelta(days=7)
    stats_row = (db.session.query(
                     func.count(Order.id),
                     func.coalesce(func.sum(Order.total), 0),
                     func.coalesce(func.avg(Order.total), 0))
                 .filter(Order.owner_id == owner_id,
                         Order.table_id == table_id,
                         Order.created_at >= week_start,
                         Order.status != "cancelled")
                 .first())
    week_orders = int(stats_row[0] or 0)
    week_revenue = float(stats_row[1] or 0)
    week_avg_ticket = float(stats_row[2] or 0)

    # Average dwell — created_at to updated_at on completed orders this week.
    dwell_row = (db.session.query(
                     func.avg(
                         func.extract("epoch", Order.updated_at) -
                         func.extract("epoch", Order.created_at)))
                 .filter(Order.owner_id == owner_id,
                         Order.table_id == table_id,
                         Order.status == "completed",
                         Order.created_at >= week_start)
                 .first())
    avg_dwell_seconds = int(dwell_row[0] or 0) if dwell_row else 0

    return jsonify({
        "ok": True,
        "table": {"id": table.id, "name": table.name},
        "stats7d": {
            "orders": week_orders,
            "revenue": week_revenue,
            "avgTicket": week_avg_ticket,
            "avgDwellSeconds": max(0, avg_dwell_seconds),
        },
        "recentOrders": [{
            "id": o.id,
            "status": o.status,
            "total": float(o.total or 0),
            "itemsCount": _items_count(o.items),
            "customerName": o.customer_name or "",
            "ageSeconds": _age_seconds(o.created_at, now),
            "createdAt": _iso(o.created_at),
        } for o in recent_orders],
        "recentCalls": [{
            "id": c.id,
            "reason": c.reason,
            "status": c.status,
            "ageSeconds": _age_seconds(c.created_at, now),
            "createdAt": _iso(c.created_at),
            "resolvedAt": _iso(c.resolved_at),
        } for c in recent_calls],
        "note": _get_note(owner_id, table_id),
        "cleaning": _is_cleaning(owner_id, table_id),
    })


# ---------------------------------------------------------------------------
# Per-table actions
# ---------------------------------------------------------------------------

@bp.route("/api/owner/tables/<table_id>/clear", methods=["POST"], endpoint="api_clear")
@login_required
def api_clear(table_id: str):
    """Resolve every open / acknowledged service-call on this table.

    Deliberately does NOT touch active orders — completing an order has
    inventory and customer-notification side effects and belongs in the
    kitchen flow. This is a single button for "I've handled this table"
    that clears the call queue.
    """
    owner_id = logged_in_owner_id()
    table = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not table:
        abort(404)
    now = datetime.now(timezone.utc)
    calls = (TableCall.query
             .filter(TableCall.owner_id == owner_id,
                     TableCall.table_id == table_id,
                     TableCall.status.in_(("open", "acknowledged")))
             .all())
    resolved_ids = []
    for c in calls:
        if c.status == "open":
            c.acknowledged_at = c.acknowledged_at or now
        c.status = "resolved"
        c.resolved_at = now
        resolved_ids.append(c.id)
    if resolved_ids:
        db.session.commit()
    # Also clear the ephemeral note — fresh slate for the next guest.
    _set_note(owner_id, table_id, "")
    return jsonify({"ok": True, "resolvedCallIds": resolved_ids, "count": len(resolved_ids)})


@bp.route("/api/owner/tables/<table_id>/note", methods=["POST"], endpoint="api_note")
@login_required
def api_note(table_id: str):
    """Set or clear a short, ephemeral sticky note for a table card."""
    owner_id = logged_in_owner_id()
    table = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not table:
        abort(404)
    payload = request.get_json(silent=True) or request.form or {}
    text = str(payload.get("note", "")).strip()
    _set_note(owner_id, table_id, text)
    return jsonify({"ok": True, "note": _get_note(owner_id, table_id)})


@bp.route("/api/owner/tables/<table_id>/close", methods=["POST"], endpoint="api_close")
@login_required
def api_close(table_id: str):
    """Mark a table as fully done: complete its oldest open order and
    resolve every outstanding call.

    This is the single button the owner taps after a guest pays and walks
    out. Inventory was already deducted at order time, so completing here
    has no inventory side-effect — it just moves the order out of the
    active set so the kitchen and the grid both clear it.
    """
    owner_id = logged_in_owner_id()
    table = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not table:
        abort(404)
    now = datetime.now(timezone.utc)

    # Complete the oldest open order on this table (if any).
    completed_order_id = None
    open_order = (Order.query
                  .filter(Order.owner_id == owner_id,
                          Order.table_id == table_id,
                          Order.status.in_(ACTIVE_ORDER_STATUSES))
                  .order_by(Order.created_at.asc())
                  .first())
    if open_order:
        try:
            _db_update_order_status(open_order.id, "completed")
            completed_order_id = open_order.id
            try:
                _notify_owner(owner_id, "order_updated",
                              {"id": open_order.id, "status": "completed"})
                _notify_order_status(open_order.id, "completed")
            except Exception:
                pass
        except Exception:
            db.session.rollback()

    # Resolve any outstanding calls on this table.
    calls = (TableCall.query
             .filter(TableCall.owner_id == owner_id,
                     TableCall.table_id == table_id,
                     TableCall.status.in_(("open", "acknowledged")))
             .all())
    resolved_ids = []
    for c in calls:
        if c.status == "open":
            c.acknowledged_at = c.acknowledged_at or now
        c.status = "resolved"
        c.resolved_at = now
        resolved_ids.append(c.id)
    if resolved_ids:
        db.session.commit()

    # Reset the table state — fresh slate for the next guest.
    _set_note(owner_id, table_id, "")
    _set_cleaning(owner_id, table_id, True)  # auto-mark cleaning after close

    # Nudge any other connected dashboards / grids to refresh.
    try:
        _notify_owner(owner_id, "table_call_update",
                      {"tableId": table_id, "kind": "table_closed"})
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "completedOrderId": completed_order_id,
        "resolvedCallIds": resolved_ids,
    })


@bp.route("/api/owner/tables/<table_id>/transfer", methods=["POST"], endpoint="api_transfer")
@login_required
def api_transfer(table_id: str):
    """Move the oldest open order from one table to another.

    Used when a party swaps tables mid-meal (e.g. moving outside, or
    combining two tables). The order id is preserved so the kitchen
    ticket isn't disrupted — only ``table_id`` and ``table_name`` change.

    Body: ``{"targetTableId": "<id>"}``. Both tables must belong to the
    caller. Refuses to overwrite an existing open order on the target.
    """
    owner_id = logged_in_owner_id()
    src = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not src:
        abort(404)
    payload = request.get_json(silent=True) or request.form or {}
    target_id = str(payload.get("targetTableId", "")).strip()
    if not target_id or target_id == table_id:
        return jsonify({"ok": False, "error": "Invalid target table."}), 400
    target = CafeTable.query.filter_by(id=target_id, owner_id=owner_id).first()
    if not target:
        return jsonify({"ok": False, "error": "Target table not found."}), 404

    open_order = (Order.query
                  .filter(Order.owner_id == owner_id,
                          Order.table_id == table_id,
                          Order.status.in_(ACTIVE_ORDER_STATUSES))
                  .order_by(Order.created_at.asc())
                  .first())
    if not open_order:
        return jsonify({"ok": False, "error": "No open order on this table."}), 400

    # Refuse to clobber: if the target already has an open order, the
    # caller should merge manually rather than silently overwrite.
    target_busy = (db.session.query(Order.id)
                   .filter(Order.owner_id == owner_id,
                           Order.table_id == target_id,
                           Order.status.in_(ACTIVE_ORDER_STATUSES))
                   .first())
    if target_busy:
        return jsonify({"ok": False,
                        "error": "Target table already has an open order. Close it first."}), 409

    open_order.table_id = target.id
    open_order.table_name = target.name
    open_order.updated_at = datetime.now(timezone.utc)
    db.session.commit()

    # Inherit the sticky note + clear source's cleaning flag (party left).
    note = _get_note(owner_id, table_id)
    if note:
        _set_note(owner_id, target_id, note)
        _set_note(owner_id, table_id, "")

    try:
        _notify_owner(owner_id, "order_updated",
                      {"id": open_order.id, "status": open_order.status,
                       "tableId": target.id})
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "orderId": open_order.id,
        "fromTableId": table_id,
        "toTableId": target.id,
    })


@bp.route("/api/owner/tables/<table_id>/cleaning", methods=["POST"], endpoint="api_cleaning")
@login_required
def api_cleaning(table_id: str):
    """Toggle the owner-side 'needs cleaning' flag for a table.

    Body: ``{"on": true|false}``. Distinct from customer service-calls so
    a busser can flag a freshly-vacated table without polluting the call
    queue. Auto-clears after 2 hours.
    """
    owner_id = logged_in_owner_id()
    table = CafeTable.query.filter_by(id=table_id, owner_id=owner_id).first()
    if not table:
        abort(404)
    payload = request.get_json(silent=True) or request.form or {}
    on = str(payload.get("on", "")).strip().lower() in {"1", "true", "yes", "on"}
    _set_cleaning(owner_id, table_id, on)
    try:
        _notify_owner(owner_id, "table_call_update",
                      {"tableId": table_id, "kind": "cleaning", "on": on})
    except Exception:
        pass
    return jsonify({"ok": True, "cleaning": _is_cleaning(owner_id, table_id)})
