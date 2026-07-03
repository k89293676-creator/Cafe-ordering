"""Orders API — /api/v1/orders.

Fixes applied:
  Bug #1  — ResponseCache was being created as a new instance on every request,
             meaning the 5-second TTL cache provided zero benefit. Fixed by
             using a module-level singleton.
  Bug #2  — reorder_api() was missing the owner notification and confirmation
             email that checkout() sends after every new order.
  Bug #5  — No cache invalidation when order status changed. Added
             _invalidate_orders_cache() helper called on cancel/status updates
             so the live dashboard reflects changes immediately.
  Issue #6 — Request deduplication via Idempotency-Key header extended to
              cancel and reorder endpoints.
  Opt #1  — ResponseCache applied to per-owner order listing (5-second TTL).
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context

from app.extensions import db, limiter
from app.services.orders import (
    _check_stock_available,
    _db_get_order,
    _db_update_order_status,
    _restore_inventory,
    compute_order_summary,
    load_orders,
    place_order_in_db,
)
from app.services.notifications import (
    _notify_order_status,
    _notify_owner,
    _push_new_order,
    _sse_customer_subs,
    _sse_lock,
)
from app.services.menu import load_menu
from app.services.tables import load_tables
from app.utils.security import api_login_required, log_security
from app.utils.serializers import _safe_text
from app.cache import IdempotencyCache, ResponseCache, _bg_queue

bp = Blueprint("api_v1_orders", __name__)

_CANCEL_GRACE_SECONDS = 120

# Bug #1 fix: module-level singleton so the TTL cache is actually reused
# across requests and provides the intended 5-second deduplication benefit.
_orders_response_cache = ResponseCache(max_entries=500)


def _invalidate_orders_cache(owner_id: int | None) -> None:
    """Bug #5 fix: evict all cached order listings for *owner_id*.

    Called whenever an order's status changes so the live dashboard
    reflects the new state immediately instead of serving stale data
    for up to 5 seconds.
    """
    if not owner_id:
        return
    try:
        # ResponseCache.invalidate_prefix() clears all keys that start with the
        # owner prefix in a single pass.  The previous code called .delete() which
        # does not exist on ResponseCache (only .invalidate() / .invalidate_prefix()
        # do), so it was silently swallowed by the except block and invalidation
        # never actually happened.
        _orders_response_cache.invalidate_prefix(f"orders:{owner_id}:")
    except Exception:
        pass  # cache eviction failure must never block a status update


@bp.route("/api/v1/checkout", methods=["POST"])
@bp.route("/api/checkout", methods=["POST"])
@limiter.limit("10 per minute; 100 per hour")
def checkout():
    if not request.is_json:
        abort(400, description="JSON required.")
    idem_cache = IdempotencyCache(ttl_seconds=86400)
    _idem_key = (request.headers.get("Idempotency-Key") or "").strip()[:128]
    if _idem_key:
        cached = idem_cache.get("checkout", _idem_key)
        if cached is not None:
            cached_body, cached_status = cached
            return cached_body, cached_status
    payload = request.get_json(silent=True) or {}
    customer_name = _safe_text(payload.get("customerName"), max_len=100, default="Guest")
    customer_email = _safe_text(payload.get("customerEmail"), max_len=254)
    customer_phone = _safe_text(payload.get("customerPhone"), max_len=30)
    table_id = _safe_text(payload.get("tableId"), max_len=64) or None
    items = payload.get("items", [])
    notes = _safe_text(payload.get("notes"), max_len=500)

    if customer_phone and not re.fullmatch(r"[0-9+\-\s().]{3,30}", customer_phone):
        abort(400, description="Invalid phone number.")
    if customer_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", customer_email):
        abort(400, description="Invalid email address.")
    if table_id and not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400, description="Invalid table ID.")

    table_name = None
    owner_id = None
    cafe_id = None
    owner_menu = None
    if table_id:
        tables = load_tables()
        table = next((t for t in tables if t["id"] == table_id), None)
        if table:
            table_name = table["name"]
            owner_id = table.get("ownerId")
            cafe_id = table.get("cafeId")
            all_menu = load_menu()
            owner_menu = {"categories": [
                c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id
            ]}
        else:
            table_name = table_id
    else:
        table_name = "Counter"

    order_summary = compute_order_summary(items, owner_menu)

    try:
        tip = round(float(payload.get("tip", 0)), 2)
        if tip < 0 or tip > 10000:
            tip = 0.0
    except (TypeError, ValueError):
        tip = 0.0

    grand_total = round(order_summary["total"] + tip, 2)

    # ── Plan monthly order limit gate ────────────────────────────────────────
    if owner_id:
        try:
            from app.models import Owner
            from sqlalchemy import func as _func
            from app.models.orders import Order as _Order
            _owner = db.session.get(Owner, owner_id)
            if _owner:
                _limit = getattr(_owner, "monthly_order_limit", None)
                if _limit is not None:
                    _now = datetime.now(timezone.utc)
                    _month_start = _now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                    _count = (
                        db.session.query(_func.count(_Order.id))
                        .filter(_Order.owner_id == owner_id, _Order.created_at >= _month_start)
                        .scalar()
                        or 0
                    )
                    if _count >= _limit:
                        return jsonify(
                            error="Monthly order limit reached. The café owner must upgrade their plan.",
                            code="ORDER_LIMIT_EXCEEDED",
                        ), 403
        except Exception:
            pass  # Never block an order on a monitoring failure

    if owner_id:
        ok, msg = _check_stock_available(owner_id, order_summary["items"])
        if not ok:
            abort(400, description=msg)

    order_data = {
        "customerName": customer_name,
        "customerEmail": customer_email,
        "customerPhone": customer_phone,
        "tableId": table_id,
        "tableName": table_name,
        "ownerId": owner_id,
        "cafeId": cafe_id,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "items": order_summary["items"],
        "subtotal": order_summary["total"],
        "tip": tip,
        "total": grand_total,
        "status": "pending",
        "origin": "table" if table_id else "counter",
        "notes": notes,
    }
    order_record = place_order_in_db(order_data)

    if owner_id:
        _notify_owner(owner_id, "new_order", {
            "id": order_record["id"],
            "tableName": table_name,
            "customerName": customer_name,
            "total": order_record["total"],
            "status": "pending",
            "pickupCode": order_record["pickupCode"],
        })
        _bg_queue.submit(_push_new_order, owner_id, customer_name, order_record.get("total", 0),
                         _name="push_new_order")
        # Invalidate the response cache so the new order appears immediately
        _invalidate_orders_cache(owner_id)

    log_security("ORDER_PLACED", f"table={table_id!r} total={order_record['total']}")

    def _send_confirmation(rec):
        from app.services.mail import _send_order_confirmation
        _send_order_confirmation(rec)

    try:
        _bg_queue.submit(_send_confirmation, order_record, _name="send_order_confirmation")
    except Exception:
        pass

    response_payload = {
        "message": "Order placed. Pay at counter.",
        "order": order_record,
        "pickupCode": order_record["pickupCode"],
        "paymentMethod": "pay_at_counter",
    }
    if _idem_key:
        idem_cache.set("checkout", _idem_key, (response_payload, 201))
    return response_payload, 201


@bp.route("/api/v1/orders")
@bp.route("/api/orders")
@limiter.limit("60 per minute")
@api_login_required
def orders_api():
    """List orders for the logged-in owner.

    Bug #1 fix: now uses the module-level _orders_response_cache singleton
    so the 5-second TTL is effective across requests instead of creating a
    new, empty cache object on every call.
    """
    from app.services.auth import logged_in_owner_id
    owner_id = logged_in_owner_id()
    try:
        limit = int(request.args.get("limit", "100"))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = int(request.args.get("offset", "0"))
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    cache_key = f"orders:{owner_id}:limit={limit}:offset={offset}"
    orders = _orders_response_cache.get_or_set(
        cache_key,
        ttl_seconds=5,
        factory=lambda: load_orders(owner_id=owner_id, limit=limit, offset=offset),
    )
    return {"orders": orders, "limit": limit, "offset": offset, "count": len(orders)}, 200



@bp.route("/api/v1/orders/lookup")
@bp.route("/api/orders/lookup")
@limiter.limit("20 per minute")
def order_lookup_by_code():
    """Find an order by its pickup code — no auth required, used by customers."""
    from app.models import Order as _Order
    code = (request.args.get("code") or "").strip().upper()
    if not code or len(code) > 16:
        abort(400, description="Pickup code required.")
    order = (
        _Order.query
        .filter(_Order.pickup_code.ilike(code))
        .order_by(_Order.id.desc())
        .first()
    )
    if not order:
        abort(404, description="No order found with that pickup code.")
    safe_order = {
        "id":           order.id,
        "status":       order.status or "pending",
        "tableName":    getattr(order, "table_name", "") or "",
        "customerName": getattr(order, "customer_name", "") or "",
        "items":        [],
        "total":        float(getattr(order, "total", 0) or 0),
        "pickupCode":   order.pickup_code or "",
        "createdAt":    str(order.created_at) if getattr(order, "created_at", None) else "",
    }
    # Try to include items if available
    try:
        import json as _json
        raw = getattr(order, "items", None)
        if isinstance(raw, str):
            safe_order["items"] = _json.loads(raw) or []
        elif isinstance(raw, list):
            safe_order["items"] = raw
    except Exception:
        pass
    return {"order": safe_order}, 200

@bp.route("/api/v1/orders/<int:order_id>")
@bp.route("/api/orders/<int:order_id>")
@limiter.limit("20 per minute; 60 per hour")
def get_order(order_id: int):
    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")
    # IDOR fix: require the pickup code so sequential order IDs cannot be
    # enumerated by unauthenticated callers.  The cancel endpoint already
    # enforces this pattern; get_order must be consistent.
    provided_code = (request.args.get("pickup_code") or "").strip().upper()
    expected_code = (order.get("pickupCode") or "").strip().upper()
    if not expected_code or provided_code != expected_code:
        abort(403, description="pickup_code query parameter is required to view this order.")
    pay_status = order.get("paymentStatus", "unpaid")
    safe_order = {
        "id": order["id"],
        "status": order.get("status", "pending"),
        "tableName": order.get("tableName", ""),
        "customerName": order.get("customerName", ""),
        "items": order.get("items", []),
        "subtotal": order.get("subtotal", 0),
        "tip": order.get("tip", 0),
        "total": order.get("total", 0),
        "discount": order.get("discount", 0),
        "tax": order.get("tax", 0),
        "serviceCharge": order.get("serviceCharge", 0),
        "pickupCode": order.get("pickupCode", ""),
        "createdAt": order.get("createdAt", ""),
        "updatedAt": order.get("updatedAt", ""),
        "paymentStatus": pay_status,
        "paymentMethod": order.get("paymentMethod", ""),
        "balanceDue": round(float(order.get("total", 0)), 2) if pay_status != "paid" else 0.0,
        "paidAt": order.get("paidAt"),
        "invoiceNumber": order.get("invoiceNumber", ""),
    }
    return {"order": safe_order}, 200


@bp.route("/api/v1/orders/<int:order_id>/stream")
@bp.route("/api/orders/<int:order_id>/stream")
@limiter.limit("30 per minute")
def customer_order_stream(order_id: int):
    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")
    # IDOR fix: verify pickup code before opening the SSE stream so that
    # arbitrary order IDs cannot be subscribed to by unauthenticated callers.
    provided_code = (request.args.get("pickup_code") or "").strip().upper()
    expected_code = (order.get("pickupCode") or "").strip().upper()
    if not expected_code or provided_code != expected_code:
        abort(403, description="pickup_code query parameter is required.")
    initial_status = order.get("status", "pending")

    my_queue: list[str] = []
    my_event = threading.Event()
    _sub_entry = (my_queue, my_event)
    with _sse_lock:
        _sse_customer_subs.setdefault(order_id, []).append(_sub_entry)

    def generate():
        yield f"data: {json.dumps({'status': initial_status, 'id': order_id})}\n\n"
        if initial_status in ("completed", "cancelled"):
            return
        last_heartbeat = time.time()
        try:
            while True:
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"
                    try:
                        data = json.loads(payload)
                        if data.get("status") in ("completed", "cancelled"):
                            return
                    except Exception:
                        pass
                if time.time() - last_heartbeat >= 25:
                    yield "event: ping\ndata: heartbeat\n\n"
                    last_heartbeat = time.time()
                _wait_secs = max(0.1, 25.0 - (time.time() - last_heartbeat))
                my_event.wait(timeout=_wait_secs)
                my_event.clear()
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                subs = _sse_customer_subs.get(order_id, [])
                try:
                    subs.remove(_sub_entry)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@bp.route("/api/v1/orders/<int:order_id>/cancel", methods=["POST"])
@bp.route("/api/orders/<int:order_id>/cancel", methods=["POST"])
@limiter.limit("10 per minute")
def customer_cancel_order(order_id: int):
    """Cancel a pending order.

    Issue #6: Idempotency-Key support — duplicate cancel requests return
    the same 200 response instead of a confusing 409.
    Bug #5 fix: invalidates the orders response cache after cancellation.
    """
    if not request.is_json:
        abort(400, description="JSON required.")

    idem_cache = IdempotencyCache(ttl_seconds=3600)
    _idem_key = (request.headers.get("Idempotency-Key") or "").strip()[:128]
    if _idem_key:
        cached = idem_cache.get(f"cancel:{order_id}", _idem_key)
        if cached is not None:
            return cached[0], cached[1]

    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")

    # Security: verify the caller owns this order by requiring the pickup code.
    payload_json = request.get_json(silent=True) or {}
    provided_code = str(payload_json.get("pickupCode") or "").strip().upper()
    expected_code = str(order.get("pickupCode") or "").strip().upper()
    if not expected_code or provided_code != expected_code:
        abort(403, description="Invalid or missing pickup code.")

    status = order.get("status", "pending")
    if status not in ("pending",):
        return {"description": f"Order cannot be cancelled (status: {status})."}, 409
    created_at_str = order.get("createdAt", "")
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - created_at).total_seconds()
            if elapsed > _CANCEL_GRACE_SECONDS:
                return {"description": f"Cancellation window expired ({_CANCEL_GRACE_SECONDS // 60} min)."}, 409
        except (ValueError, TypeError):
            pass
    _db_update_order_status(order_id, "cancelled")
    _restore_inventory(order)
    owner_id = order.get("ownerId")
    if owner_id:
        _notify_owner(owner_id, "order_updated", {"id": order_id, "status": "cancelled"})
        # Bug #5 fix: evict cached orders so the dashboard reflects cancellation
        _invalidate_orders_cache(owner_id)
    _notify_order_status(order_id, "cancelled")
    log_security("CUSTOMER_CANCEL", f"order_id={order_id}")

    result = ({"success": True, "message": "Order cancelled successfully."}, 200)
    if _idem_key:
        idem_cache.set(f"cancel:{order_id}", _idem_key, result)
    return result


@bp.route("/api/v1/reorder/<int:order_id>", methods=["POST"])
@bp.route("/api/reorder/<int:order_id>", methods=["POST"])
@api_login_required
@limiter.limit("10 per minute")
def reorder_api(order_id: int):
    """Re-place a previous order.

    Bug #2 fix: now sends owner notification and confirmation email, matching
    the behaviour of the original checkout() endpoint.
    Issue #6: Idempotency-Key deduplication prevents accidental double-reorders.
    Bug #5 fix: invalidates the orders response cache after placing the reorder.
    """
    from app.services.auth import logged_in_owner_id
    from app.models import Order

    idem_cache = IdempotencyCache(ttl_seconds=3600)
    _idem_key = (request.headers.get("Idempotency-Key") or "").strip()[:128]
    if _idem_key:
        cached = idem_cache.get(f"reorder:{order_id}", _idem_key)
        if cached is not None:
            return jsonify(**cached[0]), cached[1]

    owner_id = logged_in_owner_id()
    original = db.session.get(Order, order_id)
    if not original or original.owner_id != owner_id:
        abort(404, description="Order not found.")
    new_data = {
        "customerName": original.customer_name,
        "customerEmail": original.customer_email,
        "customerPhone": original.customer_phone,
        "tableId": original.table_id,
        "tableName": original.table_name,
        "ownerId": original.owner_id,
        "cafeId": original.cafe_id,
        "items": original.items or [],
        "subtotal": float(original.subtotal or 0),
        "tip": 0.0,
        "total": float(original.subtotal or 0),
        "status": "pending",
        "origin": original.origin or "table",
        "notes": original.notes or "",
    }
    new_order = place_order_in_db(new_data)

    # Bug #2 fix: notify the owner and send confirmation email, matching checkout()
    if owner_id:
        _notify_owner(owner_id, "new_order", {
            "id": new_order["id"],
            "tableName": new_order.get("tableName", ""),
            "customerName": new_order.get("customerName", "Guest"),
            "total": new_order.get("total", 0),
            "status": "pending",
            "pickupCode": new_order.get("pickupCode", ""),
        })
        try:
            _bg_queue.submit(
                _push_new_order, owner_id,
                new_order.get("customerName", "Guest"),
                new_order.get("total", 0),
                _name="push_reorder",
            )
        except Exception:
            pass
        # Bug #5 fix: invalidate cache so reorder appears in live dashboard
        _invalidate_orders_cache(owner_id)

    try:
        def _send_confirmation(rec):
            from app.services.mail import _send_order_confirmation
            _send_order_confirmation(rec)

        _bg_queue.submit(_send_confirmation, new_order, _name="send_reorder_confirmation")
    except Exception:
        pass

    log_security("ORDER_REORDER", f"original_id={order_id} new_id={new_order['id']}")
    response_body = {"order": new_order, "message": "Order re-placed successfully."}
    if _idem_key:
        idem_cache.set(f"reorder:{order_id}", _idem_key, (response_body, 201))
    return jsonify(**response_body), 201
