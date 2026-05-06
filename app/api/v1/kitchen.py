"""Kitchen API — /api/v1/kitchen/orders, status updates, SSE stream."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context

from app.extensions import db, limiter
from app.services.orders import _db_update_order_status
from app.services.notifications import (
    _notify_order_status,
    _notify_owner,
    _sse_lock,
    _sse_subscribers,
)
from app.utils.security import api_login_required, log_security
from app.utils.serializers import _order_dict

bp = Blueprint("api_v1_kitchen", __name__)


@bp.route("/api/v1/kitchen/orders")
@bp.route("/api/kitchen/orders")
@limiter.limit("60 per minute")
@api_login_required
def kitchen_orders_json():
    from app.models import Order
    from app.services.auth import logged_in_owner_id
    owner_id = logged_in_owner_id()
    active_statuses = ["pending", "preparing", "ready"]
    try:
        limit = int(request.args.get("limit", "100"))
        limit = max(1, min(limit, 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        include_completed = request.args.get("include_completed", "").lower() in {"1", "true"}
    except Exception:
        include_completed = False

    query = Order.query.filter_by(owner_id=owner_id)
    if not include_completed:
        query = query.filter(Order.status.in_(active_statuses))
    else:
        query = query.order_by(Order.created_at.desc())
    orders = query.order_by(Order.created_at.asc()).limit(limit).all()
    return jsonify(orders=[_order_dict(o) for o in orders]), 200


@bp.route("/api/v1/kitchen/orders/<int:order_id>/status", methods=["POST"])
@bp.route("/api/kitchen/orders/<int:order_id>/status", methods=["POST"])
@limiter.limit("60 per minute")
@api_login_required
def kitchen_update_order_status(order_id: int):
    from app.models import Order
    from app.services.auth import logged_in_owner_id
    from app.extensions import db
    if not request.is_json:
        abort(400, description="JSON required.")
    owner_id = logged_in_owner_id()
    payload = request.get_json(silent=True) or {}
    new_status = str(payload.get("status", "")).strip().lower()
    order = db.session.get(Order, order_id)
    if not order or order.owner_id != owner_id:
        abort(404, description="Order not found.")
    if not _db_update_order_status(order_id, new_status):
        return jsonify(error=f"Invalid status transition to '{new_status}'."), 400
    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": new_status})
    _notify_order_status(order_id, new_status)
    log_security("ORDER_STATUS_UPDATE", f"order_id={order_id} status={new_status!r}")
    return jsonify(success=True, id=order_id, status=new_status), 200


@bp.route("/api/v1/orders/stream")
@bp.route("/api/orders/stream")
@limiter.limit("10 per minute")
@api_login_required
def orders_stream():
    """Owner-facing SSE stream for real-time order dashboard updates."""
    from app.services.auth import logged_in_owner_id
    owner_id = logged_in_owner_id()
    my_queue: list[str] = []
    my_event = threading.Event()
    _sub_entry = (my_queue, my_event)
    with _sse_lock:
        _sse_subscribers.setdefault(owner_id, []).append(_sub_entry)

    def generate():
        yield f"data: {json.dumps({'type': 'connected', 'owner_id': owner_id})}\n\n"
        last_heartbeat = time.time()
        try:
            while True:
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"
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
                subs = _sse_subscribers.get(owner_id, [])
                try:
                    subs.remove(_sub_entry)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
