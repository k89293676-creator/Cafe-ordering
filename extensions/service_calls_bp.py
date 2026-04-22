"""'At Your Service' table-call feature.

A customer scans the QR for their table, taps the button on the menu page,
and a TableCall row is created. Owners see open calls on their dashboard
and via SSE notifications.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, jsonify, render_template, request

from app import (
    Owner,
    csrf,
    db,
    limiter,
    load_tables,
    login_required,
    logged_in_owner_id,
    _notify_owner,
)
from .models import TableCall

bp = Blueprint("service_calls", __name__)

_TABLE_ID_RE = re.compile(r"[a-zA-Z0-9\-]{1,64}")
_VALID_REASONS = {"service", "bill", "water", "help", "cutlery"}


# ---------------------------------------------------------------------------
# Public (customer) endpoint
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call", methods=["POST"])
@limiter.limit("5 per minute; 30 per hour")
def create_table_call(table_id: str):
    """Create a new service call for the given table.

    CSRF is enforced (Flask-WTF) — table_order.html exposes the token via
    the ``csrf-token`` meta tag and the JS sends it as ``X-CSRFToken``.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")

    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason", "service")).strip().lower()[:20]
    if reason not in _VALID_REASONS:
        reason = "service"
    note = str(payload.get("note", "")).strip()[:200]

    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404, description="Unknown table.")

    owner_id = table.get("ownerId")
    cafe_id = table.get("cafeId")
    table_name = table.get("name") or table_id

    # Debounce: only block the SAME table + SAME reason within the last 90 s.
    # A different reason (e.g. "bill" after "water") always creates a new call.
    _window = datetime.now(timezone.utc) - timedelta(seconds=90)
    existing = (
        TableCall.query
        .filter_by(table_id=table_id, status="open", reason=reason)
        .filter(TableCall.created_at >= _window)
        .order_by(TableCall.created_at.desc())
        .first()
    )
    if existing:
        return jsonify({"ok": True, "call": _call_dict(existing), "deduped": True})

    call = TableCall(
        owner_id=owner_id,
        cafe_id=cafe_id,
        table_id=table_id,
        table_name=table_name,
        reason=reason,
        note=note,
        status="open",
    )
    db.session.add(call)
    db.session.commit()

    if owner_id:
        try:
            _notify_owner(owner_id, "table_call", _call_dict(call))
        except Exception:  # pragma: no cover
            pass

    return jsonify({"ok": True, "call": _call_dict(call)}), 201


# ---------------------------------------------------------------------------
# Public (customer) — poll their table's current active call
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call-status", methods=["GET"])
def table_call_status(table_id: str):
    """Return the current open or acknowledged call for the table (if any).
    No auth required — the table_id acts as the token.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")
    call = (
        TableCall.query
        .filter_by(table_id=table_id)
        .filter(TableCall.status.in_(["open", "acknowledged"]))
        .order_by(TableCall.created_at.desc())
        .first()
    )
    return jsonify({"call": _call_dict(call) if call else None})


# ---------------------------------------------------------------------------
# Owner endpoints
# ---------------------------------------------------------------------------

@bp.route("/api/owner/table-calls", methods=["GET"])
@login_required
def list_table_calls():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    status = request.args.get("status", "open")
    q = TableCall.query.filter_by(owner_id=owner_id)
    if status in {"open", "acknowledged", "resolved"}:
        q = q.filter_by(status=status)
    calls = q.order_by(TableCall.created_at.desc()).limit(100).all()
    return jsonify({"calls": [_call_dict(c) for c in calls]})


@bp.route("/api/owner/table-calls/<int:call_id>/ack", methods=["POST"])
@login_required
def acknowledge_call(call_id: int):
    return _transition_call(call_id, "acknowledged")


@bp.route("/api/owner/table-calls/<int:call_id>/resolve", methods=["POST"])
@login_required
def resolve_call(call_id: int):
    return _transition_call(call_id, "resolved")


@bp.route("/api/owner/table-calls/resolve-all", methods=["POST"])
@login_required
def resolve_all_open_calls():
    """Bulk-resolve every open or acknowledged call for this owner.

    Useful when the staff has handled a wave of calls in person and wants
    to clear the board in one tap instead of resolving them one by one.
    """
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    now = datetime.now(timezone.utc)
    calls = (
        TableCall.query
        .filter_by(owner_id=owner_id)
        .filter(TableCall.status.in_(["open", "acknowledged"]))
        .all()
    )
    resolved_payloads = []
    for call in calls:
        # Preserve the original acknowledged_at if it was a real ack, so
        # response-time stats stay accurate.
        call.status = "resolved"
        call.resolved_at = now
        resolved_payloads.append(call)
    db.session.commit()
    for call in resolved_payloads:
        try:
            _notify_owner(owner_id, "table_call_update", _call_dict(call))
        except Exception:  # pragma: no cover
            pass
    return jsonify({"ok": True, "resolved": len(resolved_payloads)})


# ---------------------------------------------------------------------------
# Public (customer) — cancel their own pending call
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call/cancel", methods=["POST"])
@limiter.limit("10 per minute; 60 per hour")
def cancel_table_call(table_id: str):
    """Customer cancels their most recent OPEN (not-yet-acknowledged) call.

    Acknowledged calls can no longer be cancelled — staff is already on the
    way. The table_id itself is the implicit auth (matches the customer's
    QR-scanned URL), same model as the public status endpoint.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")
    call = (
        TableCall.query
        .filter_by(table_id=table_id, status="open")
        .order_by(TableCall.created_at.desc())
        .first()
    )
    if not call:
        return jsonify({"ok": True, "cancelled": False})
    call.status = "resolved"
    now = datetime.now(timezone.utc)
    call.resolved_at = now
    # Tag the note so owners can see it was a customer cancel, not a real serve.
    cancel_tag = "[cancelled by customer]"
    if cancel_tag not in (call.note or ""):
        call.note = (cancel_tag + " " + (call.note or "")).strip()[:200]
    db.session.commit()
    if call.owner_id:
        try:
            _notify_owner(call.owner_id, "table_call_update", _call_dict(call))
        except Exception:  # pragma: no cover
            pass
    return jsonify({"ok": True, "cancelled": True, "call": _call_dict(call)})


def _transition_call(call_id: int, target: str):
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    call = db.session.get(TableCall, call_id)
    if not call or call.owner_id != owner_id:
        abort(404)
    call.status = target
    now = datetime.now(timezone.utc)
    if target == "acknowledged" and not call.acknowledged_at:
        call.acknowledged_at = now
    if target == "resolved":
        # IMPORTANT: do NOT backfill acknowledged_at when going directly
        # open → resolved. Doing so makes the "avg response time" metric
        # always read 0s for skip-acked calls, which is misleading.
        # Leave it null; the dashboard's metric correctly excludes calls
        # without a real acknowledged_at.
        call.resolved_at = now
    db.session.commit()
    try:
        _notify_owner(owner_id, "table_call_update", _call_dict(call))
    except Exception:  # pragma: no cover
        pass
    return jsonify({"ok": True, "call": _call_dict(call)})


def _call_dict(call: TableCall) -> dict:
    return {
        "id": call.id,
        "ownerId": call.owner_id,
        "cafeId": call.cafe_id,
        "tableId": call.table_id,
        "tableName": call.table_name,
        "reason": call.reason,
        "note": call.note or "",
        "status": call.status,
        "createdAt": call.created_at.isoformat() if call.created_at else None,
        "acknowledgedAt": call.acknowledged_at.isoformat() if call.acknowledged_at else None,
        "resolvedAt": call.resolved_at.isoformat() if call.resolved_at else None,
    }
