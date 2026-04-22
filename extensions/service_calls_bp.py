"""'At Your Service' table-call feature.

A customer scans the QR for their table, taps the button on the menu page,
and a TableCall row is created. Owners see open calls on their dashboard
and via SSE notifications.

Production hardening (vs the original prototype):
    * Strict reason validation (no silent fallback).
    * Strict status state machine: open -> acknowledged -> resolved (one-way).
    * Atomic cancel that races safely with staff acknowledge.
    * Public ``/call-status`` endpoint is rate-limited and returns a slim
      payload (no ownerId/cafeId leak to the dining room).
    * ``/api/owner/table-calls?status=resolved`` filters server-side to the
      last 24h so the dashboard "resolved today" stat stays accurate even
      when historical data exceeds the per-page cap.
    * Bulk resolve never overwrites a real ``acknowledged_at``.
"""
from __future__ import annotations

import json
import re
import threading as _threading
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context

from app import (
    csrf,  # noqa: F401  (re-exported import keeps blueprint import order intact)
    db,
    limiter,
    load_tables,
    login_required,
    logged_in_owner_id,
    _notify_owner,
    _notify_table_call,
    _sse_lock,
    _sse_table_subs,
)
from .models import TableCall

bp = Blueprint("service_calls", __name__)

_TABLE_ID_RE = re.compile(r"[a-zA-Z0-9\-]{1,64}")
_VALID_REASONS = {"service", "bill", "water", "help", "cutlery"}
_LIVE_STATUSES = ("open", "acknowledged")
_ALL_STATUSES = ("open", "acknowledged", "resolved")

# Allowed forward transitions. We enforce monotonic progress so a stale
# button-click in the dashboard cannot un-resolve or skip backwards.
_ALLOWED_TRANSITIONS = {
    "open":         {"acknowledged", "resolved"},
    "acknowledged": {"resolved"},
    "resolved":     set(),
}


def _validated_table(table_id: str):
    """Return the row from tables.json for ``table_id`` or abort 4xx."""
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")
    tables = load_tables()
    table = next((t for t in tables if t.get("id") == table_id), None)
    if not table:
        abort(404, description="Unknown table.")
    return table


# ---------------------------------------------------------------------------
# Public (customer) endpoint — create a call
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call", methods=["POST"])
@limiter.limit("5 per minute; 30 per hour")
def create_table_call(table_id: str):
    """Create a new service call for the given table.

    CSRF is enforced (Flask-WTF) — table_order.html exposes the token via
    the ``csrf-token`` meta tag and the JS sends it as ``X-CSRFToken``.
    """
    table = _validated_table(table_id)

    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason", "service")).strip().lower()[:20]
    if reason not in _VALID_REASONS:
        # Bad reason from a tampered client should fail loudly, not be
        # silently coerced — silent coercion has hidden real bugs in the past
        # (a typo on a button caused every "bill" tap to log as "service").
        return jsonify({"ok": False, "error": "Invalid reason."}), 400
    note = str(payload.get("note", "")).strip()[:200]

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
        return jsonify({"ok": True, "call": _public_call_dict(existing), "deduped": True})

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
            _notify_owner(owner_id, "table_call", _owner_call_dict(call))
        except Exception:  # pragma: no cover
            pass
    try:
        _notify_table_call(table_id, "table_call", _public_call_dict(call))
    except Exception:  # pragma: no cover
        pass

    return jsonify({"ok": True, "call": _public_call_dict(call)}), 201


# ---------------------------------------------------------------------------
# Public (customer) — poll their table's current active call
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call-status", methods=["GET"])
@limiter.limit("60 per minute; 600 per hour")
def table_call_status(table_id: str):
    """Return the current open or acknowledged call for the table (if any).

    No auth required — the table_id acts as the token. We rate-limit because
    every open dining-room device polls this endpoint every few seconds; an
    abusive client could otherwise hammer it.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")
    call = (
        TableCall.query
        .filter_by(table_id=table_id)
        .filter(TableCall.status.in_(_LIVE_STATUSES))
        .order_by(TableCall.created_at.desc())
        .first()
    )
    return jsonify({"call": _public_call_dict(call) if call else None})


# ---------------------------------------------------------------------------
# Public (customer) — cancel their own pending call
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call/cancel", methods=["POST"])
@limiter.limit("10 per minute; 60 per hour")
def cancel_table_call(table_id: str):
    """Customer cancels their most recent OPEN (not-yet-acknowledged) call.

    Acknowledged calls can no longer be cancelled — staff is already on the
    way. The ``table_id`` itself is the implicit auth (matches the customer's
    QR-scanned URL), the same model as the public status endpoint.

    The cancel is implemented as an atomic conditional UPDATE to avoid a
    race with staff hitting "Acknowledge" at the same instant: only rows
    still in ``status = 'open'`` flip to resolved, so a just-acknowledged
    call is left untouched.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")

    target = (
        TableCall.query
        .filter_by(table_id=table_id, status="open")
        .order_by(TableCall.created_at.desc())
        .first()
    )
    if not target:
        return jsonify({"ok": True, "cancelled": False})

    now = datetime.now(timezone.utc)
    cancel_tag = "[cancelled by customer]"
    new_note = (cancel_tag + " " + (target.note or "")).strip()[:200]

    # Conditional update — only flips if it's still open. Returns row count.
    updated = (
        TableCall.query
        .filter(TableCall.id == target.id, TableCall.status == "open")
        .update(
            {
                "status": "resolved",
                "resolved_at": now,
                "note": new_note,
            },
            synchronize_session=False,
        )
    )
    db.session.commit()

    if not updated:
        # Lost the race — staff acknowledged at the same instant. Tell the
        # customer truthfully and let the next status poll reflect reality.
        return jsonify({"ok": True, "cancelled": False, "reason": "already_acknowledged"})

    refreshed = db.session.get(TableCall, target.id)
    if refreshed and refreshed.owner_id:
        try:
            _notify_owner(refreshed.owner_id, "table_call_update", _owner_call_dict(refreshed))
        except Exception:  # pragma: no cover
            pass
    if refreshed:
        try:
            _notify_table_call(table_id, "table_call_update", _public_call_dict(refreshed))
        except Exception:  # pragma: no cover
            pass
    return jsonify(
        {
            "ok": True,
            "cancelled": True,
            "call": _public_call_dict(refreshed) if refreshed else None,
        }
    )


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
    if status in _ALL_STATUSES:
        q = q.filter_by(status=status)
        if status == "resolved":
            # Cap historical noise: resolved tab only shows the last 24h.
            # This also keeps the dashboard's "resolved today" count
            # accurate when an owner has more than 100 historical calls.
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            q = q.filter(TableCall.resolved_at >= since)
    calls = q.order_by(TableCall.created_at.desc()).limit(200).all()
    return jsonify({"calls": [_owner_call_dict(c) for c in calls]})


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

    We deliberately do NOT touch ``acknowledged_at`` — leaving any real
    acknowledgement timestamps intact so the response-time stat stays
    truthful.
    """
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    now = datetime.now(timezone.utc)
    calls = (
        TableCall.query
        .filter_by(owner_id=owner_id)
        .filter(TableCall.status.in_(_LIVE_STATUSES))
        .all()
    )
    for call in calls:
        call.status = "resolved"
        call.resolved_at = now
    db.session.commit()
    for call in calls:
        try:
            _notify_owner(owner_id, "table_call_update", _owner_call_dict(call))
        except Exception:  # pragma: no cover
            pass
        try:
            _notify_table_call(call.table_id, "table_call_update", _public_call_dict(call))
        except Exception:  # pragma: no cover
            pass
    return jsonify({"ok": True, "resolved": len(calls)})


# ---------------------------------------------------------------------------
# Owner — undo a recent resolve (reopen)
# ---------------------------------------------------------------------------

_REOPEN_GRACE_SECONDS = 90


@bp.route("/api/owner/table-calls/<int:call_id>/reopen", methods=["POST"])
@login_required
def reopen_call(call_id: int):
    """Re-open a call that was just resolved (within the last 90 s).

    This exists so an accidental resolve tap can be undone — the dashboard
    surfaces a 10-second "Undo" toast and this is the endpoint it calls.
    The grace window is enforced server-side so this can't be abused to
    revive ancient calls.
    """
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    call = db.session.get(TableCall, call_id)
    if not call or call.owner_id != owner_id:
        abort(404)
    if call.status != "resolved":
        return jsonify({"ok": False, "error": "Only resolved calls can be re-opened."}), 409
    if not call.resolved_at:
        return jsonify({"ok": False, "error": "Missing resolve timestamp."}), 409
    age = (datetime.now(timezone.utc) - call.resolved_at).total_seconds()
    if age > _REOPEN_GRACE_SECONDS:
        return jsonify({"ok": False, "error": "Undo window has expired."}), 410

    call.status = "open"
    call.resolved_at = None
    # If staff had acknowledged before resolving, keep that ack so the
    # response-time stat stays accurate. If they jumped straight to
    # resolve, leave acknowledged_at as null.
    db.session.commit()

    try:
        _notify_owner(owner_id, "table_call_update", _owner_call_dict(call))
    except Exception:  # pragma: no cover
        pass
    try:
        _notify_table_call(call.table_id, "table_call_update", _public_call_dict(call))
    except Exception:  # pragma: no cover
        pass
    return jsonify({"ok": True, "call": _owner_call_dict(call)})


# ---------------------------------------------------------------------------
# Public (customer) — SSE stream for live updates
# ---------------------------------------------------------------------------

@bp.route("/api/table/<table_id>/call/stream", methods=["GET"])
@limiter.exempt
def table_call_stream(table_id: str):
    """SSE stream of live call updates for one table.

    The customer page subscribes to this and reacts instantly when staff
    acknowledges or resolves — no polling needed. The first frame ships
    the current snapshot so a freshly-loaded page is immediately accurate.
    """
    if not _TABLE_ID_RE.fullmatch(table_id):
        abort(400, description="Invalid table id.")
    # Make sure the table actually exists (cheap defence against random IDs).
    _validated_table(table_id)

    my_queue: list[str] = []
    my_event = _threading.Event()
    _sub_entry = (my_queue, my_event)
    with _sse_lock:
        _sse_table_subs.setdefault(table_id, []).append(_sub_entry)

    # Snapshot the current live call so the very first event reflects truth.
    snapshot = (
        TableCall.query
        .filter_by(table_id=table_id)
        .filter(TableCall.status.in_(_LIVE_STATUSES))
        .order_by(TableCall.created_at.desc())
        .first()
    )
    initial = json.dumps({
        "type": "snapshot",
        "data": _public_call_dict(snapshot) if snapshot else None,
    })

    def generate():
        yield f"data: {initial}\n\n"
        last_heartbeat = time.time()
        try:
            while True:
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"
                if time.time() - last_heartbeat >= 25:
                    yield "event: ping\ndata: heartbeat\n\n"
                    last_heartbeat = time.time()
                # Wake immediately on notify; fall back to heartbeat cadence
                _wait_secs = max(0.1, 25.0 - (time.time() - last_heartbeat))
                my_event.wait(timeout=_wait_secs)
                my_event.clear()
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                subs = _sse_table_subs.get(table_id, [])
                try:
                    subs.remove(_sub_entry)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _transition_call(call_id: int, target: str):
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    call = db.session.get(TableCall, call_id)
    if not call or call.owner_id != owner_id:
        abort(404)

    current = call.status or "open"
    if target == current:
        # Idempotent — clicking "Acknowledge" twice should not error.
        return jsonify({"ok": True, "call": _owner_call_dict(call), "noop": True})
    if target not in _ALLOWED_TRANSITIONS.get(current, set()):
        # Reject backwards moves (e.g. resolved -> acknowledged) so a stale
        # dashboard tab cannot corrupt history.
        return (
            jsonify({"ok": False, "error": f"Cannot transition from {current} to {target}."}),
            409,
        )

    now = datetime.now(timezone.utc)
    call.status = target
    if target == "acknowledged" and not call.acknowledged_at:
        call.acknowledged_at = now
    if target == "resolved":
        # Do NOT backfill acknowledged_at on direct open->resolved jumps;
        # that would zero-out the "avg response time" metric.
        call.resolved_at = now
    db.session.commit()
    try:
        _notify_owner(owner_id, "table_call_update", _owner_call_dict(call))
    except Exception:  # pragma: no cover
        pass
    try:
        _notify_table_call(call.table_id, "table_call_update", _public_call_dict(call))
    except Exception:  # pragma: no cover
        pass
    return jsonify({"ok": True, "call": _owner_call_dict(call)})


def _owner_call_dict(call: TableCall) -> dict:
    """Full payload for the owner dashboard (includes IDs for routing)."""
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


def _public_call_dict(call: TableCall) -> dict:
    """Trimmed payload for the customer-facing endpoints — no internal IDs."""
    return {
        "id": call.id,
        "tableId": call.table_id,
        "reason": call.reason,
        "note": call.note or "",
        "status": call.status,
        "createdAt": call.created_at.isoformat() if call.created_at else None,
        "acknowledgedAt": call.acknowledged_at.isoformat() if call.acknowledged_at else None,
    }
