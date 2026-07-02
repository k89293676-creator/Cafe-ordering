"""Webhook event admin endpoints — retry, inspect, and circuit-breaker management.

All endpoints require superadmin authentication.

Routes
------
GET  /api/v1/admin/webhooks                    List events (filterable by status/provider)
GET  /api/v1/admin/webhooks/stats              Summary counts by status
GET  /api/v1/admin/webhooks/<id>               Get one event
POST /api/v1/admin/webhooks/<id>/retry         Re-queue one event for delivery
POST /api/v1/admin/webhooks/retry-all          Re-queue all failed/dead events
DELETE /api/v1/admin/webhooks/<id>             Mark event as dead (permanent skip)

POST /api/v1/admin/circuit-breakers/<name>/reset  Manually reset a tripped circuit
GET  /api/v1/admin/circuit-breakers               List all circuit breaker states
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, jsonify, request
from sqlalchemy import func

from app.extensions import db, limiter
from app.models.billing import WebhookEventLog
from app.utils.security import log_security, superadmin_required

log = logging.getLogger("cafe.webhooks_admin")

bp = Blueprint("api_v1_webhooks_admin", __name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event_dict(ev: WebhookEventLog) -> dict:
    return {
        "id": ev.id,
        "provider": ev.provider,
        "eventId": ev.event_id,
        "intentId": ev.intent_id or "",
        "eventType": ev.event_type or "",
        "status": ev.status,
        "attempts": ev.attempts,
        "nextAttemptAt": ev.next_attempt_at.isoformat() if ev.next_attempt_at else None,
        "lastError": ev.last_error or "",
        "processed": ev.processed,
        "receivedAt": ev.received_at.isoformat() if ev.received_at else None,
        "isRetryable": ev.is_retryable,
    }


# ── Webhook event list ─────────────────────────────────────────────────────────

@bp.route("/api/v1/admin/webhooks")
@limiter.limit("30 per minute")
@superadmin_required
def list_webhook_events():
    """List webhook events with optional status / provider filters."""
    status_filter = request.args.get("status", "").strip().lower() or None
    provider_filter = request.args.get("provider", "").strip().lower() or None
    try:
        limit = max(1, min(int(request.args.get("limit", "100")), 500))
        offset = max(0, int(request.args.get("offset", "0")))
    except (TypeError, ValueError):
        limit, offset = 100, 0

    q = db.session.query(WebhookEventLog)
    if status_filter:
        q = q.filter(WebhookEventLog.status == status_filter)
    if provider_filter:
        q = q.filter(WebhookEventLog.provider == provider_filter)
    q = q.order_by(WebhookEventLog.received_at.desc())
    total = q.count()
    events = q.offset(offset).limit(limit).all()

    return jsonify(
        events=[_event_dict(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    ), 200


# ── Webhook stats ─────────────────────────────────────────────────────────────

@bp.route("/api/v1/admin/webhooks/stats")
@limiter.limit("30 per minute")
@superadmin_required
def webhook_stats():
    """Return counts grouped by status."""
    rows = (
        db.session.query(WebhookEventLog.status, func.count(WebhookEventLog.id))
        .group_by(WebhookEventLog.status)
        .all()
    )
    counts = {status: cnt for status, cnt in rows}
    total = sum(counts.values())
    return jsonify(counts=counts, total=total), 200


# ── Get one event ─────────────────────────────────────────────────────────────

@bp.route("/api/v1/admin/webhooks/<int:event_id>")
@limiter.limit("60 per minute")
@superadmin_required
def get_webhook_event(event_id: int):
    ev = db.session.get(WebhookEventLog, event_id)
    if not ev:
        abort(404, description="Webhook event not found.")
    return jsonify(event=_event_dict(ev)), 200


# ── Retry one event ───────────────────────────────────────────────────────────

@bp.route("/api/v1/admin/webhooks/<int:event_id>/retry", methods=["POST"])
@limiter.limit("20 per minute")
@superadmin_required
def retry_webhook_event(event_id: int):
    """Re-queue one webhook event for immediate re-delivery.

    Marks the event status back to ``pending`` and sets ``next_attempt_at``
    to now so the background worker picks it up on the next poll cycle.
    If no worker is running, ``enqueue_with_fallback`` triggers the retry
    in-process via the background task queue.
    """
    ev = db.session.get(WebhookEventLog, event_id)
    if not ev:
        abort(404, description="Webhook event not found.")
    if not ev.is_retryable and request.get_json(silent=True, force=True).get("force") is not True:
        return jsonify(
            error="Event is already delivered. Pass {'force': true} to override."
        ), 409

    ev.status = WebhookEventLog.STATUS_PENDING
    ev.next_attempt_at = datetime.now(timezone.utc)
    ev.last_error = ""
    db.session.commit()

    # Kick off delivery in background
    try:
        from app.tasks import enqueue_with_fallback
        from app.tasks.jobs import retry_failed_webhooks
        enqueue_with_fallback(retry_failed_webhooks)
    except Exception as exc:
        log.warning("Could not enqueue retry job: %s", exc)

    log_security("WEBHOOK_MANUAL_RETRY", f"event_id={event_id} provider={ev.provider!r}")
    return jsonify(success=True, event=_event_dict(ev)), 200


# ── Retry all failed/dead events ──────────────────────────────────────────────

@bp.route("/api/v1/admin/webhooks/retry-all", methods=["POST"])
@limiter.limit("5 per minute")
@superadmin_required
def retry_all_webhook_events():
    """Reset all ``failed`` and ``dead`` events to ``pending`` and enqueue delivery.

    Returns the count of events that were re-queued.
    """
    retryable_statuses = [WebhookEventLog.STATUS_FAILED, WebhookEventLog.STATUS_DEAD]
    payload = request.get_json(silent=True) or {}
    provider_filter = str(payload.get("provider", "")).strip().lower() or None

    q = db.session.query(WebhookEventLog).filter(
        WebhookEventLog.status.in_(retryable_statuses)
    )
    if provider_filter:
        q = q.filter(WebhookEventLog.provider == provider_filter)

    now = datetime.now(timezone.utc)
    count = 0
    for ev in q.all():
        ev.status = WebhookEventLog.STATUS_PENDING
        ev.next_attempt_at = now
        ev.last_error = ""
        count += 1

    db.session.commit()

    if count:
        try:
            from app.tasks import enqueue_with_fallback
            from app.tasks.jobs import retry_failed_webhooks
            enqueue_with_fallback(retry_failed_webhooks)
        except Exception as exc:
            log.warning("Could not enqueue retry-all job: %s", exc)

    log_security("WEBHOOK_RETRY_ALL", f"count={count} provider={provider_filter!r}")
    return jsonify(success=True, requeued=count), 200


# ── Mark event as dead (permanent skip) ──────────────────────────────────────

@bp.route("/api/v1/admin/webhooks/<int:event_id>", methods=["DELETE"])
@limiter.limit("20 per minute")
@superadmin_required
def discard_webhook_event(event_id: int):
    """Mark an event as ``dead`` so the retry worker skips it permanently."""
    ev = db.session.get(WebhookEventLog, event_id)
    if not ev:
        abort(404, description="Webhook event not found.")
    ev.status = WebhookEventLog.STATUS_DEAD
    ev.last_error = "Manually discarded by operator."
    db.session.commit()
    log_security("WEBHOOK_DISCARD", f"event_id={event_id} provider={ev.provider!r}")
    return jsonify(success=True, event=_event_dict(ev)), 200


# ── Circuit breaker management ─────────────────────────────────────────────────

@bp.route("/api/v1/admin/circuit-breakers")
@limiter.limit("30 per minute")
@superadmin_required
def list_circuit_breakers():
    """List all registered circuit breakers and their current state."""
    from app.middleware.circuit_breaker import all_breaker_stats
    stats = all_breaker_stats()
    open_count = sum(1 for s in stats if s["state"] == "OPEN")
    return jsonify(
        breakers=stats,
        total=len(stats),
        open_count=open_count,
        healthy=open_count == 0,
    ), 200


@bp.route("/api/v1/admin/circuit-breakers/<name>/reset", methods=["POST"])
@limiter.limit("10 per minute")
@superadmin_required
def reset_circuit_breaker(name: str):
    """Manually reset a named circuit breaker from OPEN → CLOSED.

    Use only after confirming the upstream service has recovered — a manual
    reset bypasses the recovery timeout and may cause further failures if
    the service is still unhealthy.
    """
    from app.middleware.circuit_breaker import reset_breaker, all_breaker_stats
    ok = reset_breaker(name)
    if not ok:
        return jsonify(
            error=f"No circuit breaker named '{name}'. "
            "Valid names: " + ", ".join(s["name"] for s in all_breaker_stats())
        ), 404
    log_security("CIRCUIT_BREAKER_RESET", f"name={name!r}")
    # Return fresh stats after reset
    from app.middleware.circuit_breaker import _registry, _registry_lock
    with _registry_lock:
        breaker = _registry.get(name)
    return jsonify(
        success=True,
        message=f"Circuit '{name}' manually reset to CLOSED.",
        breaker=breaker.stats if breaker else {},
    ), 200
