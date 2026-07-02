"""RQ job definitions — all functions here run inside the rqworker process.

Rules:
  - Each function must be importable without a running Flask app.
  - Use ``_get_app()`` to obtain an app context inside the job.
  - Keep jobs idempotent: the same job may be retried on failure.
  - Never import models at module level — import inside the function body.

Fixes applied:
  Bug #1 — send_order_confirmation_email: imports send_order_email (the public
             alias in mail.py) instead of the private _send_order_confirmation.
  Bug #2 — push_new_order_notification: calls _push_new_order with the correct
             (owner_id, order_id, table_name) signature.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cafe.tasks")


# ── App context helper ─────────────────────────────────────────────────────────

def _get_app():
    """Return the Flask app, creating it if necessary."""
    from app import create_app
    return create_app()


# ── Email jobs ────────────────────────────────────────────────────────────────

def send_order_confirmation_email(order_id: int) -> None:
    """Send a confirmation email for *order_id*.

    Safe to call even when mail is not configured — mail.py swallows the
    error and logs a warning instead of propagating it.
    """
    app = _get_app()
    with app.app_context():
        try:
            from app.services.mail import send_order_email  # public alias
            from app.services.orders import _db_get_order

            order = _db_get_order(order_id)
            if order and order.get("customerEmail"):
                send_order_email(order)
                log.info("order_confirmation_email sent: order_id=%s", order_id)
            else:
                log.debug(
                    "order_confirmation_email skipped: order_id=%s (no email)", order_id
                )
        except Exception:
            log.exception("send_order_confirmation_email failed: order_id=%s", order_id)
            raise


def send_status_update_email(order_id: int, new_status: str) -> None:
    """Notify the customer by email when their order status changes."""
    app = _get_app()
    with app.app_context():
        try:
            from app.services.mail import send_order_status_email
            from app.services.orders import _db_get_order

            order = _db_get_order(order_id)
            if order and order.get("customerEmail"):
                send_order_status_email(order, new_status)
                log.info(
                    "status_update_email sent: order_id=%s status=%s",
                    order_id,
                    new_status,
                )
        except Exception:
            log.exception(
                "send_status_update_email failed: order_id=%s status=%s",
                order_id,
                new_status,
            )
            raise


# ── Push notification jobs ─────────────────────────────────────────────────────

def push_new_order_notification(
    owner_id: int,
    order_id: int,
    table_name: str = "",
) -> None:
    """Deliver a Web Push notification to all subscribed owner devices.

    Fix Bug #2: previously called _push_new_order with order_id and table_name
    kwargs that didn't match the old (customer_name, total) signature. Both
    notifications.py and this call-site are now aligned.
    """
    app = _get_app()
    with app.app_context():
        try:
            from app.services.notifications import _push_new_order
            _push_new_order(
                owner_id=owner_id,
                order_id=order_id,
                table_name=table_name,
            )
            log.info(
                "push_new_order sent: owner_id=%s order_id=%s", owner_id, order_id
            )
        except Exception:
            log.exception(
                "push_new_order_notification failed: owner_id=%s order_id=%s",
                owner_id,
                order_id,
            )
            raise


# ── Aggregator sync jobs ───────────────────────────────────────────────────────

def sync_aggregator_order(aggregator_order_id: int) -> None:
    """Fetch the latest status for an aggregator order and update the DB."""
    app = _get_app()
    with app.app_context():
        try:
            from app.models import AggregatorOrder
            from app.extensions import db

            agg = db.session.get(AggregatorOrder, aggregator_order_id)
            if not agg:
                log.warning(
                    "sync_aggregator_order: id=%s not found", aggregator_order_id
                )
                return
            log.info(
                "sync_aggregator_order: id=%s platform=%s external=%s",
                aggregator_order_id,
                agg.platform,
                agg.external_order_id,
            )
        except Exception:
            log.exception(
                "sync_aggregator_order failed: id=%s", aggregator_order_id
            )
            raise


# ── Analytics pre-aggregation ──────────────────────────────────────────────────

def precompute_daily_analytics(owner_id: int, date_str: str) -> None:
    """Pre-aggregate daily revenue/order metrics and cache the result.

    *date_str* format: ``YYYY-MM-DD``.
    """
    app = _get_app()
    with app.app_context():
        try:
            from datetime import date

            from app.cache import AppCache
            from app.extensions import db
            from app.models import Order

            day = date.fromisoformat(date_str)
            orders = (
                db.session.query(Order)
                .filter(
                    Order.owner_id == owner_id,
                    db.func.date(Order.created_at) == day,
                    Order.status.notin_(["cancelled", "voided"]),
                )
                .all()
            )
            total_revenue = sum(float(o.total or 0) for o in orders)
            order_count = len(orders)
            avg_order_value = (total_revenue / order_count) if order_count else 0.0

            _cache = AppCache()
            _cache.set(
                f"analytics:daily:{owner_id}:{date_str}",
                {
                    "revenue": round(total_revenue, 2),
                    "orders": order_count,
                    "avg_order_value": round(avg_order_value, 2),
                    "date": date_str,
                },
                ttl=86400,
            )
            log.info(
                "precompute_daily_analytics: owner=%s date=%s orders=%s revenue=%.2f",
                owner_id,
                date_str,
                order_count,
                total_revenue,
            )
        except Exception:
            log.exception(
                "precompute_daily_analytics failed: owner_id=%s date=%s",
                owner_id,
                date_str,
            )
            raise


# ── Webhook retry job ──────────────────────────────────────────────────────────

def retry_failed_webhooks(owner_id: int | None = None) -> None:
    """Re-attempt delivery of pending/failed webhook events.

    Called periodically by the webhook worker or directly from an admin action.
    """
    app = _get_app()
    with app.app_context():
        try:
            from lib_webhook_retry import process_pending_webhooks  # type: ignore
            process_pending_webhooks(owner_id=owner_id)
            log.info("retry_failed_webhooks completed: owner_id=%s", owner_id)
        except ImportError:
            log.debug("lib_webhook_retry not available — skipping retry job.")
        except Exception:
            log.exception("retry_failed_webhooks failed: owner_id=%s", owner_id)
            raise
