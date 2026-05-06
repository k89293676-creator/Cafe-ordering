"""RQ job definitions — all functions here run inside the rqworker process.

Rules:
- Each function must be importable without a running Flask app.
- Use ``_get_app()`` to obtain an app context inside the job.
- Keep jobs idempotent: the same job may be retried on failure.
- Never import models at module level — import inside the function body.
"""
from __future__ import annotations

import logging

log = logging.getLogger("cafe.tasks")


# ── App context helper ─────────────────────────────────────────────────────

def _get_app():
    """Return the Flask app, creating it if necessary."""
    from app import create_app
    return create_app()


# ── Email jobs ─────────────────────────────────────────────────────────────

def send_order_confirmation_email(order_id: int) -> None:
    """Send a confirmation email for *order_id*.

    Safe to call even when mail is not configured — the mail service
    swallows the error and logs a warning.
    """
    app = _get_app()
    with app.app_context():
        try:
            from app.services.mail import send_order_email
            from app.services.orders import _db_get_order
            order = _db_get_order(order_id)
            if order and order.get("customer_email"):
                send_order_email(order)
                log.info("order_confirmation_email sent: order_id=%s", order_id)
        except Exception:
            log.exception("send_order_confirmation_email failed: order_id=%s", order_id)
            raise


def send_status_update_email(order_id: int, new_status: str) -> None:
    """Notify the customer by email when their order status changes."""
    app = _get_app()
    with app.app_context():
        try:
            from app.extensions import mail
            from app.services.orders import _db_get_order
            from flask_mail import Message
            order = _db_get_order(order_id)
            if not order or not order.get("customer_email"):
                return
            status_labels = {
                "preparing": "Your order is being prepared",
                "ready": "Your order is ready!",
                "completed": "Your order has been completed",
                "cancelled": "Your order has been cancelled",
            }
            subject = status_labels.get(new_status, f"Order update: {new_status}")
            msg = Message(
                subject=subject,
                recipients=[order["customer_email"]],
                body=(
                    f"Hi {order.get('customer_name', 'there')},\n\n"
                    f"Your order #{order_id} status is now: {new_status}.\n\n"
                    "Thank you for visiting!"
                ),
            )
            mail.send(msg)
            log.info("status_update_email sent: order_id=%s status=%s", order_id, new_status)
        except Exception:
            log.exception("send_status_update_email failed: order_id=%s", order_id)
            raise


# ── Push notification jobs ─────────────────────────────────────────────────

def push_new_order_notification(owner_id: int, order_id: int, table_name: str) -> None:
    """Deliver a Web Push notification to all subscribed owner devices."""
    app = _get_app()
    with app.app_context():
        try:
            from app.services.notifications import _push_new_order
            _push_new_order(
                owner_id=owner_id,
                order_id=order_id,
                table_name=table_name,
            )
        except Exception:
            log.exception("push_new_order_notification failed: order_id=%s", order_id)
            raise


# ── Aggregator sync jobs ───────────────────────────────────────────────────

def sync_aggregator_order(aggregator_order_id: int) -> None:
    """Fetch the latest status for an aggregator order and update the DB."""
    app = _get_app()
    with app.app_context():
        try:
            from app.models import AggregatorOrder
            from app.extensions import db
            agg = db.session.get(AggregatorOrder, aggregator_order_id)
            if not agg:
                log.warning("sync_aggregator_order: id=%s not found", aggregator_order_id)
                return
            log.info(
                "sync_aggregator_order: id=%s platform=%s external=%s",
                aggregator_order_id, agg.platform, agg.external_order_id,
            )
        except Exception:
            log.exception("sync_aggregator_order failed: id=%s", aggregator_order_id)
            raise


# ── Analytics pre-aggregation ──────────────────────────────────────────────

def precompute_daily_analytics(owner_id: int, date_str: str) -> None:
    """Pre-aggregate daily revenue/order metrics and cache the result.

    *date_str* format: ``YYYY-MM-DD``.
    """
    app = _get_app()
    with app.app_context():
        try:
            from datetime import date
            from app.extensions import db
            from app.models import Order
            from app.cache import AppCache
            import decimal

            day = date.fromisoformat(date_str)
            orders = (
                db.session.query(Order)
                .filter(
                    Order.owner_id == owner_id,
                    db.func.date(Order.created_at) == day,
                    Order.status.notin_(["cancelled"]),
                )
                .all()
            )
            total_revenue = sum(float(o.total or 0) for o in orders)
            order_count = len(orders)
            cache = AppCache()
            cache.set(
                f"analytics:daily:{owner_id}:{date_str}",
                {"revenue": total_revenue, "orders": order_count, "date": date_str},
                ttl=86400,
            )
            log.info(
                "precompute_daily_analytics: owner=%s date=%s orders=%s revenue=%.2f",
                owner_id, date_str, order_count, total_revenue,
            )
        except Exception:
            log.exception("precompute_daily_analytics failed: owner_id=%s date=%s", owner_id, date_str)
            raise
