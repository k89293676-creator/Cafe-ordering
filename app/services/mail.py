"""Mail service: order confirmation and status-update emails.

Public API
----------
send_order_email(order)          — order confirmation (alias for legacy tasks)
send_order_status_email(order, status) — status-change notification
"""
from __future__ import annotations

import logging

from flask import current_app
from flask_mail import Message

from app.extensions import mail

log = logging.getLogger("cafe.mail")


def _mail_enabled() -> bool:
    return bool(
        current_app.config.get("MAIL_DEFAULT_SENDER")
        and current_app.config.get("MAIL_PASSWORD")
    )


def _send_order_confirmation(order: dict) -> None:
    """Send an order confirmation email to the customer."""
    recipient = order.get("customerEmail")
    if not recipient or not _mail_enabled():
        return
    try:
        item_lines = "\n".join(
            f"  - {item.get('name')} x{item.get('quantity', 1)}: "
            f"{float(item.get('lineTotal', 0)):.2f}"
            for item in order.get("items", [])
        )
        pickup_code = order.get("pickupCode", "")
        sender = current_app.config.get("MAIL_DEFAULT_SENDER") or "noreply@cafe.local"
        msg = Message(
            subject=f"Order #{order.get('id')} confirmed",
            sender=sender,
            recipients=[recipient],
            body=(
                f"Hi {order.get('customerName', 'there')},\n\n"
                f"Your order has been received!\n\n"
                f"Items:\n{item_lines}\n\n"
                f"Total: {float(order.get('total') or 0):.2f}\n"
                + (f"Pickup Code: {pickup_code}\n" if pickup_code else "")
                + f"Status: {order.get('status', 'pending')}\n\n"
                "Thank you for your order!"
            ),
        )
        mail.send(msg)
        log.info(
            "order_confirmation_email sent: order_id=%s recipient=%s",
            order.get("id"),
            recipient,
        )
    except Exception as exc:
        log.warning("Order confirmation email failed: %s", exc)


# Public alias used by tasks/jobs.py — kept consistent with the import name
send_order_email = _send_order_confirmation


def send_order_status_email(order: dict, new_status: str) -> None:
    """Notify the customer when their order status changes."""
    recipient = order.get("customerEmail")
    if not recipient or not _mail_enabled():
        return
    status_subjects = {
        "preparing": "Your order is being prepared",
        "ready":     "Your order is ready for pickup!",
        "completed": "Your order is complete — thank you!",
        "cancelled": "Your order has been cancelled",
    }
    subject = status_subjects.get(new_status, f"Order update: {new_status}")
    try:
        sender = current_app.config.get("MAIL_DEFAULT_SENDER") or "noreply@cafe.local"
        msg = Message(
            subject=subject,
            sender=sender,
            recipients=[recipient],
            body=(
                f"Hi {order.get('customerName', 'there')},\n\n"
                f"Your order #{order.get('id')} is now: {new_status}.\n\n"
                "Thank you for visiting!"
            ),
        )
        mail.send(msg)
        log.info(
            "status_update_email sent: order_id=%s status=%s",
            order.get("id"),
            new_status,
        )
    except Exception as exc:
        log.warning("Status update email failed (order %s): %s", order.get("id"), exc)
