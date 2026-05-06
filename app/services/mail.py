"""Mail service: order confirmation emails."""
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
    recipient = order.get("customerEmail")
    if not recipient or not _mail_enabled():
        return
    try:
        item_lines = "\n".join(
            f"- {item.get('name')} x{item.get('quantity', 1)}: {float(item.get('lineTotal', 0)):.2f}"
            for item in order.get("items", [])
        )
        pickup_code = order.get("pickupCode", "")
        message = Message(
            subject=f"Order #{order.get('id')} confirmation",
            recipients=[recipient],
            body=(
                f"Thanks for your order, {order.get('customerName', 'Guest')}.\n\n"
                f"{item_lines}\n\n"
                f"Total: {float(order.get('total') or 0):.2f}\n"
                f"Pickup Code: {pickup_code}\n"
                f"Status: {order.get('status', 'pending')}\n"
            ),
        )
        mail.send(message)
    except Exception as exc:
        log.warning("Order confirmation email failed: %s", exc)
