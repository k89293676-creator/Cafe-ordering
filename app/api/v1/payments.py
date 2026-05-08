"""Payment and webhook endpoints."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from flask import Blueprint, request, jsonify, abort
from app.extensions import limiter

log = logging.getLogger(__name__)

bp = Blueprint("api_payments", __name__, url_prefix="")


@bp.route("/api/checkout", methods=["POST"])
@limiter.limit("10 per minute")
def checkout():
    """Create Stripe/Razorpay checkout session.

    Request JSON:
        {
            "order_id": "12345",
            "payment_method": "stripe" | "razorpay" | "cash",
            "return_url": "https://..."
        }

    Returns:
        JSON with checkout URL or confirmation
    """
    try:
        from lib_payments import create_checkout_session
        data = request.get_json() or {}
        result = create_checkout_session(data)
        return jsonify(result), 200
    except Exception as e:
        log.error("Checkout failed: %s", e)
        return jsonify({"error": str(e)}), 400


@bp.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events.

    Verifies signature and processes checkout.session.completed
    and payment_intent.succeeded events.
    """
    import os
    from lib_payments import handle_stripe_webhook

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    if not webhook_secret:
        log.error("STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({"error": "Webhook not configured"}), 500

    try:
        import stripe
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        result = handle_stripe_webhook(event)
        return jsonify(result), 200
    except ValueError as e:
        log.error("Invalid payload: %s", e)
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        from app.utils.security import log_security
        log_security("STRIPE_SIGNATURE_FAIL", f"error={e}")
        return jsonify({"error": "Invalid signature"}), 400
    except Exception as e:
        log.error("Webhook processing failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500


@bp.route("/razorpay/webhook", methods=["POST"])
def razorpay_webhook():
    """Handle Razorpay webhook events.

    Verifies signature using X-Razorpay-Signature header.
    """
    import os
    from lib_payments import handle_razorpay_webhook

    payload = request.data
    sig_header = request.headers.get("X-Razorpay-Signature")
    webhook_secret = os.getenv("RAZORPAY_WEBHOOK_SECRET")

    if not webhook_secret:
        log.error("RAZORPAY_WEBHOOK_SECRET not configured")
        return jsonify({"error": "Webhook not configured"}), 500

    try:
        expected_signature = hmac.new(
            webhook_secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(sig_header or "", expected_signature):
            from app.utils.security import log_security
            log_security("RAZORPAY_SIGNATURE_FAIL", "")
            return jsonify({"error": "Invalid signature"}), 400

        event_data = json.loads(payload)
        result = handle_razorpay_webhook(event_data)
        return jsonify(result), 200
    except Exception as e:
        log.error("Webhook processing failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500


@bp.route("/api/aggregator/webhook", methods=["POST"])
def aggregator_webhook():
    """Handle delivery aggregator webhooks (Swiggy, Zomato, etc).

    Route determined by X-Aggregator-Name header.
    """
    from lib_aggregators import handle_aggregator_webhook

    aggregator = request.headers.get("X-Aggregator-Name", "unknown")

    try:
        payload = request.get_json() or {}
        result = handle_aggregator_webhook(aggregator, payload)
        return jsonify(result), 200
    except Exception as e:
        log.error("Aggregator webhook failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500
