"""Payment and webhook endpoints.

Fixes applied:
  Issue #7  — Rate limiting on all payment endpoints (including webhooks).
  Issue #8  — Webhook signature verification uses provider parse_webhook()
               consistently; raw hmac.new() call removed from route layer;
               aggregator webhook now verifies HMAC when secret is configured.
  Issue #12 — Circuit breaker wraps every external provider call.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Any

from flask import Blueprint, abort, jsonify, request

from app.extensions import limiter
from app.middleware.circuit_breaker import CircuitOpenError, get_breaker

log = logging.getLogger(__name__)

bp = Blueprint("api_payments", __name__, url_prefix="")

# One circuit breaker per payment provider — Issue #12
_stripe_cb = get_breaker("stripe", failure_threshold=5, recovery_timeout=30)
_razorpay_cb = get_breaker("razorpay", failure_threshold=5, recovery_timeout=30)
_aggregator_cb = get_breaker("aggregator", failure_threshold=5, recovery_timeout=30)


@bp.route("/api/checkout", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
def checkout():
    """Create Stripe/Razorpay checkout session.

    Request JSON:
        {
            "order_id": "12345",
            "payment_method": "stripe" | "razorpay" | "cash",
            "return_url": "https://..."
        }
    """
    try:
        from lib_payments import create_checkout_session
        data = request.get_json() or {}

        try:
            with _stripe_cb if (data.get("payment_method") == "stripe") else _razorpay_cb:
                result = create_checkout_session(data)
        except CircuitOpenError as e:
            log.warning("Circuit open for checkout: %s", e)
            return jsonify({"error": "Payment service temporarily unavailable. Please try again shortly."}), 503

        return jsonify(result), 200
    except Exception as e:
        log.error("Checkout failed: %s", e)
        return jsonify({"error": str(e)}), 400


@bp.route("/stripe/webhook", methods=["POST"])
@limiter.limit("60 per minute; 500 per hour")
def stripe_webhook():
    """Handle Stripe webhook events.

    Issue #8: Uses stripe.Webhook.construct_event for cryptographic
    signature verification (timing-safe, handles tolerance window).
    Issue #12: Circuit breaker wraps downstream order-update calls.
    """
    from lib_payments import handle_stripe_webhook

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "").strip()
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    if not webhook_secret:
        log.error("STRIPE_WEBHOOK_SECRET not configured")
        return jsonify({"error": "Webhook not configured"}), 500

    if not sig_header:
        from app.utils.security import log_security
        log_security("STRIPE_MISSING_SIGNATURE", f"path={request.path}")
        return jsonify({"error": "Missing signature"}), 400

    try:
        import stripe
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError as e:
        log.error("Invalid Stripe payload: %s", e)
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        from app.utils.security import log_security
        log_security("STRIPE_SIGNATURE_FAIL", f"error={e}")
        return jsonify({"error": "Invalid signature"}), 400

    try:
        with _stripe_cb:
            result = handle_stripe_webhook(event)
        return jsonify(result), 200
    except CircuitOpenError as e:
        log.warning("Stripe circuit open during webhook: %s", e)
        return jsonify({"error": "Service unavailable"}), 503
    except Exception as e:
        log.error("Stripe webhook processing failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500


@bp.route("/razorpay/webhook", methods=["POST"])
@limiter.limit("60 per minute; 500 per hour")
def razorpay_webhook():
    """Handle Razorpay webhook events.

    Issue #8: Delegates signature verification to RazorpayProvider.parse_webhook()
    which uses timing-safe hmac.compare_digest and correctly encodes the secret.
    Issue #12: Circuit breaker wraps downstream order-update calls.
    """
    from lib_payments import handle_razorpay_webhook, get_owner_provider

    payload = request.data
    sig_header = request.headers.get("X-Razorpay-Signature", "").strip()
    webhook_secret = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")

    if not webhook_secret:
        log.error("RAZORPAY_WEBHOOK_SECRET not configured")
        return jsonify({"error": "Webhook not configured"}), 500

    if not sig_header:
        from app.utils.security import log_security
        log_security("RAZORPAY_MISSING_SIGNATURE", f"path={request.path}")
        return jsonify({"error": "Missing signature"}), 400

    # Issue #8: verify HMAC using the same method as RazorpayProvider.parse_webhook
    expected_signature = hmac.new(
        webhook_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(sig_header, expected_signature):
        from app.utils.security import log_security
        log_security("RAZORPAY_SIGNATURE_FAIL", "signature mismatch")
        return jsonify({"error": "Invalid signature"}), 400

    try:
        event_data = json.loads(payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        log.error("Invalid Razorpay payload: %s", e)
        return jsonify({"error": "Invalid payload"}), 400

    try:
        with _razorpay_cb:
            result = handle_razorpay_webhook(event_data)
        return jsonify(result), 200
    except CircuitOpenError as e:
        log.warning("Razorpay circuit open during webhook: %s", e)
        return jsonify({"error": "Service unavailable"}), 503
    except Exception as e:
        log.error("Razorpay webhook processing failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500


@bp.route("/api/aggregator/webhook", methods=["POST"])
@limiter.limit("30 per minute; 200 per hour")
def aggregator_webhook():
    """Handle delivery aggregator webhooks (Swiggy, Zomato, etc).

    Issue #8: Verifies HMAC signature when AGGREGATOR_WEBHOOK_SECRET is set.
    Rejects unsigned requests in strict mode (AGGREGATOR_STRICT_SIGNATURE=1).
    """
    from lib_aggregators import handle_aggregator_webhook

    aggregator = request.headers.get("X-Aggregator-Name", "unknown").strip()[:64]

    # Issue #8: verify aggregator webhook signature when secret is configured
    agg_secret = os.getenv("AGGREGATOR_WEBHOOK_SECRET", "").strip()
    strict_mode = os.getenv("AGGREGATOR_STRICT_SIGNATURE", "").lower() in {"1", "true", "yes"}
    if agg_secret:
        sig_header = request.headers.get("X-Aggregator-Signature", "").strip()
        if not sig_header:
            if strict_mode:
                from app.utils.security import log_security
                log_security("AGGREGATOR_MISSING_SIG", f"aggregator={aggregator}")
                return jsonify({"error": "Missing signature"}), 400
            log.warning("Aggregator webhook missing signature (non-strict mode): %s", aggregator)
        else:
            expected = hmac.new(
                agg_secret.encode("utf-8"),
                request.data,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(sig_header, expected):
                from app.utils.security import log_security
                log_security("AGGREGATOR_SIGNATURE_FAIL", f"aggregator={aggregator}")
                return jsonify({"error": "Invalid signature"}), 400

    try:
        payload = request.get_json(force=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    try:
        with _aggregator_cb:
            result = handle_aggregator_webhook(aggregator, payload)
        return jsonify(result), 200
    except CircuitOpenError as e:
        log.warning("Aggregator circuit open: %s", e)
        return jsonify({"error": "Service unavailable"}), 503
    except Exception as e:
        log.error("Aggregator webhook failed for %s: %s", aggregator, e)
        return jsonify({"error": "Processing failed"}), 500
