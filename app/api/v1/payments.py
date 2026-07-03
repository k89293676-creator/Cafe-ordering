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


@bp.route("/api/payment/session", methods=["POST"])
@bp.route("/api/v1/payment/session", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
def checkout():
    """Create Stripe/Razorpay checkout session.

    Previously at /api/checkout which conflicted with the order-placement
    endpoint in orders.py.  Renamed to /api/payment/session to give each
    endpoint a distinct, unambiguous path.

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

        # ── Subscription lifecycle: update plan tier and limits ────────────
        _handle_subscription_event(event)

        return jsonify(result), 200
    except CircuitOpenError as e:
        log.warning("Stripe circuit open during webhook: %s", e)
        return jsonify({"error": "Service unavailable"}), 503
    except Exception as e:
        log.error("Stripe webhook processing failed: %s", e)
        return jsonify({"error": "Processing failed"}), 500


def _handle_subscription_event(event: "stripe.Event") -> None:  # type: ignore[name-defined]
    """Mutate Owner plan_tier + limits based on Stripe subscription lifecycle events."""
    etype = event.get("type", "")
    if etype not in {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
    }:
        return

    try:
        from app.extensions import db
        from app.models import Owner
        from flask import current_app

        sub = event["data"]["object"]
        customer_id = sub.get("customer")
        if not customer_id:
            return

        owner: Owner | None = (
            db.session.query(Owner)
            .filter_by(stripe_customer_id=customer_id)
            .first()
        )
        if owner is None:
            return

        cfg = current_app.config
        price_starter = cfg.get("STRIPE_PRICE_STARTER", "")
        price_growth = cfg.get("STRIPE_PRICE_GROWTH", "")
        price_pro = cfg.get("STRIPE_PRICE_PRO", "")

        # Bug #6 fix: _PLAN_META was out of sync with PLAN_DETAILS in
        # billing_subscription.py.  The Stripe webhook was applying different
        # table/order limits than what the subscription UI advertised.
        # Values now match PLAN_DETAILS exactly:
        #   starter → 10 tables / 500 orders
        #   growth  → 30 tables / 2000 orders
        #   pro     → unlimited
        _PLAN_META: dict[str, dict] = {
            "starter": {"max_tables": 10, "monthly_order_limit": 500},
            "growth":  {"max_tables": 30, "monthly_order_limit": 2000},
            "pro":     {"max_tables": None, "monthly_order_limit": None},
            "free":    {"max_tables": 2,  "monthly_order_limit": 50},
        }

        _PRICE_TO_PLAN: dict[str, str] = {}
        if price_starter:
            _PRICE_TO_PLAN[price_starter] = "starter"
        if price_growth:
            _PRICE_TO_PLAN[price_growth] = "growth"
        if price_pro:
            _PRICE_TO_PLAN[price_pro] = "pro"

        if etype in {"customer.subscription.deleted", "invoice.payment_failed"}:
            plan_key = "free"
        else:
            status = sub.get("status", "")
            if status in ("canceled", "past_due", "unpaid"):
                plan_key = "free"
            else:
                items = sub.get("items", {}).get("data", [])
                price_id = items[0]["price"]["id"] if items else ""
                plan_key = _PRICE_TO_PLAN.get(price_id, owner.plan_tier or "free")

        meta = _PLAN_META.get(plan_key, _PLAN_META["free"])
        owner.plan_tier = plan_key
        owner.max_tables = meta["max_tables"]
        owner.monthly_order_limit = meta["monthly_order_limit"]
        owner.stripe_subscription_id = sub.get("id") or owner.stripe_subscription_id
        db.session.commit()
        log.info("Subscription event %s → owner %s plan=%s", etype, owner.id, plan_key)
    except Exception as exc:
        log.error("_handle_subscription_event failed: %s", exc)


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
