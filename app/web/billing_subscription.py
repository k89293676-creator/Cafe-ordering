"""Stripe subscription billing — plan management for café owners.

Routes
------
GET  /owner/billing/subscription         — show current plan + usage + upgrade buttons
POST /owner/billing/subscription/subscribe — create Stripe Subscription (14-day trial)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db, limiter
from app.utils.security import login_required, log_security
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.tables import load_owner_tables

log = logging.getLogger("cafe.billing_subscription")

bp = Blueprint("web_billing_subscription", __name__)

PLAN_DETAILS = {
    "starter": {
        "name": "Starter",
        "price": "£29/mo",
        "max_tables": 10,
        "monthly_order_limit": 500,
        "price_env": "STRIPE_PRICE_STARTER",
    },
    "growth": {
        "name": "Growth",
        "price": "£59/mo",
        "max_tables": 30,
        "monthly_order_limit": 2000,
        "price_env": "STRIPE_PRICE_GROWTH",
    },
    "pro": {
        "name": "Pro",
        "price": "£99/mo",
        "max_tables": None,
        "monthly_order_limit": None,
        "price_env": "STRIPE_PRICE_PRO",
    },
}


def _monthly_order_count(owner_id: int) -> int:
    """Count orders placed this calendar month (UTC)."""
    from app.models.orders import Order
    from sqlalchemy import func
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return (
        db.session.query(func.count(Order.id))
        .filter(Order.owner_id == owner_id, Order.created_at >= month_start)
        .scalar()
        or 0
    )


@bp.route("/owner/billing/subscription")
@login_required
@limiter.limit("60 per minute")
def subscription_overview():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    tables = load_owner_tables(owner_id)
    monthly_orders = _monthly_order_count(owner_id)

    return render_template(
        "owner_billing/subscribe.html",
        owner=owner,
        tables_used=len(tables),
        monthly_orders=monthly_orders,
        plans=PLAN_DETAILS,
    )


@bp.route("/owner/billing/subscription/subscribe", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def subscribe():
    """Create a Stripe Subscription with 14-day trial."""
    owner = logged_in_owner_obj()
    plan_key = (request.form.get("plan") or "").lower().strip()
    if plan_key not in PLAN_DETAILS:
        flash("Invalid plan selected.", "danger")
        return redirect(url_for("web_billing_subscription.subscription_overview"))

    price_env = PLAN_DETAILS[plan_key]["price_env"]
    price_id = current_app.config.get(price_env) or ""
    if not price_id:
        flash(f"Plan price not configured ({price_env} missing).", "danger")
        return redirect(url_for("web_billing_subscription.subscription_overview"))

    try:
        import stripe
        stripe.api_key = current_app.config.get("STRIPE_SECRET_KEY", "")

        # Create or reuse Stripe customer
        customer_id = getattr(owner, "stripe_customer_id", None) or ""
        if not customer_id:
            customer = stripe.Customer.create(
                email=owner.email or "",
                name=owner.cafe_name or owner.username,
                metadata={"owner_id": str(owner.id)},
            )
            customer_id = customer["id"]
            owner.stripe_customer_id = customer_id
            db.session.commit()

        # Create subscription with 14-day trial
        subscription = stripe.Subscription.create(
            customer=customer_id,
            items=[{"price": price_id}],
            trial_period_days=14,
            metadata={"owner_id": str(owner.id), "plan": plan_key},
        )
        owner.stripe_subscription_id = subscription["id"]

        # Update plan immediately (Stripe webhook will also update)
        plan_info = PLAN_DETAILS[plan_key]
        owner.plan_tier = plan_key
        owner.max_tables = plan_info["max_tables"]
        owner.monthly_order_limit = plan_info["monthly_order_limit"]
        owner.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=14)
        db.session.commit()

        log_security("SUBSCRIPTION_CREATED", f"owner_id={owner.id} plan={plan_key}")
        flash(
            f"You're now on the {plan_info['name']} plan! Your 14-day free trial has started.",
            "success",
        )
    except Exception as exc:  # stripe.StripeError or any other
        log.error("Stripe subscription error: %s", exc)
        flash(f"Subscription failed: {exc}", "danger")

    return redirect(url_for("web_billing_subscription.subscription_overview"))
