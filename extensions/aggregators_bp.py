"""Aggregator management blueprint (Swiggy, Zomato, Uber Eats).

Extracted from the monolith; provides /owner/aggregators/* routes used by
the owner dashboard sidebar for food-delivery platform credential management
and inbound order acknowledgement.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.extensions import db, limiter
from app.models import AggregatorOrder, AggregatorPlatformCredential, Order
from app.services.auth import logged_in_owner, logged_in_owner_id
from app.utils.security import login_required
from app.utils.serializers import _no_store
from flask import make_response

from lib_aggregators import (
    PLATFORM_GUIDES,
    PLATFORM_LABELS,
    SUPPORTED_PLATFORMS,
    AggregatorError,
    build_aggregator,
)
from lib_payments import decrypt_secret, encrypt_secret

bp = Blueprint("aggregators", __name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _secret_fingerprint(secret: str) -> str:
    if not secret:
        return ""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def _aggregator_for_credential(cred: AggregatorPlatformCredential):
    try:
        secret = decrypt_secret(cred.secret_enc) if cred.secret_enc else ""
    except Exception:
        secret = ""
    return build_aggregator(
        cred.platform,
        api_key=cred.api_key or "",
        secret=secret,
        merchant_id=cred.merchant_id or "",
        mode=getattr(cred, "mode", "test") or "test",
    )


def _aggregator_credential_view(cred: AggregatorPlatformCredential) -> dict:
    try:
        secret_plain = decrypt_secret(cred.secret_enc) if cred.secret_enc else ""
    except Exception:
        secret_plain = ""
    fp = _secret_fingerprint(secret_plain)
    verified_at = getattr(cred, "verified_at", None)
    verified_fp = getattr(cred, "verified_fingerprint", "") or ""
    is_verified = bool(verified_at and verified_fp == fp and fp)
    try:
        webhook_url = url_for("aggregators_webhook", platform=cred.platform, _external=True)
    except Exception:
        webhook_url = f"/aggregators/webhook/{cred.platform}"
    return {
        "id": cred.id, "platform": cred.platform,
        "platform_label": PLATFORM_LABELS.get(cred.platform, cred.platform.title()),
        "display_name": getattr(cred, "display_name", "") or PLATFORM_LABELS.get(cred.platform, cred.platform),
        "merchant_id": cred.merchant_id or "",
        "api_key_masked": (cred.api_key or "")[:4] + "••••" if cred.api_key else "",
        "has_secret": bool(cred.secret_enc),
        "is_active": bool(getattr(cred, "is_active", False)),
        "is_verified": is_verified,
        "verified_at": verified_at,
        "last_test_status": getattr(cred, "last_test_status", None),
        "last_test_message": getattr(cred, "last_test_message", None),
        "last_tested_at": getattr(cred, "last_tested_at", None),
        "auto_accept": bool(getattr(cred, "auto_accept", False)),
        "webhook_url": webhook_url,
        "guide": PLATFORM_GUIDES.get(cred.platform, {}),
        "created_at": cred.created_at.isoformat() if getattr(cred, "created_at", None) else None,
    }


def _billing_log_safe(*, owner_id: int, order_id, action: str, amount: float = 0,
                       payment_method: str = "", reason: str = "",
                       payload: dict | None = None) -> None:
    try:
        from app.models import BillingLog
        row = BillingLog(
            owner_id=owner_id, order_id=order_id, action=action,
            actor_owner_id=session.get("owner_id"),
            actor_username=session.get("owner_username") or "",
            amount=amount, payment_method=payment_method or "",
            reason=(reason or "")[:500], payload=payload or {},
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ---------------------------------------------------------------------------
# Aggregators overview
# ---------------------------------------------------------------------------

@bp.route("/owner/aggregators")
@login_required
def owner_aggregators():
    owner_id = logged_in_owner_id()
    creds = (AggregatorPlatformCredential.query.filter_by(owner_id=owner_id)
             .order_by(AggregatorPlatformCredential.created_at.desc()).all())
    configured = {c.platform for c in creds}
    available = [{"slug": p, "label": PLATFORM_LABELS.get(p, p.title()),
                  "guide": PLATFORM_GUIDES.get(p, {})}
                 for p in SUPPORTED_PLATFORMS if p not in configured]
    recent = (AggregatorOrder.query.filter_by(owner_id=owner_id)
              .order_by(AggregatorOrder.created_at.desc()).limit(50).all())
    return _no_store(make_response(render_template(
        "owner_aggregators/index.html",
        credentials=[_aggregator_credential_view(c) for c in creds],
        available_platforms=available,
        platform_labels=PLATFORM_LABELS,
        recent_orders=recent,
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Save credential
# ---------------------------------------------------------------------------

@bp.route("/owner/aggregators/save", methods=["POST"])
@login_required
@limiter.limit("20 per hour; 5 per minute")
def owner_aggregators_save():
    owner_id = logged_in_owner_id()
    platform = (request.form.get("platform") or "").strip().lower()
    if platform not in SUPPORTED_PLATFORMS:
        flash(f"Unsupported platform: {platform!r}.", "billing_error")
        return redirect(url_for("aggregators.owner_aggregators"))
    cred = (AggregatorPlatformCredential.query
            .filter_by(owner_id=owner_id, platform=platform).first())
    is_new = cred is None
    if is_new:
        cred = AggregatorPlatformCredential(owner_id=owner_id, platform=platform)
        db.session.add(cred)
    api_key = (request.form.get("api_key") or "").strip()
    if api_key and "•" not in api_key:
        cred.api_key = api_key
    secret = (request.form.get("secret") or "").strip()
    secret_changed = False
    if secret and "•" not in secret:
        cred.secret_enc = encrypt_secret(secret)
        secret_changed = True
    mid = (request.form.get("merchant_id") or "").strip()[:100]
    if mid:
        cred.merchant_id = mid
    display_name = (request.form.get("display_name") or "").strip()[:80]
    if display_name and hasattr(cred, "display_name"):
        cred.display_name = display_name
    if hasattr(cred, "auto_accept"):
        cred.auto_accept = bool(request.form.get("auto_accept"))
    desired_active = bool(request.form.get("is_active"))
    if not cred.api_key or not cred.secret_enc or not cred.merchant_id:
        flash(f"{PLATFORM_LABELS.get(platform, platform)} requires API key, secret and merchant ID.",
              "billing_error")
        db.session.rollback()
        return redirect(url_for("aggregators.owner_aggregators"))
    if secret_changed and hasattr(cred, "verified_at"):
        cred.verified_at = None
        if hasattr(cred, "verified_fingerprint"):
            cred.verified_fingerprint = ""
    if hasattr(cred, "is_active"):
        cred.is_active = desired_active
    db.session.commit()
    _billing_log_safe(owner_id=owner_id, order_id=None,
                      action=f"aggregator.{platform}.{'created' if is_new else 'updated'}",
                      payment_method=f"aggregator:{platform}",
                      reason=f"credential {'created' if is_new else 'updated'}; active={desired_active}",
                      payload={"platform": platform, "is_active": desired_active})
    flash(f"{PLATFORM_LABELS.get(platform, platform)} {'connected' if is_new else 'updated'}.",
          "billing_ok")
    return redirect(url_for("aggregators.owner_aggregators"))


# ---------------------------------------------------------------------------
# Test connection
# ---------------------------------------------------------------------------

@bp.route("/owner/aggregators/<int:cred_id>/test", methods=["POST"])
@login_required
@limiter.limit("30 per hour; 5 per minute")
def owner_aggregators_test(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = AggregatorPlatformCredential.query.filter_by(
        id=cred_id, owner_id=owner_id).first_or_404()
    try:
        ag = _aggregator_for_credential(cred)
        msg = ag.test_connection()
        if hasattr(cred, "last_test_status"):
            cred.last_test_status = "ok"
            cred.last_test_message = msg[:500]
        if hasattr(cred, "last_tested_at"):
            cred.last_tested_at = datetime.now(timezone.utc)
        if hasattr(cred, "verified_at"):
            try:
                cred.verified_fingerprint = _secret_fingerprint(
                    decrypt_secret(cred.secret_enc) if cred.secret_enc else "")
                cred.verified_at = datetime.now(timezone.utc)
            except Exception:
                pass
        db.session.commit()
        flash(msg, "billing_ok")
    except AggregatorError as exc:
        if hasattr(cred, "last_test_status"):
            cred.last_test_status = "error"
            cred.last_test_message = str(exc)[:500]
        if hasattr(cred, "last_tested_at"):
            cred.last_tested_at = datetime.now(timezone.utc)
        db.session.commit()
        flash(f"Test failed: {exc}", "billing_error")
    except Exception as exc:
        flash(f"Unexpected error: {exc}", "billing_error")
    return redirect(url_for("aggregators.owner_aggregators"))


# ---------------------------------------------------------------------------
# Delete credential
# ---------------------------------------------------------------------------

@bp.route("/owner/aggregators/<int:cred_id>/delete", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_aggregators_delete(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = AggregatorPlatformCredential.query.filter_by(
        id=cred_id, owner_id=owner_id).first_or_404()
    typed = (request.form.get("confirm_platform") or "").strip().lower()
    if typed != cred.platform:
        flash(f"Type '{cred.platform}' to confirm deletion.", "billing_error")
        return redirect(url_for("aggregators.owner_aggregators"))
    platform = cred.platform
    db.session.delete(cred)
    db.session.commit()
    _billing_log_safe(owner_id=owner_id, order_id=None,
                      action=f"aggregator.{platform}.deleted",
                      payment_method=f"aggregator:{platform}",
                      reason="credential removed by owner", payload={"platform": platform})
    flash(f"{PLATFORM_LABELS.get(platform, platform)} disconnected.", "billing_ok")
    return redirect(url_for("aggregators.owner_aggregators"))


# ---------------------------------------------------------------------------
# Aggregator order action (accept / reject / ready)
# ---------------------------------------------------------------------------

@bp.route("/owner/aggregators/orders/<int:agg_id>/<action>", methods=["POST"])
@login_required
@limiter.limit("120 per hour")
def owner_aggregator_order_action(agg_id: int, action: str):
    owner_id = logged_in_owner_id()
    if action not in ("accept", "reject", "ready"):
        return ("bad action", 400)
    agg = AggregatorOrder.query.filter_by(id=agg_id, owner_id=owner_id).first_or_404()
    cred = AggregatorPlatformCredential.query.filter_by(
        owner_id=owner_id, platform=agg.platform,
        is_active=True).first()
    if cred is None:
        flash(f"{agg.platform} integration is not active.", "billing_error")
        return redirect(url_for("aggregators.owner_aggregators"))
    reason = (request.form.get("reason") or "").strip()[:200]
    try:
        ag = _aggregator_for_credential(cred)
        ag.acknowledge_order(external_order_id=agg.external_order_id,
                             action=action, reason=reason)
    except AggregatorError as exc:
        flash(f"Partner rejected the {action}: {exc}", "billing_error")
        return redirect(url_for("aggregators.owner_aggregators"))
    now = datetime.now(timezone.utc)
    if action == "accept":
        if hasattr(agg, "accepted_at"):
            agg.accepted_at = now
        if hasattr(agg, "aggregator_status"):
            agg.aggregator_status = "accepted"
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o and o.status in ("pending", "new"):
                o.status = "preparing"
    elif action == "reject":
        if hasattr(agg, "rejected_at"):
            agg.rejected_at = now
        if hasattr(agg, "aggregator_status"):
            agg.aggregator_status = "rejected"
        if hasattr(agg, "rejected_reason"):
            agg.rejected_reason = reason
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "cancelled"
    else:
        if hasattr(agg, "food_ready_at"):
            agg.food_ready_at = now
        if hasattr(agg, "aggregator_status"):
            agg.aggregator_status = "ready"
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "ready"
    db.session.commit()
    _billing_log_safe(owner_id=owner_id, order_id=agg.order_id,
                      action=f"aggregator.{agg.platform}.{action}",
                      amount=float(agg.total or 0),
                      payment_method=f"aggregator:{agg.platform}",
                      reason=reason or f"order {action}",
                      payload={"external_order_id": agg.external_order_id,
                               "platform": agg.platform})
    flash(f"{PLATFORM_LABELS.get(agg.platform, agg.platform)} order #{agg.external_order_id} {action}ed.",
          "billing_ok")
    return redirect(url_for("aggregators.owner_aggregators"))
