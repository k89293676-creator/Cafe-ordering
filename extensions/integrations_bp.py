"""Integrations hub blueprint.

Provides /owner/integrations/* routes: the unified overview of every
external service (payment gateways + food-delivery aggregators) with
one-click test-all and email-me-the-setup-link functionality.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db, limiter
from app.models import AggregatorPlatformCredential, PaymentProviderCredential
from app.services.auth import logged_in_owner, logged_in_owner_id, logged_in_owner_obj
from app.utils.security import login_required
from app.utils.serializers import _no_store
from flask import make_response

from lib_payments import (
    PROVIDER_GUIDES,
    PROVIDER_LABELS,
    SUPPORTED_PROVIDERS,
    PaymentProviderError,
    build_provider,
    decrypt_secret,
)
from lib_aggregators import (
    PLATFORM_GUIDES,
    PLATFORM_LABELS,
    SUPPORTED_PLATFORMS,
    AggregatorError,
    build_aggregator,
)

bp = Blueprint("integrations", __name__)

_IH_CATEGORY_LABELS = [
    ("payment", "Payment Gateways"),
    ("delivery", "Food Delivery Aggregators"),
    ("notification", "Notifications"),
]


@dataclass
class IntegrationCard:
    key: str
    provider_type: str          # "payment" | "aggregator"
    category: str               # "payment" | "delivery" | "notification"
    label: str
    status: str                 # "connected" | "unverified" | "error" | "not_configured"
    is_active: bool
    last_test_status: str | None
    last_test_message: str | None
    manage_url: str
    webhook_url: str
    guide: dict = field(default_factory=dict)


def _ih_payment_status(cred: PaymentProviderCredential) -> str:
    if not cred.is_active:
        return "not_configured"
    if cred.last_test_status == "ok":
        return "connected"
    if cred.last_test_status == "error":
        return "error"
    return "unverified"


def _ih_aggregator_status(cred: AggregatorPlatformCredential) -> str:
    is_active = getattr(cred, "is_active", False)
    if not is_active:
        return "not_configured"
    last_status = getattr(cred, "last_test_status", None)
    if last_status == "ok":
        return "connected"
    if last_status == "error":
        return "error"
    return "unverified"


def _ih_owner_payment_views(owner_id: int) -> list[dict]:
    creds = (PaymentProviderCredential.query.filter_by(owner_id=owner_id)
             .order_by(PaymentProviderCredential.updated_at.desc()).all())
    return [{
        "id": c.id, "provider": c.provider,
        "label": PROVIDER_LABELS.get(c.provider, c.provider.title()),
        "is_active": bool(c.is_active), "mode": c.mode,
        "status": _ih_payment_status(c),
        "last_test_status": c.last_test_status,
        "last_test_message": c.last_test_message,
        "last_tested_at": c.last_tested_at.isoformat() if c.last_tested_at else None,
        "guide": PROVIDER_GUIDES.get(c.provider, {}),
    } for c in creds]


def _ih_owner_aggregator_views(owner_id: int) -> list[dict]:
    creds = (AggregatorPlatformCredential.query.filter_by(owner_id=owner_id)
             .order_by(AggregatorPlatformCredential.updated_at.desc()).all())
    return [{
        "id": c.id, "platform": c.platform,
        "label": PLATFORM_LABELS.get(c.platform, c.platform.title()),
        "is_active": bool(getattr(c, "is_active", False)),
        "status": _ih_aggregator_status(c),
        "last_test_status": getattr(c, "last_test_status", None),
        "last_test_message": getattr(c, "last_test_message", None),
        "guide": PLATFORM_GUIDES.get(c.platform, {}),
    } for c in creds]


def _ih_build_cards(owner_id: int) -> list[IntegrationCard]:
    cards = []
    pay_creds = PaymentProviderCredential.query.filter_by(owner_id=owner_id).all()
    pay_dict = {c.provider: c for c in pay_creds}
    for prov in SUPPORTED_PROVIDERS:
        cred = pay_dict.get(prov)
        if cred:
            status = _ih_payment_status(cred)
            is_active = bool(cred.is_active)
            last_status = cred.last_test_status
            last_msg = cred.last_test_message
        else:
            status = "not_configured"
            is_active = False
            last_status = None
            last_msg = None
        try:
            webhook_url = url_for("billing_webhook", provider=prov, _external=True)
        except Exception:
            webhook_url = f"/billing/webhook/{prov}"
        cards.append(IntegrationCard(
            key=prov, provider_type="payment", category="payment",
            label=PROVIDER_LABELS.get(prov, prov.title()),
            status=status, is_active=is_active,
            last_test_status=last_status, last_test_message=last_msg,
            manage_url=url_for("billing.owner_billing_payment_methods"),
            webhook_url=webhook_url,
            guide=PROVIDER_GUIDES.get(prov, {}),
        ))
    agg_creds = AggregatorPlatformCredential.query.filter_by(owner_id=owner_id).all()
    agg_dict = {c.platform: c for c in agg_creds}
    for plat in SUPPORTED_PLATFORMS:
        cred = agg_dict.get(plat)
        if cred:
            status = _ih_aggregator_status(cred)
            is_active = bool(getattr(cred, "is_active", False))
            last_status = getattr(cred, "last_test_status", None)
            last_msg = getattr(cred, "last_test_message", None)
        else:
            status = "not_configured"
            is_active = False
            last_status = None
            last_msg = None
        try:
            webhook_url = url_for("aggregators_webhook", platform=plat, _external=True)
        except Exception:
            webhook_url = f"/aggregators/webhook/{plat}"
        cards.append(IntegrationCard(
            key=plat, provider_type="aggregator", category="delivery",
            label=PLATFORM_LABELS.get(plat, plat.title()),
            status=status, is_active=is_active,
            last_test_status=last_status, last_test_message=last_msg,
            manage_url=url_for("aggregators.owner_aggregators"),
            webhook_url=webhook_url,
            guide=PLATFORM_GUIDES.get(plat, {}),
        ))
    return cards


@dataclass
class ReadinessItem:
    key: str
    severity: str
    label: str
    detail: str
    fix_hint: str


def _ih_readiness_check(owner_id: int) -> list[ReadinessItem]:
    items = []
    active_pay = PaymentProviderCredential.query.filter_by(
        owner_id=owner_id, is_active=True).count()
    items.append(ReadinessItem(
        key="payment_configured",
        severity="ok" if active_pay > 0 else "warn",
        label="Payment gateway configured",
        detail=f"{active_pay} active payment provider(s)" if active_pay else "No active payment provider",
        fix_hint="Go to Payment Methods and connect Stripe, Razorpay or Cashfree.",
    ))
    verified_pay = PaymentProviderCredential.query.filter(
        PaymentProviderCredential.owner_id == owner_id,
        PaymentProviderCredential.is_active == True,
        PaymentProviderCredential.last_test_status == "ok",
    ).count()
    items.append(ReadinessItem(
        key="payment_verified",
        severity="ok" if verified_pay > 0 else ("warn" if active_pay > 0 else "ok"),
        label="Payment gateway tested",
        detail=f"{verified_pay} verified" if verified_pay else "Run a connection test",
        fix_hint="Click Test Connection next to each payment provider.",
    ))
    return items


def _ih_readiness_summary(items: list[ReadinessItem]) -> str:
    severities = [i.severity for i in items]
    if "alert" in severities:
        return "not_ready"
    if "warn" in severities:
        return "partially_ready"
    return "ready"


def _ih_to_jsonable(card: IntegrationCard) -> dict:
    return {
        "key": card.key, "category": card.category,
        "label": card.label, "status": card.status,
        "is_active": card.is_active,
        "last_test_status": card.last_test_status,
        "manage_url": card.manage_url,
        "webhook_url": card.webhook_url,
    }


# ---------------------------------------------------------------------------
# Hub overview
# ---------------------------------------------------------------------------

@bp.route("/owner/integrations")
@login_required
def owner_integrations_hub():
    owner = logged_in_owner_obj()
    if owner is None:
        return redirect(url_for("web_auth.owner_login"))
    owner_id = owner.id
    cards = _ih_build_cards(owner_id)
    cards_by_category: dict[str, list] = {"payment": [], "delivery": [], "notification": []}
    for c in cards:
        cards_by_category.setdefault(c.category, []).append(c)
    readiness = _ih_readiness_check(owner_id)
    verdict = _ih_readiness_summary(readiness)
    return _no_store(make_response(render_template(
        "owner_integrations/index.html",
        owner=owner,
        cards_by_category=cards_by_category,
        categories=_IH_CATEGORY_LABELS,
        readiness=readiness,
        verdict=verdict,
        sms_configured=False,
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Checklist JSON
# ---------------------------------------------------------------------------

@bp.route("/owner/integrations/checklist.json")
@login_required
@limiter.limit("60 per hour")
def owner_integrations_checklist_json():
    owner_id = logged_in_owner_id()
    cards = _ih_build_cards(owner_id)
    readiness = _ih_readiness_check(owner_id)
    verdict = _ih_readiness_summary(readiness)
    return jsonify({
        "verdict": verdict,
        "readiness": [{"key": r.key, "severity": r.severity, "label": r.label,
                       "detail": r.detail, "fix_hint": r.fix_hint}
                      for r in readiness],
        "integrations": [_ih_to_jsonable(c) for c in cards],
    })


# ---------------------------------------------------------------------------
# Test all
# ---------------------------------------------------------------------------

@bp.route("/owner/integrations/test-all", methods=["POST"])
@login_required
@limiter.limit("10 per hour; 2 per minute")
def owner_integrations_test_all():
    owner_id = logged_in_owner_id()
    now = datetime.now(timezone.utc)
    ok_count = fail_count = 0

    import hashlib as _hs
    def _fp(s):
        return _hs.sha256(s.encode()).hexdigest()[:16] if s else ""

    for cred in PaymentProviderCredential.query.filter_by(owner_id=owner_id, is_active=True).all():
        try:
            provider_obj = build_provider(
                cred.provider, public_key=cred.public_key,
                secret_key=decrypt_secret(cred.secret_key_enc),
                webhook_secret=decrypt_secret(cred.webhook_secret_enc),
                mode=cred.mode)
            msg = provider_obj.test_connection()
            cred.last_test_status = "ok"
            cred.last_test_message = msg[:500]
            cred.last_tested_at = now
            try:
                cred.verified_fingerprint = _fp(decrypt_secret(cred.secret_key_enc))
                cred.verified_at = now
            except Exception:
                pass
            ok_count += 1
        except PaymentProviderError as exc:
            cred.last_test_status = "error"
            cred.last_test_message = str(exc)[:500]
            cred.last_tested_at = now
            fail_count += 1
        except Exception as exc:
            cred.last_test_status = "error"
            cred.last_test_message = f"unexpected: {exc}"[:500]
            cred.last_tested_at = now
            fail_count += 1

    for cred in AggregatorPlatformCredential.query.filter_by(owner_id=owner_id, is_active=True).all():
        try:
            from lib_aggregators import build_aggregator as _ba
            ag = _ba(cred.platform, api_key=cred.api_key or "",
                     secret=decrypt_secret(cred.secret_enc) if cred.secret_enc else "",
                     merchant_id=cred.merchant_id or "",
                     mode=getattr(cred, "mode", "test") or "test")
            msg = ag.test_connection()
            if hasattr(cred, "last_test_status"):
                cred.last_test_status = "ok"
                cred.last_test_message = msg[:500]
            if hasattr(cred, "last_tested_at"):
                cred.last_tested_at = now
            ok_count += 1
        except AggregatorError as exc:
            if hasattr(cred, "last_test_status"):
                cred.last_test_status = "error"
                cred.last_test_message = str(exc)[:500]
            if hasattr(cred, "last_tested_at"):
                cred.last_tested_at = now
            fail_count += 1
        except Exception as exc:
            if hasattr(cred, "last_test_status"):
                cred.last_test_status = "error"
                cred.last_test_message = f"unexpected: {exc}"[:500]
            if hasattr(cred, "last_tested_at"):
                cred.last_tested_at = now
            fail_count += 1

    db.session.commit()
    if ok_count == 0 and fail_count == 0:
        flash("No active integrations to test.", "billing_info")
    elif fail_count == 0:
        flash(f"All {ok_count} integration(s) passed.", "billing_ok")
    else:
        flash(f"{ok_count} passed, {fail_count} failed.", "billing_error")

    referrer = request.referrer or ""
    if "/owner/integrations" in referrer:
        return redirect(url_for("integrations.owner_integrations_hub"))
    return redirect(url_for("web_owner.owner_dashboard"))
