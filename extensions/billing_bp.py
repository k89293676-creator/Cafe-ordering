"""Billing blueprint — extracted from the monolith.

Provides all /owner/billing/* and /billing/pay/* routes used by the
owner dashboard sidebar and the customer-facing hosted payment page.
Every route is a direct translation of the legacy monolith functions,
importing helpers from lib_billing, lib_billing_security, lib_payments
and app.models so the business logic stays in one place.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import re
from datetime import datetime, timedelta, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.extensions import db, limiter
from app.models import (
    BillingLog,
    CashDrawerCount,
    Menu,
    OnlinePayment,
    Order,
    Owner,
    PaymentProviderCredential,
    Settings,
    WebhookEventLog,
)
from app.services.auth import logged_in_owner, logged_in_owner_id, logged_in_owner_obj
from app.utils.security import login_required
from app.utils.serializers import _no_store

from lib_billing import (
    VALID_PAYMENT_METHODS,
    aging_bucket_for,
    compute_bill_totals,
    compute_settlement,
    next_invoice_number,
    normalise_payments,
    parse_date_range,
    summarise_aging,
    summarise_payment_breakdown,
)
from lib_billing_security import (
    check_refund_amount_cap,
    check_refund_velocity_per_hour,
    drawer_variance_alert_pct,
    is_stepup_session_fresh,
    refund_daily_cap_pct,
    refund_velocity_per_hour,
    stepup_refund_threshold,
    stepup_required_for_refund,
    stepup_required_for_void,
    stepup_void_threshold,
    verify_password_constant_time,
)
from lib_billing_security import drawer_variance as _drawer_variance_fn
try:
    from lib_billing import drawer_variance
except ImportError:
    drawer_variance = _drawer_variance_fn

from lib_payments import (
    PROVIDER_GUIDES,
    PROVIDER_LABELS,
    SUPPORTED_PROVIDERS,
    PaymentProviderError,
    build_provider,
    decrypt_secret,
    detect_mode_from_key,
    encrypt_secret,
    mask_secret,
)

# ---------------------------------------------------------------------------
# Currency helpers
# ---------------------------------------------------------------------------

_CURRENCY_SYMBOLS = {
    "gbp": "£", "usd": "$", "eur": "€", "inr": "₹",
    "aud": "A$", "cad": "C$", "sgd": "S$", "aed": "د.إ",
    "nzd": "NZ$", "jpy": "¥", "cny": "¥", "krw": "₩",
}


def _owner_currency(owner_id: int) -> tuple[str, str]:
    """Return (currency_code, currency_symbol) for the given owner."""
    owner = db.session.get(Owner, owner_id)
    code = (getattr(owner, "currency", None) or "gbp").lower()
    return code, _CURRENCY_SYMBOLS.get(code, code.upper())


def _fmt_amount(amount: float, symbol: str) -> str:
    """Format a monetary amount with the owner's currency symbol."""
    return f"{symbol}{amount:.2f}"


bp = Blueprint("billing", __name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _today_window():
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, now


def _settings_for(owner_id: int) -> Settings:
    s = db.session.get(Settings, owner_id)
    if not s:
        s = Settings(owner_id=owner_id)
        db.session.add(s)
        db.session.commit()
    return s


def _client_ip() -> str:
    return (request.headers.get("X-Forwarded-For", request.remote_addr) or "").split(",")[0].strip()


def _billing_log(*, owner_id: int, order_id, action: str, amount: float = 0,
                 payment_method: str = "", reason: str = "",
                 payload: dict | None = None, invoice_number: str = "") -> None:
    try:
        row = BillingLog(
            owner_id=owner_id, order_id=order_id,
            invoice_number=invoice_number or "",
            action=action,
            actor_owner_id=session.get("owner_id"),
            actor_username=session.get("owner_username") or "",
            amount=amount,
            payment_method=payment_method or "",
            reason=(reason or "")[:500],
            payload=payload or {},
            ip=_client_ip()[:64],
            request_id=request.environ.get("request_id", ""),
        )
        db.session.add(row)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        import logging; logging.getLogger(__name__).warning("billing_log write failed: %s", exc)


def _order_dict(o: Order) -> dict:
    items = o.items if isinstance(o.items, list) else []
    return {
        "id": o.id, "tableId": o.table_id or "", "tableName": o.table_name or "",
        "customerName": o.customer_name or "Guest",
        "customerEmail": o.customer_email or "",
        "customerPhone": o.customer_phone or "",
        "items": items, "subtotal": float(o.subtotal or 0),
        "total": float(o.total or 0), "status": o.status or "pending",
        "createdAt": o.created_at.isoformat() if o.created_at else None,
        "pickupCode": o.pickup_code or "",
    }


def _bill_dict(o: Order) -> dict:
    base = _order_dict(o)
    payments = o.payments_breakdown if isinstance(o.payments_breakdown, list) else []
    paid_amount = sum(float(p.get("amount") or 0) for p in payments if isinstance(p, dict))
    balance_due = round(max(0.0, float(o.total or 0) - paid_amount), 2)
    base.update({
        "paymentStatus": o.payment_status or "unpaid",
        "paymentMethod": o.payment_method or "",
        "discount": float(o.discount or 0),
        "tax": float(o.tax or 0),
        "serviceCharge": float(o.service_charge or 0),
        "invoiceNumber": o.invoice_number or "",
        "paidAt": o.paid_at.isoformat() if o.paid_at else None,
        "paymentsBreakdown": payments,
        "paidAmount": paid_amount,
        "balanceDue": balance_due,
        "voidReason": o.void_reason or "",
        "refundAmount": float(o.refund_amount or 0),
        "refundReason": o.refund_reason or "",
    })
    return base


def _load_owner_order(order_id: int, owner_id: int, *, lock: bool = False) -> Order:
    q = Order.query.filter_by(id=order_id, owner_id=owner_id)
    if lock and db.engine.dialect.name == "postgresql":
        q = q.with_for_update()
    order = q.one_or_none()
    if not order:
        abort(404)
    return order


def _gross_revenue_today(owner_id: int) -> float:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    total = (db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
             .filter(Order.owner_id == owner_id,
                     Order.payment_status.in_(("paid", "refunded")),
                     Order.paid_at >= start).scalar() or 0)
    return float(total)


def _refund_total_today(owner_id: int) -> float:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    total = (db.session.query(db.func.coalesce(db.func.sum(BillingLog.amount), 0))
             .filter(BillingLog.owner_id == owner_id,
                     BillingLog.action == "refunded",
                     BillingLog.created_at >= start).scalar() or 0)
    return float(total)


def _refund_count_last_hour(owner_id: int) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    count = (db.session.query(db.func.count(BillingLog.id))
             .filter(BillingLog.owner_id == owner_id,
                     BillingLog.action == "refunded",
                     BillingLog.created_at >= since).scalar() or 0)
    return int(count)


def _invalidate_billing_cache(owner_id: int) -> None:
    try:
        from app.utils.cache import response_cache
        response_cache.invalidate_prefix(f"billing_overview::{owner_id}")
    except Exception:
        pass


def _severity_pill(severity: str) -> str:
    return {"ok": "pill pill--ok", "warn": "pill pill--warn",
            "alert": "pill pill--alert"}.get((severity or "ok").lower(), "pill pill--ok")


def _billing_overview(owner_id: int) -> dict:
    start, _now = _today_window()
    paid_today = (Order.query
                  .filter(Order.owner_id == owner_id,
                          Order.payment_status.in_(("paid", "refunded")),
                          Order.paid_at >= start).all())
    revenue = sum(float(o.total or 0) for o in paid_today)
    refunds = sum(float(o.refund_amount or 0) for o in paid_today)
    tips = sum(float(o.tip or 0) for o in paid_today)
    tax = sum(float(o.tax or 0) for o in paid_today)
    svc = sum(float(o.service_charge or 0) for o in paid_today)
    open_tabs = (Order.query
                 .filter(Order.owner_id == owner_id,
                         Order.payment_status == "unpaid",
                         Order.status != "cancelled").count())
    open_value = float(
        db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
        .filter(Order.owner_id == owner_id, Order.payment_status == "unpaid",
                Order.status != "cancelled").scalar() or 0)
    avg_ticket = round(revenue / len(paid_today), 2) if paid_today else 0.0
    refund_ratio = round(refunds / (revenue + refunds) * 100.0, 2) if (revenue + refunds) else 0.0
    return {
        "revenue": round(revenue, 2), "orders_paid": len(paid_today),
        "average_ticket": avg_ticket,
        "tax_collected": round(tax, 2), "service_charge": round(svc, 2),
        "tips": round(tips, 2), "refunds": round(refunds, 2),
        "refund_ratio": refund_ratio, "open_tabs": open_tabs,
        "open_value": round(open_value, 2),
        "as_of": datetime.now(timezone.utc).isoformat(),
        "net_revenue": round(revenue - refunds, 2),
    }


def _billing_sparkline_7d(owner_id: int) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=7)
    rows = (db.session.query(
                db.func.date(Order.paid_at).label("d"),
                db.func.coalesce(db.func.sum(Order.total), 0).label("gross"),
                db.func.coalesce(db.func.sum(Order.refund_amount), 0).label("refunds"))
            .filter(Order.owner_id == owner_id,
                    Order.payment_status.in_(("paid", "refunded")),
                    Order.paid_at >= since)
            .group_by("d").order_by("d").all())
    labels, gross, net, refund_pct = [], [], [], []
    for r in rows:
        day_gross = float(r.gross or 0)
        day_refunds = float(r.refunds or 0)
        labels.append(r.d.isoformat() if hasattr(r.d, "isoformat") else str(r.d))
        gross.append(round(day_gross, 2))
        net.append(round(day_gross - day_refunds, 2))
        refund_pct.append(round(day_refunds / day_gross * 100.0 if day_gross else 0.0, 2))
    net_vals = net or []
    return {"labels": labels, "gross": gross, "net": net_vals, "refund_pct": refund_pct,
            "total_net": round(sum(net_vals), 2), "peak": max(net_vals) if net_vals else 0.0}


def _billing_health_compute(owner_id: int) -> dict:
    snapshot: dict = {"owner_id": owner_id, "checks": [], "ok": True, "degraded": False}
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=12)
        stale = (db.session.query(db.func.count(Order.id))
                 .filter(Order.owner_id == owner_id, Order.payment_status == "unpaid",
                         Order.status != "cancelled", Order.created_at < cutoff)
                 .scalar() or 0)
        snapshot["checks"].append({
            "key": "stale_open_tabs", "label": "Open tabs older than 12h",
            "value": int(stale), "ok": stale == 0,
            "severity": "ok" if stale == 0 else ("warn" if stale < 5 else "alert"),
        })
        since = datetime.now(timezone.utc) - timedelta(days=7)
        gross = float(db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
                      .filter(Order.owner_id == owner_id,
                              Order.payment_status.in_(("paid", "refunded")),
                              Order.paid_at >= since).scalar() or 0)
        refunds_7d = float(db.session.query(db.func.coalesce(db.func.sum(Order.refund_amount), 0))
                           .filter(Order.owner_id == owner_id,
                                   Order.payment_status.in_(("paid", "refunded")),
                                   Order.paid_at >= since).scalar() or 0)
        ratio = (refunds_7d / gross * 100.0) if gross > 0 else 0.0
        snapshot["checks"].append({
            "key": "refund_ratio_7d", "label": "7-day refund ratio",
            "value": round(ratio, 2), "unit": "%", "ok": ratio < 5.0,
            "severity": "ok" if ratio < 5.0 else ("warn" if ratio < 10.0 else "alert"),
        })
    except Exception as exc:
        snapshot["degraded"] = True
        snapshot["error"] = str(exc)
    snapshot["ok"] = all(c.get("ok") for c in snapshot["checks"]) and not snapshot["degraded"]
    return snapshot


def _recompute_order_totals(order: Order, owner_id: int) -> None:
    settings = _settings_for(owner_id)
    items = order.items or []
    subtotal = round(sum(
        float(line.get("lineTotal") or
              float(line.get("price") or 0) * int(line.get("quantity") or 1))
        for line in items), 2)
    discount = max(0.0, min(float(order.discount or 0), subtotal))
    totals = compute_bill_totals(
        subtotal=subtotal, discount=discount,
        service_charge_pct=float(settings.service_charge_percent or 0),
        tax_pct=float(settings.tax_rate_percent or 0),
        tip=float(order.tip or 0),
    )
    order.subtotal = subtotal
    order.discount = totals.discount
    order.service_charge = totals.service_charge
    order.tax = totals.tax
    order.tip = totals.tip
    order.total = totals.total


def _secret_fingerprint(secret: str) -> str:
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def _credential_view(cred: PaymentProviderCredential) -> dict:
    try:
        secret_plain = decrypt_secret(cred.secret_key_enc) if cred.secret_key_enc else ""
    except Exception:
        secret_plain = ""
    current_fp = _secret_fingerprint(secret_plain)
    verified_at = getattr(cred, "verified_at", None)
    verified_fp = getattr(cred, "verified_fingerprint", "") or ""
    is_verified = bool(verified_at and verified_fp == current_fp and current_fp)
    return {
        "id": cred.id, "provider": cred.provider,
        "provider_label": PROVIDER_LABELS.get(cred.provider, cred.provider.title()),
        "display_name": cred.display_name or PROVIDER_LABELS.get(cred.provider, cred.provider),
        "public_key_masked": mask_secret(cred.public_key),
        "has_secret": bool(cred.secret_key_enc),
        "has_webhook": bool(cred.webhook_secret_enc),
        "mode": cred.mode, "is_active": bool(cred.is_active),
        "is_default": bool(cred.is_default),
        "is_verified": is_verified,
        "verified_at": cred.verified_at,
        "last_tested_at": cred.last_tested_at,
        "last_test_status": cred.last_test_status,
        "last_test_message": cred.last_test_message,
        "webhook_url": url_for("billing_webhook", provider=cred.provider, _external=True)
                       if "billing_webhook" in bp.url_map.bind("").map._rules_by_endpoint else "#",
        "guide": PROVIDER_GUIDES.get(cred.provider, {}),
    }


def _provider_for_credential(cred: PaymentProviderCredential):
    return build_provider(
        cred.provider,
        public_key=cred.public_key,
        secret_key=decrypt_secret(cred.secret_key_enc),
        webhook_secret=decrypt_secret(cred.webhook_secret_enc),
        mode=cred.mode,
    )


# ---------------------------------------------------------------------------
# Billing overview
# ---------------------------------------------------------------------------

@bp.route("/owner/billing")
@login_required
def owner_billing_overview():
    owner_id = logged_in_owner_id()
    settings = _settings_for(owner_id)
    overview = _billing_overview(owner_id)
    recent_paid = (Order.query
                   .filter(Order.owner_id == owner_id, Order.payment_status == "paid")
                   .order_by(Order.paid_at.desc().nullslast())
                   .limit(10).all())
    return _no_store(make_response(render_template(
        "owner_billing/overview.html",
        overview=overview,
        recent_paid=[_bill_dict(o) for o in recent_paid],
        settings=settings,
        sparkline=_billing_sparkline_7d(owner_id),
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Open tabs
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/open")
@login_required
def owner_billing_open():
    owner_id = logged_in_owner_id()
    table_filter = (request.args.get("table") or "").strip()[:64]
    page = max(1, int(request.args.get("page", "1") or "1"))
    per_page = 50
    q = (Order.query.filter(Order.owner_id == owner_id,
                            Order.payment_status == "unpaid",
                            Order.status != "cancelled"))
    if table_filter:
        q = q.filter(Order.table_id == table_filter)
    total = q.count()
    open_value = float(
        db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
        .filter(Order.owner_id == owner_id, Order.payment_status == "unpaid",
                Order.status != "cancelled").scalar() or 0)
    rows = (q.order_by(Order.created_at.desc())
              .offset((page - 1) * per_page).limit(per_page).all())
    return _no_store(make_response(render_template(
        "owner_billing/open.html",
        orders=[_bill_dict(o) for o in rows],
        page=page, per_page=per_page, total=total,
        table_filter=table_filter, open_value=round(open_value, 2),
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Order detail
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>")
@login_required
def owner_billing_order_detail(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id)
    settings = _settings_for(owner_id)
    totals = compute_bill_totals(
        subtotal=float(order.subtotal or 0),
        discount=float(order.discount or 0),
        service_charge_pct=0, service_charge_flat=float(order.service_charge or 0),
        tax_pct=0, tax_flat=float(order.tax or 0),
        tip=float(order.tip or 0),
    )
    bill_total = float(order.total or 0)
    already_refunded = float(order.refund_amount or 0)
    cap_pct = refund_daily_cap_pct()
    gross_today = _gross_revenue_today(owner_id)
    refunded_today = _refund_total_today(owner_id)
    cap_amount = round(gross_today * (cap_pct / 100.0), 2) if cap_pct > 0 else 0.0
    refund_cap_remaining = round(max(0.0, cap_amount - refunded_today), 2)
    menu_categories = []
    if order.payment_status == "unpaid":
        menu_record = db.session.get(Menu, owner_id)
        for cat in ((menu_record.data or {}).get("categories", []) if menu_record else []):
            visible = [{"id": it.get("id"), "name": it.get("name") or "Unnamed",
                        "price": float(it.get("price") or 0)}
                       for it in (cat.get("items") or [])
                       if it.get("id") and it.get("available", True)]
            if visible:
                menu_categories.append({"id": cat.get("id"), "name": cat.get("name") or "Menu",
                                        "items": visible})
    return _no_store(make_response(render_template(
        "owner_billing/order_detail.html",
        order=_bill_dict(order), totals=totals, settings=settings,
        valid_methods=VALID_PAYMENT_METHODS,
        owner_username=logged_in_owner(),
        stepup_refund_threshold=stepup_refund_threshold(),
        stepup_void_threshold=stepup_void_threshold(),
        void_stepup_required=stepup_required_for_void(bill_total),
        refund_stepup_required=stepup_required_for_refund(bill_total - already_refunded),
        stepup_fresh=is_stepup_session_fresh(session.get("billing_stepup_at")),
        refund_cap_remaining=refund_cap_remaining,
        menu_categories=menu_categories,
    )))


# ---------------------------------------------------------------------------
# Adjust
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/adjust", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def owner_billing_adjust(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Cannot adjust a settled bill. Issue a refund instead.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    settings = _settings_for(owner_id)
    try:
        discount = max(0.0, min(float(request.form.get("discount", 0) or 0),
                                float(order.subtotal or 0)))
        svc_pct = float(request.form.get("service_charge_pct",
                                         settings.service_charge_percent or 0) or 0)
        tax_pct = float(request.form.get("tax_pct", settings.tax_rate_percent or 0) or 0)
        tip = max(0.0, float(request.form.get("tip", order.tip or 0) or 0))
    except ValueError:
        flash("Invalid number in adjustment form.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    totals = compute_bill_totals(subtotal=float(order.subtotal or 0),
                                 discount=discount, service_charge_pct=svc_pct,
                                 tax_pct=tax_pct, tip=tip)
    order.discount = totals.discount
    order.service_charge = totals.service_charge
    order.tax = totals.tax
    order.tip = totals.tip
    order.total = totals.total
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="adjusted",
                 amount=totals.total,
                 payload={"discount": totals.discount, "service_charge": totals.service_charge,
                          "tax": totals.tax, "tip": totals.tip, "total": totals.total})
    _invalidate_billing_cache(owner_id)
    _, _sym = _owner_currency(owner_id)
    flash(f"Bill updated. New total {_sym}{totals.total:.2f}.", "billing_ok")
    return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))


# ---------------------------------------------------------------------------
# Add/remove line items
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/items/add", methods=["POST"])
@login_required
@limiter.limit("120 per minute")
def owner_billing_add_item(order_id: int):
    from sqlalchemy.orm.attributes import flag_modified
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Cannot add items to a settled bill.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    item_id = (request.form.get("item_id") or "").strip()
    try:
        qty = max(1, min(int(request.form.get("quantity", 1) or 1), 100))
    except (TypeError, ValueError):
        qty = 1
    if not item_id:
        flash("Pick a menu item to add.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    menu_record = db.session.get(Menu, owner_id)
    menu_item = None
    for cat in ((menu_record.data or {}).get("categories", []) if menu_record else []):
        for it in (cat.get("items") or []):
            if it.get("id") == item_id:
                menu_item = it
                break
        if menu_item:
            break
    if not menu_item:
        flash("That item is no longer on the menu.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if not menu_item.get("available", True):
        flash(f"'{menu_item.get('name')}' is currently unavailable.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    price = float(menu_item.get("price") or 0)
    name = str(menu_item.get("name") or item_id)
    items = list(order.items or [])
    merged = False
    for line in items:
        if (line.get("id") == item_id and not line.get("modifiers")
                and not (line.get("notes") or "").strip()):
            line["quantity"] = int(line.get("quantity") or 1) + qty
            line["lineTotal"] = round(price * line["quantity"], 2)
            merged = True
            break
    if not merged:
        items.append({"id": item_id, "name": name, "price": price, "quantity": qty,
                      "modifiers": [], "notes": "", "lineTotal": round(price * qty, 2)})
    order.items = items
    flag_modified(order, "items")
    _recompute_order_totals(order, owner_id)
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="item_added",
                 amount=round(price * qty, 2),
                 payload={"item_id": item_id, "name": name, "quantity": qty,
                          "new_total": float(order.total or 0)})
    _invalidate_billing_cache(owner_id)
    _, _sym = _owner_currency(owner_id)
    flash(f"Added {qty}× {name}. New total {_sym}{float(order.total or 0):.2f}.", "billing_ok")
    return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))


@bp.route("/owner/billing/orders/<int:order_id>/items/<int:idx>/remove", methods=["POST"])
@login_required
@limiter.limit("120 per minute")
def owner_billing_remove_item(order_id: int, idx: int):
    from sqlalchemy.orm.attributes import flag_modified
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Cannot remove items from a settled bill.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    items = list(order.items or [])
    if not (0 <= idx < len(items)):
        flash("That line no longer exists.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if len(items) <= 1:
        flash("A bill must keep at least one item. Void the bill to cancel it.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    removed = items.pop(idx)
    order.items = items
    flag_modified(order, "items")
    _recompute_order_totals(order, owner_id)
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="item_removed",
                 amount=float(removed.get("lineTotal") or 0),
                 payload={"item_id": removed.get("id"), "name": removed.get("name"),
                          "new_total": float(order.total or 0)})
    _invalidate_billing_cache(owner_id)
    _, _sym = _owner_currency(owner_id)
    flash(f"Removed {removed.get('name', 'item')}. New total {_sym}{float(order.total or 0):.2f}.",
          "billing_ok")
    return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))


# ---------------------------------------------------------------------------
# Settle
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/settle", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def owner_billing_settle(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status == "paid":
        flash("This bill is already settled.", "billing_info")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if order.payment_status == "voided":
        flash("This bill is voided and cannot be settled.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    methods = request.form.getlist("payment_method")
    amounts = request.form.getlist("payment_amount")
    refs = request.form.getlist("payment_reference") or [""] * len(methods)
    raw_payments = []
    for i, m in enumerate(methods):
        try:
            amt = float(amounts[i] or 0)
        except (ValueError, IndexError):
            amt = 0.0
        raw_payments.append({"method": m, "amount": amt,
                              "reference": refs[i] if i < len(refs) else ""})
    payments = normalise_payments(raw_payments)
    totals = compute_bill_totals(
        subtotal=float(order.subtotal or 0), discount=float(order.discount or 0),
        service_charge_pct=0, service_charge_flat=float(order.service_charge or 0),
        tax_pct=0, tax_flat=float(order.tax or 0), tip=float(order.tip or 0),
    )
    paid_amount, change_due, err = compute_settlement(totals, payments)
    if err:
        flash(err, "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    settings = _settings_for(owner_id)
    invoice_no, new_seq = next_invoice_number(settings.invoice_prefix or "INV",
                                              int(settings.invoice_seq or 0))
    settings.invoice_seq = new_seq
    primary_method = max(payments, key=lambda p: p["amount"])["method"] if payments else ""
    order.payment_status = "paid"
    order.payment_method = primary_method
    order.payments_breakdown = payments
    order.invoice_number = invoice_no
    order.paid_at = datetime.now(timezone.utc)
    order.settled_by = owner_id
    order.updated_at = order.paid_at
    if order.status in ("pending", "preparing", "ready"):
        order.status = "served"
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="settled",
                 invoice_number=invoice_no, amount=totals.total,
                 payment_method=primary_method,
                 payload={"payments": payments, "change_due": change_due,
                          "paid_amount": paid_amount})
    _invalidate_billing_cache(owner_id)
    msg = f"Settled. Invoice {invoice_no}."
    if change_due > 0:
        _, _sym = _owner_currency(owner_id)
        msg += f" Change due: {_sym}{change_due:.2f}."
    flash(msg, "billing_ok")
    return redirect(url_for("billing.owner_billing_invoice", order_id=order_id))


# ---------------------------------------------------------------------------
# Void
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/void", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def owner_billing_void(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Only unpaid bills can be voided.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    reason = (request.form.get("reason") or "").strip()[:500]
    if not reason:
        flash("Please enter a reason for voiding.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if stepup_required_for_void(float(order.total or 0)) and \
       not is_stepup_session_fresh(session.get("billing_stepup_at")):
        flash("High-value void requires your password. Please re-enter it.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    order.payment_status = "voided"
    order.void_reason = reason
    order.status = "cancelled"
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="voided",
                 amount=float(order.total or 0), reason=reason)
    _invalidate_billing_cache(owner_id)
    flash(f"Bill voided: {reason}", "billing_ok")
    return redirect(url_for("billing.owner_billing_open"))


# ---------------------------------------------------------------------------
# Refund
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/refund", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def owner_billing_refund(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status not in ("paid", "refunded"):
        flash("Only paid bills can be refunded.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    try:
        amount = float(request.form.get("amount", 0) or 0)
    except ValueError:
        flash("Invalid refund amount.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    reason = (request.form.get("reason") or "").strip()[:500]
    if amount <= 0:
        flash("Refund amount must be positive.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    already = float(order.refund_amount or 0)
    max_refundable = float(order.total or 0) - already
    if amount > max_refundable + 0.01:
        _, _sym = _owner_currency(owner_id)
        flash(f"Cannot refund {_sym}{amount:.2f} — only {_sym}{max_refundable:.2f} remains.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if not reason:
        flash("Refunds require a reason for the audit log.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    if stepup_required_for_refund(amount) and \
       not is_stepup_session_fresh(session.get("billing_stepup_at")):
        flash("High-value refund requires your password.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    cap_verdict = check_refund_amount_cap(
        requested=amount, refunded_today=_refund_total_today(owner_id),
        gross_revenue_today=_gross_revenue_today(owner_id))
    if not cap_verdict.allowed:
        flash(cap_verdict.reason or "Daily refund cap reached.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    vel_verdict = check_refund_velocity_per_hour(
        refund_count_last_hour=_refund_count_last_hour(owner_id))
    if not vel_verdict.allowed:
        flash(vel_verdict.reason or "Too many refunds in the last hour.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    order.refund_amount = round(already + amount, 2)
    order.refund_reason = reason
    if abs(float(order.refund_amount) - float(order.total or 0)) < 0.01:
        order.payment_status = "refunded"
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="refunded",
                 amount=amount, reason=reason, invoice_number=order.invoice_number or "",
                 payload={"refund_total": float(order.refund_amount)})
    _invalidate_billing_cache(owner_id)
    _, _sym = _owner_currency(owner_id)
    flash(f"Refunded {_sym}{amount:.2f}. Total refunded: {_sym}{float(order.refund_amount):.2f}.",
          "billing_ok")
    return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))


# ---------------------------------------------------------------------------
# Invoice
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/invoice/<int:order_id>")
@login_required
def owner_billing_invoice(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id)
    settings = _settings_for(owner_id)
    owner = db.session.get(Owner, owner_id)
    return render_template("owner_billing/invoice.html",
                           order=_bill_dict(order), settings=settings, owner=owner)


# ---------------------------------------------------------------------------
# EOD report + CSV
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/eod")
@login_required
def owner_billing_eod():
    owner_id = logged_in_owner_id()
    today_start, _ = _today_window()
    date_str = (request.args.get("date") or "").strip()
    if date_str:
        try:
            day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            day = today_start
        rng_from, rng_to = day, day + timedelta(days=1)
        range_label = day.strftime("%Y-%m-%d")
    else:
        rng_from, rng_to, range_label = parse_date_range(
            from_str=request.args.get("from", ""),
            to_str=request.args.get("to", ""),
            today=today_start,
        )
    paid = (Order.query
            .filter(Order.owner_id == owner_id,
                    Order.payment_status.in_(("paid", "refunded")),
                    Order.paid_at >= rng_from, Order.paid_at < rng_to)
            .order_by(Order.paid_at.asc()).all())
    voided = (Order.query
              .filter(Order.owner_id == owner_id,
                      Order.payment_status == "voided",
                      Order.updated_at >= rng_from, Order.updated_at < rng_to).all())
    flat_payments = [p for o in paid
                     for p in (o.payments_breakdown or [])
                     if isinstance(p, dict)]
    by_mode = summarise_payment_breakdown(flat_payments)
    summary = {
        "date": rng_from.strftime("%Y-%m-%d"),
        "from": rng_from.strftime("%Y-%m-%d"),
        "to": (rng_to - timedelta(days=1)).strftime("%Y-%m-%d"),
        "range_label": range_label,
        "preset_week_from": (today_start - timedelta(days=6)).strftime("%Y-%m-%d"),
        "preset_month_from": (today_start - timedelta(days=29)).strftime("%Y-%m-%d"),
        "orders": len(paid),
        "gross_revenue": round(sum(float(o.total or 0) for o in paid), 2),
        "discounts": round(sum(float(o.discount or 0) for o in paid), 2),
        "service_charge": round(sum(float(o.service_charge or 0) for o in paid), 2),
        "tax": round(sum(float(o.tax or 0) for o in paid), 2),
        "tips": round(sum(float(o.tip or 0) for o in paid), 2),
        "refunds": round(sum(float(o.refund_amount or 0) for o in paid), 2),
        "voided_count": len(voided),
        "voided_value": round(sum(float(o.total or 0) for o in voided), 2),
        "by_mode": by_mode,
    }
    summary["net_revenue"] = round(summary["gross_revenue"] - summary["refunds"], 2)
    return _no_store(make_response(render_template(
        "owner_billing/eod.html",
        summary=summary, paid=[_bill_dict(o) for o in paid],
        voided=[_bill_dict(o) for o in voided],
        owner_username=logged_in_owner(),
    )))


@bp.route("/owner/billing/eod.csv")
@login_required
def owner_billing_eod_csv():
    owner_id = logged_in_owner_id()
    today_start, _ = _today_window()
    date_str = (request.args.get("date") or "").strip()
    if date_str:
        try:
            day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            day = today_start
        rng_from, rng_to = day, day + timedelta(days=1)
        fname_label = day.strftime("%Y-%m-%d")
    else:
        rng_from, rng_to, _ = parse_date_range(
            from_str=request.args.get("from", ""),
            to_str=request.args.get("to", ""),
            today=today_start,
        )
        fname_label = f"{rng_from:%Y-%m-%d}_to_{(rng_to - timedelta(days=1)):%Y-%m-%d}"
    rows = (Order.query
            .filter(Order.owner_id == owner_id,
                    Order.payment_status.in_(("paid", "refunded")),
                    Order.paid_at >= rng_from, Order.paid_at < rng_to)
            .order_by(Order.paid_at.asc()).all())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["invoice_number", "order_id", "paid_at_utc", "table", "customer",
                "subtotal", "discount", "service_charge", "tax", "tip",
                "total", "refund_amount", "primary_method", "status"])
    for o in rows:
        w.writerow([o.invoice_number or "", o.id,
                    o.paid_at.isoformat() if o.paid_at else "",
                    o.table_name or "", o.customer_name or "",
                    float(o.subtotal or 0), float(o.discount or 0),
                    float(o.service_charge or 0), float(o.tax or 0),
                    float(o.tip or 0), float(o.total or 0),
                    float(o.refund_amount or 0), o.payment_method or "", o.payment_status or ""])
    out = make_response(buf.getvalue())
    out.headers["Content-Type"] = "text/csv; charset=utf-8"
    out.headers["Content-Disposition"] = f'attachment; filename="eod-{fname_label}.csv"'
    return out


# ---------------------------------------------------------------------------
# Refunds list
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/refunds")
@login_required
def owner_billing_refunds():
    owner_id = logged_in_owner_id()
    today_start, _ = _today_window()
    rng_from, rng_to, range_label = parse_date_range(
        from_str=request.args.get("from", ""),
        to_str=request.args.get("to", ""),
        today=today_start,
    )
    logs = (BillingLog.query
            .filter(BillingLog.owner_id == owner_id, BillingLog.action == "refunded",
                    BillingLog.created_at >= rng_from, BillingLog.created_at < rng_to)
            .order_by(BillingLog.created_at.desc()).all())
    rows = []
    total_refunded = 0.0
    for lg in logs:
        amt = float(lg.amount or 0)
        total_refunded += amt
        rows.append({"id": lg.id, "order_id": lg.order_id,
                     "invoice_number": lg.invoice_number or "",
                     "amount": round(amt, 2), "reason": lg.reason or "",
                     "actor": getattr(lg, "actor_username", "") or "",
                     "created_at": lg.created_at.isoformat() if lg.created_at else ""})
    summary = {
        "from": rng_from.strftime("%Y-%m-%d"),
        "to": (rng_to - timedelta(days=1)).strftime("%Y-%m-%d"),
        "range_label": range_label,
        "preset_week_from": (today_start - timedelta(days=6)).strftime("%Y-%m-%d"),
        "preset_month_from": (today_start - timedelta(days=29)).strftime("%Y-%m-%d"),
        "count": len(rows), "total_refunded": round(total_refunded, 2),
        "todays_refunds": round(_refund_total_today(owner_id), 2),
        "hourly_count": _refund_count_last_hour(owner_id),
        "hourly_limit": refund_velocity_per_hour(),
        "stepup_threshold": stepup_refund_threshold(),
        "daily_cap_pct": refund_daily_cap_pct(),
    }
    return _no_store(make_response(render_template(
        "owner_billing/refunds.html",
        summary=summary, rows=rows, blocked=[],
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Aging
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/aging")
@login_required
def owner_billing_aging():
    owner_id = logged_in_owner_id()
    open_tabs = (Order.query
                 .filter(Order.owner_id == owner_id, Order.payment_status == "unpaid",
                         Order.status != "cancelled")
                 .order_by(Order.created_at.asc()).all())
    now = datetime.now(timezone.utc)
    items = [{"createdAt": o.created_at.isoformat() if o.created_at else None,
               "total": float(o.total or 0), "id": o.id} for o in open_tabs]
    buckets = summarise_aging(items, now=now)
    bucket_pill = {"under_1h": "pill-paid", "1h_to_4h": "pill-unpaid",
                   "4h_to_24h": "pill-refunded", "over_24h": "pill-voided"}
    age_labels: dict = {}
    age_classes: dict = {}
    for o in open_tabs:
        if not o.created_at:
            age_labels[o.id] = "?"
            age_classes[o.id] = "pill-unpaid"
            continue
        secs = max(0.0, (now - o.created_at).total_seconds())
        hours = secs / 3600.0
        label = f"{int(secs/60)}m" if hours < 1 else (f"{hours:.1f}h" if hours < 24
                                                       else f"{int(hours/24)}d {int(hours%24)}h")
        age_labels[o.id] = label
        age_classes[o.id] = bucket_pill.get(aging_bucket_for(secs), "pill-unpaid")
    return _no_store(make_response(render_template(
        "owner_billing/aging.html",
        buckets=buckets, orders=[_bill_dict(o) for o in open_tabs],
        age_labels=age_labels, age_classes=age_classes,
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Cash drawer
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/drawer", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute", methods=["POST"])
def owner_billing_drawer():
    owner_id = logged_in_owner_id()
    today_start, _ = _today_window()
    if request.method == "POST":
        try:
            counted = float(request.form.get("counted_cash", "0") or 0)
            float_left = float(request.form.get("float_left", "0") or 0)
        except ValueError:
            flash("Invalid number in the count form.", "billing_error")
            return redirect(url_for("billing.owner_billing_drawer"))
        notes = (request.form.get("notes") or "").strip()[:500]
        try:
            day = datetime.strptime(
                (request.form.get("day") or today_start.strftime("%Y-%m-%d")).strip(),
                "%Y-%m-%d").date()
        except ValueError:
            day = today_start.date()
        day_start = datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)
        cash_in = float(
            db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
            .filter(Order.owner_id == owner_id, Order.payment_status.in_(("paid", "refunded")),
                    Order.payment_method == "cash",
                    Order.paid_at >= day_start, Order.paid_at < day_end).scalar() or 0)
        cash_refunded = float(
            db.session.query(db.func.coalesce(db.func.sum(Order.refund_amount), 0))
            .filter(Order.owner_id == owner_id, Order.payment_status.in_(("paid", "refunded")),
                    Order.payment_method == "cash",
                    Order.paid_at >= day_start, Order.paid_at < day_end).scalar() or 0)
        expected = cash_in - cash_refunded
        try:
            variance_d = drawer_variance(counted=counted, expected=expected, float_left=float_left)
        except TypeError:
            variance_d = drawer_variance(expected_cash=expected, counted_cash=counted)
        row = CashDrawerCount(
            owner_id=owner_id, counted_by_owner_id=owner_id,
            counted_by_username=logged_in_owner() or "",
            day=day, expected_cash=round(expected, 2), counted_cash=round(counted, 2),
            float_left=round(float_left, 2),
            variance=variance_d["variance"], variance_pct=variance_d["variance_pct"],
            severity=variance_d["severity"], notes=notes,
        )
        db.session.add(row)
        db.session.commit()
        _billing_log(owner_id=owner_id, order_id=None, action="drawer_count",
                     amount=counted, reason=notes, payload=variance_d)
        _, _sym = _owner_currency(owner_id)
        flash(f"Drawer recorded — variance {_sym}{variance_d['variance']:.2f} ({variance_d['severity']}).",
              "billing_ok")
        return redirect(url_for("billing.owner_billing_drawer"))
    history = (CashDrawerCount.query.filter_by(owner_id=owner_id)
               .order_by(CashDrawerCount.day.desc(), CashDrawerCount.created_at.desc())
               .limit(60).all())
    history_rows = [{"id": h.id, "day": h.day.strftime("%Y-%m-%d") if h.day else "",
                     "expected_cash": float(h.expected_cash or 0),
                     "counted_cash": float(h.counted_cash or 0),
                     "float_left": float(h.float_left or 0),
                     "variance": float(h.variance or 0),
                     "variance_pct": float(h.variance_pct or 0),
                     "severity": h.severity or "ok",
                     "severity_class": _severity_pill(h.severity or "ok"),
                     "notes": h.notes or "", "counted_by": h.counted_by_username or "",
                     "created_at": h.created_at.isoformat() if h.created_at else ""}
                    for h in history]
    cash_in_today = float(
        db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
        .filter(Order.owner_id == owner_id, Order.payment_status.in_(("paid", "refunded")),
                Order.payment_method == "cash", Order.paid_at >= today_start).scalar() or 0)
    cash_ref_today = float(
        db.session.query(db.func.coalesce(db.func.sum(Order.refund_amount), 0))
        .filter(Order.owner_id == owner_id, Order.payment_status.in_(("paid", "refunded")),
                Order.payment_method == "cash", Order.paid_at >= today_start).scalar() or 0)
    expected_today = round(cash_in_today - cash_ref_today, 2)
    return _no_store(make_response(render_template(
        "owner_billing/drawer.html",
        history=history_rows, expected_today=expected_today,
        today=today_start.strftime("%Y-%m-%d"),
        variance_alert_pct=drawer_variance_alert_pct(),
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/health")
@login_required
def owner_billing_health():
    owner_id = logged_in_owner_id()
    snapshot = _billing_health_compute(owner_id)
    for c in snapshot.get("checks", []):
        c["pill_class"] = _severity_pill(c.get("severity", "ok"))
    return _no_store(make_response(render_template(
        "owner_billing/health.html",
        snapshot=snapshot, owner_username=logged_in_owner(),
    )))


@bp.route("/owner/billing/health.json")
@login_required
@limiter.limit("60 per hour")
def owner_billing_health_json():
    owner_id = logged_in_owner_id()
    return jsonify(_billing_health_compute(owner_id))


# ---------------------------------------------------------------------------
# Billing logs
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/logs")
@login_required
def owner_billing_logs():
    owner_id = logged_in_owner_id()
    page = max(1, int(request.args.get("page", "1") or "1"))
    per_page = 100
    action = (request.args.get("action") or "").strip().lower()
    q = BillingLog.query.filter_by(owner_id=owner_id)
    if action in ("settled", "voided", "refunded", "adjusted"):
        q = q.filter(BillingLog.action == action)
    total = q.count()
    logs = (q.order_by(BillingLog.created_at.desc())
              .offset((page - 1) * per_page).limit(per_page).all())
    summary_q = (db.session.query(BillingLog.action,
                                  db.func.count(BillingLog.id),
                                  db.func.sum(BillingLog.amount))
                 .filter_by(owner_id=owner_id).group_by(BillingLog.action))
    summary = {r[0]: {"count": r[1], "amount": float(r[2] or 0)} for r in summary_q.all()}
    return _no_store(make_response(render_template(
        "owner_billing/logs.html",
        logs=logs, page=page, per_page=per_page, total=total,
        action=action, summary=summary, owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Billing settings
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/settings", methods=["GET", "POST"])
@login_required
def owner_billing_settings():
    owner_id = logged_in_owner_id()
    settings = _settings_for(owner_id)
    if request.method == "POST":
        try:
            settings.tax_rate_percent = max(0.0, min(float(
                request.form.get("tax_rate_percent", 0) or 0), 100.0))
            settings.service_charge_percent = max(0.0, min(float(
                request.form.get("service_charge_percent", 0) or 0), 100.0))
        except ValueError:
            flash("Tax / service charge must be a number 0–100.", "billing_error")
            return redirect(url_for("billing.owner_billing_settings"))
        settings.tax_label = (request.form.get("tax_label") or "GST").strip()[:32] or "GST"
        settings.gstin = (request.form.get("gstin") or "").strip()[:32]
        settings.invoice_prefix = re.sub(
            r"[^A-Za-z0-9_\-/]", "",
            (request.form.get("invoice_prefix") or "INV"))[:16] or "INV"
        settings.billing_address = (request.form.get("billing_address") or "").strip()[:500]
        settings.billing_phone = (request.form.get("billing_phone") or "").strip()[:30]
        db.session.commit()
        flash("Billing settings saved.", "billing_ok")
        return redirect(url_for("billing.owner_billing_settings"))
    return _no_store(make_response(render_template(
        "owner_billing/settings.html",
        settings=settings, owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Payment methods
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/payment-methods")
@login_required
def owner_billing_payment_methods():
    owner_id = logged_in_owner_id()
    creds = (PaymentProviderCredential.query.filter_by(owner_id=owner_id)
             .order_by(PaymentProviderCredential.created_at.desc()).all())
    configured = {c.provider for c in creds}
    available = [{"slug": p, "label": PROVIDER_LABELS.get(p, p.title()),
                  "guide": PROVIDER_GUIDES.get(p, {})}
                 for p in SUPPORTED_PROVIDERS if p not in configured]
    try:
        sample_webhook = url_for("billing_webhook", provider="<provider>", _external=True)
    except Exception:
        sample_webhook = "/billing/webhook/<provider>"
    return _no_store(make_response(render_template(
        "owner_billing/payment_methods.html",
        credentials=[_credential_view(c) for c in creds],
        available_providers=available,
        provider_labels=PROVIDER_LABELS,
        provider_guides=PROVIDER_GUIDES,
        sample_webhook_url=sample_webhook,
        owner_username=logged_in_owner(),
    )))


@bp.route("/owner/billing/payment-methods/save", methods=["POST"])
@login_required
@limiter.limit("20 per hour; 5 per minute")
def owner_billing_payment_methods_save():
    owner_id = logged_in_owner_id()
    provider = (request.form.get("provider") or "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        flash(f"Unsupported provider: {provider!r}.", "billing_error")
        return redirect(url_for("billing.owner_billing_payment_methods"))
    cred = PaymentProviderCredential.query.filter_by(owner_id=owner_id, provider=provider).first()
    is_new = cred is None
    if is_new:
        cred = PaymentProviderCredential(owner_id=owner_id, provider=provider)
        db.session.add(cred)
    cred.display_name = (request.form.get("display_name") or "").strip()[:80]
    submitted_public = (request.form.get("public_key") or "").strip()[:200]
    if submitted_public and "•" not in submitted_public:
        cred.public_key = submitted_public
    secret_key = (request.form.get("secret_key") or "").strip()
    webhook_secret = (request.form.get("webhook_secret") or "").strip()
    secret_changed = False
    if secret_key:
        cred.secret_key_enc = encrypt_secret(secret_key)
        secret_changed = True
    if webhook_secret:
        cred.webhook_secret_enc = encrypt_secret(webhook_secret)
    if not cred.public_key or not cred.secret_key_enc:
        flash(f"{PROVIDER_LABELS.get(provider, provider)} requires both key id and secret.",
              "billing_error")
        db.session.rollback()
        return redirect(url_for("billing.owner_billing_payment_methods"))
    requested_mode = (request.form.get("mode") or "").strip().lower()
    if requested_mode in ("test", "live"):
        cred.mode = requested_mode
    elif secret_key or cred.public_key:
        detected = detect_mode_from_key(
            provider, cred.public_key or "",
            secret_key or (decrypt_secret(cred.secret_key_enc) if cred.secret_key_enc else ""))
        if detected != "unknown":
            cred.mode = detected
    if secret_changed:
        cred.verified_at = None
        cred.verified_fingerprint = ""
    desired_active = bool(request.form.get("is_active"))
    desired_default = bool(request.form.get("is_default"))
    cred.is_active = desired_active
    if desired_default and desired_active:
        PaymentProviderCredential.query.filter(
            PaymentProviderCredential.owner_id == owner_id,
            PaymentProviderCredential.id != (cred.id or -1),
        ).update({"is_default": False})
        cred.is_default = True
    elif not desired_default:
        cred.is_default = False
    db.session.commit()
    flash(f"{PROVIDER_LABELS.get(provider, provider)} saved ({cred.mode} mode, "
          f"{'active' if cred.is_active else 'disabled'}).", "billing_ok")
    return redirect(url_for("billing.owner_billing_payment_methods"))


@bp.route("/owner/billing/payment-methods/<int:cred_id>/test", methods=["POST"])
@login_required
@limiter.limit("30 per hour; 5 per minute")
def owner_billing_payment_methods_test(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(id=cred_id, owner_id=owner_id).first_or_404()
    try:
        provider_obj = _provider_for_credential(cred)
        msg = provider_obj.test_connection()
        cred.last_test_status = "ok"
        cred.last_test_message = msg[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        try:
            cred.verified_fingerprint = _secret_fingerprint(decrypt_secret(cred.secret_key_enc))
            cred.verified_at = cred.last_tested_at
        except Exception:
            pass
        db.session.commit()
        flash(msg, "billing_ok")
    except PaymentProviderError as exc:
        cred.last_test_status = "error"
        cred.last_test_message = str(exc)[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        db.session.commit()
        flash(f"Test failed: {exc}", "billing_error")
    except Exception as exc:
        flash(f"Unexpected error: {exc}", "billing_error")
    return redirect(url_for("billing.owner_billing_payment_methods"))


@bp.route("/owner/billing/payment-methods/<int:cred_id>/rotate-webhook", methods=["POST"])
@login_required
@limiter.limit("20 per hour; 5 per minute")
def owner_billing_payment_methods_rotate_webhook(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(id=cred_id, owner_id=owner_id).first_or_404()
    new_secret = (request.form.get("webhook_secret") or "").strip()
    if not new_secret:
        flash("Paste the new webhook secret to rotate it.", "billing_error")
        return redirect(url_for("billing.owner_billing_payment_methods"))
    if "•" in new_secret:
        flash("That looks like the masked placeholder, not a real secret.", "billing_error")
        return redirect(url_for("billing.owner_billing_payment_methods"))
    cred.webhook_secret_enc = encrypt_secret(new_secret)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=None,
                 action=f"payment_methods.{cred.provider}.webhook_rotated",
                 amount=0, payment_method=cred.provider,
                 reason="webhook signing secret rotated",
                 payload={"provider": cred.provider,
                          "secret_fingerprint": _secret_fingerprint(new_secret)})
    flash(f"{PROVIDER_LABELS.get(cred.provider, cred.provider).title()} webhook secret rotated.",
          "billing_ok")
    return redirect(url_for("billing.owner_billing_payment_methods"))


@bp.route("/owner/billing/payment-methods/<int:cred_id>/delete", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_billing_payment_methods_delete(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(id=cred_id, owner_id=owner_id).first_or_404()
    typed = (request.form.get("confirm_provider") or "").strip().lower()
    if typed != cred.provider:
        flash(f"Type '{cred.provider}' to confirm deletion.", "billing_error")
        return redirect(url_for("billing.owner_billing_payment_methods"))
    provider = cred.provider
    db.session.delete(cred)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=None,
                 action=f"payment_methods.{provider}.deleted", amount=0,
                 payment_method=provider, reason="credential removed by owner")
    flash(f"{PROVIDER_LABELS.get(provider, provider)} disconnected.", "billing_ok")
    return redirect(url_for("billing.owner_billing_payment_methods"))


# ---------------------------------------------------------------------------
# Online charge flow (owner side)
# ---------------------------------------------------------------------------

@bp.route("/owner/billing/orders/<int:order_id>/charge", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def owner_billing_create_charge(order_id: int):
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first_or_404()
    if (order.payment_status or "unpaid") == "paid":
        flash("This bill is already settled.", "billing_info")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    cred = (PaymentProviderCredential.query
            .filter_by(owner_id=owner_id, is_active=True, is_default=True).first()
            or PaymentProviderCredential.query.filter_by(owner_id=owner_id, is_active=True).first())
    if not cred:
        flash("No active payment provider. Add one under Payment Methods.", "billing_error")
        return redirect(url_for("billing.owner_billing_payment_methods"))
    amount = float(order.total or 0)
    if amount <= 0:
        flash("Cannot charge zero amount.", "billing_error")
        return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))
    try:
        provider_obj = _provider_for_credential(cred)
        intent = provider_obj.create_payment_intent(
            amount=amount, currency=(_owner_currency(owner_id)[0].upper()),
            metadata={"order_id": order_id, "owner_id": owner_id})
        op = OnlinePayment(
            order_id=order_id, owner_id=owner_id, provider=cred.provider,
            intent_id=intent.id, amount=amount, currency=(_owner_currency(owner_id)[0].upper()),
            status="pending", raw=intent.raw or {})
        db.session.add(op)
        db.session.commit()
        pay_url = url_for("billing.billing_pay_page", order_id=order_id, _external=True)
        flash(f"Payment link created. Share with customer: {pay_url}", "billing_ok")
    except PaymentProviderError as exc:
        flash(f"Could not create payment: {exc}", "billing_error")
    except Exception as exc:
        flash(f"Unexpected error: {exc}", "billing_error")
    return redirect(url_for("billing.owner_billing_order_detail", order_id=order_id))


# ---------------------------------------------------------------------------
# Customer pay page
# ---------------------------------------------------------------------------

@bp.route("/billing/pay/<int:order_id>")
def billing_pay_page(order_id: int):
    order = Order.query.get_or_404(order_id)
    op = (OnlinePayment.query.filter_by(order_id=order.id)
          .order_by(OnlinePayment.created_at.desc()).first())
    if op is None:
        return ("No active payment for this order.", 404)
    cred = PaymentProviderCredential.query.filter_by(
        owner_id=op.owner_id, provider=op.provider).first()
    if cred is None:
        return ("Payment provider is no longer configured.", 410)
    raw = op.raw if isinstance(op.raw, dict) else {}
    return _no_store(make_response(render_template(
        "owner_billing/customer_pay.html",
        order=order, payment=op, provider=op.provider,
        public_key=cred.public_key, mode=cred.mode,
        amount_minor=int(round(float(op.amount or 0) * 100)),
        currency=op.currency or (_owner_currency(owner_id)[0].upper()),
        checkout_url=raw.get("checkout_url") or "",
        cashfree_session_id=(raw.get("extra") or {}).get("payment_session_id", "")
                            if op.provider == "cashfree" else "",
    )))


@bp.route("/billing/pay/<int:order_id>/status")
@limiter.limit("60 per minute")
def billing_pay_status(order_id: int):
    op = (OnlinePayment.query.filter_by(order_id=order_id)
          .order_by(OnlinePayment.created_at.desc()).first())
    if op is None:
        return jsonify({"status": "unknown"}), 404
    if op.status == "pending":
        cred = PaymentProviderCredential.query.filter_by(
            owner_id=op.owner_id, provider=op.provider).first()
        if cred is not None:
            try:
                provider = _provider_for_credential(cred)
                event = provider.fetch_payment_status(op.intent_id)
                if event.status and event.status != op.status:
                    op.status = event.status
                    db.session.add(op)
                    db.session.commit()
            except Exception:
                pass
    return jsonify({"status": op.status, "order_id": op.order_id, "intent_id": op.intent_id})


@bp.route("/billing/pay/<int:order_id>/razorpay/verify", methods=["POST"])
@limiter.limit("30 per minute")
def billing_pay_razorpay_verify(order_id: int):
    payload = request.get_json(silent=True) or request.form
    rzp_order_id = (payload.get("razorpay_order_id") or "").strip()
    rzp_payment_id = (payload.get("razorpay_payment_id") or "").strip()
    rzp_signature = (payload.get("razorpay_signature") or "").strip()
    if not (rzp_order_id and rzp_payment_id and rzp_signature):
        return jsonify({"ok": False, "error": "missing fields"}), 400
    op = (OnlinePayment.query.filter_by(order_id=order_id, provider="razorpay",
                                        intent_id=rzp_order_id)
          .order_by(OnlinePayment.created_at.desc()).first())
    if op is None:
        return jsonify({"ok": False, "error": "unknown payment"}), 404
    cred = PaymentProviderCredential.query.filter_by(
        owner_id=op.owner_id, provider="razorpay", is_active=True).first()
    if cred is None:
        return jsonify({"ok": False, "error": "razorpay not configured"}), 410
    api_secret = decrypt_secret(cred.secret_key_enc) or ""
    if not api_secret:
        return jsonify({"ok": False, "error": "secret unavailable"}), 500
    expected = hmac.new(
        api_secret.encode("utf-8"),
        f"{rzp_order_id}|{rzp_payment_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, rzp_signature):
        return jsonify({"ok": False, "error": "signature invalid"}), 400
    if op.status != "succeeded":
        op.status = "succeeded"
        op.raw = {"event_type": "razorpay.handler.verified",
                  "razorpay_payment_id": rzp_payment_id, "verified_via": "client_handler"}
        db.session.add(op)
        db.session.commit()
    return jsonify({"ok": True, "status": op.status})
