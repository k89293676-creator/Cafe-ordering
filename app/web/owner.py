"""Owner dashboard and profile routes."""
from __future__ import annotations

import datetime as _dt
import re

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import func as _sqla_func

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.tables import load_owner_tables, load_settings
from app.services.menu import load_owner_menu
from app.services.orders import load_orders
from app.utils.security import login_required, log_security, _client_ip
from app.utils.serializers import _safe_text, _feedback_dict

bp = Blueprint("web_owner", __name__)

_COMPLETED_STATUSES = ("served", "completed", "closed", "paid")


@bp.route("/owner/dashboard")
@login_required
def owner_dashboard():
    from app.models import Feedback, Ingredient, Menu, Order
    from app.models.billing import PaymentProviderCredential, WebhookEventLog

    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    tables = load_owner_tables(owner_id)
    settings = load_settings(owner_id)
    recent_orders = load_orders(owner_id=owner_id, limit=50)

    pending_orders = [o for o in recent_orders if o["status"] == "pending"]
    preparing_count = sum(1 for o in recent_orders if o["status"] == "preparing")
    revenue_today = sum(
        o["total"] for o in recent_orders
        if o.get("createdAt", "").startswith(_dt.date.today().isoformat())
        and o["status"] not in ("cancelled", "voided")
    )

    # All-time completed-order stats
    total_completed: int = db.session.query(Order).filter(
        Order.owner_id == owner_id,
        Order.status.in_(_COMPLETED_STATUSES),
    ).count()
    total_revenue: float = float(
        db.session.query(
            _sqla_func.coalesce(_sqla_func.sum(Order.total), 0)
        ).filter(
            Order.owner_id == owner_id,
            Order.status.in_(_COMPLETED_STATUSES),
        ).scalar() or 0
    )

    # Menu item count
    _menu = db.session.get(Menu, owner_id)
    _categories = (_menu.data or {}).get("categories", []) if _menu else []
    total_items: int = sum(len(cat.get("items", [])) for cat in _categories)

    # Feedback
    _feedbacks = (
        Feedback.query.filter_by(owner_id=owner_id)
        .order_by(Feedback.id.desc())
        .limit(20)
        .all()
    )
    owner_feedback = [_feedback_dict(f) for f in _feedbacks]
    total_feedback: int = Feedback.query.filter_by(owner_id=owner_id).count()
    avg_rating: float = (
        round(sum(f["rating"] for f in owner_feedback) / len(owner_feedback), 1)
        if owner_feedback else 0
    )

    # Low-stock ingredients
    low_stock_alerts = Ingredient.query.filter(
        Ingredient.owner_id == owner_id,
        Ingredient.stock <= Ingredient.low_stock_threshold,
    ).all()

    # Integration health (payments + aggregators)
    try:
        _pcreds = PaymentProviderCredential.query.filter_by(owner_id=owner_id).all()
    except Exception:
        _pcreds = []
    try:
        from app.models.aggregator import AggregatorPlatformCredential
        _acreds = AggregatorPlatformCredential.query.filter_by(owner_id=owner_id).all()
    except Exception:
        _acreds = []

    _int_items = []
    for _c in _pcreds:
        _mode = getattr(_c, "mode", "test") or "test"
        _active = bool(_c.is_active)
        _state = (
            "live" if (_active and _mode == "live") else
            "ready" if (_active and _mode == "test") else
            "disabled"
        )
        _int_items.append({
            "display_name": _c.display_name or _c.provider.title(),
            "label": _c.provider.title(),
            "mode": _mode,
            "state": _state,
            "last_test_message": _c.last_test_message or "",
            "test_url": "#",
            "manage_url": "#",
        })

    integration_health = {
        "configured": len(_pcreds) + len(_acreds),
        "payments_configured": len(_pcreds),
        "payments_live": sum(1 for c in _pcreds if c.is_active and getattr(c, "mode", "") == "live"),
        "aggregators_configured": len(_acreds),
        "aggregators_live": sum(1 for c in _acreds if getattr(c, "is_active", True)),
        "counts": {
            "live":       sum(1 for c in _pcreds if c.is_active and getattr(c, "mode", "") == "live"),
            "ready":      sum(1 for c in _pcreds if c.is_active and getattr(c, "mode", "") == "test"),
            "unverified": sum(1 for c in _pcreds if not getattr(c, "last_tested_at", None)),
            "failing":    sum(1 for c in _pcreds if getattr(c, "last_test_status", "") == "fail"),
        },
        "items": _int_items,
    }

    # Recent webhook activity
    try:
        _recent_wh = (
            WebhookEventLog.query.order_by(WebhookEventLog.id.desc()).limit(10).all()
        )
        _wh_24h = WebhookEventLog.query.filter(
            WebhookEventLog.received_at
            >= _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=24)
        ).count()
        webhook_activity = {
            "counts": {"total_24h": _wh_24h},
            "items": [
                {
                    "received_at": w.received_at,
                    "label": f"{w.provider}: {w.event_type or 'event'}",
                    "intent_id": w.intent_id or "",
                    "is_signature_failure": False,
                }
                for w in _recent_wh
            ],
        }
    except Exception:
        webhook_activity = {"counts": {"total_24h": 0}, "items": []}

    # Impersonation state
    is_impersonating = False
    impersonator_username = ""
    try:
        from extensions.multi_tenant_bp import is_impersonating as _is_imp
        from flask import session as _sess
        is_impersonating = bool(_is_imp())
        impersonator_username = _sess.get("impersonator_username", "")
    except Exception:
        pass

    return render_template(
        "owner_dashboard.html",
        owner=owner,
        tables=tables,
        settings=settings,
        recent_orders=recent_orders,
        pending_orders=pending_orders,
        pending_count=len(pending_orders),
        preparing_count=preparing_count,
        revenue_today=revenue_today,
        total_completed=total_completed,
        total_revenue=total_revenue,
        total_items=total_items,
        owner_feedback=owner_feedback,
        total_feedback=total_feedback,
        avg_rating=avg_rating,
        low_stock_alerts=low_stock_alerts,
        integration_health=integration_health,
        webhook_activity=webhook_activity,
        is_impersonating=is_impersonating,
        impersonator_username=impersonator_username,
        owner_username=owner.username if owner else "",
    )


@bp.route("/owner/profile", methods=["GET", "POST"])
@login_required
def owner_profile():
    from app.services.auth import _is_strong_password, _make_password_hash, _password_matches
    from app.models import Owner
    owner = logged_in_owner_obj()
    if request.method == "POST":
        action = request.form.get("action", "update")
        if action == "change_password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            if not _password_matches(owner.password_hash, current_pw):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("web_owner.owner_profile"))
            if not _is_strong_password(new_pw):
                flash("New password must be at least 8 characters with letters and digits.", "error")
                return redirect(url_for("web_owner.owner_profile"))
            owner.password_hash = _make_password_hash(new_pw)
            db.session.commit()
            from app.services.auth import revoke_all_tokens_for_owner
            revoke_all_tokens_for_owner(owner.id)
            log_security("PASSWORD_CHANGED", f"owner_id={owner.id}")
            flash("Password updated. Please log in again on other devices.", "success")
        elif action == "update_profile":
            email = _safe_text(request.form.get("email"), max_len=254)
            phone = _safe_text(request.form.get("phone"), max_len=30)
            cafe_name = _safe_text(request.form.get("cafe_name"), max_len=100)
            if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                flash("Invalid email address.", "error")
                return redirect(url_for("web_owner.owner_profile"))
            if email and email != owner.email:
                existing = Owner.query.filter_by(email=email).first()
                if existing and existing.id != owner.id:
                    flash("Email already in use.", "error")
                    return redirect(url_for("web_owner.owner_profile"))
                owner.email = email
            owner.phone = phone
            owner.cafe_name = cafe_name
            db.session.commit()
            flash("Profile updated.", "success")
        return redirect(url_for("web_owner.owner_profile"))
    settings = load_settings(owner.id)
    return render_template("owner_profile.html", owner=owner, settings=settings)


@bp.route("/owner/tables", methods=["GET"])
@login_required
def owner_tables():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    tables = load_owner_tables(owner_id)
    settings = load_settings(owner_id)
    return render_template("owner_tables.html", owner=owner, tables=tables, settings=settings)


@bp.route("/owner/tables/add", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def owner_add_table():
    from app.models import CafeTable
    from app.services.tables import normalize_id, unique_id, next_table_number
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    name = _safe_text(request.form.get("name"), max_len=50)
    if not name:
        num = next_table_number(load_owner_tables(owner_id))
        name = f"Table {num}"
    existing_ids = {t["id"] for t in load_owner_tables(owner_id)}
    table_id = unique_id(normalize_id(name), existing_ids)
    table = CafeTable(id=table_id, name=name, owner_id=owner_id, cafe_id=owner.cafe_id)
    db.session.add(table)
    db.session.commit()
    flash(f"Table '{name}' added.", "success")
    return redirect(url_for("web_owner.owner_tables"))


@bp.route("/owner/tables/<table_id>/delete", methods=["POST"])
@login_required
def owner_delete_table(table_id: str):
    from app.models import CafeTable
    owner_id = logged_in_owner_id()
    table = db.session.get(CafeTable, table_id)
    if not table or table.owner_id != owner_id:
        abort(404)
    db.session.delete(table)
    db.session.commit()
    flash("Table deleted.", "success")
    return redirect(url_for("web_owner.owner_tables"))


@bp.route("/owner/tables/<table_id>/rename", methods=["POST"])
@login_required
def owner_rename_table(table_id: str):
    from app.models import CafeTable
    owner_id = logged_in_owner_id()
    table = db.session.get(CafeTable, table_id)
    if not table or table.owner_id != owner_id:
        abort(404)
    name = _safe_text(request.form.get("name"), max_len=50)
    if name:
        table.name = name
        db.session.commit()
        flash("Table renamed.", "success")
    return redirect(url_for("web_owner.owner_tables"))


@bp.route("/kitchen")
@login_required
def kitchen():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    settings = load_settings(owner_id)
    return render_template("kitchen.html", owner=owner, settings=settings)
