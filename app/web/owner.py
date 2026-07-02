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
from app.services.orders import load_orders, _db_update_order_status
from app.services.notifications import _notify_owner, _notify_order_status
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

    _active_statuses = {"pending", "preparing", "ready"}
    pending_orders = [o for o in recent_orders if o["status"] in _active_statuses]
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

    # Build menu dict and JSON blob for the inline editor in the dashboard template.
    import json as _json
    _menu_row = db.session.get(Menu, owner_id)
    _menu_categories = []
    if _menu_row and isinstance(getattr(_menu_row, "data", None), dict):
        for _cat in (_menu_row.data or {}).get("categories", []):
            _cat_copy = dict(_cat)
            _cat_copy["ownerId"] = owner_id
            _menu_categories.append(_cat_copy)
    _menu_dict = {"categories": _menu_categories}
    menu_json = _json.dumps(_menu_dict, indent=2)

    return render_template(
        "owner_dashboard.html",
        owner=owner,
        tables=tables,
        settings=settings,
        recent_orders=recent_orders,
        pending_orders=pending_orders,
        completed_orders=[o for o in recent_orders if o.get("status") in _COMPLETED_STATUSES],
        pending_count=sum(1 for o in pending_orders if o["status"] == "pending"),
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
        menu=_menu_dict,
        menu_json=menu_json,
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
        elif action in ("update_profile", "profile"):
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
            _allowed_currencies = {"gbp","usd","eur","inr","aud","cad","sgd","aed","nzd","jpy"}
            _new_cur = (request.form.get("currency") or "gbp").lower().strip()
            if _new_cur in _allowed_currencies:
                owner.currency = _new_cur
            db.session.commit()
            flash("Profile updated.", "success")
        return redirect(url_for("web_owner.owner_profile"))
    settings = load_settings(owner.id)
    return render_template("owner_profile.html", owner=owner, settings=settings,
                           owner_username=owner.username if owner else "")


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

    # ── Plan limit gate ───────────────────────────────────────────
    existing_tables = load_owner_tables(owner_id)
    max_t = getattr(owner, "max_tables", None)
    if max_t is not None and len(existing_tables) >= max_t:
        flash(
            f"Table limit reached ({max_t} tables on your current plan). "
            "Upgrade your plan to add more tables.",
            "danger",
        )
        return redirect(url_for("web_owner.owner_tables"))

    name = _safe_text(request.form.get("name"), max_len=50)
    if not name:
        num = next_table_number(existing_tables)
        name = f"Table {num}"
    existing_ids = {t["id"] for t in existing_tables}
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


@bp.route("/owner/orders/<int:order_id>/status", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def update_order_status(order_id: int):
    """Update an order's status from the owner dashboard (form POST)."""
    from app.models import Order

    owner_id = logged_in_owner_id()
    new_status = (request.form.get("status") or "").strip().lower()

    # Map legacy "confirmed" -> "preparing" for backward compatibility
    if new_status == "confirmed":
        new_status = "preparing"

    order = db.session.get(Order, order_id)
    if not order or order.owner_id != owner_id:
        abort(404, description="Order not found.")

    if _db_update_order_status(order_id, new_status):
        _notify_owner(owner_id, "order_updated", {"id": order_id, "status": new_status})
        _notify_order_status(order_id, new_status)
        log_security("ORDER_STATUS_UPDATE", f"order_id={order_id} status={new_status!r}")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"ok": True, "status": new_status}, 200
    return redirect(request.referrer or url_for("web_owner.owner_dashboard"))


@bp.route("/kitchen")
@login_required
def kitchen():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    settings = load_settings(owner_id)
    return render_template("kitchen.html", owner=owner, settings=settings,
                           owner_username=owner.username if owner else "")


# ---------------------------------------------------------------------------
# Reorder — look up past orders by customer phone
# ---------------------------------------------------------------------------

@bp.route("/owner/reorder")
@login_required
def reorder_view():
    from app.models import Order
    from app.services.menu import load_owner_menu
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    phone = request.args.get("phone", "").strip()[:30]
    past_orders = []
    if phone:
        past_orders = (Order.query
                       .filter_by(owner_id=owner_id, customer_phone=phone)
                       .order_by(Order.created_at.desc())
                       .limit(20).all())

    def _order_dict(o):
        return {
            "id": o.id,
            "tableId": o.table_id or "",
            "tableName": o.table_name or "",
            "customerName": o.customer_name or "Guest",
            "customerPhone": o.customer_phone or "",
            "items": o.items or [],
            "total": float(o.total or 0),
            "status": o.status or "pending",
            "createdAt": o.created_at.isoformat() if o.created_at else None,
        }

    return render_template(
        "reorder.html",
        phone=phone,
        past_orders=[_order_dict(o) for o in past_orders],
        owner=owner,
    )


# ---------------------------------------------------------------------------
# Customers — aggregated customer ledger from order history
# ---------------------------------------------------------------------------

@bp.route("/owner/customers")
@login_required
def owner_customers():
    import csv as _csv
    import io as _io
    from datetime import datetime as _dt
    from flask import Response as _Resp
    from app.models import Order

    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    search = (request.args.get("q") or "").strip().lower()[:80]
    export = request.args.get("export") == "csv"

    orders = (Order.query
              .filter_by(owner_id=owner_id)
              .order_by(Order.created_at.desc())
              .all())

    customer_map: dict = {}
    for o in orders:
        key = (o.customer_phone or o.customer_email or o.customer_name or f"guest-{o.id}").lower().strip()
        if key not in customer_map:
            customer_map[key] = {
                "name": o.customer_name or "Guest",
                "email": o.customer_email or "",
                "phone": o.customer_phone or "",
                "orderCount": 0,
                "completedCount": 0,
                "totalSpend": 0.0,
                "lastOrder": o.created_at.isoformat() if o.created_at else None,
                "firstOrder": o.created_at.isoformat() if o.created_at else None,
            }
        c = customer_map[key]
        c["orderCount"] += 1
        if o.status == "completed":
            c["completedCount"] += 1
            c["totalSpend"] += float(o.total or 0)
        ts = o.created_at.isoformat() if o.created_at else None
        if ts and (not c["firstOrder"] or ts < c["firstOrder"]):
            c["firstOrder"] = ts

    for c in customer_map.values():
        c["totalSpend"] = round(c["totalSpend"], 2)
        c["avgOrder"] = round(c["totalSpend"] / c["completedCount"], 2) if c["completedCount"] else 0.0

    customers = sorted(customer_map.values(), key=lambda c: c["totalSpend"], reverse=True)
    if search:
        customers = [c for c in customers
                     if search in c["name"].lower()
                     or search in c["email"].lower()
                     or search in c["phone"]]

    if export:
        out = _io.StringIO()
        w = _csv.writer(out)
        w.writerow(["name", "email", "phone", "order_count", "completed_orders",
                    "total_spend", "avg_order", "first_order", "last_order"])
        for c in customers:
            w.writerow([c["name"], c["email"], c["phone"], c["orderCount"],
                        c["completedCount"], c["totalSpend"], c["avgOrder"],
                        c["firstOrder"] or "", c["lastOrder"] or ""])
        out.seek(0)
        fname = f"customers_{_dt.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return _Resp(out.getvalue(), mimetype="text/csv",
                     headers={"Content-Disposition": f"attachment; filename={fname}"})

    return render_template(
        "owner_customers.html",
        customers=customers,
        search=search,
        owner=owner,
        owner_username=owner.username if owner else "",
    )


# ---------------------------------------------------------------------------
# Download all table QR posters as a zip
# ---------------------------------------------------------------------------

@bp.route("/owner/tables/qr-posters.zip")
@login_required
def download_all_table_qr_posters():
    import io as _io
    import re as _re
    import zipfile
    from app.services.tables import load_tables, load_settings

    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    tables = load_owner_tables(owner_id)
    if not tables:
        flash("Add at least one table before downloading posters.")
        return redirect(url_for("web_owner.owner_tables"))

    cafe_name = (owner.cafe_name if owner else None) or "Welcome"
    branding = load_settings(owner_id) if owner_id else {}
    brand_color = branding.get("brandColor", "#4f46e5")
    logo_url = branding.get("logoUrl", "")

    # Try PIL / qrcode for branded posters; fall back to raw QR bytes if unavailable
    try:
        import qrcode as _qr
        from PIL import Image as _Image, ImageDraw as _Draw, ImageFont as _Font
        _have_pil = True
    except ImportError:
        _have_pil = False

    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for table in tables:
            table_url = url_for("web_public.table_order", table_id=table["id"], _external=True)
            png_buf = _io.BytesIO()
            if _have_pil:
                qr = _qr.make(table_url)
                qr.save(png_buf, format="PNG")
            else:
                try:
                    import qrcode as _qr
                    qr = _qr.QRCode(error_correction=_qr.constants.ERROR_CORRECT_H)
                    qr.add_data(table_url)
                    qr.make(fit=True)
                    qr.make_image(fill_color="black", back_color="white").save(png_buf, format="PNG")
                except Exception as _qr_err:
                    import logging as _lg
                    _lg.getLogger("cafe.owner").warning("QR fallback failed: %s", _qr_err)
                    png_buf = __import__("io").BytesIO()
            safe_name = _re.sub(r"[^a-zA-Z0-9_\-]+", "_",
                                str(table.get("name") or table["id"]))[:40] or table["id"]
            zf.writestr(f"qr-{safe_name}-{table['id']}.png", png_buf.getvalue())
    buf.seek(0)

    safe_cafe = _re.sub(r"[^a-zA-Z0-9_\-]+", "_", cafe_name)[:40] or "cafe"
    from flask import Response as _Resp
    return _Resp(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_cafe}-table-qr-posters.zip"'},
    )

@bp.route("/owner/tables/<table_id>/qr.png")
@login_required
def table_qr(table_id: str):
    """Generate and return QR code PNG for a single table."""
    import io as _io
    from app.models import CafeTable

    owner_id = logged_in_owner_id()
    table = db.session.get(CafeTable, table_id)
    if not table or table.owner_id != owner_id:
        abort(404)

    table_url = url_for("web_public.table_order", table_id=table_id, _external=True)

    try:
        import qrcode as _qr
        qr = _qr.QRCode(
            version=1,
            error_correction=_qr.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(table_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        buf = _io.BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)

        from flask import Response as _Resp
        return _Resp(buf.getvalue(), mimetype="image/png")
    except ImportError:
        abort(503, "QR code generation not available")
    except Exception as _e:
        abort(500, f"QR generation failed: {_e}")

