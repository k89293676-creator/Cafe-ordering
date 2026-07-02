"""Superadmin routes: owner management, system flags, audit log, security events."""
from __future__ import annotations

import time

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_obj
from app.utils.security import (
    SECURITY_EVENT_BUFFER,
    _superadmin_key_configured,
    _superadmin_key_matches,
    log_security,
    superadmin_required,
    superadmin_destructive,
)

bp = Blueprint("web_superadmin", __name__)


@bp.route("/superadmin/verify-key", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def superadmin_verify_key():
    if request.method == "POST":
        key = request.form.get("key", "").strip()
        if _superadmin_key_matches(key):
            session["superadmin_verified"] = True
            log_security("SUPERADMIN_KEY_VERIFIED", "")
            return redirect(url_for("web_superadmin.superadmin_dashboard"))
        log_security("SUPERADMIN_KEY_REJECTED", "")
        time.sleep(1)
        flash("Invalid key.", "error")
    return render_template("superadmin/verify_key.html")


@bp.route("/superadmin")
@bp.route("/superadmin/")
@superadmin_required
def superadmin_dashboard():
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import func as _f
    from app.models import Owner, Order, Cafe, Feedback, TableCall

    now_utc = datetime.now(timezone.utc)
    today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_start = today_start - timedelta(days=7)
    prev_week_start = week_start - timedelta(days=7)

    owner_count = db.session.query(_f.count(Owner.id)).scalar() or 0
    order_count = db.session.query(_f.count(Order.id)).scalar() or 0
    cafe_count = db.session.query(_f.count(Cafe.id)).scalar() or 0
    active_cafe_count = cafe_count
    active_owners = Owner.query.filter_by(is_active=True).count()
    pending_approvals = Owner.query.filter_by(approval_status="pending").count()

    total_revenue = float(
        db.session.query(_f.coalesce(_f.sum(Order.total), 0))
        .filter(Order.status == "completed").scalar() or 0
    )
    avg_rating_raw = db.session.query(_f.avg(Feedback.rating)).scalar()
    avg_rating = round(float(avg_rating_raw), 1) if avg_rating_raw else 0.0
    total_feedback = db.session.query(_f.count(Feedback.id)).scalar() or 0

    open_calls = 0
    try:
        open_calls = TableCall.query.filter_by(status="open").count()
    except Exception:
        pass

    orders_today = Order.query.filter(Order.created_at >= today_start).count()
    revenue_today = float(
        db.session.query(_f.coalesce(_f.sum(Order.total), 0))
        .filter(Order.created_at >= today_start, Order.status != "cancelled").scalar() or 0
    )
    revenue_7d = float(
        db.session.query(_f.coalesce(_f.sum(Order.total), 0))
        .filter(Order.created_at >= week_start, Order.status != "cancelled").scalar() or 0
    )
    orders_7d = Order.query.filter(Order.created_at >= week_start).count()
    new_owners_7d = Owner.query.filter(Owner.created_at >= week_start).count()

    completed_7d = Order.query.filter(
        Order.created_at >= week_start, Order.status == "completed"
    ).count()
    avg_ticket = round(revenue_7d / completed_7d, 2) if completed_7d else 0.0

    orders_yesterday = Order.query.filter(
        Order.created_at >= yesterday_start, Order.created_at < today_start
    ).count()
    orders_prev_7d = Order.query.filter(
        Order.created_at >= prev_week_start, Order.created_at < week_start
    ).count()

    def _pct_delta(new, old):
        if not old:
            return None
        return round((new - old) / old * 100, 1)

    deltas = {
        "orders_today_vs_yesterday": _pct_delta(orders_today, orders_yesterday),
        "orders_7d_vs_prev": _pct_delta(orders_7d, orders_prev_7d),
    }

    daily_series = []
    for i in range(13, -1, -1):
        day_start = today_start - timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        cnt = Order.query.filter(
            Order.created_at >= day_start, Order.created_at < day_end
        ).count()
        daily_series.append({"date": day_start.strftime("%m/%d"), "count": cnt})

    db_latency_ms = None
    try:
        import time as _t
        t0 = _t.monotonic()
        db.session.execute(db.text("SELECT 1"))
        db_latency_ms = round((_t.monotonic() - t0) * 1000, 1)
    except Exception:
        pass

    from app import config as _cfg
    uptime_s = int(time.time() - (_cfg.APP_START_TIME or time.time()))
    uptime_h = uptime_s // 3600
    uptime_m = (uptime_s % 3600) // 60
    health = {
        "db_latency_ms": db_latency_ms,
        "env": "production" if _cfg.IS_PRODUCTION else "development",
        "uptime": f"{uptime_h}h {uptime_m}m",
        "version": _cfg.APP_VERSION,
        "events_buffered": len(SECURITY_EVENT_BUFFER),
        "verified_until": None,
    }

    cafes = [{"id": c.id, "name": c.name} for c in Cafe.query.order_by(Cafe.name).all()]

    from app.services.orders import load_orders
    recent_orders = load_orders(limit=20)

    owner_username = session.get("owner_username", "Superadmin")

    return render_template(
        "superadmin/dashboard.html",
        owner_count=owner_count,
        order_count=order_count,
        cafe_count=cafe_count,
        active_cafe_count=active_cafe_count,
        active_owners=active_owners,
        active_owner_count=active_owners,
        pending_approvals=pending_approvals,
        total_orders=order_count,
        total_revenue=total_revenue,
        avg_rating=avg_rating,
        total_feedback=total_feedback,
        open_calls=open_calls,
        health=health,
        orders_today=orders_today,
        revenue_today=revenue_today,
        revenue_7d=revenue_7d,
        orders_7d=orders_7d,
        avg_ticket=avg_ticket,
        new_owners_7d=new_owners_7d,
        deltas=deltas,
        daily_series=daily_series,
        cafes=cafes,
        recent_orders=recent_orders,
        owner_username=owner_username,
    )


@bp.route("/superadmin/owners")
@superadmin_required
def superadmin_owners():
    from app.models import Owner
    owners = Owner.query.order_by(Owner.id).all()
    return render_template("superadmin/owners.html", owners=owners)


@bp.route("/superadmin/owners/<int:owner_id>/toggle", methods=["POST"])
@superadmin_required
def superadmin_toggle_owner(owner_id: int):
    from app.models import Owner
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot deactivate a superadmin account.", "error")
        return redirect(url_for("web_superadmin.superadmin_owners"))
    owner.is_active = not owner.is_active
    db.session.commit()
    action = "activated" if owner.is_active else "deactivated"
    log_security(f"SUPERADMIN_OWNER_{action.upper()}", f"owner_id={owner_id}")
    flash(f"Owner {owner.username!r} {action}.", "success")
    return redirect(url_for("web_superadmin.superadmin_owners"))


@bp.route("/superadmin/owners/<int:owner_id>/delete", methods=["POST"])
@superadmin_destructive
def superadmin_delete_owner(owner_id: int):
    from app.models import Owner
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot delete a superadmin.", "error")
        return redirect(url_for("web_superadmin.superadmin_owners"))
    username = owner.username
    db.session.delete(owner)
    db.session.commit()
    log_security("SUPERADMIN_OWNER_DELETED", f"username={username!r}")
    flash(f"Owner {username!r} deleted permanently.", "success")
    return redirect(url_for("web_superadmin.superadmin_owners"))


@bp.route("/superadmin/owners/<int:owner_id>/approve", methods=["POST"])
@superadmin_required
def superadmin_approve_owner(owner_id: int):
    from app.models import Owner
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    owner.approval_status = "active"
    owner.is_active = True
    db.session.commit()
    log_security("SUPERADMIN_OWNER_APPROVED", f"owner_id={owner_id}")
    flash(f"Owner {owner.username!r} approved.", "success")
    return redirect(url_for("web_superadmin.superadmin_owners"))


@bp.route("/superadmin/owners/<int:owner_id>/admin-key", methods=["POST"])
@superadmin_required
def superadmin_generate_admin_key(owner_id: int):
    from app.models import Owner
    from app.services.auth import generate_admin_key_for_owner
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    raw = generate_admin_key_for_owner(owner_id, owner.username)
    log_security("SUPERADMIN_GENERATED_ADMIN_KEY", f"owner_id={owner_id}")
    flash(f"Admin key generated (shown once only): {raw}", "success")
    return redirect(url_for("web_superadmin.superadmin_owners"))


@bp.route("/superadmin/system-flags", methods=["GET", "POST"])
@superadmin_required
def superadmin_system_flags():
    from app.models import SystemFlag
    if request.method == "POST":
        key = request.form.get("key", "").strip()[:100]
        value = request.form.get("value", "").strip()[:500]
        if key:
            flag = db.session.get(SystemFlag, key) or SystemFlag(key=key)
            flag.value = value
            db.session.add(flag)
            db.session.commit()
            log_security("SYSTEM_FLAG_SET", f"key={key!r} value={value!r}")
            flash(f"Flag '{key}' set.", "success")
        return redirect(url_for("web_superadmin.superadmin_system_flags"))
    flags = SystemFlag.query.order_by(SystemFlag.key).all()
    return render_template("superadmin/system_flags.html", flags=flags)


@bp.route("/superadmin/security-log")
@superadmin_required
def superadmin_security_log():
    events = list(reversed(list(SECURITY_EVENT_BUFFER)))
    return render_template("superadmin/security_log.html", events=events[:500])


@bp.route("/superadmin/leads")
@superadmin_required
def superadmin_leads():
    from app.models import OwnerLead
    leads = OwnerLead.query.order_by(OwnerLead.created_at.desc()).limit(200).all()
    return render_template("superadmin/leads.html", leads=leads)


@bp.route("/superadmin/analytics")
@superadmin_required
def superadmin_analytics():
    from app.models import Cafe, Owner, Order
    per_cafe = []
    cafes = Cafe.query.all()
    for cafe in cafes:
        owners = Owner.query.filter_by(cafe_id=cafe.id).all()
        owner_ids = [o.id for o in owners]
        if not owner_ids:
            continue
        orders = Order.query.filter(Order.owner_id.in_(owner_ids)).all()
        revenue = sum(float(o.total or 0) for o in orders if o.status == "completed")
        per_cafe.append({
            "cafe": {"id": cafe.id, "name": cafe.name, "slug": cafe.slug},
            "total_orders": len(orders),
            "revenue": round(revenue, 2),
            "owner_count": len(owners),
        })
    from sqlalchemy import func as _f
    orphan_orders = db.session.query(_f.count(Order.id)).filter(
        Order.cafe_id.is_(None)
    ).scalar() or 0
    return render_template(
        "superadmin/analytics.html",
        per_cafe=per_cafe,
        orphan_orders=orphan_orders,
    )
