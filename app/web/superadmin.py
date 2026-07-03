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


@bp.route("/superadmin/last-error")
@superadmin_required
def superadmin_last_error():
    """Read-only diagnostic: last N security/error events from the in-memory buffer.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    events = list(reversed(list(SECURITY_EVENT_BUFFER)))[:50]
    if request.accept_mimetypes.best == "application/json" or request.args.get("format") == "json":
        return jsonify(errors=events, captured=len(events)), 200
    return jsonify(errors=events, captured=len(events)), 200


@bp.route("/superadmin/audit")
@superadmin_required
def superadmin_audit():
    """Browse the in-memory security audit ring buffer.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    q = (request.args.get("q") or "").strip().lower()
    event_filter = (request.args.get("event") or "").strip()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 100

    events = list(SECURITY_EVENT_BUFFER)
    events.reverse()

    if event_filter:
        events = [e for e in events if e.get("event", "").startswith(event_filter)]
    if q:
        events = [
            e for e in events
            if q in (e.get("event", "") + " " + e.get("detail", "") + " " + str(e.get("ip", ""))).lower()
        ]

    total = len(events)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    start = (page - 1) * per_page
    page_events = events[start: start + per_page]
    event_types = sorted({e.get("event", "") for e in SECURITY_EVENT_BUFFER if e.get("event")})
    log_security("SUPERADMIN_AUDIT_VIEW", f"q={q!r} event_filter={event_filter!r}")
    return render_template(
        "superadmin/audit.html",
        events=page_events,
        total=total,
        page=page,
        pages=pages,
        per_page=per_page,
        q=q,
        event_filter=event_filter,
        event_types=event_types,
        buffer_capacity=getattr(SECURITY_EVENT_BUFFER, "maxlen", 1000),
        verified_until=None,
    )


@bp.route("/superadmin/audit.json")
@superadmin_required
def superadmin_audit_json():
    """Filterable JSON export of the security audit buffer.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    from datetime import datetime, timezone
    q = (request.args.get("q") or "").strip().lower()
    event_filter = (request.args.get("event") or "").strip()
    events = list(SECURITY_EVENT_BUFFER)
    events.reverse()
    if event_filter:
        events = [e for e in events if e.get("event", "").startswith(event_filter)]
    if q:
        events = [
            e for e in events
            if q in (e.get("event", "") + " " + e.get("detail", "") + " " + str(e.get("ip", ""))).lower()
        ]
    out = []
    for e in events:
        ts = float(e.get("ts", 0) or 0)
        out.append({
            "ts": ts,
            "iso": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None,
            "event": e.get("event", ""),
            "ip": e.get("ip", ""),
            "actor": e.get("actor"),
            "detail": e.get("detail", ""),
        })
    log_security("SUPERADMIN_AUDIT_EXPORT", f"format=json count={len(out)}")
    return jsonify(events=out, total=len(out)), 200


@bp.route("/superadmin/audit.csv")
@superadmin_required
def superadmin_audit_csv():
    """CSV export of the security audit buffer.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    import csv as _csv
    import io as _io
    from datetime import datetime, timezone
    from flask import Response as _Resp

    q = (request.args.get("q") or "").strip().lower()
    event_filter = (request.args.get("event") or "").strip()
    events = list(SECURITY_EVENT_BUFFER)
    events.reverse()
    if event_filter:
        events = [e for e in events if e.get("event", "").startswith(event_filter)]
    if q:
        events = [
            e for e in events
            if q in (e.get("event", "") + " " + e.get("detail", "") + " " + str(e.get("ip", ""))).lower()
        ]
    buf = _io.StringIO()
    writer = _csv.writer(buf)
    writer.writerow(["timestamp_iso", "epoch", "event", "ip", "actor", "detail"])
    for e in events:
        ts = float(e.get("ts", 0) or 0)
        writer.writerow([
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else "",
            ts,
            e.get("event", ""),
            e.get("ip", ""),
            e.get("actor") if e.get("actor") is not None else "",
            e.get("detail", ""),
        ])
    log_security("SUPERADMIN_AUDIT_EXPORT", f"format=csv count={len(events)}")
    from datetime import datetime as _dt
    fname = "security-audit-" + _dt.utcnow().strftime("%Y%m%dT%H%M%SZ") + ".csv"
    return _Resp(buf.getvalue(), mimetype="text/csv",
                 headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@bp.route("/superadmin/devops")
@superadmin_required
def superadmin_devops():
    """Operational hub: schema diagnostics, payment reconciliation, aggregator health.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    return render_template("superadmin/devops_index.html")


def _collect_schema_diag() -> dict:
    """Collect lightweight schema/pool diagnostics for the devops views."""
    import time as _t
    diag: dict = {}

    try:
        t0 = _t.monotonic()
        db.session.execute(db.text("SELECT 1"))
        diag["db_latency_ms"] = round((_t.monotonic() - t0) * 1000, 1)
    except Exception as exc:
        diag["db_latency_ms"] = None
        diag["db_error"] = str(exc)

    try:
        pool = db.engine.pool
        diag["pool"] = {
            "size": getattr(pool, "size", lambda: None)(),
            "checkedin": getattr(pool, "checkedin", lambda: None)(),
            "checkedout": getattr(pool, "checkedout", lambda: None)(),
            "overflow": getattr(pool, "overflow", lambda: None)(),
        }
    except Exception:
        diag["pool"] = {}

    try:
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        from alembic.config import Config as _AlembicConfig
        import os as _os
        alembic_cfg = _AlembicConfig(_os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), "alembic.ini"))
        with db.engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            current = ctx.get_current_revision()
        script = ScriptDirectory.from_config(alembic_cfg)
        heads = script.get_heads()
        diag["alembic"] = {"current": current, "heads": heads, "in_sync": current in heads}
    except Exception as exc:
        diag["alembic"] = {"error": str(exc)}

    return diag


@bp.route("/superadmin/devops/schema.json")
@superadmin_required
def superadmin_devops_schema_json():
    """Machine-readable schema/pool diagnostics.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    diag = _collect_schema_diag()
    return jsonify(diag), 200


@bp.route("/superadmin/devops/schema")
@superadmin_required
def superadmin_devops_schema():
    """Human-readable schema diagnostics page.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    diag = _collect_schema_diag()
    return render_template("superadmin/devops_schema.html", diag=diag)


@bp.route("/superadmin/devops/aggregators")
@superadmin_required
def superadmin_devops_aggregators():
    """Aggregator (Swiggy / Zomato / UberEats) integration health view.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    from datetime import datetime, timezone, timedelta
    from app.models import AggregatorPlatformCredential, AggregatorOrder, WebhookEventLog

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    yday = datetime.now(timezone.utc) - timedelta(hours=24)

    try:
        from app.models.aggregator import SUPPORTED_PLATFORMS
    except ImportError:
        SUPPORTED_PLATFORMS = []

    platforms_summary = []
    for plat in SUPPORTED_PLATFORMS:
        creds = AggregatorPlatformCredential.query.filter_by(platform=plat).all()
        active = [c for c in creds if getattr(c, "is_active", True)]
        platforms_summary.append({
            "platform": plat,
            "configured": len(creds),
            "active": len(active),
            "modes": sorted({getattr(c, "mode", "test") or "test" for c in creds}),
        })

    volume_rows = (
        db.session.query(
            AggregatorOrder.platform,
            AggregatorOrder.aggregator_status,
            db.func.count(),
            db.func.coalesce(db.func.sum(AggregatorOrder.total), 0),
        )
        .filter(AggregatorOrder.created_at >= today_start)
        .group_by(AggregatorOrder.platform, AggregatorOrder.aggregator_status)
        .all()
    )
    volume_today = [
        {"platform": p, "status": s, "count": int(c), "gmv": float(g or 0)}
        for p, s, c, g in volume_rows
    ]

    pending_count = AggregatorOrder.query.filter(
        AggregatorOrder.aggregator_status == "placed",
        AggregatorOrder.accepted_at.is_(None),
        AggregatorOrder.rejected_at.is_(None),
    ).count()

    sig_failures = (
        WebhookEventLog.query
        .filter(WebhookEventLog.provider.like("agg:%"))
        .filter(WebhookEventLog.event_type == "signature_invalid")
        .filter(WebhookEventLog.received_at >= yday)
        .count()
    )

    recent_events = (
        WebhookEventLog.query
        .filter(WebhookEventLog.provider.like("agg:%"))
        .order_by(WebhookEventLog.received_at.desc())
        .limit(20).all()
    )

    return render_template(
        "superadmin/devops_aggregators.html",
        platforms=platforms_summary,
        volume_today=volume_today,
        pending_count=pending_count,
        sig_failures=sig_failures,
        recent_events=recent_events,
    )


@bp.route("/superadmin/admin-keys")
@superadmin_required
def superadmin_admin_keys():
    """List all admin access keys and let superadmins generate/revoke them.

    Bug fix: route existed in the legacy monolith but was not ported.
    """
    from flask import session as _sess
    from app.models import Owner
    from app.services.auth import _load_admin_keys_from_db, generate_admin_key_for_owner
    from app.services.auth import logged_in_owner

    keys = _load_admin_keys_from_db()
    keys_by_owner = {int(k.get("owner_id", -1)): k for k in keys}
    owners = Owner.query.order_by(Owner.username).all()
    rows = []
    for owner in owners:
        record = keys_by_owner.get(int(owner.id))
        rows.append({
            "owner_id": owner.id,
            "username": owner.username,
            "email": owner.email or "",
            "is_superadmin": bool(owner.is_superadmin),
            "is_active": bool(owner.is_active),
            "has_key": record is not None,
            "generated_at": (record or {}).get("generated_at"),
        })
    new_key = _sess.pop("_new_admin_key", None)
    new_key_owner = _sess.pop("_new_admin_key_owner", None)
    return render_template(
        "superadmin/admin_keys.html",
        rows=rows,
        new_key=new_key,
        new_key_owner=new_key_owner,
        owner_username=logged_in_owner(),
    )


@bp.route("/superadmin/admin-keys/generate", methods=["POST"])
@superadmin_required
def superadmin_admin_keys_generate():
    """Generate (or rotate) an admin key for an owner.

    Accepts JSON ``{"owner_id": <int>}`` or form field ``owner_id``.
    Returns ``{"ok": true, "key": "<raw-key>", "owner_id": <int>}`` on
    success.  The raw key is shown exactly once; store it securely.

    Requires a *real* superadmin principal (``owner.is_superadmin=True``),
    not just a generic admin session, to prevent privilege escalation via the
    shared ``admin_authenticated`` session key.
    """
    from app.models import Owner
    from app.services.auth import generate_admin_key_for_owner, logged_in_owner_obj

    # Enforce is_superadmin principal — superadmin_required alone permits
    # generic admin sessions, which is not sufficient for key issuance.
    caller = logged_in_owner_obj()
    if not (caller and getattr(caller, "is_superadmin", False)):
        log_security("SUPERADMIN_KEY_GEN_DENIED", f"caller_id={getattr(caller, 'id', None)}")
        return jsonify(ok=False, error="Superadmin principal required"), 403

    data = request.get_json(silent=True) or {}
    owner_id_raw = data.get("owner_id") or request.form.get("owner_id")
    try:
        owner_id = int(owner_id_raw)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="owner_id is required and must be an integer"), 400

    owner = db.session.get(Owner, owner_id)
    if not owner:
        return jsonify(ok=False, error=f"Owner {owner_id} not found"), 404

    raw = generate_admin_key_for_owner(owner_id, owner.username)
    log_security("SUPERADMIN_GENERATED_ADMIN_KEY_API", f"owner_id={owner_id}")
    return jsonify(ok=True, key=raw, owner_id=owner_id), 201


@bp.route("/superadmin/admin-keys/revoke", methods=["POST"])
@superadmin_required
def superadmin_admin_keys_revoke():
    """Revoke the admin key for an owner.

    Accepts JSON ``{"owner_id": <int>}`` or form field ``owner_id``.
    Returns ``{"ok": true, "revoked": true}`` if a key existed and was
    removed, or ``{"ok": true, "revoked": false}`` if no key was found.

    Requires a *real* superadmin principal (``owner.is_superadmin=True``),
    not just a generic admin session, to prevent privilege escalation via the
    shared ``admin_authenticated`` session key.
    """
    from app.models import Owner
    from app.services.auth import revoke_admin_key_for_owner, logged_in_owner_obj

    # Enforce is_superadmin principal — same reasoning as /generate above.
    caller = logged_in_owner_obj()
    if not (caller and getattr(caller, "is_superadmin", False)):
        log_security("SUPERADMIN_KEY_REVOKE_DENIED", f"caller_id={getattr(caller, 'id', None)}")
        return jsonify(ok=False, error="Superadmin principal required"), 403

    data = request.get_json(silent=True) or {}
    owner_id_raw = data.get("owner_id") or request.form.get("owner_id")
    try:
        owner_id = int(owner_id_raw)
    except (TypeError, ValueError):
        return jsonify(ok=False, error="owner_id is required and must be an integer"), 400

    owner = db.session.get(Owner, owner_id)
    if not owner:
        return jsonify(ok=False, error=f"Owner {owner_id} not found"), 404

    revoked = revoke_admin_key_for_owner(owner_id)
    log_security("SUPERADMIN_REVOKED_ADMIN_KEY_API", f"owner_id={owner_id} revoked={revoked}")
    return jsonify(ok=True, revoked=revoked), 200


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
