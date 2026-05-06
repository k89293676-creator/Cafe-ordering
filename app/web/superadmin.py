"""Superadmin routes: owner management, system flags, audit log, security events."""
from __future__ import annotations

import os
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
    return render_template("superadmin_verify.html")


@bp.route("/superadmin")
@bp.route("/superadmin/")
@superadmin_required
def superadmin_dashboard():
    from app.models import Owner, Order, Cafe
    owner_count = db.session.query(db.func.count(Owner.id)).scalar() or 0
    order_count = db.session.query(db.func.count(Order.id)).scalar() or 0
    cafe_count = db.session.query(db.func.count(Cafe.id)).scalar() or 0
    active_owners = Owner.query.filter_by(is_active=True).count()
    pending_approvals = Owner.query.filter_by(approval_status="pending").count()
    return render_template(
        "superadmin_dashboard.html",
        owner_count=owner_count,
        order_count=order_count,
        cafe_count=cafe_count,
        active_owners=active_owners,
        pending_approvals=pending_approvals,
    )


@bp.route("/superadmin/owners")
@superadmin_required
def superadmin_owners():
    from app.models import Owner
    owners = Owner.query.order_by(Owner.id).all()
    return render_template("superadmin_owners.html", owners=owners)


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
    return render_template("superadmin_system_flags.html", flags=flags)


@bp.route("/superadmin/security-log")
@superadmin_required
def superadmin_security_log():
    events = list(reversed(list(SECURITY_EVENT_BUFFER)))
    return render_template("superadmin_security_log.html", events=events[:500])


@bp.route("/superadmin/leads")
@superadmin_required
def superadmin_leads():
    from app.models import OwnerLead
    leads = OwnerLead.query.order_by(OwnerLead.created_at.desc()).limit(200).all()
    return render_template("superadmin_leads.html", leads=leads)
