"""Owner dashboard and profile routes."""
from __future__ import annotations

import re

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.tables import load_owner_tables, load_settings
from app.services.menu import load_owner_menu
from app.services.orders import load_orders
from app.utils.security import login_required, log_security, _client_ip
from app.utils.serializers import _safe_text

bp = Blueprint("web_owner", __name__)


@bp.route("/owner/dashboard")
@login_required
def owner_dashboard():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    tables = load_owner_tables(owner_id)
    settings = load_settings(owner_id)
    recent_orders = load_orders(owner_id=owner_id, limit=50)
    pending_count = sum(1 for o in recent_orders if o["status"] == "pending")
    preparing_count = sum(1 for o in recent_orders if o["status"] == "preparing")
    revenue_today = sum(
        o["total"] for o in recent_orders
        if o.get("createdAt", "").startswith(__import__("datetime").date.today().isoformat())
        and o["status"] not in ("cancelled", "voided")
    )
    return render_template(
        "owner_dashboard.html",
        owner=owner,
        tables=tables,
        settings=settings,
        recent_orders=recent_orders,
        pending_count=pending_count,
        preparing_count=preparing_count,
        revenue_today=revenue_today,
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
