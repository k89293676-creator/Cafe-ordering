"""Public-facing routes: home, owner landing, table order page."""
from __future__ import annotations

import re
import time

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db, limiter
from app.services.auth import logged_in_owner
from app.services.tables import load_tables, load_owner_tables
from app.services.menu import load_owner_menu, load_menu
from app.services.tables import load_settings
from app.utils.security import log_security

bp = Blueprint("web_public", __name__)


@bp.route("/")
def home():
    if logged_in_owner():
        return redirect(url_for("web_owner.owner_dashboard"))
    return redirect(url_for("web_public.owner_landing"))


@bp.route("/welcome")
def owner_landing():
    if logged_in_owner():
        return redirect(url_for("web_owner.owner_dashboard"))
    return render_template("landing.html")


@bp.route("/owner-lead", methods=["POST"])
@limiter.limit("3 per 10 minutes")
def owner_lead_submit():
    from app.models import OwnerLead
    from app.utils.serializers import _safe_text
    name = _safe_text(request.form.get("contact_name"), max_len=100)
    cafe = _safe_text(request.form.get("cafe_name"), max_len=100)
    email = _safe_text(request.form.get("email"), max_len=254)
    phone = _safe_text(request.form.get("phone"), max_len=30)
    city = _safe_text(request.form.get("city"), max_len=100)
    message = _safe_text(request.form.get("message"), max_len=1000)
    try:
        table_count = int(request.form.get("table_count", "0") or "0")
    except ValueError:
        table_count = 0

    if not name or not cafe or not email:
        flash("Please fill in all required fields.", "error")
        return redirect(url_for("web_public.owner_landing"))

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Invalid email address.", "error")
        return redirect(url_for("web_public.owner_landing"))

    from app.utils.security import _client_ip
    lead = OwnerLead(
        contact_name=name,
        cafe_name=cafe,
        email=email,
        phone=phone,
        city=city,
        table_count=table_count,
        message=message,
        submitted_ip=_client_ip(),
        submitted_ua=(request.user_agent.string or "")[:500],
    )
    db.session.add(lead)
    db.session.commit()
    log_security("OWNER_LEAD_SUBMITTED", f"email={email!r}")
    flash("Thanks! We'll be in touch shortly.", "success")
    return redirect(url_for("web_public.owner_landing"))


@bp.route("/table/<table_id>")
@limiter.limit("60 per minute")
def table_order(table_id: str):
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(404)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404)
    owner_id = table.get("ownerId")
    menu = load_owner_menu(owner_id) if owner_id else {"categories": []}
    settings = load_settings(owner_id)
    return render_template(
        "table_order.html",
        table=table,
        menu=menu,
        settings=settings,
    )


@bp.route("/at-your-service/<table_id>")
@limiter.limit("30 per minute")
def at_your_service(table_id: str):
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(404)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404)
    owner_id = table.get("ownerId")
    settings = load_settings(owner_id)
    return render_template("at_your_service.html", table=table, settings=settings)
