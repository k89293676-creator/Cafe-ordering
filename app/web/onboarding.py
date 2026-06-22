"""Owner onboarding wizard — 3-step JS-driven setup flow.

Routes
------
GET  /owner/onboarding          — render the wizard
POST /owner/onboarding/complete — mark onboarding_complete = True
"""
from __future__ import annotations

import logging

from flask import Blueprint, flash, redirect, render_template, url_for

from app.extensions import db, limiter
from app.utils.security import login_required
from app.services.auth import logged_in_owner_obj

log = logging.getLogger("cafe.onboarding")

bp = Blueprint("web_onboarding", __name__)


@bp.route("/owner/onboarding")
@login_required
@limiter.limit("60 per minute")
def onboarding():
    owner = logged_in_owner_obj()
    return render_template("owner_onboarding.html", owner=owner)


@bp.route("/owner/onboarding/complete", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def onboarding_complete():
    owner = logged_in_owner_obj()
    owner.onboarding_complete = True
    db.session.commit()
    flash("Setup complete! Welcome to your dashboard.", "success")
    return redirect(url_for("web_owner.owner_dashboard"))
