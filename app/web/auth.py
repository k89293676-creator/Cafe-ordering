"""Owner auth routes: login, logout, signup, 2FA, remember-me."""
from __future__ import annotations

import os
import re
import time

from flask import (
    Blueprint,
    abort,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import logout_user

from app.extensions import db, limiter
from app.services.auth import (
    _complete_login,
    _is_strong_password,
    _make_password_hash,
    _password_matches,
    create_owner_in_db,
    create_remember_token,
    logged_in_owner,
    logged_in_owner_obj,
    revoke_all_tokens_for_owner,
    revoke_remember_token,
    validate_remember_token,
)
from app.utils.security import (
    _clear_failed_logins,
    _client_ip,
    _is_ip_locked_out,
    _record_failed_login,
    log_security,
)
from app.utils.serializers import _no_store, _safe_redirect_target

bp = Blueprint("web_auth", __name__)

_REMEMBER_COOKIE = "cafe_remember"
_REGISTRATION_OPEN = os.environ.get("REGISTRATION_OPEN", "true").lower() in {"1", "true", "yes", "on"}


@bp.route("/owner/login", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def owner_login():
    if logged_in_owner():
        return redirect(url_for("web_owner.owner_dashboard"))

    # Auto-login via remember-me cookie.
    if request.method == "GET":
        remember_raw = request.cookies.get(_REMEMBER_COOKIE)
        if remember_raw:
            token_data = validate_remember_token(remember_raw)
            if token_data:
                from app.models import Owner
                owner = db.session.get(Owner, token_data["id"])
                if owner and owner.is_active:
                    _complete_login(owner)
                    log_security("REMEMBER_ME_LOGIN", f"owner_id={owner.id}")
                    resp = make_response(redirect(url_for("web_owner.owner_dashboard")))
                    return resp

    if request.method == "POST":
        from app.models import Owner
        username = (request.form.get("username") or "").strip()[:100]
        password = request.form.get("password") or ""
        remember_me = request.form.get("remember_me") == "1"

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("owner_login.html"), 400

        ip = _client_ip()
        if _is_ip_locked_out(ip):
            log_security("LOGIN_LOCKED_OUT", f"ip={ip!r} username={username!r}")
            flash("Too many failed attempts. Please try again later.", "error")
            return render_template("owner_login.html"), 429

        owner = Owner.query.filter(
            (Owner.username == username) | (Owner.email == username)
        ).first()

        if not owner or not _password_matches(owner.password_hash, password):
            _record_failed_login(ip)
            log_security("LOGIN_FAILED", f"username={username!r}")
            time.sleep(0.5)
            flash("Invalid credentials.", "error")
            return render_template("owner_login.html"), 401

        if not owner.is_active:
            flash("Account is inactive.", "error")
            return render_template("owner_login.html"), 403

        if owner.totp_enabled:
            session["pending_owner_id"] = owner.id
            session["pending_remember_me"] = remember_me
            return redirect(url_for("web_auth.owner_login_totp_verify"))

        _clear_failed_logins(ip)
        _complete_login(owner)
        log_security("LOGIN_SUCCESS", f"owner_id={owner.id}")

        resp = make_response(redirect(_safe_redirect_target(
            request.args.get("next"), url_for("web_owner.owner_dashboard")
        )))
        if remember_me:
            raw = create_remember_token(owner.id)
            resp.set_cookie(
                _REMEMBER_COOKIE, raw, max_age=90 * 86400,
                httponly=True, samesite="Lax",
                secure=bool(request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"),
            )
        return resp

    resp = make_response(render_template("owner_login.html"))
    return _no_store(resp)


@bp.route("/owner/login/2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def owner_login_totp_verify():
    from app.models import Owner
    pending_id = session.get("pending_owner_id")
    if not pending_id:
        return redirect(url_for("web_auth.owner_login"))
    owner = db.session.get(Owner, pending_id)
    if not owner:
        session.pop("pending_owner_id", None)
        return redirect(url_for("web_auth.owner_login"))
    if request.method == "POST":
        code = (request.form.get("totp_code") or "").strip()
        remember_me = session.get("pending_remember_me", False)
        try:
            import pyotp  # type: ignore
            totp = pyotp.TOTP(owner.totp_secret)
            if totp.verify(code):
                session.pop("pending_owner_id", None)
                session.pop("pending_remember_me", None)
                _complete_login(owner)
                log_security("TOTP_LOGIN_SUCCESS", f"owner_id={owner.id}")
                resp = make_response(redirect(url_for("web_owner.owner_dashboard")))
                if remember_me:
                    raw = create_remember_token(owner.id)
                    resp.set_cookie(_REMEMBER_COOKIE, raw, max_age=90 * 86400, httponly=True, samesite="Lax")
                return resp
            else:
                log_security("TOTP_FAILED", f"owner_id={owner.id}")
                flash("Invalid or expired code.", "error")
        except ImportError:
            flash("TOTP library not installed.", "error")
    return render_template("owner_login_totp.html", owner=owner)


@bp.route("/owner/logout")
def owner_logout():
    remember_raw = request.cookies.get(_REMEMBER_COOKIE)
    if remember_raw:
        revoke_remember_token(remember_raw)
    log_security("LOGOUT", f"owner_id={session.get('owner_id')}")
    session.clear()
    logout_user()
    resp = make_response(redirect(url_for("web_auth.owner_login")))
    resp.delete_cookie(_REMEMBER_COOKIE)
    return resp


@bp.route("/owner/signup", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def owner_signup():
    if not _REGISTRATION_OPEN:
        flash("Public registration is not open. Please contact an admin.", "error")
        return redirect(url_for("web_auth.owner_login"))

    if logged_in_owner():
        return redirect(url_for("web_owner.owner_dashboard"))

    if request.method == "POST":
        from app.models import Owner
        username = (request.form.get("username") or "").strip()[:50]
        email = (request.form.get("email") or "").strip()[:254]
        password = request.form.get("password") or ""
        cafe_name = (request.form.get("cafe_name") or "").strip()[:100]
        invite_code = (request.form.get("invite_code") or "").strip()

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("owner_signup.html"), 400
        if not re.fullmatch(r"[a-zA-Z0-9_.\-]{3,50}", username):
            flash("Username may only contain letters, digits, underscores, hyphens or dots (3–50 chars).", "error")
            return render_template("owner_signup.html"), 400
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Invalid email address.", "error")
            return render_template("owner_signup.html"), 400
        if not _is_strong_password(password):
            flash("Password must be at least 8 characters and contain letters and digits.", "error")
            return render_template("owner_signup.html"), 400

        if Owner.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("owner_signup.html"), 409
        if email and Owner.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("owner_signup.html"), 409

        # Validate invite code if provided (or required).
        if invite_code:
            from app.services.auth import consume_admin_key
            owner_id = consume_admin_key(invite_code)
            if not owner_id:
                flash("Invalid or already-used invite code.", "error")
                return render_template("owner_signup.html"), 403

        pw_hash = _make_password_hash(password)
        create_owner_in_db(username, email or None, pw_hash, cafe_name)
        log_security("OWNER_SIGNUP", f"username={username!r}")
        flash("Account created! Please sign in.", "success")
        return redirect(url_for("web_auth.owner_login"))

    resp = make_response(render_template("owner_signup.html"))
    return _no_store(resp)


@bp.route("/owner/redeem-key", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def owner_redeem_key():
    if not logged_in_owner():
        return redirect(url_for("web_auth.owner_login"))
    if request.method == "POST":
        from app.services.auth import find_admin_key_owner
        key = (request.form.get("key") or "").strip()
        if not key:
            flash("Please enter a key.", "error")
            return render_template("owner_redeem_key.html")
        owner_id = find_admin_key_owner(key)
        if not owner_id:
            flash("Invalid or already-used key.", "error")
            return render_template("owner_redeem_key.html")
        flash("Key redeemed successfully!", "success")
        return redirect(url_for("web_owner.owner_dashboard"))
    return render_template("owner_redeem_key.html")
