from __future__ import annotations

import io
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import qrcode
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MENU_PATH = BASE_DIR / "menu.json"
ORDERS_PATH = BASE_DIR / "orders.json"
OWNERS_PATH = BASE_DIR / "owners.json"
TABLES_PATH = BASE_DIR / "tables.json"

# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production" or os.environ.get("RAILWAY_ENVIRONMENT") is not None

# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------

_secret_key = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
if _secret_key:
    app.secret_key = _secret_key
else:
    app.secret_key = secrets.token_hex(32)
    print(
        "WARNING: SECRET_KEY not set. Sessions will not survive restarts. "
        "Set SECRET_KEY in your environment for production.",
        flush=True,
    )

# ---------------------------------------------------------------------------
# App config
# ---------------------------------------------------------------------------

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB request size limit
    WTF_CSRF_TIME_LIMIT=3600,            # CSRF tokens expire after 1 hour
    WTF_CSRF_SSL_STRICT=False,           # Allow non-HTTPS in dev
)

# ---------------------------------------------------------------------------
# Security extensions
# ---------------------------------------------------------------------------

# CSRF protection — all POST/PUT/PATCH/DELETE forms must include token.
# JSON API endpoints are explicitly exempted below via @csrf.exempt.
csrf = CSRFProtect(app)

# Rate limiter — keyed by remote IP.
# Uses in-memory storage (acceptable for single-worker; use Redis in production).
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# Content-Security-Policy definition.
# 'unsafe-inline' for style-src is needed for inline style="" attributes in templates.
# All JS is served from 'self' — no inline scripts exist after dashboard refactor.
_csp = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:"],
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri": "'self'",
}

# Flask-Talisman adds security headers on every response.
# force_https=False because Railway terminates TLS at the proxy.
Talisman(
    app,
    force_https=False,
    strict_transport_security=IS_PRODUCTION,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    session_cookie_secure=IS_PRODUCTION,
    content_security_policy=_csp,
    content_security_policy_nonce_in=None,
    referrer_policy="strict-origin-when-cross-origin",
    feature_policy={
        "geolocation": "'none'",
        "camera": "'none'",
        "microphone": "'none'",
    },
    frame_options="DENY",
    x_content_type_options=True,
    x_xss_protection=True,
)

# ---------------------------------------------------------------------------
# Additional security headers not covered by Talisman
# ---------------------------------------------------------------------------

@app.after_request
def extra_security_headers(response: Response) -> Response:
    response.headers["Server"] = "CafePortal"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
    )
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response

# ---------------------------------------------------------------------------
# Security logging
# ---------------------------------------------------------------------------

security_log = logging.getLogger("cafe.security")
if not security_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[SECURITY] %(asctime)s %(levelname)s %(message)s"))
    security_log.addHandler(_handler)
    security_log.setLevel(logging.INFO)


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def log_security(event: str, detail: str = "") -> None:
    security_log.info("%s ip=%s %s", event, _client_ip(), detail)

# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def read_json(path: Path, default):
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return default


def write_json(path: Path, data) -> None:
    try:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except OSError as exc:
        app.logger.error("Failed to write %s: %s", path, exc)
        raise


def load_menu() -> dict:
    menu = read_json(MENU_PATH, {"categories": []})
    # Back-fill category IDs if missing (e.g. seed data without IDs)
    changed = False
    existing_ids: set[str] = set()
    for cat in menu.get("categories", []):
        if not cat.get("id"):
            cat["id"] = unique_id(normalize_id(cat.get("name", "category")), existing_ids)
            changed = True
        existing_ids.add(cat["id"])
    if changed:
        write_json(MENU_PATH, menu)
    return menu


def load_orders() -> list[dict]:
    return read_json(ORDERS_PATH, [])


def load_owners() -> list[dict]:
    return read_json(OWNERS_PATH, [])


def load_tables() -> list[dict]:
    return read_json(TABLES_PATH, [])


def save_orders(orders: list[dict]) -> None:
    write_json(ORDERS_PATH, orders)


def save_owners(owners: list[dict]) -> None:
    write_json(OWNERS_PATH, owners)


def save_tables(tables: list[dict]) -> None:
    write_json(TABLES_PATH, tables)


def save_menu(menu: dict) -> None:
    write_json(MENU_PATH, menu)

# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------

def next_id(records: list[dict]) -> int:
    return max(
        (r.get("id", 0) for r in records if isinstance(r.get("id"), int)),
        default=0,
    ) + 1


def next_table_number(tables: list[dict]) -> int:
    nums = []
    for t in tables:
        tid = t.get("id", "")
        if isinstance(tid, str) and tid.startswith("table-"):
            try:
                nums.append(int(tid[len("table-"):]))
            except ValueError:
                pass
    return max(nums, default=0) + 1


def normalize_id(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or "item"


def unique_id(base: str, existing: set) -> str:
    if base not in existing:
        return base
    counter = 2
    while f"{base}-{counter}" in existing:
        counter += 1
    return f"{base}-{counter}"

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def logged_in_owner() -> str | None:
    return session.get("owner_username")


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not logged_in_owner():
            log_security("UNAUTHORISED_ACCESS", f"path={request.path}")
            return redirect(url_for("owner_login"))
        return view_func(*args, **kwargs)
    return wrapper


def _normalise_mobile(mobile: str) -> str:
    return re.sub(r"[^\d]", "", mobile)


def _is_valid_mobile(mobile: str) -> bool:
    return 7 <= len(_normalise_mobile(mobile)) <= 15


def _is_strong_password(password: str) -> bool:
    """Require at least 8 chars with one letter and one digit."""
    return (
        len(password) >= 8
        and any(c.isalpha() for c in password)
        and any(c.isdigit() for c in password)
    )

# ---------------------------------------------------------------------------
# OTP helpers — use secrets module (cryptographically secure)
# ---------------------------------------------------------------------------

def generate_otp() -> str:
    return f"{secrets.randbelow(900000) + 100000:06d}"


OTP_VALIDITY_SECONDS = 600  # 10 minutes


def _otp_is_expired() -> bool:
    created_at_str = session.get("signup_otp_created_at")
    if not created_at_str:
        return True
    try:
        created_at = datetime.fromisoformat(created_at_str)
        return (datetime.now(timezone.utc) - created_at).total_seconds() > OTP_VALIDITY_SECONDS
    except ValueError:
        return True

# ---------------------------------------------------------------------------
# Order computation
# ---------------------------------------------------------------------------

def compute_order_summary(items: list[dict]) -> dict:
    menu = load_menu()
    menu_items = {
        item["id"]: item
        for category in menu["categories"]
        for item in category["items"]
    }
    if not items:
        abort(400, description="Order must contain at least one item.")

    total = 0.0
    summary = []
    for entry in items:
        item_id = entry.get("id")
        quantity = max(int(entry.get("quantity", 1)), 1)
        menu_item = menu_items.get(item_id)
        if not menu_item:
            abort(400, description=f"Unknown item id: {item_id!r}")
        item_total = menu_item["price"] * quantity
        total += item_total
        summary.append(
            {
                "id": item_id,
                "name": menu_item["name"],
                "price": menu_item["price"],
                "quantity": quantity,
                "lineTotal": round(item_total, 2),
            }
        )

    return {"items": summary, "total": round(total, 2)}

# ---------------------------------------------------------------------------
# Error handlers — generic messages, no stack traces exposed
# ---------------------------------------------------------------------------

@app.errorhandler(400)
def err_bad_request(e):
    if request.is_json:
        return jsonify(description=str(e)), 400
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def err_forbidden(e):
    if request.is_json:
        return jsonify(description="Forbidden."), 403
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def err_not_found(e):
    if request.is_json:
        return jsonify(description="Not found."), 404
    return render_template("errors/404.html"), 404


@app.errorhandler(CSRFError)
def err_csrf(e):
    log_security("CSRF_VIOLATION", f"path={request.path}")
    flash("Your session has expired or the request was invalid. Please try again.")
    return redirect(request.referrer or url_for("home")), 302


@app.errorhandler(429)
def err_rate_limit(e):
    log_security("RATE_LIMIT_HIT", f"path={request.path}")
    if request.is_json:
        return jsonify(description="Too many requests. Please slow down."), 429
    return render_template("errors/429.html"), 429


@app.errorhandler(413)
def err_payload_too_large(e):
    if request.is_json:
        return jsonify(description="Request payload too large."), 413
    return render_template("errors/400.html"), 413


@app.errorhandler(500)
def err_server(e):
    app.logger.exception("Internal server error: %s", e)
    if request.is_json:
        return jsonify(description="An internal error occurred."), 500
    return render_template("errors/500.html"), 500

# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def home() -> str:
    return render_template("index.html", owner_username=logged_in_owner())


@app.route("/table/<table_id>")
@limiter.limit("60 per minute")
def table_order(table_id: str) -> str:
    # Sanitise table_id: only alphanumeric and hyphens allowed
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(404)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404, description="Table not found.")
    return render_template("table_order.html", table=table)

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/owner/login", methods=["GET", "POST"])
@limiter.limit("15 per minute; 50 per hour", methods=["POST"])
def owner_login() -> str | Response:
    if logged_in_owner():
        return redirect(url_for("owner_dashboard"))

    owners = load_owners()
    allow_signup = len(owners) == 0

    if request.method == "POST":
        identifier = str(request.form.get("identifier", "")).strip()[:128]
        password = str(request.form.get("password", ""))[:256]

        owner = next(
            (
                o for o in owners
                if o["username"] == identifier
                or _normalise_mobile(o.get("mobile", "")) == _normalise_mobile(identifier)
            ),
            None,
        )

        if owner and check_password_hash(owner["passwordHash"], password):
            session.clear()
            session["owner_username"] = owner["username"]
            session.permanent = True
            log_security("LOGIN_SUCCESS", f"user={owner['username']!r}")
            return redirect(url_for("owner_dashboard"))

        # Constant-time-safe failure path — always log
        log_security("LOGIN_FAILURE", f"identifier={identifier!r}")
        flash("Sign in failed. Check your credentials.")

    return render_template("owner_login.html", allow_signup=allow_signup)


@app.route("/owner/signup", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def owner_signup() -> str | Response:
    if logged_in_owner():
        return redirect(url_for("owner_dashboard"))
    owners = load_owners()
    if len(owners) > 0:
        return redirect(url_for("owner_login"))

    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()[:64]
        mobile = str(request.form.get("mobile", "")).strip()[:20]
        password = str(request.form.get("password", ""))[:256]

        if not username or not mobile or not password:
            flash("Username, mobile number, and password are all required.")
            return render_template("owner_signup.html")

        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{3,64}", username):
            flash("Username may only contain letters, digits, underscores, hyphens, and dots (3–64 chars).")
            return render_template("owner_signup.html")

        if not _is_valid_mobile(mobile):
            flash("Please enter a valid mobile number (7–15 digits).")
            return render_template("owner_signup.html")

        if not _is_strong_password(password):
            flash("Password must be at least 8 characters and contain at least one letter and one digit.")
            return render_template("owner_signup.html")

        otp = generate_otp()
        session["pending_signup"] = {
            "username": username,
            "mobile": _normalise_mobile(mobile),
            "passwordHash": generate_password_hash(password, method="scrypt"),
        }
        session["signup_otp"] = otp
        session["signup_otp_created_at"] = datetime.now(timezone.utc).isoformat()

        log_security("SIGNUP_OTP_ISSUED", f"user={username!r}")
        # In production: send OTP via SMS. Here we pass it through URL for demo.
        return redirect(url_for("owner_signup_verify", otp_hint=otp))

    return render_template("owner_signup.html")


@app.route("/owner/signup/verify", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def owner_signup_verify() -> str | Response:
    owners = load_owners()
    if len(owners) > 0:
        return redirect(url_for("owner_login"))

    pending = session.get("pending_signup")
    if not pending:
        flash("Session expired. Please start registration again.")
        return redirect(url_for("owner_signup"))

    otp_hint = request.args.get("otp_hint", "")

    if request.method == "POST":
        # Check OTP expiry
        if _otp_is_expired():
            session.pop("pending_signup", None)
            session.pop("signup_otp", None)
            session.pop("signup_otp_created_at", None)
            log_security("OTP_EXPIRED", f"user={pending.get('username', '?')!r}")
            flash("Your OTP has expired. Please register again.")
            return redirect(url_for("owner_signup"))

        entered = str(request.form.get("otp", "")).strip()[:6]
        stored = session.get("signup_otp", "")

        if not secrets.compare_digest(entered, stored):
            log_security("OTP_FAILURE", f"user={pending.get('username', '?')!r}")
            flash("Incorrect OTP. Please try again.")
            return render_template("owner_signup_verify.html", otp_hint=otp_hint)

        # OTP correct — create account
        new_owner = {
            "id": next_id(owners),
            "username": pending["username"],
            "mobile": pending["mobile"],
            "passwordHash": pending["passwordHash"],
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        owners.append(new_owner)
        save_owners(owners)
        # Clear all session data (including pending signup keys) then log in
        session.clear()
        session["owner_username"] = pending["username"]
        session.permanent = True
        log_security("SIGNUP_SUCCESS", f"user={pending['username']!r}")
        return redirect(url_for("owner_dashboard"))

    return render_template("owner_signup_verify.html", otp_hint=otp_hint)


@app.route("/owner/logout")
def owner_logout() -> Response:
    username = logged_in_owner()
    session.clear()
    if username:
        log_security("LOGOUT", f"user={username!r}")
    return redirect(url_for("home"))

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/owner/dashboard")
@login_required
def owner_dashboard() -> str:
    tables = load_tables()
    orders = sorted(load_orders(), key=lambda o: o["createdAt"], reverse=True)
    menu = load_menu()
    pending_orders = [o for o in orders if o.get("status") != "completed"]
    completed_orders = [o for o in orders if o.get("status") == "completed"]
    total_items = sum(len(cat["items"]) for cat in menu.get("categories", []))
    return render_template(
        "owner_dashboard.html",
        owner_username=logged_in_owner(),
        tables=tables,
        menu=menu,
        menu_json=json.dumps(menu, indent=2),
        pending_orders=pending_orders,
        completed_orders=completed_orders,
        total_items=total_items,
    )

# ---------------------------------------------------------------------------
# Menu management (all require login)
# ---------------------------------------------------------------------------

@app.route("/owner/menu/category", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_menu_category() -> Response:
    name = str(request.form.get("categoryName", "")).strip()[:100]
    if not name:
        flash("Category name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#menu")

    menu = load_menu()
    existing_ids = {c["id"] for c in menu["categories"]}
    category_id = unique_id(normalize_id(name), existing_ids)
    menu["categories"].append({"id": category_id, "name": name, "items": []})
    save_menu(menu)
    flash(f"Category '{name}' created.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/category/<category_id>/delete", methods=["POST"])
@login_required
def delete_menu_category(category_id: str) -> Response:
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", category_id):
        abort(400)
    menu = load_menu()
    menu["categories"] = [c for c in menu["categories"] if c["id"] != category_id]
    save_menu(menu)
    flash("Category deleted.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/category/<category_id>/rename", methods=["POST"])
@login_required
def rename_menu_category(category_id: str) -> Response:
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", category_id):
        abort(400)
    new_name = str(request.form.get("categoryName", "")).strip()[:100]
    if not new_name:
        flash("Category name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#menu")

    menu = load_menu()
    category = next((c for c in menu["categories"] if c["id"] == category_id), None)
    if not category:
        flash("Category not found.")
        return redirect(url_for("owner_dashboard") + "#menu")

    category["name"] = new_name
    save_menu(menu)
    flash("Category renamed.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/item", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def save_menu_item() -> Response:
    form = request.form
    category_id = str(form.get("categoryId", "")).strip()[:100]
    item_id = str(form.get("itemId", "")).strip()[:100]
    name = str(form.get("itemName", "")).strip()[:200]
    description = str(form.get("itemDescription", "")).strip()[:500]
    price_text = str(form.get("itemPrice", "")).strip()[:20]
    tags_text = str(form.get("itemTags", "")).strip()[:300]

    if not category_id or not name or not price_text:
        flash("Item name, price, and category are required.")
        return redirect(url_for("owner_dashboard") + "#menu")

    try:
        price = round(float(price_text), 2)
        if price < 0 or price > 9999.99:
            raise ValueError("Price out of range")
    except ValueError:
        flash("Item price must be a valid positive number.")
        return redirect(url_for("owner_dashboard") + "#menu")

    tags = [t.strip()[:50] for t in tags_text.split(",") if t.strip()][:10]
    menu = load_menu()
    category = next((c for c in menu["categories"] if c["id"] == category_id), None)
    if not category:
        flash("Selected category does not exist.")
        return redirect(url_for("owner_dashboard") + "#menu")

    if item_id:
        item = next((i for i in category["items"] if i["id"] == item_id), None)
        if item:
            item.update({"name": name, "description": description, "price": price, "tags": tags})
            flash("Menu item updated.")
        else:
            flash("Menu item not found.")
            return redirect(url_for("owner_dashboard") + "#menu")
    else:
        existing_ids = {i["id"] for c in menu["categories"] for i in c["items"]}
        new_item_id = unique_id(normalize_id(name), existing_ids)
        category["items"].append(
            {"id": new_item_id, "name": name, "description": description, "price": price, "tags": tags}
        )
        flash("Menu item added.")

    save_menu(menu)
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/item/<item_id>/delete", methods=["POST"])
@login_required
def delete_menu_item(item_id: str) -> Response:
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", item_id):
        abort(400)
    menu = load_menu()
    for category in menu["categories"]:
        category["items"] = [i for i in category["items"] if i["id"] != item_id]
    save_menu(menu)
    flash("Menu item deleted.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def update_menu() -> Response:
    if "menuJson" in request.form:
        menu_text = request.form.get("menuJson", "")[:50_000]
        try:
            menu_data = json.loads(menu_text)
            if not isinstance(menu_data, dict) or "categories" not in menu_data:
                raise ValueError("Invalid structure")
        except (json.JSONDecodeError, ValueError):
            flash("Invalid menu JSON. Please fix formatting and try again.")
            return redirect(url_for("owner_dashboard") + "#menu")
        save_menu(menu_data)
        flash("Menu updated successfully.")
        return redirect(url_for("owner_dashboard") + "#menu")

    if "menuFile" in request.files:
        menu_file = request.files["menuFile"]
        if menu_file and menu_file.filename:
            try:
                menu_data = json.load(menu_file)
                if not isinstance(menu_data, dict) or "categories" not in menu_data:
                    raise ValueError("Invalid structure")
            except Exception:
                flash("Uploaded file is not valid menu JSON.")
                return redirect(url_for("owner_dashboard") + "#menu")
            save_menu(menu_data)
            flash("Menu file uploaded successfully.")
            return redirect(url_for("owner_dashboard") + "#menu")

    flash("No menu data was provided.")
    return redirect(url_for("owner_dashboard") + "#menu")

# ---------------------------------------------------------------------------
# Table management
# ---------------------------------------------------------------------------

@app.route("/owner/tables", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def create_table() -> Response:
    table_name = str(request.form.get("tableName", "")).strip()[:100]
    if not table_name:
        flash("Table name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#tables")

    tables = load_tables()
    table_num = next_table_number(tables)
    table_id = f"table-{table_num}"
    tables.append(
        {
            "id": table_id,
            "name": table_name,
            "createdAt": datetime.utcnow().isoformat() + "Z",
        }
    )
    save_tables(tables)
    return redirect(url_for("owner_dashboard") + "#tables")


@app.route("/owner/tables/<table_id>/delete", methods=["POST"])
@login_required
def delete_table(table_id: str) -> Response:
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    tables = load_tables()
    filtered = [t for t in tables if t["id"] != table_id]
    save_tables(filtered)
    return redirect(url_for("owner_dashboard") + "#tables")


@app.route("/owner/tables/<table_id>/qr.png")
@login_required
@limiter.limit("60 per hour")
def table_qr(table_id: str) -> Response:
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    try:
        tables = load_tables()
        table = next((t for t in tables if t["id"] == table_id), None)
        if not table:
            abort(404, description="Table not found.")
        table_url = url_for("table_order", table_id=table_id, _external=True)
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(table_url)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        buf.seek(0)
        response = Response(buf.read(), mimetype="image/png")
        response.headers["Cache-Control"] = "no-store"
        return response
    except Exception as exc:
        app.logger.error("QR generation failed for %s: %s", table_id, exc)
        abort(500)

# ---------------------------------------------------------------------------
# Order management
# ---------------------------------------------------------------------------

VALID_ORDER_STATUSES = {"pending", "preparing", "ready", "completed"}


@app.route("/owner/order/<int:order_id>/status", methods=["POST"])
@login_required
def update_order_status(order_id: int) -> Response:
    new_status = str(request.form.get("status", "")).strip()
    if new_status not in VALID_ORDER_STATUSES:
        flash("Invalid order status.")
        return redirect(url_for("owner_dashboard") + "#orders")
    orders = load_orders()
    found = False
    for order in orders:
        if order["id"] == order_id:
            order["status"] = new_status
            found = True
            break
    if not found:
        flash("Order not found.")
        return redirect(url_for("owner_dashboard") + "#orders")
    save_orders(orders)
    return redirect(url_for("owner_dashboard") + "#orders")


@app.route("/owner/order/<int:order_id>/complete", methods=["POST"])
@login_required
def complete_order(order_id: int) -> Response:
    orders = load_orders()
    for order in orders:
        if order["id"] == order_id:
            order["status"] = "completed"
            break
    save_orders(orders)
    return redirect(url_for("owner_dashboard") + "#orders")


@app.route("/owner/menu/download")
@login_required
def download_menu() -> Response:
    menu = load_menu()
    return Response(
        json.dumps(menu, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=menu.json"},
    )

# ---------------------------------------------------------------------------
# Public JSON API — CSRF exempted (clients send JSON, not form data)
# ---------------------------------------------------------------------------

@app.route("/api/menu", methods=["GET"])
@csrf.exempt
@limiter.limit("120 per minute")
def menu_api() -> Response:
    response = jsonify(load_menu())
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/api/order-preview", methods=["POST"])
@csrf.exempt
@limiter.limit("30 per minute")
def order_preview() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    return compute_order_summary(payload.get("items", [])), 200


@app.route("/api/checkout", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute; 100 per hour")
def checkout() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    customer_name = str(payload.get("customerName", "Guest")).strip()[:100] or "Guest"
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    items = payload.get("items", [])

    if table_id and not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400, description="Invalid table ID.")

    table_name = None
    if table_id:
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        table_name = table["name"] if table else table_id
    else:
        table_name = "Online"

    order_summary = compute_order_summary(items)
    orders = load_orders()
    order_record = {
        "id": next_id(orders),
        "customerName": customer_name,
        "tableId": table_id,
        "tableName": table_name,
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "items": order_summary["items"],
        "total": order_summary["total"],
        "status": "pending",
        "origin": "table" if table_id else "online",
    }
    orders.append(order_record)
    save_orders(orders)
    log_security("ORDER_PLACED", f"table={table_id!r} total={order_record['total']}")
    return {"message": "Order placed successfully.", "order": order_record}, 201


@app.route("/api/orders", methods=["GET"])
@csrf.exempt
@limiter.limit("60 per minute")
def orders_api() -> tuple[dict, int]:
    return {"orders": load_orders()}, 200


@app.route("/api/order/<int:order_id>", methods=["GET"])
@csrf.exempt
@limiter.limit("120 per minute")
def get_order(order_id: int) -> tuple[dict, int]:
    orders = load_orders()
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        abort(404, description="Order not found.")
    return {"order": order}, 200

# ---------------------------------------------------------------------------
# Init data files
# ---------------------------------------------------------------------------

def _init_data_files() -> None:
    if not ORDERS_PATH.exists():
        write_json(ORDERS_PATH, [])
    if not OWNERS_PATH.exists():
        write_json(OWNERS_PATH, [])
    if not TABLES_PATH.exists():
        write_json(TABLES_PATH, [])
    if not MENU_PATH.exists():
        write_json(MENU_PATH, {"categories": []})


try:
    _init_data_files()
except Exception as exc:
    import sys
    print(f"WARNING: Could not initialise data files: {exc}", file=sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
