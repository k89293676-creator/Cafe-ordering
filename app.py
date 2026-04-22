from __future__ import annotations

import base64
import csv
import io
import json
import logging
import mimetypes
import os
import random
import re
import secrets
import string
import sys
import tempfile
import threading
from logging.handlers import RotatingFileHandler
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlparse

import portalocker
import pyotp
import qrcode
from dotenv import load_dotenv
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
    stream_with_context,
    send_file,
)
from flask_bcrypt import Bcrypt
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    current_user,
    login_required as flask_login_required,
    login_user,
    logout_user,
)
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR")) if os.environ.get("DATA_DIR") else BASE_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)
MENU_PATH = DATA_DIR / "menu.json"
ORDERS_PATH = DATA_DIR / "orders.json"
OWNERS_PATH = DATA_DIR / "owners.json"
TABLES_PATH = DATA_DIR / "tables.json"
FEEDBACK_PATH = DATA_DIR / "feedback.json"
TOKENS_PATH = DATA_DIR / "tokens.json"

_orders_lock = threading.Lock()
_menu_lock = threading.Lock()
_tables_lock = threading.Lock()

# Boot time + version are surfaced via /health for uptime tracking on Railway.
APP_START_TIME = time.time()
APP_VERSION = os.environ.get("APP_VERSION") or os.environ.get("RAILWAY_GIT_COMMIT_SHA", "dev")[:12]

app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

IS_PRODUCTION = (
    os.environ.get("IS_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}
    or os.environ.get("FLASK_ENV") == "production"
    or os.environ.get("RAILWAY_ENVIRONMENT") is not None
)

_raw_db_url = os.environ.get("DATABASE_URL", "")
if _raw_db_url.startswith("postgres://"):
    _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)

_allow_sqlite_in_production = os.environ.get("ALLOW_SQLITE_IN_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}
_using_ephemeral_production_sqlite = IS_PRODUCTION and not _raw_db_url and not _allow_sqlite_in_production

if _using_ephemeral_production_sqlite:
    raise RuntimeError(
        "DATABASE_URL is not configured in production. Refusing to start with an "
        "ephemeral SQLite database — Railway's container filesystem is wiped on "
        "every redeploy, which would silently destroy all owners, cafes and orders.\n\n"
        "Fix: in your Railway project, click 'New' → 'Database' → 'Add PostgreSQL'. "
        "Railway will inject DATABASE_URL automatically and the app will reuse it.\n\n"
        "If you understand the data-loss risk and explicitly want SQLite anyway, "
        "set ALLOW_SQLITE_IN_PRODUCTION=1."
    )

_secret_key = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
if _secret_key:
    app.secret_key = _secret_key
else:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY is required in production.")
    app.secret_key = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set. Sessions will not survive restarts.", flush=True)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_SSL_STRICT=False,
    SQLALCHEMY_DATABASE_URI=(
        _raw_db_url if _raw_db_url else f"sqlite:///{DATA_DIR / 'app.db'}"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "smtp.sendgrid.net"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
    MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes", "on"},
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME") or ("apikey" if os.environ.get("SENDGRID_API_KEY") else None),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD") or os.environ.get("SENDGRID_API_KEY"),
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER"),
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    level = logging.INFO if IS_PRODUCTION else logging.DEBUG
    log_file = os.environ.get("LOG_FILE")
    if IS_PRODUCTION and log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
        handler.setFormatter(JsonFormatter())
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    app.logger.propagate = False


configure_logging()

Compress(app)
csrf = CSRFProtect(app)

_rate_limit_storage_uri = os.environ.get("REDIS_URL") or "memory://"
if _rate_limit_storage_uri == "memory://":
    app.logger.warning("REDIS_URL not set; using in-memory rate limiting storage.")

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri=_rate_limit_storage_uri,
)

_csp = {
    "default-src": "'self'",
    "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
    "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
    "img-src": [
        "'self'",
        "data:",
        "https://loremflickr.com",
        "https://image.pollinations.ai",
        "https://*.unsplash.com",
        "https://images.unsplash.com",
        "https://*.googleusercontent.com",
        "blob:",
    ],
    "connect-src": ["'self'", "https://loremflickr.com", "https://image.pollinations.ai"],
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri": "'self'",
}

if IS_PRODUCTION:
    try:
        Talisman(
            app,
            force_https=False,
            strict_transport_security=IS_PRODUCTION,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            session_cookie_secure=IS_PRODUCTION,
            content_security_policy=_csp,
            permissions_policy={
                "geolocation": "()",
                "camera": "()",
                "microphone": "()",
                "payment": "()",
                "usb": "()",
            },
        )
    except TypeError:
        Talisman(
            app,
            force_https=False,
            strict_transport_security=IS_PRODUCTION,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            session_cookie_secure=IS_PRODUCTION,
            content_security_policy=_csp,
        )

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "owner_login"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Cafe(db.Model):
    __tablename__ = "cafes"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, default="")
    slug = db.Column(db.Text, unique=True, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Owner(db.Model):
    __tablename__ = "owners"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    cafe_name = db.Column(db.Text, default="")
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    google_place_id = db.Column(db.Text, default="")
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
    is_superadmin = db.Column(db.Boolean, default=False, nullable=False, server_default="false")
    totp_secret = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, server_default="false")
    phone = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    def get_id(self) -> str:
        return str(self.id)


class CafeTable(db.Model):
    __tablename__ = "cafe_tables"
    id = db.Column(db.Text, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Menu(db.Model):
    __tablename__ = "menus"
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), primary_key=True)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    data = db.Column(db.JSON, nullable=False, default=lambda: {"categories": []})


class Ingredient(db.Model):
    __tablename__ = "ingredients"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), nullable=False)
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    name = db.Column(db.Text, nullable=False)
    unit = db.Column(db.Text, default="unit")
    stock = db.Column(db.Numeric(10, 3), default=0)
    low_stock_threshold = db.Column(db.Numeric(10, 3), default=5)
    menu_item_id = db.Column(db.Text, nullable=True)
    qty_per_order = db.Column(db.Numeric(10, 3), default=1)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    table_id = db.Column(db.Text)
    table_name = db.Column(db.Text)
    customer_name = db.Column(db.Text, default="Guest")
    customer_email = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    items = db.Column(db.JSON, nullable=False, default=list)
    modifiers = db.Column(db.JSON, default=dict)
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    tip = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    status = db.Column(db.Text, default="pending")
    pickup_code = db.Column(db.Text, default="")
    origin = db.Column(db.Text, default="table")
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"), nullable=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True)
    table_id = db.Column(db.Text)
    customer_name = db.Column(db.Text, default="Guest")
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class RememberToken(db.Model):
    __tablename__ = "remember_tokens"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"))
    token_hash = db.Column(db.Text, unique=True, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Settings(db.Model):
    __tablename__ = "settings"
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), primary_key=True)
    logo_url = db.Column(db.Text, default="")
    brand_color = db.Column(db.Text, default="#4f46e5")
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


USE_DB = True
db.init_app(app)
migrate.init_app(app, db)

_DB_READY = False
_DB_INIT_ERROR = "Database has not been initialized yet."
_DB_INIT_LAST_ATTEMPT = 0.0
_DB_INIT_LOCK = threading.Lock()


def _init_db() -> None:
    with app.app_context():
        if _using_ephemeral_production_sqlite:
            app.logger.error(
                "DATABASE_URL is not set in production. Running with SQLite fallback; "
                "data may be lost on Railway redeploys. Attach Railway PostgreSQL for durable persistence."
            )
        db.create_all()
        inspector = inspect(db.engine)

        def add_column_if_missing(table_name: str, column_sql: str, column_name: str) -> None:
            if table_name not in inspector.get_table_names():
                return
            existing = {col["name"] for col in inspector.get_columns(table_name)}
            if column_name not in existing:
                db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}"))
                db.session.commit()

        add_column_if_missing("orders", "customer_phone TEXT DEFAULT ''", "customer_phone")
        add_column_if_missing("orders", "pickup_code TEXT DEFAULT ''", "pickup_code")
        add_column_if_missing("orders", "modifiers JSON", "modifiers")
        add_column_if_missing("orders", "notes TEXT DEFAULT ''", "notes")
        add_column_if_missing("orders", "cafe_id INTEGER", "cafe_id")
        add_column_if_missing("orders", "updated_at TIMESTAMP", "updated_at")
        add_column_if_missing("owners", "is_superadmin BOOLEAN DEFAULT false", "is_superadmin")
        add_column_if_missing("owners", "totp_secret TEXT", "totp_secret")
        add_column_if_missing("owners", "totp_enabled BOOLEAN DEFAULT false", "totp_enabled")
        add_column_if_missing("owners", "phone TEXT DEFAULT ''", "phone")
        add_column_if_missing("owners", "cafe_id INTEGER", "cafe_id")
        add_column_if_missing("feedback", "order_id INTEGER", "order_id")
        add_column_if_missing("feedback", "cafe_id INTEGER", "cafe_id")
        _seed_sqlalchemy_from_json()
    app.logger.info("DB schema ready: %s", app.config["SQLALCHEMY_DATABASE_URI"])


def _initialize_runtime_state(force: bool = False) -> bool:
    global _DB_READY, _DB_INIT_ERROR, _DB_INIT_LAST_ATTEMPT
    if _DB_READY:
        return True
    now = time.monotonic()
    if not force and now - _DB_INIT_LAST_ATTEMPT < 1:
        return False
    with _DB_INIT_LOCK:
        if _DB_READY:
            return True
        now = time.monotonic()
        if not force and now - _DB_INIT_LAST_ATTEMPT < 1:
            return False
        _DB_INIT_LAST_ATTEMPT = now
        try:
            _init_db()
            _make_superadmin_if_missing()
            _DB_READY = True
            _DB_INIT_ERROR = ""
            return True
        except Exception as exc:
            _DB_INIT_ERROR = str(exc)
            app.logger.exception("Database initialization failed; app will keep serving /health and retry.")
            return False


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def extra_security_headers(response: Response) -> Response:
    response.headers["Server"] = "CafePortal"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


security_log = logging.getLogger("cafe.security")
if not security_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[SECURITY] %(asctime)s %(levelname)s %(message)s"))
    security_log.addHandler(_handler)
    security_log.setLevel(logging.INFO)
    security_log.propagate = False


_ALLOWED_UPLOADS = {
    ".json": {"application/json", "text/json"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
}


def validate_uploaded_file(uploaded_file, file_bytes: bytes) -> tuple[str | None, str | None]:
    filename = (uploaded_file.filename or "").lower()
    ext = Path(filename).suffix
    if ext not in _ALLOWED_UPLOADS:
        return "Unsupported file type.", None
    guessed_type = (mimetypes.guess_type(filename)[0] or "").lower()
    provided_type = (uploaded_file.mimetype or "").split(";", 1)[0].lower()
    allowed_types = _ALLOWED_UPLOADS[ext]
    if guessed_type not in allowed_types:
        return "File extension does not match MIME type.", None
    if provided_type and provided_type not in allowed_types and provided_type != "application/octet-stream":
        return "File MIME type not allowed.", None
    if not file_bytes:
        return "File is empty.", None
    return None, "image" if ext in {".jpg", ".jpeg", ".png"} else "json"


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def log_security(event: str, detail: str = "") -> None:
    security_log.info("%s ip=%s %s", event, _client_ip(), detail)


# ---------------------------------------------------------------------------
# JSON file helpers (fallback)
# ---------------------------------------------------------------------------

def _json_lock_path(path: Path) -> str:
    return str(path) + ".lock"


def safe_read_json(path: Path, default):
    try:
        with portalocker.Lock(_json_lock_path(path), timeout=10):
            if not path.exists():
                return default
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
    except json.JSONDecodeError:
        return default
    except (OSError, portalocker.exceptions.LockException) as exc:
        app.logger.error("Failed to read %s: %s", path, exc)
        return default


def atomic_write_json(path: Path, data) -> None:
    tmp_path = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with portalocker.Lock(_json_lock_path(path), timeout=10):
            fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".~", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
    except (OSError, portalocker.exceptions.LockException) as exc:
        app.logger.error("Failed to write %s: %s", path, exc)
        raise
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Data access helpers
# ---------------------------------------------------------------------------

def _iso(dt) -> str:
    return dt.isoformat() if dt else ""


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _owner_dict(owner: Owner) -> dict:
    return {
        "id": owner.id,
        "username": owner.username,
        "email": owner.email,
        "passwordHash": owner.password_hash,
        "cafeName": owner.cafe_name or "",
        "cafeId": owner.cafe_id,
        "googlePlaceId": owner.google_place_id or "",
        "isActive": bool(owner.is_active),
        "isSuperadmin": bool(owner.is_superadmin),
        "totpEnabled": bool(owner.totp_enabled),
        "phone": owner.phone or "",
        "createdAt": _iso(owner.created_at),
    }


def _cafe_dict(cafe: Cafe) -> dict:
    return {
        "id": cafe.id,
        "name": cafe.name,
        "slug": cafe.slug or "",
        "isActive": bool(cafe.is_active),
        "createdAt": _iso(cafe.created_at),
    }


def _order_dict(order: Order) -> dict:
    return {
        "id": order.id,
        "ownerId": order.owner_id,
        "cafeId": order.cafe_id,
        "tableId": order.table_id,
        "tableName": order.table_name,
        "customerName": order.customer_name or "Guest",
        "customerEmail": order.customer_email or "",
        "customerPhone": order.customer_phone or "",
        "items": order.items if isinstance(order.items, list) else [],
        "modifiers": order.modifiers if isinstance(order.modifiers, dict) else {},
        "subtotal": float(order.subtotal or 0),
        "tip": float(order.tip or 0),
        "total": float(order.total or 0),
        "status": order.status or "pending",
        "pickupCode": order.pickup_code or "",
        "origin": order.origin or "table",
        "notes": order.notes or "",
        "createdAt": _iso(order.created_at),
        "updatedAt": _iso(order.updated_at),
    }


def _feedback_dict(feedback: Feedback) -> dict:
    return {
        "id": feedback.id,
        "ownerId": feedback.owner_id,
        "cafeId": feedback.cafe_id,
        "orderId": feedback.order_id,
        "tableId": feedback.table_id,
        "customerName": feedback.customer_name or "Guest",
        "rating": feedback.rating,
        "comment": feedback.comment or "",
        "createdAt": _iso(feedback.created_at),
    }


def _settings_dict(settings: Settings | None) -> dict:
    if not settings:
        return {"logoUrl": "", "brandColor": "#4f46e5"}
    return {"logoUrl": settings.logo_url or "", "brandColor": settings.brand_color or "#4f46e5"}


def load_owners() -> list[dict]:
    return [_owner_dict(o) for o in Owner.query.order_by(Owner.id).all()]


def load_cafes() -> list[dict]:
    return [_cafe_dict(c) for c in Cafe.query.order_by(Cafe.id).all()]


def create_cafe_in_db(name: str, slug: str | None = None) -> dict:
    cafe = Cafe(name=name, slug=slug)
    db.session.add(cafe)
    db.session.commit()
    return _cafe_dict(cafe)


def create_owner_in_db(username: str, email: str | None, password_hash: str,
                       cafe_name: str = "", cafe_id: int | None = None,
                       is_superadmin: bool = False) -> dict:
    owner = Owner(
        username=username,
        email=email or None,
        password_hash=password_hash,
        cafe_name=cafe_name,
        cafe_id=cafe_id,
        is_superadmin=is_superadmin,
    )
    db.session.add(owner)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        msg = str(getattr(exc, "orig", exc)).lower()
        if "email" in msg:
            raise ValueError("That email address is already registered.") from exc
        if "username" in msg:
            raise ValueError("That username is already taken.") from exc
        raise ValueError("An account with those details already exists.") from exc
    return _owner_dict(owner)


def load_tables() -> list[dict]:
    rows = CafeTable.query.order_by(CafeTable.created_at).all()
    return [
        {"id": t.id, "name": t.name, "ownerId": t.owner_id,
         "cafeId": t.cafe_id, "createdAt": _iso(t.created_at)}
        for t in rows
    ]


def save_tables(tables: list[dict]) -> None:
    keep_ids = {t["id"] for t in tables}
    for existing in CafeTable.query.all():
        if existing.id not in keep_ids:
            db.session.delete(existing)
    for table in tables:
        record = db.session.get(CafeTable, table["id"]) or CafeTable(id=table["id"])
        record.name = table["name"]
        record.owner_id = table.get("ownerId")
        record.cafe_id = table.get("cafeId")
        db.session.add(record)
    db.session.commit()


def load_menu() -> dict:
    all_categories = []
    for menu in Menu.query.all():
        for category in (menu.data or {}).get("categories", []):
            cat = dict(category)
            cat["ownerId"] = menu.owner_id
            cat["cafeId"] = menu.cafe_id
            all_categories.append(cat)
    return {"categories": all_categories}


def save_menu(menu: dict) -> None:
    by_owner: dict[int, list] = {}
    for category in menu.get("categories", []):
        owner_id = category.get("ownerId")
        if owner_id is None:
            continue
        cat_copy = {k: v for k, v in category.items() if k not in ("ownerId", "cafeId")}
        by_owner.setdefault(owner_id, []).append(cat_copy)
    owner_ids = {o.id for o in Owner.query.all()} | {m.owner_id for m in Menu.query.all()}
    for owner_id in owner_ids:
        categories = by_owner.get(owner_id, [])
        record = db.session.get(Menu, owner_id) or Menu(owner_id=owner_id)
        record.data = {"categories": categories}
        owner = db.session.get(Owner, owner_id)
        if owner:
            record.cafe_id = owner.cafe_id
        db.session.add(record)
    db.session.commit()


def load_orders(owner_id: int | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
    query = Order.query
    if owner_id is not None:
        query = query.filter(Order.owner_id == owner_id)
    query = query.order_by(Order.id)
    if limit is not None and limit > 0:
        query = query.limit(limit)
    if offset:
        query = query.offset(offset)
    return [_order_dict(o) for o in query.all()]


def place_order_in_db(order: dict) -> dict:
    pickup_code = _generate_pickup_code()
    record = Order(
        owner_id=order.get("ownerId"),
        cafe_id=order.get("cafeId"),
        table_id=order.get("tableId"),
        table_name=order.get("tableName"),
        customer_name=order.get("customerName", "Guest"),
        customer_email=order.get("customerEmail", ""),
        customer_phone=order.get("customerPhone", ""),
        items=order.get("items", []),
        modifiers=order.get("modifiers", {}),
        subtotal=order.get("subtotal", order.get("total", 0)),
        tip=order.get("tip", 0),
        total=order.get("total", 0),
        status=order.get("status", "pending"),
        pickup_code=pickup_code,
        origin=order.get("origin", "table"),
        notes=order.get("notes", ""),
        created_at=_parse_dt(order.get("createdAt")) or datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(record)
    db.session.flush()
    _deduct_inventory(record.owner_id, record.items)
    db.session.commit()
    return _order_dict(record)


def _generate_pickup_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def _deduct_inventory(owner_id: int | None, items: list) -> None:
    if not owner_id or not items:
        return
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).all()
            for ing in ingredients:
                deduct = float(ing.qty_per_order or 1) * qty
                ing.stock = max(0, float(ing.stock or 0) - deduct)
                db.session.add(ing)
    except Exception as exc:
        app.logger.warning("Inventory deduction failed: %s", exc)


def _restore_inventory(order: dict) -> None:
    owner_id = order.get("ownerId")
    items = order.get("items") or []
    if not owner_id or not items:
        return
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).all()
            for ing in ingredients:
                add_back = float(ing.qty_per_order or 1) * qty
                ing.stock = float(ing.stock or 0) + add_back
                db.session.add(ing)
        db.session.commit()
    except Exception as exc:
        app.logger.warning("Inventory restore failed: %s", exc)


def _check_stock_available(owner_id: int | None, items: list) -> tuple[bool, str]:
    if not owner_id or not items:
        return True, ""
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).all()
            for ing in ingredients:
                needed = float(ing.qty_per_order or 1) * qty
                if float(ing.stock or 0) < needed:
                    name = item.get("name") or f"item {item_id}"
                    ing_name = getattr(ing, "name", None) or "ingredient"
                    return False, f"Not enough stock for '{name}' (insufficient {ing_name})."
    except Exception as exc:
        app.logger.warning("Stock check failed: %s", exc)
        return True, ""
    return True, ""


def _db_update_order_status(order_id: int, new_status: str) -> bool:
    order = db.session.get(Order, order_id)
    if not order:
        return False
    order.status = new_status
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return True


def _db_get_order(order_id: int) -> dict | None:
    order = db.session.get(Order, order_id)
    return _order_dict(order) if order else None


def _db_delete_order(order_id: int) -> bool:
    order = db.session.get(Order, order_id)
    if not order:
        return False
    db.session.delete(order)
    db.session.commit()
    return True


def load_feedback() -> list[dict]:
    return [_feedback_dict(f) for f in Feedback.query.order_by(Feedback.id.desc()).all()]


def save_feedback_entry(entry: dict) -> dict:
    feedback = Feedback(
        owner_id=entry.get("ownerId"),
        cafe_id=entry.get("cafeId"),
        order_id=entry.get("orderId"),
        table_id=entry.get("tableId"),
        customer_name=entry.get("customerName", "Guest"),
        rating=entry["rating"],
        comment=entry.get("comment", ""),
        created_at=_parse_dt(entry.get("createdAt")) or datetime.now(timezone.utc),
    )
    db.session.add(feedback)
    db.session.commit()
    return _feedback_dict(feedback)


def load_settings(owner_id: int | None) -> dict:
    if not owner_id:
        return _settings_dict(None)
    return _settings_dict(db.session.get(Settings, owner_id))


def save_settings(owner_id: int, logo_url: str, brand_color: str) -> dict:
    settings = db.session.get(Settings, owner_id) or Settings(owner_id=owner_id)
    settings.logo_url = logo_url
    settings.brand_color = brand_color if re.fullmatch(r"#[0-9a-fA-F]{6}", brand_color) else "#4f46e5"
    settings.updated_at = datetime.now(timezone.utc)
    db.session.add(settings)
    db.session.commit()
    return _settings_dict(settings)


def _seed_sqlalchemy_from_json() -> None:
    if Owner.query.count() or not OWNERS_PATH.exists():
        return
    owners = safe_read_json(OWNERS_PATH, [])
    tables = safe_read_json(TABLES_PATH, [])
    menu = safe_read_json(MENU_PATH, {"categories": []})
    orders = safe_read_json(ORDERS_PATH, [])
    feedback_list = safe_read_json(FEEDBACK_PATH, [])
    if owners:
        for o in owners:
            rec = Owner(
                username=o["username"],
                email=o.get("email"),
                password_hash=o.get("passwordHash", ""),
                cafe_name=o.get("cafeName", ""),
                is_active=o.get("isActive", True),
            )
            db.session.add(rec)
        db.session.commit()
    if tables:
        save_tables(tables)
    if menu.get("categories"):
        save_menu(menu)
    for order in orders:
        place_order_in_db(order)
    for entry in feedback_list:
        save_feedback_entry(entry)


# ---------------------------------------------------------------------------
# Remember-me tokens
# ---------------------------------------------------------------------------

_REMEMBER_COOKIE = "cafe_remember"
_REMEMBER_DAYS = 90


def _hash_token(raw: str) -> str:
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()


def create_remember_token(owner_id: int) -> str:
    raw = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw)
    expires = datetime.now(timezone.utc) + timedelta(days=_REMEMBER_DAYS)
    stale = (
        RememberToken.query.filter_by(owner_id=owner_id)
        .order_by(RememberToken.created_at.desc())
        .offset(4)
        .all()
    )
    for token in stale:
        db.session.delete(token)
    db.session.add(RememberToken(owner_id=owner_id, token_hash=token_hash, expires_at=expires))
    db.session.commit()
    return raw


def validate_remember_token(raw: str) -> dict | None:
    if not raw:
        return None
    token = RememberToken.query.filter_by(token_hash=_hash_token(raw)).first()
    if not token:
        return None
    now = datetime.now(timezone.utc)
    expires_at = token.expires_at
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at and expires_at < now:
        db.session.delete(token)
        db.session.commit()
        return None
    owner = db.session.get(Owner, token.owner_id)
    return _owner_dict(owner) if owner and owner.is_active else None


def revoke_remember_token(raw: str) -> None:
    if not raw:
        return
    token = RememberToken.query.filter_by(token_hash=_hash_token(raw)).first()
    if token:
        db.session.delete(token)
        db.session.commit()


def revoke_all_tokens_for_owner(owner_id: int) -> None:
    RememberToken.query.filter_by(owner_id=owner_id).delete()
    db.session.commit()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def next_id(records: list[dict]) -> int:
    return max((r.get("id", 0) for r in records if isinstance(r.get("id"), int)), default=0) + 1


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
    return re.sub(r"-+", "-", slug).strip("-") or "item"


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
    if current_user.is_authenticated:
        return current_user.username
    return session.get("owner_username")


def logged_in_owner_id() -> int | None:
    if current_user.is_authenticated:
        return current_user.id
    return session.get("owner_id")


def logged_in_owner_obj() -> Owner | None:
    if current_user.is_authenticated:
        return current_user
    owner_id = session.get("owner_id")
    if owner_id:
        return db.session.get(Owner, owner_id)
    return None


@login_manager.user_loader
def load_owner_user(owner_id: str):
    try:
        owner = db.session.get(Owner, int(owner_id))
    except (TypeError, ValueError):
        return None
    return owner if owner and owner.is_active else None


def login_required(view_func):
    @flask_login_required
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not logged_in_owner():
            log_security("UNAUTHORISED_ACCESS", f"path={request.path}")
            return redirect(url_for("owner_login"))
        return view_func(*args, **kwargs)
    return wrapper


def superadmin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        owner = logged_in_owner_obj()
        if not owner or not getattr(owner, "is_superadmin", False):
            abort(403)
        return view_func(*args, **kwargs)
    return wrapper


def _is_strong_password(password: str) -> bool:
    return (
        len(password) >= 8
        and any(c.isalpha() for c in password)
        and any(c.isdigit() for c in password)
    )


def _make_password_hash(password: str) -> str:
    return bcrypt.generate_password_hash(password).decode("utf-8")


def _password_matches(password_hash: str, password: str) -> bool:
    try:
        if password_hash.startswith("$2"):
            return bcrypt.check_password_hash(password_hash, password)
        return check_password_hash(password_hash, password)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# IP login lockout
# ---------------------------------------------------------------------------

_failed_logins: dict[str, list[float]] = {}
_failed_logins_lock = threading.Lock()
_MAX_FAIL_ATTEMPTS = 5
_LOCKOUT_WINDOW = 900.0


def _is_ip_locked_out(ip: str) -> bool:
    now = time.monotonic()
    with _failed_logins_lock:
        recent = [t for t in _failed_logins.get(ip, []) if now - t < _LOCKOUT_WINDOW]
        _failed_logins[ip] = recent
        return len(recent) >= _MAX_FAIL_ATTEMPTS


def _record_failed_login(ip: str) -> None:
    now = time.monotonic()
    with _failed_logins_lock:
        recent = [t for t in _failed_logins.get(ip, []) if now - t < _LOCKOUT_WINDOW]
        recent.append(now)
        _failed_logins[ip] = recent


def _clear_failed_logins(ip: str) -> None:
    with _failed_logins_lock:
        _failed_logins.pop(ip, None)


def api_login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not logged_in_owner():
            log_security("API_UNAUTHORISED", f"path={request.path}")
            return jsonify(description="Authentication required."), 401
        return view_func(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Cache control
# ---------------------------------------------------------------------------

def _no_store(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------------------------
# Order computation
# ---------------------------------------------------------------------------

def compute_order_summary(items: list[dict], owner_menu: dict | None = None) -> dict:
    if not isinstance(items, list):
        abort(400, description="items must be a list.")
    menu = owner_menu if owner_menu is not None else load_menu()
    menu_items = {
        item["id"]: item
        for category in menu.get("categories", [])
        for item in category.get("items", [])
    }
    if not items:
        abort(400, description="Order must contain at least one item.")

    total = 0.0
    summary = []
    for entry in items:
        if not isinstance(entry, dict):
            abort(400, description="Each item entry must be an object.")
        item_id = entry.get("id")
        if not item_id or not isinstance(item_id, str):
            abort(400, description="Each item entry must have a valid string 'id'.")
        try:
            quantity = max(int(float(entry.get("quantity", 1))), 1)
        except (TypeError, ValueError):
            abort(400, description=f"Invalid quantity for item {item_id!r}.")
        menu_item = menu_items.get(item_id)
        if not menu_item:
            abort(400, description=f"Unknown item id: {item_id!r}")
        if not menu_item.get("available", True):
            abort(400, description=f"Sorry, '{menu_item['name']}' is currently sold out.")
        modifiers = entry.get("modifiers", [])
        modifier_total = 0.0
        modifier_list = []
        if isinstance(modifiers, list):
            for mod in modifiers:
                if isinstance(mod, dict):
                    try:
                        mod_price = round(float(mod.get("price", 0)), 2)
                    except (TypeError, ValueError):
                        mod_price = 0.0
                    modifier_total += mod_price
                    modifier_list.append({"name": str(mod.get("name", ""))[:50], "price": mod_price})
        item_unit_price = menu_item["price"] + modifier_total
        item_total = item_unit_price * quantity
        total += item_total
        summary.append({
            "id": item_id,
            "name": menu_item["name"],
            "price": menu_item["price"],
            "quantity": quantity,
            "modifiers": modifier_list,
            "size": str(entry.get("size", ""))[:50],
            "extras": str(entry.get("extras", ""))[:200],
            "notes": str(entry.get("notes", ""))[:500],
            "lineTotal": round(item_total, 2),
        })

    return {"items": summary, "total": round(total, 2)}


def _resolve_order_table_labels(order: dict, tables: list[dict]) -> dict:
    order_copy = dict(order)
    table_id = order_copy.get("tableId")
    table_name = order_copy.get("tableName")
    if table_id:
        matched = next((t for t in tables if t["id"] == table_id), None)
        if matched:
            order_copy["tableName"] = matched["name"]
        elif not table_name:
            order_copy["tableName"] = table_id
    return order_copy


def _mail_enabled() -> bool:
    return bool(app.config.get("MAIL_DEFAULT_SENDER") and app.config.get("MAIL_PASSWORD"))


def _send_order_confirmation(order: dict) -> None:
    recipient = order.get("customerEmail")
    if not recipient or not _mail_enabled():
        return
    try:
        item_lines = "\n".join(
            f"- {item.get('name')} x{item.get('quantity', 1)}: ₹{float(item.get('lineTotal', 0)):.2f}"
            for item in order.get("items", [])
        )
        pickup_code = order.get("pickupCode", "")
        message = Message(
            subject=f"Order #{order.get('id')} confirmation",
            recipients=[recipient],
            body=(
                f"Thanks for your order, {order.get('customerName', 'Guest')}.\n\n"
                f"{item_lines}\n\n"
                f"Total: ₹{float(order.get('total') or 0):.2f}\n"
                f"Pickup Code: {pickup_code}\n"
                f"Status: {order.get('status', 'pending')}\n"
            ),
        )
        mail.send(message)
    except Exception as exc:
        app.logger.warning("Order confirmation email failed: %s", exc)


# ---------------------------------------------------------------------------
# SSE
# ---------------------------------------------------------------------------

_sse_subscribers: dict[int, list] = {}
_sse_customer_subs: dict[int, list] = {}
_sse_lock = threading.Lock()


def _local_dispatch_owner(owner_id: int, payload: str) -> None:
    with _sse_lock:
        queues = _sse_subscribers.get(owner_id, [])
        dead = []
        for q in queues:
            try:
                q.append(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            queues.remove(q)


def _local_dispatch_customer(order_id: int, payload: str) -> None:
    with _sse_lock:
        queues = _sse_customer_subs.get(order_id, [])
        dead = []
        for q in queues:
            try:
                q.append(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            queues.remove(q)


# Optional Redis pub/sub fan-out for multi-worker deployments.
_REDIS_URL = os.environ.get("REDIS_URL")
_redis_client = None
_REDIS_OWNER_CHANNEL = "sse:owner"
_REDIS_CUSTOMER_CHANNEL = "sse:customer"

if _REDIS_URL:
    try:
        import redis as _redis_lib  # type: ignore

        _redis_client = _redis_lib.Redis.from_url(_REDIS_URL, decode_responses=True)
        _redis_client.ping()
        app.logger.info("SSE: Redis pub/sub enabled at %s", _REDIS_URL)

        def _redis_subscriber_loop() -> None:
            backoff = 1
            while True:
                try:
                    pubsub = _redis_client.pubsub(ignore_subscribe_messages=True)
                    pubsub.subscribe(_REDIS_OWNER_CHANNEL, _REDIS_CUSTOMER_CHANNEL)
                    backoff = 1
                    for message in pubsub.listen():
                        try:
                            channel = message.get("channel")
                            raw = message.get("data")
                            if not raw:
                                continue
                            envelope = json.loads(raw)
                            if channel == _REDIS_OWNER_CHANNEL:
                                _local_dispatch_owner(int(envelope["owner_id"]), envelope["payload"])
                            elif channel == _REDIS_CUSTOMER_CHANNEL:
                                _local_dispatch_customer(int(envelope["order_id"]), envelope["payload"])
                        except Exception as inner_exc:
                            app.logger.warning("SSE redis dispatch error: %s", inner_exc)
                except Exception as exc:
                    app.logger.warning("SSE redis subscriber error: %s; retrying in %ss", exc, backoff)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 30)

        threading.Thread(target=_redis_subscriber_loop, name="sse-redis-sub", daemon=True).start()
    except Exception as _redis_err:
        app.logger.warning("SSE: Redis unavailable (%s); falling back to in-memory.", _redis_err)
        _redis_client = None


def _notify_owner(owner_id: int, event_type: str, data: dict) -> None:
    payload = json.dumps({"type": event_type, "data": data})
    if _redis_client is not None:
        try:
            _redis_client.publish(
                _REDIS_OWNER_CHANNEL,
                json.dumps({"owner_id": owner_id, "payload": payload}),
            )
            return
        except Exception as exc:
            app.logger.warning("SSE redis publish failed (owner): %s; using local.", exc)
    _local_dispatch_owner(owner_id, payload)


def _notify_order_status(order_id: int, status: str) -> None:
    payload = json.dumps({"status": status, "id": order_id})
    if _redis_client is not None:
        try:
            _redis_client.publish(
                _REDIS_CUSTOMER_CHANNEL,
                json.dumps({"order_id": order_id, "payload": payload}),
            )
            return
        except Exception as exc:
            app.logger.warning("SSE redis publish failed (customer): %s; using local.", exc)
    _local_dispatch_customer(order_id, payload)


# Aliases requested by spec for explicit Redis-backed notifiers.
_notify_owner_redis = _notify_owner
_notify_order_status_redis = _notify_order_status


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

def _wants_json() -> bool:
    if request.is_json:
        return True
    if request.path.startswith("/api/"):
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json"


def _safe_redirect_target(target: str | None, fallback: str) -> str:
    if not target:
        return fallback
    host_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    if test_url.scheme in {"http", "https"} and test_url.netloc == host_url.netloc:
        return target
    return fallback


@app.errorhandler(400)
def err_bad_request(e):
    if _wants_json():
        return jsonify(description=str(getattr(e, "description", e))), 400
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def err_forbidden(e):
    if _wants_json():
        return jsonify(description="Forbidden."), 403
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def err_not_found(e):
    if _wants_json():
        return jsonify(description="Not found."), 404
    return render_template("errors/404.html"), 404


@app.errorhandler(CSRFError)
def err_csrf(e):
    log_security("CSRF_VIOLATION", f"path={request.path}")
    flash("Your session has expired. Please try again.")
    return redirect(_safe_redirect_target(request.referrer, url_for("home"))), 302


@app.errorhandler(429)
def err_rate_limit(e):
    log_security("RATE_LIMIT_HIT", f"path={request.path}")
    if _wants_json():
        return jsonify(description="Too many requests."), 429
    return render_template("errors/429.html"), 429


@app.errorhandler(500)
def err_server(e):
    app.logger.exception("Internal server error: %s", e)
    if _wants_json():
        return jsonify(description="An internal error occurred."), 500
    return render_template("errors/500.html"), 500


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
@limiter.exempt
def health_check():
    """Cheap liveness probe for Railway. No DB / disk calls — must always be fast."""
    return jsonify(
        status="ok",
        service="cafe-ordering-saas",
        version=APP_VERSION,
        uptimeSeconds=int(time.time() - APP_START_TIME),
        env=("production" if os.environ.get("IS_PRODUCTION", "").lower() == "true"
             or os.environ.get("RAILWAY_ENVIRONMENT") else "development"),
    ), 200


@app.route("/ready")
@limiter.exempt
def readiness_check():
    """Lightweight readiness probe: DB ping only. Used by Railway for rolling deploys."""
    if not _initialize_runtime_state(force=True):
        return jsonify(status="degraded",
                       service="cafe-ordering-saas",
                       db="error",
                       db_error=_DB_INIT_ERROR), 503
    db_status = "ok"
    try:
        db.session.execute(text("SELECT 1"))
    except Exception as exc:
        app.logger.warning("Readiness database probe failed: %s", exc)
        db_status = "error"
    status_code = 200 if db_status == "ok" else 503
    return jsonify(status="ok" if db_status == "ok" else "degraded",
                   service="cafe-ordering-saas",
                   db=db_status), status_code


@app.route("/health/full")
@limiter.exempt
def health_check_full():
    """Deep diagnostics: DB latency, disk writability, redis (if configured), worker info.
    Returns 200 when all critical checks pass, 503 otherwise. Safe to expose publicly —
    no secrets or business data are returned."""
    checks: dict = {}
    overall_ok = True

    # ── Database ────────────────────────────────────────────────────────────
    if not _initialize_runtime_state(force=False):
        checks["database"] = {"ok": False, "error": _DB_INIT_ERROR or "init failed"}
        overall_ok = False
    else:
        t0 = time.time()
        try:
            db.session.execute(text("SELECT 1"))
            checks["database"] = {"ok": True, "latencyMs": round((time.time() - t0) * 1000, 2)}
        except Exception as exc:
            checks["database"] = {"ok": False, "error": str(exc)[:200]}
            overall_ok = False

    # ── Disk writability (DATA_DIR) ─────────────────────────────────────────
    try:
        probe = DATA_DIR / ".healthcheck.tmp"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks["disk"] = {"ok": True, "path": str(DATA_DIR)}
    except Exception as exc:
        checks["disk"] = {"ok": False, "error": str(exc)[:200]}
        # Disk is non-critical when DATABASE_URL is configured (DB is the source of truth).
        if not os.environ.get("DATABASE_URL"):
            overall_ok = False

    # ── Redis (rate-limit storage) — optional ───────────────────────────────
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            import redis  # type: ignore
            client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.time()
            client.ping()
            checks["redis"] = {"ok": True, "latencyMs": round((time.time() - t0) * 1000, 2)}
        except Exception as exc:
            checks["redis"] = {"ok": False, "error": str(exc)[:200]}
            # Redis is non-critical — in-memory fallback works for single-process deploys.
    else:
        checks["redis"] = {"ok": True, "configured": False}

    # ── Worker / runtime info ───────────────────────────────────────────────
    checks["runtime"] = {
        "ok": True,
        "pid": os.getpid(),
        "pythonVersion": sys.version.split()[0],
        "uptimeSeconds": int(time.time() - APP_START_TIME),
    }

    return jsonify(
        status="ok" if overall_ok else "degraded",
        service="cafe-ordering-saas",
        version=APP_VERSION,
        checks=checks,
    ), (200 if overall_ok else 503)


@app.route("/metrics")
@limiter.exempt
def public_metrics():
    """Aggregated, non-sensitive runtime metrics. Useful for uptime dashboards.
    Counts only — no per-customer or per-cafe data is exposed."""
    payload: dict = {
        "service": "cafe-ordering-saas",
        "version": APP_VERSION,
        "uptimeSeconds": int(time.time() - APP_START_TIME),
    }
    try:
        if _initialize_runtime_state(force=False):
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            payload["ordersToday"] = db.session.query(Order).filter(Order.created_at >= today_start).count()
            payload["activeOrders"] = db.session.query(Order).filter(
                Order.status.in_(("pending", "confirmed", "preparing", "ready"))
            ).count()
        else:
            payload["ordersToday"] = None
            payload["activeOrders"] = None
    except Exception as exc:
        app.logger.warning("Metrics query failed: %s", exc)
        payload["ordersToday"] = None
        payload["activeOrders"] = None
    return jsonify(payload), 200


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def home() -> str:
    owner_id = logged_in_owner_id()
    owner_cafe = ""
    if owner_id:
        owner = db.session.get(Owner, owner_id)
        if owner:
            owner_cafe = owner.cafe_name or ""
    return render_template("index.html",
                           owner_username=logged_in_owner(),
                           owner_cafe=owner_cafe)


@app.route("/table/<table_id>")
@limiter.limit("60 per minute")
def table_order(table_id: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(404)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404, description="Table not found.")
    owner_id = table.get("ownerId")
    owner = db.session.get(Owner, owner_id) if owner_id else None
    cafe_name = (owner.cafe_name if owner else None) or "Cafe 11:11"
    branding = load_settings(owner_id)
    return render_template("table_order.html", table=table,
                           cafe_name=cafe_name,
                           google_place_id="",
                           branding=branding,
                           stripe_publishable_key="")


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.before_request
def _ensure_runtime_ready():
    if request.endpoint in {"health_check", "readiness_check", "static"}:
        return None
    if _initialize_runtime_state():
        return None
    message = "Service is starting. Database is not ready yet."
    if _wants_json():
        return jsonify(status="starting", description=message, db_error=_DB_INIT_ERROR), 503
    return message, 503


@app.before_request
def _auto_login_from_token() -> None:
    if logged_in_owner():
        return
    raw = request.cookies.get(_REMEMBER_COOKIE)
    if not raw:
        return
    try:
        owner = validate_remember_token(raw)
    except Exception:
        owner = None
    if owner:
        session["owner_username"] = owner["username"]
        session["owner_id"] = owner["id"]
        session.permanent = True
        owner_model = db.session.get(Owner, owner["id"])
        if owner_model:
            login_user(owner_model, remember=False)
        log_security("AUTO_LOGIN_TOKEN", f"user={owner['username']!r}")


@app.route("/owner/login", methods=["GET", "POST"])
@limiter.limit("15 per minute; 50 per hour", methods=["POST"])
def owner_login() -> str | Response:
    if logged_in_owner():
        return redirect(url_for("owner_dashboard"))

    ip = _client_ip()

    if request.method == "POST":
        if _is_ip_locked_out(ip):
            flash("Too many failed attempts. Please try again in 15 minutes.")
            return _no_store(app.make_response(render_template("owner_login.html")))

        identifier = str(request.form.get("identifier", "")).strip()[:128]
        password = str(request.form.get("password", ""))[:256]
        remember_me = request.form.get("remember_me") == "on"

        owner = Owner.query.filter(
            (Owner.username == identifier) | (Owner.email == identifier)
        ).first()

        if owner and not owner.is_active:
            flash("This account has been suspended.")
            return _no_store(app.make_response(render_template("owner_login.html")))

        if owner and _password_matches(owner.password_hash, password):
            _clear_failed_logins(ip)

            if owner.totp_enabled:
                session["pending_totp_owner_id"] = owner.id
                session["pending_totp_remember"] = remember_me
                return redirect(url_for("owner_login_totp_verify"))

            _complete_login(owner, remember_me)
            log_security("LOGIN_SUCCESS", f"user={owner.username!r}")
            resp = redirect(url_for("owner_dashboard"))
            if remember_me:
                raw_token = create_remember_token(owner.id)
                resp.set_cookie(_REMEMBER_COOKIE, raw_token,
                                max_age=int(timedelta(days=_REMEMBER_DAYS).total_seconds()),
                                httponly=True, secure=IS_PRODUCTION, samesite="Lax", path="/")
            return resp

        _record_failed_login(ip)
        log_security("LOGIN_FAILURE", f"identifier={identifier!r}")
        flash("Sign in failed. Check your credentials.")

    return _no_store(app.make_response(render_template("owner_login.html")))


def _complete_login(owner: Owner, remember_me: bool = False) -> None:
    session.clear()
    session["owner_username"] = owner.username
    session["owner_id"] = owner.id
    session.permanent = True
    login_user(owner, remember=False)


@app.route("/owner/login/totp", methods=["GET", "POST"])
def owner_login_totp_verify():
    pending_id = session.get("pending_totp_owner_id")
    if not pending_id:
        return redirect(url_for("owner_login"))
    owner = db.session.get(Owner, pending_id)
    if not owner:
        session.pop("pending_totp_owner_id", None)
        return redirect(url_for("owner_login"))

    if request.method == "POST":
        code = str(request.form.get("totp_code", "")).strip()
        totp = pyotp.TOTP(owner.totp_secret)
        if totp.verify(code):
            remember_me = session.pop("pending_totp_remember", False)
            session.pop("pending_totp_owner_id", None)
            _complete_login(owner, remember_me)
            log_security("LOGIN_TOTP_SUCCESS", f"user={owner.username!r}")
            resp = redirect(url_for("owner_dashboard"))
            if remember_me:
                raw_token = create_remember_token(owner.id)
                resp.set_cookie(_REMEMBER_COOKIE, raw_token,
                                max_age=int(timedelta(days=_REMEMBER_DAYS).total_seconds()),
                                httponly=True, secure=IS_PRODUCTION, samesite="Lax", path="/")
            return resp
        flash("Invalid TOTP code. Please try again.")

    return render_template("owner_login_otp_verify.html")


@app.route("/owner/signup", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def owner_signup() -> str | Response:
    if logged_in_owner():
        return redirect(url_for("owner_dashboard"))

    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()[:64]
        email = str(request.form.get("email", "")).strip()[:254] or None
        cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
        password = str(request.form.get("password", ""))[:256]

        if not username or not password:
            flash("Username and password are required.")
            return render_template("owner_signup.html")

        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{3,64}", username):
            flash("Username may only contain letters, digits, underscores, hyphens, and dots (3-64 chars).")
            return render_template("owner_signup.html")

        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.")
            return render_template("owner_signup.html")

        if not _is_strong_password(password):
            flash("Password must be at least 8 characters with a letter and digit.")
            return render_template("owner_signup.html")

        if Owner.query.filter_by(username=username).first():
            flash("That username is already taken.")
            return render_template("owner_signup.html")

        if email and Owner.query.filter(Owner.email == email).first():
            flash("An account with that email already exists.")
            return render_template("owner_signup.html")

        password_hash = _make_password_hash(password)
        new_owner = create_owner_in_db(username, email, password_hash, cafe_name)
        owner_model = db.session.get(Owner, new_owner["id"])
        _complete_login(owner_model)
        log_security("SIGNUP_SUCCESS", f"user={username!r}")
        return redirect(url_for("owner_dashboard"))

    return render_template("owner_signup.html")


@app.route("/owner/logout")
def owner_logout() -> Response:
    username = logged_in_owner()
    logout_user()
    raw_token = request.cookies.get(_REMEMBER_COOKIE)
    if raw_token:
        try:
            revoke_remember_token(raw_token)
        except Exception:
            pass
    session.clear()
    if username:
        log_security("LOGOUT", f"user={username!r}")
    resp = redirect(url_for("home"))
    resp.delete_cookie(_REMEMBER_COOKIE, path="/")
    return resp


# ---------------------------------------------------------------------------
# TOTP 2FA setup
# ---------------------------------------------------------------------------

@app.route("/owner/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    owner = logged_in_owner_obj()
    if not owner:
        return redirect(url_for("owner_logout"))

    if request.method == "POST":
        code = str(request.form.get("totp_code", "")).strip()
        pending_secret = session.get("pending_totp_secret")
        if not pending_secret:
            flash("Session expired. Please start 2FA setup again.")
            return redirect(url_for("totp_setup"))
        totp = pyotp.TOTP(pending_secret)
        if totp.verify(code):
            owner.totp_secret = pending_secret
            owner.totp_enabled = True
            db.session.commit()
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled successfully.")
            return redirect(url_for("owner_profile"))
        flash("Invalid code. Please try again.")

    secret = session.get("pending_totp_secret") or pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=owner.username, issuer_name="CafePortal")
    qr_img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    buf.seek(0)
    qr_b64 = base64.b64encode(buf.read()).decode()
    return render_template("owner_2fa_setup.html", secret=secret, qr_b64=qr_b64)


@app.route("/owner/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    owner = logged_in_owner_obj()
    if not owner:
        return redirect(url_for("owner_logout"))
    owner.totp_enabled = False
    owner.totp_secret = None
    db.session.commit()
    flash("Two-factor authentication disabled.")
    return redirect(url_for("owner_profile"))


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route("/owner/profile", methods=["GET", "POST"])
@login_required
def owner_profile() -> str | Response:
    owner_id = logged_in_owner_id()
    owner = db.session.get(Owner, owner_id)
    if not owner:
        return redirect(url_for("owner_logout"))

    if request.method == "POST":
        action = request.form.get("action", "profile")

        if action == "profile":
            cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
            email = str(request.form.get("email", "")).strip()[:254] or None
            phone = str(request.form.get("phone", "")).strip()[:30]
            logo_url = str(request.form.get("logo_url", "")).strip()[:500]
            brand_color = str(request.form.get("brand_color", "#4f46e5")).strip()[:7]

            if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                flash("Please enter a valid email address.")
                return redirect(url_for("owner_profile"))

            if email and Owner.query.filter(Owner.email == email, Owner.id != owner_id).first():
                flash("That email is already used by another account.")
                return redirect(url_for("owner_profile"))

            owner.cafe_name = cafe_name
            owner.email = email
            owner.phone = phone
            db.session.commit()
            save_settings(owner_id, logo_url, brand_color)
            flash("Profile updated.")

        elif action == "password":
            current_pw = str(request.form.get("current_password", ""))[:256]
            new_pw = str(request.form.get("new_password", ""))[:256]
            confirm_pw = str(request.form.get("confirm_password", ""))[:256]

            if not _password_matches(owner.password_hash, current_pw):
                flash("Current password is incorrect.")
                return redirect(url_for("owner_profile"))

            if new_pw != confirm_pw:
                flash("New passwords do not match.")
                return redirect(url_for("owner_profile"))

            if not _is_strong_password(new_pw):
                flash("Password must be at least 8 characters with a letter and digit.")
                return redirect(url_for("owner_profile"))

            owner.password_hash = _make_password_hash(new_pw)
            db.session.commit()
            revoke_all_tokens_for_owner(owner_id)
            session.clear()
            flash("Password changed. Please sign in again.")
            return redirect(url_for("owner_login"))

        return redirect(url_for("owner_profile"))

    resp = app.make_response(render_template(
        "owner_profile.html",
        owner=_owner_dict(owner),
        owner_username=logged_in_owner(),
        branding=load_settings(owner_id),
    ))
    return _no_store(resp)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/owner/dashboard")
@login_required
def owner_dashboard() -> Response:
    owner_id = logged_in_owner_id()
    all_tables = load_tables()
    tables = [t for t in all_tables if t.get("ownerId") == owner_id]
    all_orders = sorted(load_orders(), key=lambda o: o.get("createdAt", ""), reverse=True)
    orders = [o for o in all_orders if o.get("ownerId") == owner_id]
    orders = [_resolve_order_table_labels(o, tables) for o in orders]
    all_menu = load_menu()
    menu = {"categories": [c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id]}
    pending_orders = [o for o in orders if o.get("status") not in ("completed", "cancelled")]
    completed_orders = [o for o in orders if o.get("status") == "completed"]
    total_items = sum(len(cat.get("items", [])) for cat in menu.get("categories", []))
    total_revenue = round(sum(float(o.get("total") or 0) for o in completed_orders), 2)

    owner = db.session.get(Owner, owner_id)

    all_feedback = load_feedback()
    owner_feedback = [f for f in all_feedback if f.get("ownerId") == owner_id]
    avg_rating = 0.0
    if owner_feedback:
        avg_rating = round(sum(f["rating"] for f in owner_feedback) / len(owner_feedback), 1)

    ingredients = Ingredient.query.filter_by(owner_id=owner_id).all()
    low_stock = [i for i in ingredients if float(i.stock or 0) <= float(i.low_stock_threshold or 5)]

    resp = app.make_response(render_template(
        "owner_dashboard.html",
        owner_username=logged_in_owner(),
        owner=_owner_dict(owner) if owner else {},
        tables=tables,
        menu=menu,
        menu_json=json.dumps(menu, indent=2),
        pending_orders=pending_orders,
        completed_orders=completed_orders,
        total_items=total_items,
        total_revenue=total_revenue,
        owner_feedback=owner_feedback[:10],
        avg_rating=avg_rating,
        total_feedback=len(owner_feedback),
        low_stock_alerts=low_stock,
    ))
    return _no_store(resp)


# ---------------------------------------------------------------------------
# Kitchen view
# ---------------------------------------------------------------------------

@app.route("/kitchen")
@login_required
def kitchen_view():
    owner_id = logged_in_owner_id()
    all_tables = load_tables()
    tables = {t["id"]: t["name"] for t in all_tables if t.get("ownerId") == owner_id}
    active_statuses = {"pending", "confirmed", "preparing", "ready"}
    orders = Order.query.filter(
        Order.owner_id == owner_id,
        Order.status.in_(active_statuses)
    ).order_by(Order.created_at.asc()).all()
    orders_dicts = []
    for o in orders:
        od = _order_dict(o)
        od["tableName"] = tables.get(o.table_id, o.table_name or o.table_id or "—")
        orders_dicts.append(od)
    return render_template("kitchen.html",
                           orders=orders_dicts,
                           owner_username=logged_in_owner())


# ---------------------------------------------------------------------------
# Reorder — past orders by phone
# ---------------------------------------------------------------------------

@app.route("/owner/reorder")
@login_required
def reorder_view():
    owner_id = logged_in_owner_id()
    phone = request.args.get("phone", "").strip()[:30]
    past_orders = []
    if phone:
        past_orders = Order.query.filter_by(owner_id=owner_id, customer_phone=phone).order_by(Order.created_at.desc()).limit(20).all()
    return render_template("reorder.html",
                           phone=phone,
                           past_orders=[_order_dict(o) for o in past_orders],
                           owner_username=logged_in_owner())


# NOTE: CSRF is enforced — the owner UI sends X-CSRFToken from the meta tag.
@app.route("/api/reorder/<int:order_id>", methods=["POST"])
@api_login_required
def reorder_api(order_id: int):
    owner_id = logged_in_owner_id()
    original = db.session.get(Order, order_id)
    if not original or original.owner_id != owner_id:
        abort(404)
    new_order_data = {
        "ownerId": owner_id,
        "cafeId": original.cafe_id,
        "tableId": original.table_id,
        "tableName": original.table_name,
        "customerName": original.customer_name,
        "customerEmail": original.customer_email,
        "customerPhone": original.customer_phone,
        "items": original.items,
        "modifiers": original.modifiers or {},
        "subtotal": float(original.subtotal or 0),
        "tip": 0,
        "total": float(original.subtotal or 0),
        "status": "pending",
        "origin": "reorder",
        "notes": "",
    }
    new_record = place_order_in_db(new_order_data)
    if owner_id:
        _notify_owner(owner_id, "new_order", {"id": new_record["id"], "customerName": new_record["customerName"], "total": new_record["total"], "status": "pending"})
    return jsonify(order=new_record), 201


# ---------------------------------------------------------------------------
# Inventory management
# ---------------------------------------------------------------------------

@app.route("/owner/inventory")
@login_required
def inventory_view():
    owner_id = logged_in_owner_id()
    ingredients = Ingredient.query.filter_by(owner_id=owner_id).order_by(Ingredient.name).all()
    all_menu = load_menu()
    menu_items = [
        item
        for cat in all_menu.get("categories", [])
        if cat.get("ownerId") == owner_id
        for item in cat.get("items", [])
    ]
    return render_template("inventory.html",
                           ingredients=ingredients,
                           menu_items=menu_items,
                           owner_username=logged_in_owner())


@app.route("/owner/inventory/add", methods=["POST"])
@login_required
def add_ingredient():
    owner_id = logged_in_owner_id()
    name = str(request.form.get("name", "")).strip()[:200]
    unit = str(request.form.get("unit", "unit")).strip()[:50]
    menu_item_id = str(request.form.get("menu_item_id", "")).strip()[:100] or None
    qty_per_order = str(request.form.get("qty_per_order", "1")).strip()
    low_stock_threshold = str(request.form.get("low_stock_threshold", "5")).strip()
    stock = str(request.form.get("stock", "0")).strip()

    if not name:
        flash("Ingredient name is required.")
        return redirect(url_for("inventory_view"))
    try:
        qty_per_order_f = float(qty_per_order)
        low_stock_f = float(low_stock_threshold)
        stock_f = float(stock)
    except ValueError:
        flash("Invalid numeric value.")
        return redirect(url_for("inventory_view"))

    owner = db.session.get(Owner, owner_id)
    ing = Ingredient(
        owner_id=owner_id,
        cafe_id=owner.cafe_id if owner else None,
        name=name,
        unit=unit,
        stock=stock_f,
        low_stock_threshold=low_stock_f,
        menu_item_id=menu_item_id,
        qty_per_order=qty_per_order_f,
    )
    db.session.add(ing)
    db.session.commit()
    flash(f"Ingredient '{name}' added.")
    return redirect(url_for("inventory_view"))


@app.route("/owner/inventory/<int:ing_id>/update", methods=["POST"])
@login_required
def update_ingredient(ing_id: int):
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(403)
    try:
        ing.stock = float(request.form.get("stock", ing.stock))
        ing.low_stock_threshold = float(request.form.get("low_stock_threshold", ing.low_stock_threshold))
    except ValueError:
        flash("Invalid value.")
        return redirect(url_for("inventory_view"))
    db.session.commit()
    flash("Ingredient updated.")
    return redirect(url_for("inventory_view"))


@app.route("/owner/inventory/<int:ing_id>/delete", methods=["POST"])
@login_required
def delete_ingredient(ing_id: int):
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(403)
    db.session.delete(ing)
    db.session.commit()
    flash("Ingredient deleted.")
    return redirect(url_for("inventory_view"))


@app.route("/owner/inventory/<int:ing_id>/restock", methods=["POST"])
@login_required
def restock_ingredient(ing_id: int):
    """Quick restock: add a delta to existing stock (positive or negative)."""
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(403)
    try:
        delta = float(request.form.get("delta", "0"))
    except ValueError:
        flash("Invalid restock amount.")
        return redirect(url_for("inventory_view"))
    new_stock = max(0.0, float(ing.stock or 0) + delta)
    ing.stock = new_stock
    db.session.commit()
    flash(f"{ing.name}: stock {'+' if delta >= 0 else ''}{delta} → {new_stock} {ing.unit}")
    return redirect(url_for("inventory_view"))


@app.route("/owner/inventory/export")
@login_required
def export_inventory_csv():
    owner_id = logged_in_owner_id()
    ings = Ingredient.query.filter_by(owner_id=owner_id).order_by(Ingredient.name).all()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "name", "unit", "stock", "low_stock_threshold", "menu_item_id", "qty_per_order", "status"])
    for i in ings:
        status = "LOW" if float(i.stock or 0) <= float(i.low_stock_threshold or 0) else "OK"
        w.writerow([i.id, i.name, i.unit, i.stock, i.low_stock_threshold,
                    i.menu_item_id or "", i.qty_per_order, status])
    out.seek(0)
    fname = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ---------------------------------------------------------------------------
# Kitchen JSON feed (for in-page polling without losing scroll/state)
# ---------------------------------------------------------------------------

@app.route("/api/kitchen/orders")
@api_login_required
def kitchen_orders_json():
    owner_id = logged_in_owner_id()
    all_tables = load_tables()
    table_names = {t["id"]: t["name"] for t in all_tables if t.get("ownerId") == owner_id}
    active = {"pending", "confirmed", "preparing", "ready"}
    orders = (Order.query
              .filter(Order.owner_id == owner_id, Order.status.in_(active))
              .order_by(Order.created_at.asc())
              .all())
    payload = []
    now_ts = datetime.now(timezone.utc)
    for o in orders:
        d = _order_dict(o)
        d["tableName"] = table_names.get(o.table_id, o.table_name or "—")
        try:
            age_seconds = int((now_ts - o.created_at).total_seconds()) if o.created_at else 0
        except Exception:
            age_seconds = 0
        d["ageSeconds"] = max(0, age_seconds)
        payload.append(d)
    return jsonify(orders=payload, fetchedAt=_iso(now_ts))


@app.route("/api/kitchen/orders/<int:order_id>/status", methods=["POST"])
@login_required
def kitchen_update_order_status(order_id: int):
    """JSON endpoint so the kitchen view can advance order status without a full page reload."""
    owner_id = logged_in_owner_id()
    payload = request.get_json(silent=True) or {}
    new_status = str(payload.get("status", "")).strip()[:32]
    allowed = {"pending", "confirmed", "preparing", "ready", "completed", "cancelled"}
    if new_status not in allowed:
        return jsonify(error="Invalid status"), 400
    order = _db_get_order(order_id)
    if not order:
        return jsonify(error="Order not found"), 404
    if order.get("ownerId") != owner_id:
        abort(403)
    prev_status = order.get("status", "pending")
    _db_update_order_status(order_id, new_status)
    if new_status == "cancelled" and prev_status != "cancelled":
        _restore_inventory(order)
    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": new_status})
    _notify_order_status(order_id, new_status)
    return jsonify(ok=True, orderId=order_id, status=new_status)


# ---------------------------------------------------------------------------
# Printable receipt / "Print Bill" — used from the Table Calls dashboard tab
# so the owner can hand a printed bill to a customer who tapped "Bill".
# ---------------------------------------------------------------------------

def _find_open_order_for_table(owner_id: int, table_id: str):
    """Most recent non-completed/cancelled order for a table belonging to this owner."""
    return (Order.query
            .filter(Order.owner_id == owner_id,
                    Order.table_id == table_id,
                    Order.status.notin_(("completed", "cancelled")))
            .order_by(Order.created_at.desc())
            .first())


@app.route("/owner/order/<int:order_id>/receipt")
@login_required
def order_receipt(order_id: int):
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first()
    if not order:
        abort(404)
    owner = db.session.get(Owner, owner_id)
    cafe_name = (owner.cafe_name if owner else None) or "Cafe"
    order_d = _order_dict(order)
    table_name = order.table_name or order.table_id or "—"
    try:
        all_tables = load_tables()
        for t in all_tables:
            if t.get("id") == order.table_id and t.get("ownerId") == owner_id:
                table_name = t.get("name") or table_name
                break
    except Exception:
        pass
    order_d["tableName"] = table_name
    printed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template("receipt.html",
                           order=order_d,
                           cafe_name=cafe_name,
                           printed_at=printed_at)


@app.route("/owner/table/<table_id>/bill")
@login_required
def owner_table_bill(table_id: str):
    """Shortcut from a Bill table-call: jump straight to the latest open order's receipt."""
    owner_id = logged_in_owner_id()
    order = _find_open_order_for_table(owner_id, table_id)
    if not order:
        flash("No open order found for that table.", "warning")
        return redirect(url_for("owner_dashboard") + "#table-calls")
    return redirect(url_for("order_receipt", order_id=order.id, autoprint=1))


@app.route("/owner/order/<int:order_id>/mark-paid", methods=["POST"])
@login_required
def mark_order_paid(order_id: int):
    """Complete an order from the receipt screen (closes the bill in one click)."""
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first()
    if not order:
        abort(404)
    if order.status not in ("completed", "cancelled"):
        _db_update_order_status(order_id, "completed")
        _notify_owner(owner_id, "order_updated", {"id": order_id, "status": "completed"})
        _notify_order_status(order_id, "completed")
        flash(f"Order #{order_id} marked as paid and completed.", "success")
    return redirect(url_for("owner_dashboard") + "#table-calls")


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

@app.route("/owner/export/orders")
@login_required
def export_orders_csv():
    owner_id = logged_in_owner_id()
    date_from = request.args.get("date_from") or request.args.get("from") or ""
    date_to = request.args.get("date_to") or request.args.get("to") or ""
    status_filter = (request.args.get("status") or "").strip().lower()

    query = Order.query.filter_by(owner_id=owner_id)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            query = query.filter(Order.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc)
            query = query.filter(Order.created_at <= dt_to)
        except ValueError:
            pass

    if status_filter and status_filter in {"pending", "confirmed", "preparing", "ready", "completed", "cancelled"}:
        query = query.filter(Order.status == status_filter)

    orders = query.order_by(Order.created_at.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "status", "pickup_code", "table_name", "customer_name",
        "customer_email", "customer_phone", "subtotal", "tip", "total",
        "items_count", "origin", "created_at"
    ])
    for o in orders:
        writer.writerow([
            o.id, o.status, o.pickup_code or "",
            o.table_name or "", o.customer_name or "Guest",
            o.customer_email or "", o.customer_phone or "",
            float(o.subtotal or 0), float(o.tip or 0), float(o.total or 0),
            len(o.items) if isinstance(o.items, list) else 0,
            o.origin or "", _iso(o.created_at),
        ])

    output.seek(0)
    filename = f"orders_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# PDF Daily Report
# ---------------------------------------------------------------------------

@app.route("/owner/report/daily")
@login_required
def daily_report_pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    owner_id = logged_in_owner_id()
    date_str = request.args.get("date", datetime.now().strftime("%Y-%m-%d"))
    try:
        report_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        report_date = datetime.now(timezone.utc)

    day_start = report_date.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = report_date.replace(hour=23, minute=59, second=59)

    orders = Order.query.filter(
        Order.owner_id == owner_id,
        Order.created_at >= day_start,
        Order.created_at <= day_end,
    ).order_by(Order.created_at.asc()).all()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    owner = db.session.get(Owner, owner_id)
    cafe_name = (owner.cafe_name if owner else None) or "Cafe"
    elements.append(Paragraph(f"{cafe_name} — Daily Report", styles["Title"]))
    elements.append(Paragraph(f"Date: {date_str}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    total_revenue = sum(float(o.total or 0) for o in orders if o.status == "completed")
    elements.append(Paragraph(f"Total Orders: {len(orders)}", styles["Normal"]))
    elements.append(Paragraph(f"Completed Orders: {sum(1 for o in orders if o.status == 'completed')}", styles["Normal"]))
    elements.append(Paragraph(f"Total Revenue: ₹{total_revenue:.2f}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    table_data = [["ID", "Table", "Customer", "Items", "Total", "Status", "Pickup Code"]]
    for o in orders:
        items_count = len(o.items) if isinstance(o.items, list) else 0
        table_data.append([
            str(o.id),
            o.table_name or "—",
            o.customer_name or "Guest",
            str(items_count),
            f"₹{float(o.total or 0):.2f}",
            o.status or "pending",
            o.pickup_code or "—",
        ])

    if len(table_data) > 1:
        tbl = Table(table_data, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(tbl)
    else:
        elements.append(Paragraph("No orders for this date.", styles["Normal"]))

    doc.build(elements)
    buf.seek(0)
    filename = f"daily_report_{date_str}.pdf"
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# SSE endpoints
# ---------------------------------------------------------------------------

@app.route("/api/orders/stream")
@csrf.exempt
@api_login_required
def orders_stream():
    owner_id = logged_in_owner_id()

    def generate():
        my_queue = []
        with _sse_lock:
            if owner_id not in _sse_subscribers:
                _sse_subscribers[owner_id] = []
            _sse_subscribers[owner_id].append(my_queue)

        try:
            yield "event: ping\ndata: connected\n\n"
            last_heartbeat = time.time()
            while True:
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"
                if time.time() - last_heartbeat > 25:
                    yield "event: ping\ndata: heartbeat\n\n"
                    last_heartbeat = time.time()
                time.sleep(0.5)
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                queues = _sse_subscribers.get(owner_id, [])
                if my_queue in queues:
                    queues.remove(my_queue)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# Menu management
# ---------------------------------------------------------------------------

@app.route("/owner/menu/category", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_menu_category() -> Response:
    owner_id = logged_in_owner_id()
    name = str(request.form.get("categoryName", "")).strip()[:100]
    if not name:
        flash("Category name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#menu")
    menu = load_menu()
    existing_ids = {c["id"] for c in menu["categories"] if c.get("ownerId") == owner_id}
    category_id = unique_id(normalize_id(name), existing_ids)
    menu["categories"].append({"id": category_id, "name": name, "items": [], "ownerId": owner_id})
    save_menu(menu)
    flash(f"Category '{name}' created.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/category/<category_id>/delete", methods=["POST"])
@login_required
def delete_menu_category(category_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", category_id):
        abort(400)
    menu = load_menu()
    category = next((c for c in menu["categories"] if c["id"] == category_id), None)
    if not category or category.get("ownerId") != owner_id:
        abort(403)
    menu["categories"] = [c for c in menu["categories"] if c["id"] != category_id]
    save_menu(menu)
    flash("Category deleted.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/category/<category_id>/rename", methods=["POST"])
@login_required
def rename_menu_category(category_id: str) -> Response:
    owner_id = logged_in_owner_id()
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
    if category.get("ownerId") != owner_id:
        abort(403)
    category["name"] = new_name
    save_menu(menu)
    flash("Category renamed.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/item", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def save_menu_item() -> Response:
    owner_id = logged_in_owner_id()
    form = request.form
    category_id = str(form.get("categoryId", "")).strip()[:100]
    item_id = str(form.get("itemId", "")).strip()[:100]
    name = str(form.get("itemName", "")).strip()[:200]
    description = str(form.get("itemDescription", "")).strip()[:500]
    price_text = str(form.get("itemPrice", "")).strip()[:20]
    tags_text = str(form.get("itemTags", "")).strip()[:300]
    image_url = str(form.get("itemImageUrl", "")).strip()[:500]
    dietary_tags_text = str(form.get("itemDietaryTags", "")).strip()[:300]
    try:
        prep_time = max(0, min(300, int(form.get("itemPrepTime") or 0)))
    except (TypeError, ValueError):
        prep_time = 0

    if not category_id or not name or not price_text:
        flash("Item name, price, and category are required.")
        return redirect(url_for("owner_dashboard") + "#menu")

    try:
        price = round(float(price_text), 2)
        if price < 0 or price > 99999.99:
            raise ValueError
    except ValueError:
        flash("Item price must be a valid positive number.")
        return redirect(url_for("owner_dashboard") + "#menu")

    tags = [t.strip()[:50] for t in tags_text.split(",") if t.strip()][:10]
    dietary_tags = [t.strip()[:50] for t in dietary_tags_text.split(",") if t.strip()][:10]
    menu = load_menu()
    category = next((c for c in menu["categories"] if c["id"] == category_id), None)
    if not category:
        flash("Category not found.")
        return redirect(url_for("owner_dashboard") + "#menu")
    if category.get("ownerId") != owner_id:
        abort(403)

    if item_id:
        item = next((i for i in category["items"] if i["id"] == item_id), None)
        if item:
            item.update({"name": name, "description": description, "price": price, "tags": tags,
                         "dietary_tags": dietary_tags, "image_url": image_url, "prep_time": prep_time})
            flash("Menu item updated.")
        else:
            flash("Menu item not found.")
    else:
        existing_item_ids = {i["id"] for i in category["items"]}
        new_item_id = unique_id(normalize_id(name), existing_item_ids)
        category["items"].append({
            "id": new_item_id, "name": name, "description": description,
            "price": price, "tags": tags, "available": True,
            "dietary_tags": dietary_tags, "image_url": image_url, "prep_time": prep_time,
        })
        flash(f"'{name}' added to menu.")

    save_menu(menu)
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/item/<item_id>/delete", methods=["POST"])
@login_required
def delete_menu_item(item_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", item_id):
        abort(400)
    menu = load_menu()
    for category in menu["categories"]:
        if category.get("ownerId") != owner_id:
            continue
        before = len(category["items"])
        category["items"] = [i for i in category["items"] if i["id"] != item_id]
        if len(category["items"]) < before:
            save_menu(menu)
            flash("Menu item deleted.")
            return redirect(url_for("owner_dashboard") + "#menu")
    flash("Item not found or you do not have permission.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/item/<item_id>/toggle-availability", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def toggle_menu_item_availability(item_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", item_id):
        abort(400)
    menu = load_menu()
    for cat in menu.get("categories", []):
        if cat.get("ownerId") != owner_id:
            continue
        item = next((i for i in cat["items"] if i["id"] == item_id), None)
        if item:
            item["available"] = not item.get("available", True)
            save_menu(menu)
            label = "available" if item["available"] else "sold out"
            flash(f"'{item['name']}' marked as {label}.")
            return redirect(url_for("owner_dashboard") + "#menu")
    flash("Item not found.")
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/download")
@login_required
def download_menu() -> Response:
    owner_id = logged_in_owner_id()
    menu = load_menu()
    owner_menu = {"categories": [c for c in menu.get("categories", []) if c.get("ownerId") == owner_id]}
    return Response(
        json.dumps(owner_menu, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=menu.json"},
    )


@app.route("/owner/menu/import", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def update_menu() -> Response:
    owner_id = logged_in_owner_id()
    raw_json: str | None = None

    uploaded_file = request.files.get("menu_file")
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read(16 * 1024 * 1024)
        upload_error, upload_kind = validate_uploaded_file(uploaded_file, file_bytes)
        if upload_error:
            flash(upload_error)
            return redirect(url_for("owner_dashboard") + "#menu")
        if upload_kind == "json":
            try:
                raw_json = file_bytes.decode("utf-8")
            except Exception:
                flash("Could not read the uploaded file.")
                return redirect(url_for("owner_dashboard") + "#menu")
        else:
            flash("Only JSON menu files can be imported.")
            return redirect(url_for("owner_dashboard") + "#menu")
    else:
        raw_json = request.form.get("menu_data", "").strip()

    if not raw_json:
        flash("No menu data provided.")
        return redirect(url_for("owner_dashboard") + "#menu")

    try:
        imported = json.loads(raw_json)
    except json.JSONDecodeError:
        flash("Invalid JSON.")
        return redirect(url_for("owner_dashboard") + "#menu")

    if not isinstance(imported, dict) or "categories" not in imported:
        flash("JSON must be an object with a 'categories' key.")
        return redirect(url_for("owner_dashboard") + "#menu")

    categories = imported.get("categories", [])
    if not isinstance(categories, list):
        flash("'categories' must be an array.")
        return redirect(url_for("owner_dashboard") + "#menu")

    existing_menu = load_menu()
    other_categories = [c for c in existing_menu.get("categories", []) if c.get("ownerId") != owner_id]
    existing_ids: set[str] = {c.get("id", "") for c in other_categories}
    new_categories = []
    for cat in categories:
        if not isinstance(cat, dict):
            continue
        cat_name = str(cat.get("name", "category"))[:200]
        cat_id = unique_id(normalize_id(cat_name), existing_ids)
        existing_ids.add(cat_id)
        items = []
        item_ids: set[str] = set()
        for item in cat.get("items", []):
            if not isinstance(item, dict):
                continue
            item_name = str(item.get("name", "item"))[:200]
            try:
                item_price = round(float(item.get("price", 0)), 2)
            except (TypeError, ValueError):
                item_price = 0.0
            item_id = unique_id(normalize_id(item_name), item_ids)
            item_ids.add(item_id)
            items.append({
                "id": item_id, "name": item_name,
                "description": str(item.get("description", ""))[:500],
                "price": item_price,
                "tags": [str(t)[:50] for t in item.get("tags", []) if isinstance(t, str)][:10],
                "available": True,
            })
        new_categories.append({"id": cat_id, "name": cat_name, "ownerId": owner_id, "items": items})

    existing_menu["categories"] = other_categories + new_categories
    save_menu(existing_menu)
    flash(f"Menu imported — {len(new_categories)} categor{'y' if len(new_categories) == 1 else 'ies'} loaded.")
    return redirect(url_for("owner_dashboard") + "#menu")


# ---------------------------------------------------------------------------
# Table management
# ---------------------------------------------------------------------------

@app.route("/owner/table", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def create_table() -> Response:
    owner_id = logged_in_owner_id()
    name = str(request.form.get("tableName", "")).strip()[:100]
    if not name:
        flash("Table name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#tables")
    with _tables_lock:
        tables = load_tables()
        table_num = next_table_number(tables)
        table_id = f"table-{table_num}"
        table_url = url_for("table_order", table_id=table_id, _external=True)
        owner = db.session.get(Owner, owner_id)
        tables.append({
            "id": table_id, "name": name, "ownerId": owner_id,
            "cafeId": owner.cafe_id if owner else None,
            "url": table_url,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        })
        save_tables(tables)
    flash(f"Table '{name}' created.")
    return redirect(url_for("owner_dashboard") + "#tables")


@app.route("/owner/table/<table_id>/delete", methods=["POST"])
@login_required
def delete_table(table_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    with _tables_lock:
        tables = load_tables()
        table = next((t for t in tables if t["id"] == table_id), None)
        if not table or table.get("ownerId") != owner_id:
            abort(403)
        tables = [t for t in tables if t["id"] != table_id]
        save_tables(tables)
    flash("Table deleted.")
    return redirect(url_for("owner_dashboard") + "#tables")


@app.route("/owner/table/<table_id>/rename", methods=["POST"])
@login_required
def rename_table(table_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    new_name = str(request.form.get("tableName", "")).strip()[:100]
    if not new_name:
        flash("Table name cannot be empty.")
        return redirect(url_for("owner_dashboard") + "#tables")
    with _tables_lock:
        tables = load_tables()
        table = next((t for t in tables if t["id"] == table_id), None)
        if not table or table.get("ownerId") != owner_id:
            abort(403)
        table["name"] = new_name
        save_tables(tables)
    flash("Table renamed.")
    return redirect(url_for("owner_dashboard") + "#tables")


@app.route("/owner/table/<table_id>/qr")
@login_required
def table_qr(table_id: str) -> Response:
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table or table.get("ownerId") != owner_id:
        abort(403)
    table_url = url_for("table_order", table_id=table_id, _external=True)
    qr_img = qrcode.make(table_url)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    buf.seek(0)
    return Response(buf.read(), mimetype="image/png")


# ---------------------------------------------------------------------------
# Order management
# ---------------------------------------------------------------------------

@app.route("/owner/order/<int:order_id>/status", methods=["POST"])
@login_required
def update_order_status(order_id: int) -> Response:
    owner_id = logged_in_owner_id()
    new_status = str(request.form.get("status", "")).strip()[:32]
    allowed = {"pending", "confirmed", "preparing", "ready", "completed", "cancelled"}
    if new_status not in allowed:
        flash("Invalid status value.")
        return redirect(url_for("owner_dashboard") + "#orders")
    order = _db_get_order(order_id)
    if not order:
        flash("Order not found.")
        return redirect(url_for("owner_dashboard") + "#orders")
    if order.get("ownerId") != owner_id:
        abort(403)
    prev_status = order.get("status", "pending")
    _db_update_order_status(order_id, new_status)
    if new_status == "cancelled" and prev_status != "cancelled":
        _restore_inventory(order)
    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": new_status})
    _notify_order_status(order_id, new_status)
    return redirect(_safe_redirect_target(request.referrer, url_for("owner_dashboard") + "#orders"))


@app.route("/owner/order/<int:order_id>/complete", methods=["POST"])
@login_required
def complete_order(order_id: int) -> Response:
    owner_id = logged_in_owner_id()
    order = _db_get_order(order_id)
    if not order or order.get("ownerId") != owner_id:
        abort(403)
    _db_update_order_status(order_id, "completed")
    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": "completed"})
    _notify_order_status(order_id, "completed")
    return redirect(url_for("owner_dashboard") + "#orders")


@app.route("/owner/order/<int:order_id>/delete", methods=["POST"])
@login_required
def delete_order(order_id: int) -> Response:
    owner_id = logged_in_owner_id()
    order = _db_get_order(order_id)
    if not order or order.get("ownerId") != owner_id:
        abort(403)
    _db_delete_order(order_id)
    flash("Order deleted.")
    return redirect(url_for("owner_dashboard") + "#orders")


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------

@app.route("/api/owner/analytics/day-orders")
@login_required
def analytics_day_orders():
    """Return a JSON list of orders for a given date (YYYY-MM-DD) for chart drill-down."""
    owner_id = logged_in_owner_id()
    date_str = (request.args.get("date") or "").strip()[:10]
    try:
        day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return jsonify(error="Invalid date, expected YYYY-MM-DD"), 400
    day_end = day.replace(hour=23, minute=59, second=59)
    orders = (Order.query
              .filter(Order.owner_id == owner_id,
                      Order.created_at >= day,
                      Order.created_at <= day_end)
              .order_by(Order.created_at.asc())
              .all())
    return jsonify(date=date_str, orders=[_order_dict(o) for o in orders])


@app.route("/owner/analytics")
@login_required
def owner_analytics():
    owner_id = logged_in_owner_id()

    # Optional date-range filter (?from=YYYY-MM-DD&to=YYYY-MM-DD)
    q = Order.query.filter_by(owner_id=owner_id)
    df = (request.args.get("from") or request.args.get("date_from") or "").strip()
    dt_ = (request.args.get("to") or request.args.get("date_to") or "").strip()
    try:
        if df:
            q = q.filter(Order.created_at >= datetime.strptime(df, "%Y-%m-%d").replace(tzinfo=timezone.utc))
        if dt_:
            end_dt = datetime.strptime(dt_, "%Y-%m-%d").replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            q = q.filter(Order.created_at <= end_dt)
    except ValueError:
        pass
    orders = q.all()
    feedback_list = Feedback.query.filter_by(owner_id=owner_id).all()

    # Build full date series for last 30 days (so chart shows continuity)
    today = datetime.now(timezone.utc).date()
    rev_by_day: dict[str, float] = {}
    ord_by_day: dict[str, int] = {}
    for i in range(29, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        rev_by_day[d] = 0.0
        ord_by_day[d] = 0
    for o in orders:
        if not o.created_at:
            continue
        key = o.created_at.strftime("%Y-%m-%d")
        if key in ord_by_day:
            ord_by_day[key] += 1
            if o.status == "completed":
                rev_by_day[key] += float(o.total or 0)

    # Top items by quantity (completed orders only)
    item_counts: dict[str, int] = {}
    item_revenue: dict[str, float] = {}
    for o in orders:
        if o.status not in ("completed", "ready", "preparing", "confirmed", "pending"):
            continue
        for item in (o.items if isinstance(o.items, list) else []):
            name = item.get("name", "Unknown")
            qty = int(item.get("quantity", 1) or 1)
            item_counts[name] = item_counts.get(name, 0) + qty
            item_revenue[name] = item_revenue.get(name, 0.0) + float(item.get("lineTotal", 0) or 0)
    top_items_pairs = sorted(item_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Hourly distribution (0-23) of completed orders
    hour_counts = [0] * 24
    for o in orders:
        if o.status == "completed" and o.created_at:
            hour_counts[o.created_at.hour] += 1

    completed = [o for o in orders if o.status == "completed"]
    total_revenue = round(sum(float(o.total or 0) for o in completed), 2)
    total_completed = len(completed)
    avg_order_value = round(total_revenue / total_completed, 2) if total_completed else 0.0

    avg_rating = round(sum(f.rating for f in feedback_list) / len(feedback_list), 1) if feedback_list else 0.0

    analytics_payload = {
        "totalRevenue": total_revenue,
        "totalOrders": total_completed,
        "totalAllOrders": len(orders),
        "avgOrderValue": avg_order_value,
        "avgRating": avg_rating,
        "feedbackCount": len(feedback_list),
        "revenueByDay": [{"date": d[5:], "fullDate": d, "revenue": round(v, 2)} for d, v in rev_by_day.items()],
        "ordersByDay": [{"date": d[5:], "fullDate": d, "count": c} for d, c in ord_by_day.items()],
        "topItems": [
            {"name": n, "count": c, "revenue": round(item_revenue.get(n, 0.0), 2)}
            for n, c in top_items_pairs
        ],
        "peakHours": [
            {"hour": f"{h:02d}:00", "count": hour_counts[h]} for h in range(24)
        ],
        "dateFrom": df,
        "dateTo": dt_,
    }

    return render_template(
        "owner_analytics.html",
        owner_username=logged_in_owner(),
        analytics=analytics_payload,
        # Backward-compat keys (still referenced by older parts of layout)
        daily=[(d, {"revenue": v, "orders": ord_by_day[d]}) for d, v in rev_by_day.items()],
        top_items=top_items_pairs,
        total_orders=total_completed,
        total_revenue=total_revenue,
        avg_rating=avg_rating,
        total_feedback=len(feedback_list),
    )


# ---------------------------------------------------------------------------
# Superadmin dashboard
# ---------------------------------------------------------------------------

@app.route("/superadmin")
@app.route("/superadmin/dashboard")
@login_required
@superadmin_required
def superadmin_dashboard():
    owners = Owner.query.order_by(Owner.created_at.desc()).all()
    cafes = Cafe.query.order_by(Cafe.created_at.desc()).all()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total)).filter_by(status="completed").scalar() or 0
    total_feedback = Feedback.query.count()
    avg_rating_row = db.session.query(db.func.avg(Feedback.rating)).scalar()
    avg_rating = round(float(avg_rating_row), 1) if avg_rating_row else 0.0

    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(20).all()

    return render_template(
        "superadmin/dashboard.html",
        owners=owners,
        cafes=cafes,
        total_orders=total_orders,
        total_revenue=round(float(total_revenue), 2),
        total_feedback=total_feedback,
        avg_rating=avg_rating,
        recent_orders=[_order_dict(o) for o in recent_orders],
        owner_count=len(owners),
        active_owner_count=sum(1 for o in owners if o.is_active),
        cafe_count=len(cafes),
        active_cafe_count=sum(1 for c in cafes if c.is_active),
    )


@app.route("/superadmin/cafes/create", methods=["POST"])
@login_required
@superadmin_required
def superadmin_create_cafe():
    name = str(request.form.get("name", "")).strip()[:200]
    if not name:
        flash("Cafe name is required.")
        return redirect(url_for("superadmin_dashboard"))
    slug = normalize_id(name)
    existing_slugs = {c.slug for c in Cafe.query.all() if c.slug}
    slug = unique_id(slug, existing_slugs)
    create_cafe_in_db(name=name, slug=slug)
    flash(f"Cafe '{name}' created.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/cafes/<int:cafe_id>/toggle", methods=["POST"])
@login_required
@superadmin_required
def superadmin_toggle_cafe(cafe_id: int):
    cafe = db.session.get(Cafe, cafe_id)
    if not cafe:
        abort(404)
    cafe.is_active = not cafe.is_active
    db.session.commit()
    status = "activated" if cafe.is_active else "deactivated"
    flash(f"Cafe '{cafe.name}' {status}.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/owners/create", methods=["POST"])
@login_required
@superadmin_required
def superadmin_create_owner():
    username = str(request.form.get("username", "")).strip()[:64]
    email = str(request.form.get("email", "")).strip()[:254] or None
    cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
    password = str(request.form.get("password", ""))[:256]
    cafe_id_str = request.form.get("cafe_id", "")
    cafe_id = int(cafe_id_str) if cafe_id_str and cafe_id_str.isdigit() else None

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("superadmin_dashboard"))

    if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{3,64}", username):
        flash("Invalid username format.")
        return redirect(url_for("superadmin_dashboard"))

    if Owner.query.filter_by(username=username).first():
        flash("Username already exists.")
        return redirect(url_for("superadmin_dashboard"))

    password_hash = _make_password_hash(password)
    create_owner_in_db(username, email, password_hash, cafe_name, cafe_id)
    flash(f"Owner '{username}' created.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/owners/<int:owner_id>/toggle", methods=["POST"])
@login_required
@superadmin_required
def superadmin_toggle_owner(owner_id: int):
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot deactivate a superadmin.")
        return redirect(url_for("superadmin_dashboard"))
    owner.is_active = not owner.is_active
    db.session.commit()
    status = "activated" if owner.is_active else "deactivated"
    flash(f"Owner '{owner.username}' {status}.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/owners/<int:owner_id>/reset", methods=["POST"])
@login_required
@superadmin_required
def superadmin_reset_password(owner_id: int):
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    tmp_password = secrets.token_urlsafe(12)
    owner.password_hash = _make_password_hash(tmp_password)
    db.session.commit()
    revoke_all_tokens_for_owner(owner_id)
    flash(f"Password for '{owner.username}' reset. Temp password: {tmp_password}", "password_reset")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/owners/<int:owner_id>/assign-cafe", methods=["POST"])
@login_required
@superadmin_required
def superadmin_assign_cafe(owner_id: int):
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    cafe_id_str = request.form.get("cafe_id", "")
    owner.cafe_id = int(cafe_id_str) if cafe_id_str and cafe_id_str.isdigit() else None
    db.session.commit()
    flash(f"Owner '{owner.username}' assigned to cafe.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/analytics")
@login_required
@superadmin_required
def superadmin_analytics():
    per_cafe: list[dict] = []
    cafes = Cafe.query.all()
    for cafe in cafes:
        owners = Owner.query.filter_by(cafe_id=cafe.id).all()
        owner_ids = [o.id for o in owners]
        if not owner_ids:
            continue
        orders = Order.query.filter(Order.owner_id.in_(owner_ids)).all()
        revenue = sum(float(o.total or 0) for o in orders if o.status == "completed")
        per_cafe.append({
            "cafe": _cafe_dict(cafe),
            "total_orders": len(orders),
            "revenue": round(revenue, 2),
            "owner_count": len(owners),
        })

    orphan_orders = Order.query.filter(Order.cafe_id == None).count()
    return render_template(
        "superadmin/analytics.html",
        per_cafe=per_cafe,
        orphan_orders=orphan_orders,
        owner_username=logged_in_owner(),
    )


# ---------------------------------------------------------------------------
# Public JSON API
# ---------------------------------------------------------------------------

@app.route("/api/menu", methods=["GET"])
@csrf.exempt
@limiter.limit("120 per minute")
def menu_api() -> Response:
    import copy
    table_id = request.args.get("table_id", "").strip()[:64]
    all_menu = load_menu()
    if table_id:
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")
            filtered = {"categories": [c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id]}
        else:
            filtered = {"categories": []}
    else:
        filtered = {"categories": []}

    # Compute popular items from the last 30 days (ordered ≥ 3 times)
    popular_ids: set[str] = set()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        recent_orders = Order.query.filter(
            Order.created_at >= cutoff,
            Order.status.in_(["completed", "preparing", "ready", "pending"]),
        ).all()
        item_counts: dict[str, int] = {}
        for _o in recent_orders:
            for _item in (_o.items or []):
                _iid = _item.get("id", "")
                if _iid:
                    item_counts[_iid] = item_counts.get(_iid, 0) + int(_item.get("quantity", 1))
        popular_ids = {iid for iid, cnt in item_counts.items() if cnt >= 3}
    except Exception:
        popular_ids = set()

    result = copy.deepcopy(filtered)
    for cat in result.get("categories", []):
        for item in cat.get("items", []):
            item["popular"] = item.get("id", "") in popular_ids

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.route("/api/order-preview", methods=["POST"])
@limiter.limit("30 per minute")
def order_preview() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    owner_menu = None
    if table_id and re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            all_menu = load_menu()
            owner_menu = {"categories": [
                c for c in all_menu.get("categories", []) if c.get("ownerId") == table.get("ownerId")
            ]}
    return compute_order_summary(payload.get("items", []), owner_menu), 200


@app.route("/api/checkout", methods=["POST"])
@limiter.limit("20 per minute; 100 per hour")
def checkout() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    customer_name = str(payload.get("customerName", "Guest")).strip()[:100] or "Guest"
    customer_email = str(payload.get("customerEmail", "")).strip()[:254]
    customer_phone = str(payload.get("customerPhone", "")).strip()[:30]
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    items = payload.get("items", [])
    notes = str(payload.get("notes", "")).strip()[:500]

    if customer_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", customer_email):
        abort(400, description="Invalid email address.")

    if table_id and not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400, description="Invalid table ID.")

    table_name = None
    owner_id = None
    cafe_id = None
    owner_menu = None
    if table_id:
        tables = load_tables()
        table = next((t for t in tables if t["id"] == table_id), None)
        if table:
            table_name = table["name"]
            owner_id = table.get("ownerId")
            cafe_id = table.get("cafeId")
            all_menu = load_menu()
            owner_menu = {"categories": [
                c for c in all_menu.get("categories", []) if c.get("ownerId") == owner_id
            ]}
        else:
            table_name = table_id
    else:
        table_name = "Counter"

    order_summary = compute_order_summary(items, owner_menu)

    try:
        tip = round(float(payload.get("tip", 0)), 2)
        if tip < 0 or tip > 10000:
            tip = 0.0
    except (TypeError, ValueError):
        tip = 0.0

    grand_total = round(order_summary["total"] + tip, 2)

    if owner_id:
        ok, msg = _check_stock_available(owner_id, order_summary["items"])
        if not ok:
            abort(400, description=msg)

    order_data = {
        "customerName": customer_name,
        "customerEmail": customer_email,
        "customerPhone": customer_phone,
        "tableId": table_id,
        "tableName": table_name,
        "ownerId": owner_id,
        "cafeId": cafe_id,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "items": order_summary["items"],
        "subtotal": order_summary["total"],
        "tip": tip,
        "total": grand_total,
        "status": "pending",
        "origin": "table" if table_id else "counter",
        "notes": notes,
    }

    order_record = place_order_in_db(order_data)

    if owner_id:
        _notify_owner(owner_id, "new_order", {
            "id": order_record["id"],
            "tableName": table_name,
            "customerName": customer_name,
            "total": order_record["total"],
            "status": "pending",
            "pickupCode": order_record["pickupCode"],
        })

    log_security("ORDER_PLACED", f"table={table_id!r} total={order_record['total']}")
    _send_order_confirmation(order_record)
    return {
        "message": "Order placed. Pay at counter.",
        "order": order_record,
        "pickupCode": order_record["pickupCode"],
        "paymentMethod": "pay_at_counter",
    }, 201


@app.route("/api/orders", methods=["GET"])
@csrf.exempt
@limiter.limit("60 per minute")
@api_login_required
def orders_api() -> tuple[dict, int]:
    owner_id = logged_in_owner_id()
    all_orders = load_orders()
    owner_orders = [o for o in all_orders if o.get("ownerId") == owner_id]
    return {"orders": owner_orders}, 200


@app.route("/api/orders/<int:order_id>", methods=["GET"])
@csrf.exempt
@limiter.limit("20 per minute; 60 per hour")
def get_order(order_id: int) -> tuple[dict, int]:
    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")
    safe_order = {
        "id": order["id"],
        "status": order.get("status", "pending"),
        "tableName": order.get("tableName", ""),
        "customerName": order.get("customerName", ""),
        "items": order.get("items", []),
        "total": order.get("total", 0),
        "pickupCode": order.get("pickupCode", ""),
        "createdAt": order.get("createdAt", ""),
    }
    return {"order": safe_order}, 200


@app.route("/api/orders/<int:order_id>/stream")
@csrf.exempt
@limiter.limit("30 per minute")
def customer_order_stream(order_id: int) -> Response:
    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")
    initial_status = order.get("status", "pending")

    my_queue: list[str] = []
    with _sse_lock:
        _sse_customer_subs.setdefault(order_id, []).append(my_queue)

    def generate():
        yield f"data: {json.dumps({'status': initial_status, 'id': order_id})}\n\n"
        if initial_status in ("completed", "cancelled"):
            return
        last_heartbeat = time.time()
        try:
            while True:
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"
                    try:
                        data = json.loads(payload)
                        if data.get("status") in ("completed", "cancelled"):
                            return
                    except Exception:
                        pass
                if time.time() - last_heartbeat >= 25:
                    yield "event: ping\ndata: heartbeat\n\n"
                    last_heartbeat = time.time()
                time.sleep(0.5)
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                subs = _sse_customer_subs.get(order_id, [])
                try:
                    subs.remove(my_queue)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


_CANCEL_GRACE_SECONDS = 120


@app.route("/api/orders/<int:order_id>/cancel", methods=["POST"])
@limiter.limit("10 per minute")
def customer_cancel_order(order_id: int) -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")

    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")

    status = order.get("status", "pending")
    if status not in ("pending",):
        return {"description": f"Order cannot be cancelled (status: {status})."}, 409

    created_at_str = order.get("createdAt", "")
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - created_at).total_seconds()
            if elapsed > _CANCEL_GRACE_SECONDS:
                return {"description": f"Cancellation window expired ({_CANCEL_GRACE_SECONDS // 60} min)."}, 409
        except (ValueError, TypeError):
            pass

    _db_update_order_status(order_id, "cancelled")
    _restore_inventory(order)
    owner_id = order.get("ownerId")
    if owner_id:
        _notify_owner(owner_id, "order_updated", {"id": order_id, "status": "cancelled"})
    _notify_order_status(order_id, "cancelled")
    log_security("CUSTOMER_CANCEL", f"order_id={order_id}")
    return {"success": True, "message": "Order cancelled successfully."}, 200


# ---------------------------------------------------------------------------
# Feedback API
# ---------------------------------------------------------------------------

@app.route("/api/feedback", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def submit_feedback() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    customer_name = str(payload.get("customerName", "Guest")).strip()[:100] or "Guest"
    order_id = payload.get("orderId")
    rating = payload.get("rating")
    comment = str(payload.get("comment", "")).strip()[:1000]

    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except (TypeError, ValueError):
        abort(400, description="Rating must be an integer between 1 and 5.")

    owner_id = None
    cafe_id = None
    if table_id and re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")
            cafe_id = table.get("cafeId")

    if order_id:
        order = _db_get_order(int(order_id))
        if order:
            owner_id = owner_id or order.get("ownerId")
            cafe_id = cafe_id or order.get("cafeId")

    entry = {
        "ownerId": owner_id,
        "cafeId": cafe_id,
        "orderId": int(order_id) if order_id else None,
        "tableId": table_id,
        "customerName": customer_name,
        "rating": rating,
        "comment": comment,
    }
    saved = save_feedback_entry(entry)
    return {"message": "Thank you for your feedback!", "feedback": saved}, 201


@app.route("/api/feedback/summary")
@csrf.exempt
@api_login_required
def feedback_summary():
    owner_id = logged_in_owner_id()
    feedback_list = Feedback.query.filter_by(owner_id=owner_id).all()
    avg = 0.0
    if feedback_list:
        avg = round(sum(f.rating for f in feedback_list) / len(feedback_list), 1)
    breakdown = {str(i): sum(1 for f in feedback_list if f.rating == i) for i in range(1, 6)}
    return jsonify(average=avg, count=len(feedback_list), breakdown=breakdown)


# ---------------------------------------------------------------------------
# Customers route
# ---------------------------------------------------------------------------

@app.route("/owner/customers")
@login_required
def owner_customers():
    owner_id = logged_in_owner_id()
    search = (request.args.get("q") or "").strip().lower()[:80]
    export = request.args.get("export") == "csv"

    orders = Order.query.filter_by(owner_id=owner_id).order_by(Order.created_at.desc()).all()

    customer_map: dict[str, dict] = {}
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
                "lastOrder": _iso(o.created_at),
                "firstOrder": _iso(o.created_at),
            }
        c = customer_map[key]
        c["orderCount"] += 1
        if o.status == "completed":
            c["completedCount"] += 1
            c["totalSpend"] += float(o.total or 0)
        if o.created_at and (not c["firstOrder"] or _iso(o.created_at) < c["firstOrder"]):
            c["firstOrder"] = _iso(o.created_at)

    for c in customer_map.values():
        c["totalSpend"] = round(c["totalSpend"], 2)
        c["avgOrder"] = round(c["totalSpend"] / c["completedCount"], 2) if c["completedCount"] else 0.0

    customers = sorted(customer_map.values(), key=lambda c: c["totalSpend"], reverse=True)

    if search:
        customers = [
            c for c in customers
            if search in (c["name"] or "").lower()
            or search in (c["email"] or "").lower()
            or search in (c["phone"] or "").lower()
        ]

    total_completed = sum(c["completedCount"] for c in customer_map.values())
    repeat_count = sum(1 for c in customer_map.values() if c["orderCount"] > 1)
    repeat_rate = round((repeat_count / len(customer_map)) * 100, 1) if customer_map else 0.0

    if export:
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["name", "email", "phone", "orders", "completed", "total_spend", "avg_order", "first_order", "last_order"])
        for c in customers:
            w.writerow([c["name"], c["email"], c["phone"], c["orderCount"], c["completedCount"],
                        c["totalSpend"], c["avgOrder"], c["firstOrder"], c["lastOrder"]])
        out.seek(0)
        fname = f"customers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})

    return render_template("owner_customers.html",
                           customers=customers[:200],
                           total_orders=total_completed,
                           repeat_rate=repeat_rate,
                           total_unique=len(customer_map),
                           search=search,
                           owner_username=logged_in_owner())


# ---------------------------------------------------------------------------
# Menu CSV export (referenced by analytics page)
# ---------------------------------------------------------------------------

@app.route("/owner/export/menu")
@login_required
def export_menu_csv():
    owner_id = logged_in_owner_id()
    menu = load_menu()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["category", "id", "name", "price", "description", "available"])
    for cat in menu.get("categories", []):
        if cat.get("ownerId") != owner_id:
            continue
        for item in cat.get("items", []):
            w.writerow([
                cat.get("name", ""),
                item.get("id", ""),
                item.get("name", ""),
                item.get("price", ""),
                (item.get("description") or "")[:300],
                "yes" if item.get("available", True) else "no",
            ])
    out.seek(0)
    fname = f"menu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# ---------------------------------------------------------------------------
# Admin blueprint (legacy superadmin via key)
# ---------------------------------------------------------------------------

from admin import admin_bp
app.register_blueprint(admin_bp)

# ---------------------------------------------------------------------------
# Modular feature blueprints (gradual decomposition of the monolith).
# ---------------------------------------------------------------------------
try:
    from extensions import register_extensions
    register_extensions(app)
except Exception as _ext_exc:  # pragma: no cover - never block startup on extras
    app.logger.warning("extensions: failed to register: %s", _ext_exc)


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

def _make_superadmin_if_missing() -> None:
    sa_user = os.environ.get("SUPERADMIN_USERNAME", "superadmin")
    sa_pass = os.environ.get("SUPERADMIN_PASSWORD", "")
    if not sa_pass:
        return
    with app.app_context():
        existing = Owner.query.filter_by(username=sa_user).first()
        if existing:
            if not existing.is_superadmin:
                existing.is_superadmin = True
                db.session.commit()
                app.logger.info("Promoted '%s' to superadmin.", sa_user)
            return
        pw_hash = _make_password_hash(sa_pass)
        owner = Owner(
            username=sa_user,
            email=None,
            password_hash=pw_hash,
            cafe_name="",
            is_superadmin=True,
            is_active=True,
        )
        db.session.add(owner)
        db.session.commit()
        app.logger.info("Superadmin '%s' created.", sa_user)


if not IS_PRODUCTION:
    _initialize_runtime_state(force=True)
else:
    app.logger.info("Deferring database initialization until first non-health request.")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
