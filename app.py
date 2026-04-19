from __future__ import annotations

import base64
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import tempfile
import threading
from logging.handlers import RotatingFileHandler
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import csv
import portalocker
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
)
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_compress import Compress
from flask_login import (
    LoginManager,
    current_user,
    login_required as flask_login_required,
    login_user,
    logout_user,
)
from flask_mail import Mail, Message
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from sqlalchemy import inspect, text
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

try:
    import stripe
except ImportError:
    stripe = None

load_dotenv()

# ---------------------------------------------------------------------------
# Paths (used as fallback when DATABASE_URL is not set)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------

_secret_key = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET")
if _secret_key:
    app.secret_key = _secret_key
else:
    if IS_PRODUCTION:
        raise RuntimeError("SECRET_KEY is required when IS_PRODUCTION=true or FLASK_ENV=production.")
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
    if IS_PRODUCTION:
        log_path = Path(os.environ.get("LOG_FILE", DATA_DIR / "logs" / "app.log"))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
        handler.setFormatter(JsonFormatter())
    else:
        handler = logging.StreamHandler()
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

# ---------------------------------------------------------------------------
# Security extensions
# ---------------------------------------------------------------------------

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
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:", "https://lh3.googleusercontent.com", "https://maps.googleapis.com"],
    "connect-src": ["'self'", "https://maps.googleapis.com", "https://places.googleapis.com"],
    "frame-src": ["https://www.google.com"],
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
            content_security_policy_nonce_in=None,
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

if stripe is not None and os.environ.get("STRIPE_SECRET_KEY"):
    stripe.api_key = os.environ["STRIPE_SECRET_KEY"]


class Owner(db.Model):
    __tablename__ = "owners"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    cafe_name = db.Column(db.Text, default="")
    google_place_id = db.Column(db.Text, default="")
    is_active = db.Column(db.Boolean, default=True, nullable=False, server_default="true")
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
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Menu(db.Model):
    __tablename__ = "menus"
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"), primary_key=True)
    data = db.Column(db.JSON, nullable=False, default=lambda: {"categories": []})


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
    table_id = db.Column(db.Text)
    table_name = db.Column(db.Text)
    customer_name = db.Column(db.Text, default="Guest")
    customer_email = db.Column(db.Text, default="")
    items = db.Column(db.JSON, nullable=False, default=list)
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    tip = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    status = db.Column(db.Text, default="pending")
    origin = db.Column(db.Text, default="table")
    payment_intent = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"))
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


def _init_db() -> None:
    """Create SQLAlchemy tables and run safe additive column upgrades."""
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)

        def add_column(table_name: str, column_sql: str, column_name: str) -> None:
            existing = {col["name"] for col in inspector.get_columns(table_name)}
            if column_name in existing:
                return
            db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}"))
            db.session.commit()

        add_column("orders", "customer_email TEXT DEFAULT ''", "customer_email")
        add_column("orders", "subtotal NUMERIC(10, 2) DEFAULT 0", "subtotal")
        add_column("orders", "tip NUMERIC(10, 2) DEFAULT 0", "tip")
        add_column("orders", "payment_intent TEXT DEFAULT ''", "payment_intent")
        add_column("orders", "updated_at TIMESTAMP", "updated_at")
        _seed_sqlalchemy_from_json()
    app.logger.info("SQLAlchemy database schema ready: %s", app.config["SQLALCHEMY_DATABASE_URI"])

# ---------------------------------------------------------------------------
# Security headers
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
        return "Unsupported file type. Upload .json, .jpg, or .png only.", None
    guessed_type = (mimetypes.guess_type(filename)[0] or "").lower()
    provided_type = (uploaded_file.mimetype or "").split(";", 1)[0].lower()
    allowed_types = _ALLOWED_UPLOADS[ext]
    if guessed_type not in allowed_types:
        return "Uploaded file extension does not match an allowed MIME type.", None
    if provided_type and provided_type not in allowed_types and provided_type != "application/octet-stream":
        return "Uploaded file MIME type is not allowed.", None
    if not file_bytes:
        return "Uploaded file is empty.", None
    return None, "image" if ext in {".jpg", ".jpeg", ".png"} else "json"

def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def log_security(event: str, detail: str = "") -> None:
    security_log.info("%s ip=%s %s", event, _client_ip(), detail)

# ---------------------------------------------------------------------------
# JSON file helpers (fallback when no DATABASE_URL)
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
    except json.JSONDecodeError as exc:
        app.logger.error("Corrupt JSON in %s (%s) — returning default", path, exc)
        try:
            corrupt = path.with_suffix(path.suffix + f".corrupt.{int(time.time())}")
            path.replace(corrupt)
        except OSError:
            pass
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
        if tmp_path:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


def read_json(path: Path, default):
    return safe_read_json(path, default)


def write_json(path: Path, data) -> None:
    atomic_write_json(path, data)


_MENU_CACHE_TTL_SECONDS = 30
_menu_cache: dict[str, object] = {"expires_at": 0.0, "data": None}
_menu_cache_lock = threading.Lock()


def _clone_json_data(data):
    return json.loads(json.dumps(data))


def _get_cached_menu():
    with _menu_cache_lock:
        if _menu_cache["data"] is not None and time.monotonic() < float(_menu_cache["expires_at"]):
            return _clone_json_data(_menu_cache["data"])
    return None


def _set_cached_menu(menu: dict) -> None:
    with _menu_cache_lock:
        _menu_cache["data"] = _clone_json_data(menu)
        _menu_cache["expires_at"] = time.monotonic() + _MENU_CACHE_TTL_SECONDS


def _invalidate_menu_cache() -> None:
    with _menu_cache_lock:
        _menu_cache["data"] = None
        _menu_cache["expires_at"] = 0.0

# ---------------------------------------------------------------------------
# Data access — SQLAlchemy
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
        "googlePlaceId": owner.google_place_id or "",
        "isActive": bool(owner.is_active),
        "createdAt": _iso(owner.created_at),
    }


def _table_dict(table: CafeTable) -> dict:
    return {
        "id": table.id,
        "name": table.name,
        "ownerId": table.owner_id,
        "createdAt": _iso(table.created_at),
    }


def _order_dict(order: Order) -> dict:
    return {
        "id": order.id,
        "ownerId": order.owner_id,
        "tableId": order.table_id,
        "tableName": order.table_name,
        "customerName": order.customer_name or "Guest",
        "customerEmail": order.customer_email or "",
        "items": order.items if isinstance(order.items, list) else [],
        "subtotal": float(order.subtotal or 0),
        "tip": float(order.tip or 0),
        "total": float(order.total or 0),
        "status": order.status or "pending",
        "origin": order.origin or "table",
        "paymentIntent": order.payment_intent or "",
        "createdAt": _iso(order.created_at),
        "updatedAt": _iso(order.updated_at),
    }


def _feedback_dict(feedback: Feedback) -> dict:
    return {
        "id": feedback.id,
        "ownerId": feedback.owner_id,
        "tableId": feedback.table_id,
        "customerName": feedback.customer_name or "Guest",
        "rating": feedback.rating,
        "comment": feedback.comment or "",
        "createdAt": _iso(feedback.created_at),
    }


def _settings_dict(settings: Settings | None) -> dict:
    if not settings:
        return {"logoUrl": "", "brandColor": "#4f46e5"}
    return {
        "logoUrl": settings.logo_url or "",
        "brandColor": settings.brand_color or "#4f46e5",
    }


def load_owners() -> list[dict]:
    return [_owner_dict(owner) for owner in Owner.query.order_by(Owner.id).all()]


def save_owners(owners: list[dict]) -> None:
    keep_ids = {owner.get("id") for owner in owners if owner.get("id")}
    for existing in Owner.query.all():
        if existing.id not in keep_ids:
            db.session.delete(existing)
    for owner in owners:
        record = db.session.get(Owner, owner.get("id")) if owner.get("id") else Owner()
        record.username = owner["username"]
        record.email = owner.get("email")
        record.password_hash = owner.get("passwordHash", "")
        record.cafe_name = owner.get("cafeName", "")
        record.google_place_id = owner.get("googlePlaceId", "")
        record.is_active = owner.get("isActive", True)
        record.created_at = _parse_dt(owner.get("createdAt")) or record.created_at
        db.session.add(record)
    db.session.commit()


def create_owner_in_db(username: str, email: str | None, password_hash: str, cafe_name: str = "") -> dict:
    owner = Owner(username=username, email=email or None, password_hash=password_hash, cafe_name=cafe_name)
    db.session.add(owner)
    db.session.commit()
    return _owner_dict(owner)


def load_tables() -> list[dict]:
    return [_table_dict(table) for table in CafeTable.query.order_by(CafeTable.created_at).all()]


def save_tables(tables: list[dict]) -> None:
    keep_ids = {table["id"] for table in tables}
    for existing in CafeTable.query.all():
        if existing.id not in keep_ids:
            db.session.delete(existing)
    for table in tables:
        record = db.session.get(CafeTable, table["id"]) or CafeTable(id=table["id"])
        record.name = table["name"]
        record.owner_id = table.get("ownerId")
        record.created_at = _parse_dt(table.get("createdAt")) or record.created_at
        db.session.add(record)
    db.session.commit()


def load_menu() -> dict:
    cached_menu = _get_cached_menu()
    if cached_menu is not None:
        return cached_menu
    all_categories = []
    for menu in Menu.query.all():
        for category in (menu.data or {}).get("categories", []):
            category_copy = dict(category)
            category_copy["ownerId"] = menu.owner_id
            all_categories.append(category_copy)
    result = {"categories": all_categories}
    _set_cached_menu(result)
    return _clone_json_data(result)


def save_menu(menu: dict) -> None:
    by_owner: dict[int, list] = {}
    for category in menu.get("categories", []):
        owner_id = category.get("ownerId")
        if owner_id is None:
            continue
        category_copy = {k: v for k, v in category.items() if k != "ownerId"}
        by_owner.setdefault(owner_id, []).append(category_copy)
    owner_ids = {owner.id for owner in Owner.query.all()} | {m.owner_id for m in Menu.query.all()}
    for owner_id in owner_ids:
        categories = by_owner.get(owner_id, [])
        record = db.session.get(Menu, owner_id) or Menu(owner_id=owner_id)
        record.data = {"categories": categories}
        db.session.add(record)
    db.session.commit()
    _set_cached_menu(menu)


def load_orders() -> list[dict]:
    return [_order_dict(order) for order in Order.query.order_by(Order.id).all()]


def save_orders(orders: list[dict]) -> None:
    keep_ids = {order.get("id") for order in orders if isinstance(order.get("id"), int)}
    for existing in Order.query.all():
        if existing.id not in keep_ids:
            db.session.delete(existing)
    for order in orders:
        record = db.session.get(Order, order.get("id")) if order.get("id") else Order()
        record.owner_id = order.get("ownerId")
        record.table_id = order.get("tableId")
        record.table_name = order.get("tableName")
        record.customer_name = order.get("customerName", "Guest")
        record.customer_email = order.get("customerEmail", "")
        record.items = order.get("items", [])
        record.subtotal = order.get("subtotal", order.get("total", 0))
        record.tip = order.get("tip", 0)
        record.total = order.get("total", 0)
        record.status = order.get("status", "pending")
        record.origin = order.get("origin", "table")
        record.payment_intent = order.get("paymentIntent", "")
        record.created_at = _parse_dt(order.get("createdAt")) or record.created_at
        record.updated_at = datetime.now(timezone.utc)
        db.session.add(record)
    db.session.commit()


def place_order_in_db(order: dict) -> dict:
    record = Order(
        owner_id=order.get("ownerId"),
        table_id=order.get("tableId"),
        table_name=order.get("tableName"),
        customer_name=order.get("customerName", "Guest"),
        customer_email=order.get("customerEmail", ""),
        items=order.get("items", []),
        subtotal=order.get("subtotal", order.get("total", 0)),
        tip=order.get("tip", 0),
        total=order.get("total", 0),
        status=order.get("status", "pending"),
        origin=order.get("origin", "table"),
        payment_intent=order.get("paymentIntent", ""),
        created_at=_parse_dt(order.get("createdAt")) or datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(record)
    db.session.commit()
    return _order_dict(record)


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


def _db_set_payment_intent(order_id: int, payment_intent: str, status: str | None = None) -> dict | None:
    order = db.session.get(Order, order_id)
    if not order:
        return None
    order.payment_intent = payment_intent or order.payment_intent
    if status:
        order.status = status
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return _order_dict(order)


def load_feedback() -> list[dict]:
    return [_feedback_dict(feedback) for feedback in Feedback.query.order_by(Feedback.id.desc()).all()]


def save_feedback_entry(entry: dict) -> dict:
    feedback = Feedback(
        owner_id=entry.get("ownerId"),
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
    feedback = safe_read_json(FEEDBACK_PATH, [])
    if owners:
        save_owners(owners)
    if tables:
        save_tables(tables)
    if menu.get("categories"):
        save_menu(menu)
    if orders:
        save_orders(orders)
    for entry in feedback:
        save_feedback_entry(entry)

# ---------------------------------------------------------------------------
# Persistent "remember me" token system
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
# ID generation (used in JSON fallback mode)
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
    if current_user.is_authenticated:
        return current_user.username
    return session.get("owner_username")


def logged_in_owner_id() -> int | None:
    if current_user.is_authenticated:
        return current_user.id
    return session.get("owner_id")


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
# IP-based login lockout
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

# ---------------------------------------------------------------------------
# API auth decorator
# ---------------------------------------------------------------------------

def api_login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not logged_in_owner():
            log_security("API_UNAUTHORISED", f"path={request.path}")
            return jsonify(description="Authentication required."), 401
        return view_func(*args, **kwargs)
    return wrapper

# ---------------------------------------------------------------------------
# Cache-control helper
# ---------------------------------------------------------------------------

def _no_store(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


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

# ---------------------------------------------------------------------------
# Order computation — scoped to owner's menu
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
        # Handle per-item modifiers
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
        summary.append(
            {
                "id": item_id,
                "name": menu_item["name"],
                "price": menu_item["price"],
                "quantity": quantity,
                "modifiers": modifier_list,
                "lineTotal": round(item_total, 2),
            }
        )

    return {"items": summary, "total": round(total, 2)}


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
        message = Message(
            subject=f"Order #{order.get('id')} confirmation",
            recipients=[recipient],
            body=(
                f"Thanks for your order, {order.get('customerName', 'Guest')}.\n\n"
                f"{item_lines}\n\n"
                f"Total: ₹{float(order.get('total') or 0):.2f}\n"
                f"Status: {order.get('status', 'pending')}\n"
            ),
        )
        mail.send(message)
    except Exception as exc:
        app.logger.warning("Order confirmation email failed: %s", exc)


def _stripe_enabled() -> bool:
    return stripe is not None and bool(os.environ.get("STRIPE_SECRET_KEY"))


def _create_stripe_checkout_session(order: dict, table_id: str | None):
    if not _stripe_enabled():
        return None
    success_url = url_for("table_order", table_id=table_id, _external=True) if table_id else url_for("home", _external=True)
    cancel_url = success_url
    return stripe.checkout.Session.create(
        mode="payment",
        payment_method_types=["card"],
        customer_email=order.get("customerEmail") or None,
        line_items=[
            {
                "price_data": {
                    "currency": os.environ.get("STRIPE_CURRENCY", "inr").lower(),
                    "product_data": {"name": f"Cafe order #{order['id']}"},
                    "unit_amount": max(int(round(float(order.get("total") or 0) * 100)), 50),
                },
                "quantity": 1,
            }
        ],
        metadata={"order_id": str(order["id"])},
        payment_intent_data={"metadata": {"order_id": str(order["id"])}},
        success_url=f"{success_url}?order={order['id']}&payment=success",
        cancel_url=f"{cancel_url}?order={order['id']}&payment=cancelled",
    )

# ---------------------------------------------------------------------------
# SSE — server-sent events for live order updates (owner + customer)
# ---------------------------------------------------------------------------

_sse_subscribers: dict[int, list] = {}          # owner_id → [queue, ...]
_sse_customer_subs: dict[int, list] = {}        # order_id → [queue, ...]
_sse_lock = threading.Lock()


def _notify_owner(owner_id: int, event_type: str, data: dict) -> None:
    """Push an SSE event to all connected dashboards for this owner."""
    payload = json.dumps({"type": event_type, "data": data})
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


def _notify_order_status(order_id: int, status: str) -> None:
    """Push a status update to customer SSE streams watching this order."""
    payload = json.dumps({"status": status, "id": order_id})
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

# ---------------------------------------------------------------------------
# Menu AI extraction
# ---------------------------------------------------------------------------

def _extract_menu_from_pdf_bytes(pdf_bytes: bytes) -> dict | None:
    """Extract menu text from a PDF using pypdf (pure Python, no binary deps)."""
    try:
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        all_text = ""
        for page in reader.pages:
            all_text += (page.extract_text() or "") + "\n"
        text = all_text.strip()
        if not text:
            return None
        return _parse_menu_text(text)
    except ImportError:
        app.logger.warning("pypdf not available for PDF menu extraction")
        return None
    except Exception as exc:
        app.logger.warning("pypdf extraction failed: %s", exc)
        return None


def _extract_menu_with_gemini(img_bytes: bytes) -> dict | None:
    """Use Google Gemini Vision API to extract a structured menu from an image."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    try:
        import google.generativeai as genai  # type: ignore
        from PIL import Image as PILImage
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        img = PILImage.open(io.BytesIO(img_bytes))
        prompt = (
            "You are a restaurant menu digitiser. Extract every menu item visible in this image. "
            "Return ONLY valid JSON — no markdown, no code fences — in this exact format: "
            "{\"categories\": [{\"name\": \"Category Name\", \"items\": "
            "[{\"name\": \"Item Name\", \"price\": 150.0, \"description\": \"\", \"tags\": []}]}]}. "
            "If no price is visible, use 0. Group items under sensible category names. "
            "Output only the JSON object."
        )
        response = model.generate_content([prompt, img])
        text = response.text.strip()
        # Strip any accidental markdown code fences
        text = re.sub(r"^```[a-z]*\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        return json.loads(text.strip())
    except ImportError:
        app.logger.warning("google-generativeai package not installed")
        return None
    except Exception as exc:
        app.logger.warning("Gemini extraction failed: %s", exc)
        return None


def _extract_menu_from_image_bytes(img_bytes: bytes, mime_type: str) -> dict | None:
    """Extract menu structure from image bytes.

    Priority:
    1. pytesseract OCR (if installed locally)
    2. Google Gemini Vision API (if GEMINI_API_KEY env var is set)
    Returns a dict with 'categories' on success, else None.
    """
    # 1. Try local pytesseract
    try:
        import pytesseract  # type: ignore
        from PIL import Image
        img = Image.open(io.BytesIO(img_bytes))
        text = pytesseract.image_to_string(img)
        if text.strip():
            return _parse_menu_text(text)
    except ImportError:
        pass
    except Exception as exc:
        app.logger.debug("pytesseract failed: %s", exc)

    # 2. Try Gemini Vision
    result = _extract_menu_with_gemini(img_bytes)
    if result is not None:
        return result

    return None


def _parse_menu_text(text: str) -> dict:
    """Parse raw OCR text into a basic menu structure."""
    categories = []
    current_cat = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Detect price pattern (e.g. "Espresso  ₹120" or "Latte - 150")
        price_match = re.search(r'[₹$£€]?\s*(\d{1,5}(?:\.\d{1,2})?)\s*$', line)
        if price_match and current_cat is not None:
            price_str = price_match.group(1)
            item_name = line[:price_match.start()].strip().rstrip('-–—:').strip()
            if item_name and 2 <= len(item_name) <= 100:
                try:
                    price = float(price_str)
                    current_cat["items"].append({
                        "name": item_name,
                        "price": price,
                        "description": "",
                        "tags": [],
                    })
                except ValueError:
                    pass
        elif len(line) <= 50 and not any(c.isdigit() for c in line[:5]):
            # Looks like a category heading
            current_cat = {"name": line.title(), "items": []}
            categories.append(current_cat)

    if not categories:
        categories = [{"name": "Imported Items", "items": []}]

    return {"categories": [c for c in categories if c["items"]]}

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
    flash("Your session has expired or the request was invalid. Please try again.")
    return redirect(request.referrer or url_for("home")), 302


@app.errorhandler(429)
def err_rate_limit(e):
    log_security("RATE_LIMIT_HIT", f"path={request.path}")
    if _wants_json():
        return jsonify(description="Too many requests. Please slow down."), 429
    return render_template("errors/429.html"), 429


@app.errorhandler(413)
def err_payload_too_large(e):
    if _wants_json():
        return jsonify(description="Request payload too large (max 16 MB)."), 413
    return render_template("errors/400.html"), 413


@app.errorhandler(500)
def err_server(e):
    app.logger.exception("Internal server error: %s", e)
    if _wants_json():
        return jsonify(description="An internal error occurred."), 500
    return render_template("errors/500.html"), 500

# ---------------------------------------------------------------------------
# Health check (Railway / Render / any load-balancer)
# ---------------------------------------------------------------------------

@app.route("/health")
@limiter.exempt
def health_check():
    """Simple liveness probe — returns 200 so Railway knows the app is up."""
    return {"status": "ok", "service": "cafe-ordering"}, 200


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/")
def home() -> str:
    owner_id = logged_in_owner_id()
    owner_cafe = ""
    google_place_id = ""
    if owner_id:
        owners = load_owners()
        owner = next((o for o in owners if o["id"] == owner_id), None)
        if owner:
            owner_cafe = owner.get("cafeName", "")
            google_place_id = owner.get("googlePlaceId", "")
    return render_template("index.html",
                           owner_username=logged_in_owner(),
                           owner_cafe=owner_cafe,
                           google_place_id=google_place_id)


@app.route("/table/<table_id>")
@limiter.limit("60 per minute")
def table_order(table_id: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(404)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        abort(404, description="Table not found.")
    # Get owner info for branding
    owner_id = table.get("ownerId")
    owners = load_owners()
    owner = next((o for o in owners if o["id"] == owner_id), None)
    cafe_name = (owner or {}).get("cafeName", "") or "Cafe 11:11"
    google_place_id = (owner or {}).get("googlePlaceId", "")
    branding = load_settings(owner_id)
    return render_template("table_order.html", table=table,
                           cafe_name=cafe_name,
                           google_place_id=google_place_id,
                           branding=branding,
                           stripe_publishable_key=os.environ.get("STRIPE_PUBLISHABLE_KEY", ""))

# ---------------------------------------------------------------------------
# Auth routes — login
# ---------------------------------------------------------------------------

@app.before_request
def _auto_login_from_token() -> None:
    """If there is no active session but a valid remember-me cookie exists, restore the session."""
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
            log_security("LOGIN_LOCKOUT_BLOCKED", f"ip={ip!r}")
            flash("Too many failed attempts. Please try again in 15 minutes.")
            return _no_store(app.make_response(render_template("owner_login.html")))

        identifier = str(request.form.get("identifier", "")).strip()[:128]
        password = str(request.form.get("password", ""))[:256]
        remember_me = request.form.get("remember_me") == "on"

        owners = load_owners()
        owner = next(
            (
                o for o in owners
                if o["username"] == identifier
                or (o.get("email") or "").lower() == identifier.lower()
            ),
            None,
        )

        if owner and not owner.get("isActive", True):
            log_security("LOGIN_BLOCKED_INACTIVE", f"user={owner['username']!r} ip={ip!r}")
            flash("This account has been suspended. Please contact support.")
            return _no_store(app.make_response(render_template("owner_login.html")))

        if owner and _password_matches(owner["passwordHash"], password):
            _clear_failed_logins(ip)
            session.clear()
            session["owner_username"] = owner["username"]
            session["owner_id"] = owner["id"]
            session.permanent = True  # always keep session alive across browser restarts
            owner_model = db.session.get(Owner, owner["id"])
            if owner_model:
                login_user(owner_model, remember=False)
            log_security("LOGIN_SUCCESS", f"user={owner['username']!r} remember={remember_me}")

            resp = redirect(url_for("owner_dashboard"))

            if remember_me:
                # Issue a long-lived persistent token stored server-side
                raw_token = create_remember_token(owner["id"])
                resp.set_cookie(
                    _REMEMBER_COOKIE,
                    raw_token,
                    max_age=int(timedelta(days=_REMEMBER_DAYS).total_seconds()),
                    httponly=True,
                    secure=IS_PRODUCTION,
                    samesite="Lax",
                    path="/",
                )
            return resp

        _record_failed_login(ip)
        log_security("LOGIN_FAILURE", f"identifier={identifier!r} ip={ip!r}")
        flash("Sign in failed. Check your credentials and try again.")

    return _no_store(app.make_response(render_template("owner_login.html")))

# ---------------------------------------------------------------------------
# Auth routes — signup
# ---------------------------------------------------------------------------

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
            flash("Username may only contain letters, digits, underscores, hyphens, and dots (3–64 chars).")
            return render_template("owner_signup.html")

        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.")
            return render_template("owner_signup.html")

        if not _is_strong_password(password):
            flash("Password must be at least 8 characters and contain at least one letter and one digit.")
            return render_template("owner_signup.html")

        owners = load_owners()
        if any(o["username"] == username for o in owners):
            flash("That username is already taken. Please choose another.")
            return render_template("owner_signup.html")
        if email and any((o.get("email") or "").lower() == email.lower() for o in owners):
            flash("An account with that email already exists.")
            return render_template("owner_signup.html")

        password_hash = _make_password_hash(password)

        if USE_DB:
            try:
                new_owner = create_owner_in_db(username, email, password_hash, cafe_name)
            except Exception as e:
                app.logger.error("DB owner creation failed: %s", e)
                flash("Could not create account. Please try again.")
                return render_template("owner_signup.html")
        else:
            new_owner = {
                "id": next_id(owners),
                "username": username,
                "email": email,
                "cafeName": cafe_name,
                "googlePlaceId": "",
                "passwordHash": password_hash,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
            owners.append(new_owner)
            save_owners(owners)

        session.clear()
        session["owner_username"] = new_owner["username"]
        session["owner_id"] = new_owner["id"]
        session.permanent = True
        owner_model = db.session.get(Owner, new_owner["id"])
        if owner_model:
            login_user(owner_model, remember=False)
        log_security("SIGNUP_SUCCESS", f"user={username!r}")
        return redirect(url_for("owner_dashboard"))

    return render_template("owner_signup.html")


@app.route("/owner/logout")
def owner_logout() -> Response:
    username = logged_in_owner()
    logout_user()
    session.clear()
    if username:
        log_security("LOGOUT", f"user={username!r}")
    resp = redirect(url_for("home"))
    # Revoke the remember-me token and clear the cookie
    raw_token = request.cookies.get(_REMEMBER_COOKIE)
    if raw_token:
        try:
            revoke_remember_token(raw_token)
        except Exception:
            pass
        resp.delete_cookie(_REMEMBER_COOKIE, path="/")
    return resp

# ---------------------------------------------------------------------------
# Profile management
# ---------------------------------------------------------------------------

@app.route("/owner/profile", methods=["GET", "POST"])
@login_required
def owner_profile() -> str | Response:
    owner_id = logged_in_owner_id()
    owners = load_owners()
    owner = next((o for o in owners if o["id"] == owner_id), None)
    if not owner:
        return redirect(url_for("owner_logout"))

    if request.method == "POST":
        action = request.form.get("action", "profile")

        if action == "profile":
            cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
            email = str(request.form.get("email", "")).strip()[:254] or None
            google_place_id = str(request.form.get("google_place_id", "")).strip()[:300]
            logo_url = str(request.form.get("logo_url", "")).strip()[:500]
            brand_color = str(request.form.get("brand_color", "#4f46e5")).strip()[:7]

            if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                flash("Please enter a valid email address.")
                return redirect(url_for("owner_profile"))

            # Check email uniqueness (excluding self)
            if email and any(
                (o.get("email") or "").lower() == email.lower() and o["id"] != owner_id
                for o in owners
            ):
                flash("That email is already used by another account.")
                return redirect(url_for("owner_profile"))

            owner["cafeName"] = cafe_name
            owner["email"] = email
            owner["googlePlaceId"] = google_place_id
            save_owners(owners)
            save_settings(owner_id, logo_url, brand_color)
            flash("Profile updated successfully.")

        elif action == "password":
            current_pw = str(request.form.get("current_password", ""))[:256]
            new_pw = str(request.form.get("new_password", ""))[:256]
            confirm_pw = str(request.form.get("confirm_password", ""))[:256]

            if not _password_matches(owner["passwordHash"], current_pw):
                flash("Current password is incorrect.")
                return redirect(url_for("owner_profile"))

            if new_pw != confirm_pw:
                flash("New passwords do not match.")
                return redirect(url_for("owner_profile"))

            if not _is_strong_password(new_pw):
                flash("Password must be at least 8 characters with a letter and digit.")
                return redirect(url_for("owner_profile"))

            owner["passwordHash"] = _make_password_hash(new_pw)
            save_owners(owners)
            # Revoke all persistent tokens — force relogin on all devices after password change
            try:
                revoke_all_tokens_for_owner(owner_id)
            except Exception:
                pass
            session.clear()
            flash("Password changed successfully. Please sign in again.")

        return redirect(url_for("owner_profile"))

    resp = app.make_response(render_template(
        "owner_profile.html",
        owner=owner,
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

    # Load owner info
    owners = load_owners()
    owner = next((o for o in owners if o["id"] == owner_id), {})

    # Recent feedback
    all_feedback = load_feedback()
    owner_feedback = [f for f in all_feedback if f.get("ownerId") == owner_id]
    avg_rating = 0.0
    if owner_feedback:
        avg_rating = round(sum(f["rating"] for f in owner_feedback) / len(owner_feedback), 1)

    resp = app.make_response(render_template(
        "owner_dashboard.html",
        owner_username=logged_in_owner(),
        owner=owner,
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
    ))
    return _no_store(resp)

# ---------------------------------------------------------------------------
# SSE — live order stream for the dashboard
# ---------------------------------------------------------------------------

@app.route("/api/orders/stream")
@csrf.exempt
@api_login_required
def orders_stream():
    """Server-Sent Events endpoint for real-time order updates."""
    owner_id = logged_in_owner_id()

    def generate():
        my_queue = []
        with _sse_lock:
            if owner_id not in _sse_subscribers:
                _sse_subscribers[owner_id] = []
            _sse_subscribers[owner_id].append(my_queue)

        try:
            # Send initial ping
            yield "event: ping\ndata: connected\n\n"
            last_heartbeat = time.time()
            while True:
                # Send pending events
                while my_queue:
                    payload = my_queue.pop(0)
                    yield f"data: {payload}\n\n"

                # Heartbeat every 25 seconds
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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
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
        abort(403, description="You do not own this category.")
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
        abort(403, description="You do not own this category.")

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

    if not category_id or not name or not price_text:
        flash("Item name, price, and category are required.")
        return redirect(url_for("owner_dashboard") + "#menu")

    try:
        price = round(float(price_text), 2)
        if price < 0 or price > 99999.99:
            raise ValueError("Price out of range")
    except ValueError:
        flash("Item price must be a valid positive number (up to ₹99,999.99).")
        return redirect(url_for("owner_dashboard") + "#menu")

    tags = [t.strip()[:50] for t in tags_text.split(",") if t.strip()][:10]
    menu = load_menu()
    category = next((c for c in menu["categories"] if c["id"] == category_id), None)
    if not category:
        flash("Selected category does not exist.")
        return redirect(url_for("owner_dashboard") + "#menu")
    if category.get("ownerId") != owner_id:
        abort(403, description="You do not own this category.")

    if item_id:
        item = next((i for i in category["items"] if i["id"] == item_id), None)
        if item:
            item.update({"name": name, "description": description, "price": price, "tags": tags})
            flash("Menu item updated.")
        else:
            flash("Menu item not found.")
    else:
        existing_item_ids = {i["id"] for i in category["items"]}
        new_item_id = unique_id(normalize_id(name), existing_item_ids)
        category["items"].append(
            {"id": new_item_id, "name": name, "description": description, "price": price, "tags": tags}
        )
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
    """Flip an item's available flag (sold-out ↔ available)."""
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
    flash("Item not found or you do not have permission.")
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
        tables.append(
            {
                "id": table_id,
                "name": name,
                "ownerId": owner_id,
                "url": table_url,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
        )
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
            abort(403, description="You do not own this table.")
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
            abort(403, description="You do not own this table.")
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
        abort(403, description="You do not own this table.")
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
    allowed = {"pending", "preparing", "ready", "completed", "cancelled"}
    if new_status not in allowed:
        flash("Invalid status value.")
        return redirect(url_for("owner_dashboard") + "#orders")

    if USE_DB:
        order = _db_get_order(order_id)
        if not order:
            flash("Order not found.")
            return redirect(url_for("owner_dashboard") + "#orders")
        if order.get("ownerId") != owner_id:
            abort(403, description="You do not own this order.")
        _db_update_order_status(order_id, new_status)
    else:
        with _orders_lock:
            orders = load_orders()
            found = False
            for order in orders:
                if order["id"] == order_id:
                    if order.get("ownerId") != owner_id:
                        abort(403, description="You do not own this order.")
                    order["status"] = new_status
                    found = True
                    break
            if not found:
                flash("Order not found.")
                return redirect(url_for("owner_dashboard") + "#orders")
            save_orders(orders)

    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": new_status})
    _notify_order_status(order_id, new_status)
    return redirect(url_for("owner_dashboard") + "#orders")


@app.route("/owner/order/<int:order_id>/complete", methods=["POST"])
@login_required
def complete_order(order_id: int) -> Response:
    owner_id = logged_in_owner_id()
    if USE_DB:
        order = _db_get_order(order_id)
        if not order:
            flash("Order not found.")
            return redirect(url_for("owner_dashboard") + "#orders")
        if order.get("ownerId") != owner_id:
            abort(403, description="You do not own this order.")
        _db_update_order_status(order_id, "completed")
    else:
        with _orders_lock:
            orders = load_orders()
            found = False
            for order in orders:
                if order["id"] == order_id:
                    if order.get("ownerId") != owner_id:
                        abort(403, description="You do not own this order.")
                    order["status"] = "completed"
                    found = True
                    break
            if not found:
                flash("Order not found.")
                return redirect(url_for("owner_dashboard") + "#orders")
            save_orders(orders)
    _notify_owner(owner_id, "order_updated", {"id": order_id, "status": "completed"})
    _notify_order_status(order_id, "completed")
    return redirect(url_for("owner_dashboard") + "#orders")


@app.route("/owner/order/<int:order_id>/delete", methods=["POST"])
@login_required
def delete_order(order_id: int) -> Response:
    owner_id = logged_in_owner_id()
    if USE_DB:
        order = _db_get_order(order_id)
        if not order or order.get("ownerId") != owner_id:
            abort(403, description="You do not own this order.")
        _db_delete_order(order_id)
    else:
        with _orders_lock:
            orders = load_orders()
            order = next((o for o in orders if o["id"] == order_id), None)
            if not order or order.get("ownerId") != owner_id:
                abort(403, description="You do not own this order.")
            orders = [o for o in orders if o["id"] != order_id]
            save_orders(orders)
    flash("Order deleted.")
    return redirect(url_for("owner_dashboard") + "#orders")


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
    """Import a menu from pasted JSON, uploaded menu.json, or JPG/PNG."""
    owner_id = logged_in_owner_id()
    raw_json: str | None = None
    imported_from_image = False

    uploaded_file = request.files.get("menu_file")
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read(16 * 1024 * 1024)
        upload_error, upload_kind = validate_uploaded_file(uploaded_file, file_bytes)
        if upload_error:
            flash(upload_error)
            return redirect(url_for("owner_dashboard") + "#menu")

        if upload_kind == "image":
            imported_from_image = True
            mime_type = mimetypes.guess_type(uploaded_file.filename or "")[0] or "image/jpeg"
            extracted_menu = _extract_menu_from_image_bytes(file_bytes, mime_type)
            if not extracted_menu:
                has_gemini_key = bool(os.environ.get("GEMINI_API_KEY"))
                if has_gemini_key:
                    tip = "Gemini API is configured but extraction failed. Try a clearer, well-lit photo."
                else:
                    tip = (
                        "To enable AI image extraction, add a GEMINI_API_KEY environment variable. "
                        "Until then, paste your menu as JSON or upload a .json file."
                    )
                flash(f"Could not extract menu from image. {tip}")
                return redirect(url_for("owner_dashboard") + "#menu")
            imported = extracted_menu
        else:
            try:
                raw_json = file_bytes.decode("utf-8")
            except Exception:
                flash("Could not read the uploaded file. Please upload a valid UTF-8 JSON file.")
                return redirect(url_for("owner_dashboard") + "#menu")
    else:
        raw_json = request.form.get("menu_data", "").strip()

    if not imported_from_image:
        if not raw_json:
            flash("No menu data provided.")
            return redirect(url_for("owner_dashboard") + "#menu")

        try:
            imported = json.loads(raw_json)
        except json.JSONDecodeError:
            flash("Invalid JSON — please check the format and try again.")
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
                "id": item_id,
                "name": item_name,
                "description": str(item.get("description", ""))[:500],
                "price": item_price,
                "tags": [str(t)[:50] for t in item.get("tags", []) if isinstance(t, str)][:10],
            })
        new_categories.append({
            "id": cat_id,
            "name": cat_name,
            "ownerId": owner_id,
            "items": items,
        })

    existing_menu["categories"] = other_categories + new_categories
    save_menu(existing_menu)
    method = "extracted from image" if imported_from_image else "imported"
    flash(f"Menu {method} — {len(new_categories)} categor{'y' if len(new_categories) == 1 else 'ies'} loaded.")
    return redirect(url_for("owner_dashboard") + "#menu")

# ---------------------------------------------------------------------------
# Public JSON API
# ---------------------------------------------------------------------------

@app.route("/api/menu", methods=["GET"])
@csrf.exempt
@limiter.limit("120 per minute")
def menu_api() -> Response:
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
    response = jsonify(filtered)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
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
            owner_menu = {
                "categories": [
                    c for c in all_menu.get("categories", [])
                    if c.get("ownerId") == table.get("ownerId")
                ]
            }
    return compute_order_summary(payload.get("items", []), owner_menu), 200


@app.route("/api/checkout", methods=["POST"])
@limiter.limit("20 per minute; 100 per hour")
def checkout() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    payload = request.get_json(silent=True) or {}
    customer_name = str(payload.get("customerName", "Guest")).strip()[:100] or "Guest"
    customer_email = str(payload.get("customerEmail", "")).strip()[:254]
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    items = payload.get("items", [])

    if customer_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", customer_email):
        abort(400, description="Invalid email address.")

    if table_id and not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400, description="Invalid table ID.")

    table_name = None
    owner_id = None
    owner_menu = None
    if table_id:
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            table_name = table["name"]
            owner_id = table.get("ownerId")
            all_menu = load_menu()
            owner_menu = {
                "categories": [
                    c for c in all_menu.get("categories", [])
                    if c.get("ownerId") == owner_id
                ]
            }
        else:
            table_name = table_id
    else:
        table_name = "Online"

    order_summary = compute_order_summary(items, owner_menu)

    # Tip handling
    try:
        tip = round(float(payload.get("tip", 0)), 2)
        if tip < 0 or tip > 10000:
            tip = 0.0
    except (TypeError, ValueError):
        tip = 0.0

    grand_total = round(order_summary["total"] + tip, 2)

    order_data = {
        "customerName": customer_name,
        "customerEmail": customer_email,
        "tableId": table_id,
        "tableName": table_name,
        "ownerId": owner_id,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "items": order_summary["items"],
        "subtotal": order_summary["total"],
        "tip": tip,
        "total": grand_total,
        "status": "pending",
        "origin": "table" if table_id else "online",
    }

    if USE_DB:
        order_record = place_order_in_db(order_data)
    else:
        with _orders_lock:
            orders = load_orders()
            order_data["id"] = next_id(orders)
            orders.append(order_data)
            save_orders(orders)
            order_record = order_data

    # Notify dashboard via SSE
    if owner_id:
        _notify_owner(owner_id, "new_order", {
            "id": order_record["id"],
            "tableName": table_name,
            "customerName": customer_name,
            "total": order_record["total"],
            "status": "pending",
        })

    log_security("ORDER_PLACED", f"table={table_id!r} total={order_record['total']}")
    try:
        checkout_session = _create_stripe_checkout_session(order_record, table_id)
    except Exception as exc:
        app.logger.error("Stripe Checkout creation failed: %s", exc)
        return {"description": "Payment could not be started. Please try again."}, 502

    if checkout_session:
        payment_intent = checkout_session.get("payment_intent") or ""
        if payment_intent:
            updated = _db_set_payment_intent(order_record["id"], payment_intent)
            if updated:
                order_record = updated
        return {
            "message": "Order created. Redirecting to payment.",
            "order": order_record,
            "checkoutUrl": checkout_session.url,
        }, 201

    _send_order_confirmation(order_record)
    return {"message": "Order placed successfully.", "order": order_record}, 201


@app.route("/stripe/webhook", methods=["POST"])
@csrf.exempt
@limiter.exempt
def stripe_webhook() -> tuple[dict, int]:
    if stripe is None:
        return {"received": True}, 200
    payload = request.get_data()
    signature = request.headers.get("Stripe-Signature", "")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
        else:
            event = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        app.logger.warning("Invalid Stripe webhook: %s", exc)
        return {"description": "Invalid webhook."}, 400

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})
    if event_type == "checkout.session.completed":
        order_id = data.get("metadata", {}).get("order_id")
        payment_intent = data.get("payment_intent") or ""
        if order_id and str(order_id).isdigit():
            order = _db_set_payment_intent(int(order_id), payment_intent, "pending")
            if order:
                _send_order_confirmation(order)
                if order.get("ownerId"):
                    _notify_owner(order["ownerId"], "order_paid", {"id": order["id"], "status": order["status"]})
    elif event_type == "payment_intent.succeeded":
        order_id = data.get("metadata", {}).get("order_id")
        if order_id and str(order_id).isdigit():
            _db_set_payment_intent(int(order_id), data.get("id") or "", "pending")
    return {"received": True}, 200


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
    orders = load_orders()
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        abort(404, description="Order not found.")
    safe_order = {
        "id": order["id"],
        "status": order.get("status", "pending"),
        "tableName": order.get("tableName", ""),
        "customerName": order.get("customerName", ""),
        "items": order.get("items", []),
        "total": order.get("total", 0),
        "createdAt": order.get("createdAt", ""),
    }
    return {"order": safe_order}, 200


@app.route("/api/orders/<int:order_id>/stream")
@csrf.exempt
@limiter.limit("30 per minute")
def customer_order_stream(order_id: int) -> Response:
    """SSE stream giving real-time status updates for one order (customer-facing)."""
    orders = load_orders()
    order = next((o for o in orders if o["id"] == order_id), None)
    if not order:
        abort(404, description="Order not found.")
    initial_status = order.get("status", "pending")

    my_queue: list[str] = []
    with _sse_lock:
        _sse_customer_subs.setdefault(order_id, []).append(my_queue)

    def generate():
        # Send current status immediately so the client is always in sync
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
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

# ---------------------------------------------------------------------------
# Customer order cancellation (within grace period)
# ---------------------------------------------------------------------------

_CANCEL_GRACE_SECONDS = 120  # 2 minutes

@app.route("/api/orders/<int:order_id>/cancel", methods=["POST"])
@limiter.limit("10 per minute")
def customer_cancel_order(order_id: int) -> tuple[dict, int]:
    """Allow a customer to cancel their own order within the grace period."""
    if not request.is_json:
        abort(400, description="JSON required.")

    if USE_DB:
        order = _db_get_order(order_id)
    else:
        orders = load_orders()
        order = next((o for o in orders if o["id"] == order_id), None)

    if not order:
        abort(404, description="Order not found.")

    status = order.get("status", "pending")
    if status not in ("pending",):
        return {"description": f"Order cannot be cancelled (status: {status})."}, 409

    # Enforce grace period
    created_at_str = order.get("createdAt", "")
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - created_at).total_seconds()
            if elapsed > _CANCEL_GRACE_SECONDS:
                return {
                    "description": f"Cancellation window expired. Orders can only be cancelled within {_CANCEL_GRACE_SECONDS // 60} minutes of placing."
                }, 409
        except (ValueError, TypeError):
            pass

    if USE_DB:
        _db_update_order_status(order_id, "cancelled")
    else:
        with _orders_lock:
            orders = load_orders()
            for o in orders:
                if o["id"] == order_id:
                    o["status"] = "cancelled"
                    break
            save_orders(orders)

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
    rating = payload.get("rating")
    comment = str(payload.get("comment", "")).strip()[:1000]

    try:
        rating = int(rating)
        if not (1 <= rating <= 5):
            raise ValueError()
    except (TypeError, ValueError):
        abort(400, description="Rating must be an integer between 1 and 5.")

    owner_id = None
    if table_id and re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        table = next((t for t in load_tables() if t["id"] == table_id), None)
        if table:
            owner_id = table.get("ownerId")

    entry = {
        "ownerId": owner_id,
        "tableId": table_id,
        "customerName": customer_name,
        "rating": rating,
        "comment": comment,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    result = save_feedback_entry(entry)
    return {"message": "Thank you for your feedback!", "feedback": {"id": result["id"]}}, 201


@app.route("/api/feedback", methods=["GET"])
@csrf.exempt
@limiter.limit("30 per minute")
def get_feedback() -> tuple[dict, int]:
    """Get public feedback for a table/owner."""
    table_id = request.args.get("table_id", "").strip()[:64]
    if not table_id:
        return {"feedback": []}, 200
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table:
        return {"feedback": []}, 200
    owner_id = table.get("ownerId")
    all_feedback = load_feedback()
    owner_feedback = [
        {
            "id": f["id"],
            "customerName": f.get("customerName", "Guest"),
            "rating": f["rating"],
            "comment": f.get("comment", ""),
            "createdAt": f.get("createdAt", ""),
        }
        for f in all_feedback
        if f.get("ownerId") == owner_id
    ]
    avg = round(sum(f["rating"] for f in owner_feedback) / len(owner_feedback), 1) if owner_feedback else 0
    return {"feedback": owner_feedback[:20], "average": avg, "total": len(owner_feedback)}, 200


# ---------------------------------------------------------------------------
# Analytics — revenue charts with 1-hour cache
# ---------------------------------------------------------------------------

_analytics_cache: dict = {}
_analytics_cache_ts: float = 0.0
_ANALYTICS_TTL: int = 3600


def _build_analytics(owner_id: int) -> dict:
    """Aggregate order data into analytics payload."""
    from collections import defaultdict
    all_orders = load_orders()
    orders = [o for o in all_orders if o.get("ownerId") == owner_id and o.get("status") == "completed"]

    daily: dict = defaultdict(float)
    item_counts: dict = defaultdict(int)
    hourly: dict = defaultdict(int)

    for o in orders:
        created = o.get("createdAt", "")[:10]
        daily[created] = round(daily[created] + float(o.get("total") or 0), 2)
        try:
            hour = datetime.fromisoformat(o.get("createdAt", "").replace("Z", "+00:00")).hour
            hourly[hour] += 1
        except (ValueError, TypeError):
            pass
        for it in o.get("items", []):
            item_counts[it.get("name", "?")] += it.get("quantity", 1)

    sorted_days = sorted(daily.keys())[-30:]
    revenue_by_day = [{"date": d, "revenue": daily[d]} for d in sorted_days]

    top_items = sorted(item_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_items_data = [{"name": n, "count": c} for n, c in top_items]
    peak_hours = [
        {"hour": f"{hour:02d}:00", "count": hourly.get(hour, 0)}
        for hour in range(24)
    ]

    total_revenue = round(sum(float(o.get("total") or 0) for o in orders), 2)
    total_orders = len(orders)
    avg_order = round(total_revenue / total_orders, 2) if total_orders else 0

    return {
        "revenueByDay": revenue_by_day,
        "topItems": top_items_data,
        "peakHours": peak_hours,
        "totalRevenue": total_revenue,
        "totalOrders": total_orders,
        "avgOrderValue": avg_order,
    }


@app.route("/api/owner/analytics")
@login_required
def owner_analytics_data() -> tuple[dict, int]:
    """Cached analytics JSON for Chart.js."""
    global _analytics_cache, _analytics_cache_ts
    owner_id = logged_in_owner_id()
    now = time.time()
    cache_key = f"analytics_{owner_id}"
    if cache_key in _analytics_cache and (now - _analytics_cache_ts) < _ANALYTICS_TTL:
        return _analytics_cache[cache_key], 200
    data = _build_analytics(owner_id)
    _analytics_cache[cache_key] = data
    _analytics_cache_ts = now
    return data, 200


@app.route("/owner/analytics")
@login_required
def owner_analytics_page():
    """Analytics dashboard with Chart.js charts."""
    owner_id = logged_in_owner_id()
    data = _build_analytics(owner_id)
    resp = app.make_response(render_template(
        "owner_analytics.html",
        owner_username=logged_in_owner(),
        analytics=data,
    ))
    return _no_store(resp)


# ---------------------------------------------------------------------------
# Customer insights
# ---------------------------------------------------------------------------


@app.route("/owner/customers")
@login_required
def owner_customers_page():
    """Top customers by spend and order frequency."""
    from collections import defaultdict
    owner_id = logged_in_owner_id()
    all_orders = load_orders()
    orders = [o for o in all_orders if o.get("ownerId") == owner_id and o.get("status") == "completed"]

    customer_spend: dict = defaultdict(float)
    customer_count: dict = defaultdict(int)

    for o in orders:
        name = o.get("customerName") or "Guest"
        total = float(o.get("total") or 0)
        customer_spend[name] = round(customer_spend[name] + total, 2)
        customer_count[name] += 1

    customers = [
        {
            "name": name,
            "totalSpend": customer_spend[name],
            "orderCount": customer_count[name],
            "avgOrder": round(customer_spend[name] / customer_count[name], 2),
        }
        for name in customer_spend
    ]
    customers.sort(key=lambda x: x["totalSpend"], reverse=True)

    total_orders = len(orders)
    repeat_customers = sum(1 for c in customers if c["orderCount"] > 1)
    repeat_rate = round(repeat_customers / len(customers) * 100, 1) if customers else 0

    resp = app.make_response(render_template(
        "owner_customers.html",
        owner_username=logged_in_owner(),
        customers=customers[:20],
        total_orders=total_orders,
        repeat_rate=repeat_rate,
    ))
    return _no_store(resp)


# ---------------------------------------------------------------------------
# CSV export routes
# ---------------------------------------------------------------------------


@app.route("/owner/export/orders")
@login_required
def export_orders_csv():
    """Download orders as CSV."""
    owner_id = logged_in_owner_id()
    date_from = request.args.get("from", "")[:10]
    date_to = request.args.get("to", "")[:10]

    all_orders = load_orders()
    rows = [o for o in all_orders if o.get("ownerId") == owner_id]
    if date_from:
        rows = [o for o in rows if o.get("createdAt", "")[:10] >= date_from]
    if date_to:
        rows = [o for o in rows if o.get("createdAt", "")[:10] <= date_to]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Date", "Customer", "Table", "Items", "Subtotal", "Tip", "Total", "Status"])
    for o in rows:
        items_str = "; ".join(
            f"{it.get('name')} x{it.get('quantity', 1)}" for it in o.get("items", [])
        )
        writer.writerow([
            o.get("id", ""),
            o.get("createdAt", "")[:19],
            o.get("customerName", "Guest"),
            o.get("tableName", ""),
            items_str,
            o.get("subtotal", o.get("total", 0)),
            o.get("tip", 0),
            o.get("total", 0),
            o.get("status", ""),
        ])

    return Response(
        buf.getvalue().encode("utf-8"),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=orders.csv"},
    )


@app.route("/owner/export/menu")
@login_required
def export_menu_csv():
    """Download menu as CSV."""
    owner_id = logged_in_owner_id()
    menu = load_menu()
    owner_cats = [c for c in menu.get("categories", []) if c.get("ownerId") == owner_id]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Category", "Item ID", "Name", "Description", "Price", "Available", "Dietary Tags", "Prep Time (min)", "Modifiers"])
    for cat in owner_cats:
        for item in cat.get("items", []):
            mods = "; ".join(
                f"{m.get('name')} +{m.get('price', 0)}" for m in item.get("modifiers", [])
            )
            writer.writerow([
                cat.get("name", ""),
                item.get("id", ""),
                item.get("name", ""),
                item.get("description", ""),
                item.get("price", 0),
                item.get("available", True),
                ", ".join(item.get("dietary_tags", [])),
                item.get("prep_time", ""),
                mods,
            ])

    return Response(
        buf.getvalue().encode("utf-8"),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=menu.csv"},
    )

# ---------------------------------------------------------------------------
# Admin blueprint
# ---------------------------------------------------------------------------

try:
    from admin.routes import admin_bp  # noqa: E402 (after app setup)

    @admin_bp.context_processor
    def _inject_now():
        return {"now": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

    app.register_blueprint(admin_bp)
    app.logger.info("Super Admin blueprint registered at /admin")
except Exception as _admin_import_err:  # noqa: BLE001
    app.logger.error(
        "Failed to load admin blueprint — /admin will not be available: %s",
        _admin_import_err,
        exc_info=True,
    )


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

try:
    _init_db()
except Exception as exc:
    import sys as _sys
    print(f"ERROR: Could not initialise SQLAlchemy data store: {exc}", file=_sys.stderr, flush=True)
    raise

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
