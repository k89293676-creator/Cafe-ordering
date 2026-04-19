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
from contextlib import contextmanager
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
from flask_limiter import Limiter
from flask_compress import Compress
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

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
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
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

# ---------------------------------------------------------------------------
# PostgreSQL setup
# ---------------------------------------------------------------------------

try:
    import psycopg2
    from psycopg2.pool import ThreadedConnectionPool
    from psycopg2.extras import Json, RealDictCursor
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False

_raw_db_url = os.environ.get("DATABASE_URL", "")
if _raw_db_url.startswith("postgres://"):
    _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)

if _raw_db_url:
    app.config["SQLALCHEMY_DATABASE_URI"] = _raw_db_url

db = SQLAlchemy()
migrate = Migrate()


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
    items = db.Column(db.JSON, nullable=False, default=list)
    total = db.Column(db.Numeric(10, 2), default=0)
    status = db.Column(db.Text, default="pending")
    origin = db.Column(db.Text, default="table")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


USE_DB = _HAS_PSYCOPG2 and bool(_raw_db_url)
if USE_DB:
    db.init_app(app)
    migrate.init_app(app, db)
_db_pool = None

if USE_DB:
    try:
        _db_pool = ThreadedConnectionPool(2, 20, _raw_db_url)
        app.logger.info("PostgreSQL connection pool created.")
    except Exception as _db_pool_err:
        app.logger.error("DB pool creation failed: %s", _db_pool_err)
        USE_DB = False


@contextmanager
def _get_conn():
    conn = _db_pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _db_pool.putconn(conn)


def _init_db() -> None:
    """Create tables, indexes, constraints and triggers if they do not exist."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            # ── Core tables ──────────────────────────────────────────────────
            cur.execute("""
                CREATE TABLE IF NOT EXISTS owners (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    cafe_name TEXT DEFAULT '',
                    google_place_id TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS remember_tokens (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER REFERENCES owners(id) ON DELETE CASCADE,
                    token_hash TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_tokens_owner_id ON remember_tokens(owner_id);
                CREATE INDEX IF NOT EXISTS idx_tokens_hash ON remember_tokens(token_hash);
                CREATE TABLE IF NOT EXISTS cafe_tables (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_id INTEGER REFERENCES owners(id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS menus (
                    owner_id INTEGER PRIMARY KEY REFERENCES owners(id) ON DELETE CASCADE,
                    data JSONB NOT NULL DEFAULT '{"categories": []}'
                );
                CREATE TABLE IF NOT EXISTS orders (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER REFERENCES owners(id),
                    table_id TEXT,
                    table_name TEXT,
                    customer_name TEXT DEFAULT 'Guest',
                    items JSONB NOT NULL DEFAULT '[]',
                    total NUMERIC(10,2) DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    origin TEXT DEFAULT 'table',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS feedback (
                    id SERIAL PRIMARY KEY,
                    owner_id INTEGER REFERENCES owners(id),
                    table_id TEXT,
                    customer_name TEXT DEFAULT 'Guest',
                    rating INTEGER NOT NULL,
                    comment TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # ── Additive schema upgrades (safe to re-run) ────────────────────
            # is_active column for owners (admin can deactivate owners)
            cur.execute("""
                ALTER TABLE owners
                    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
            """)
            # updated_at column for orders (tracks last status change)
            cur.execute("""
                ALTER TABLE orders
                    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
            """)

            # ── Performance indexes ──────────────────────────────────────────
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_orders_owner_id     ON orders(owner_id);
                CREATE INDEX IF NOT EXISTS idx_orders_status        ON orders(status);
                CREATE INDEX IF NOT EXISTS idx_orders_created_at    ON orders(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_orders_table_id      ON orders(table_id);
                CREATE INDEX IF NOT EXISTS idx_tables_owner_id      ON cafe_tables(owner_id);
                CREATE INDEX IF NOT EXISTS idx_feedback_owner_id    ON feedback(owner_id);
                CREATE INDEX IF NOT EXISTS idx_orders_owner_status  ON orders(owner_id, status);
            """)

            # ── CHECK constraints (skip if already present) ──────────────────
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'orders_status_check'
                    ) THEN
                        ALTER TABLE orders
                            ADD CONSTRAINT orders_status_check
                            CHECK (status IN ('pending','preparing','ready','completed','cancelled'));
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'feedback_rating_range'
                    ) THEN
                        ALTER TABLE feedback
                            ADD CONSTRAINT feedback_rating_range
                            CHECK (rating BETWEEN 1 AND 5);
                    END IF;
                END $$;
            """)

            # ── updated_at auto-maintenance trigger ──────────────────────────
            cur.execute("""
                CREATE OR REPLACE FUNCTION _cafe_set_updated_at()
                RETURNS TRIGGER LANGUAGE plpgsql AS $$
                BEGIN
                    NEW.updated_at = NOW();
                    RETURN NEW;
                END;
                $$;

                DROP TRIGGER IF EXISTS trg_orders_updated_at ON orders;
                CREATE TRIGGER trg_orders_updated_at
                    BEFORE UPDATE ON orders
                    FOR EACH ROW EXECUTE FUNCTION _cafe_set_updated_at();
            """)

    app.logger.info("Database schema, indexes, constraints and triggers ready.")

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
# Data access — owners
# ---------------------------------------------------------------------------

def load_owners() -> list[dict]:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, email, password_hash, cafe_name, google_place_id, is_active, created_at "
                    "FROM owners ORDER BY id"
                )
                return [
                    {
                        "id": row[0],
                        "username": row[1],
                        "email": row[2],
                        "passwordHash": row[3],
                        "cafeName": row[4] or "",
                        "googlePlaceId": row[5] or "",
                        "isActive": bool(row[6]) if row[6] is not None else True,
                        "createdAt": row[7].isoformat() if row[7] else "",
                    }
                    for row in cur.fetchall()
                ]
    owners = read_json(OWNERS_PATH, [])
    for o in owners:
        o.setdefault("isActive", True)
    return owners


def save_owners(owners: list[dict]) -> None:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                for owner in owners:
                    cur.execute(
                        """
                        INSERT INTO owners (id, username, email, password_hash, cafe_name, google_place_id, is_active, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            username = EXCLUDED.username,
                            email = EXCLUDED.email,
                            password_hash = EXCLUDED.password_hash,
                            cafe_name = EXCLUDED.cafe_name,
                            google_place_id = EXCLUDED.google_place_id,
                            is_active = EXCLUDED.is_active
                        """,
                        (
                            owner.get("id"),
                            owner["username"],
                            owner.get("email"),
                            owner.get("passwordHash", ""),
                            owner.get("cafeName", ""),
                            owner.get("googlePlaceId", ""),
                            owner.get("isActive", True),
                            owner.get("createdAt", datetime.now(timezone.utc).isoformat()),
                        ),
                    )
        return
    write_json(OWNERS_PATH, owners)


def create_owner_in_db(username: str, email: str | None, password_hash: str, cafe_name: str = "") -> dict:
    """Insert a new owner and return the full owner dict with DB-generated ID."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO owners (username, email, password_hash, cafe_name)
                VALUES (%s, %s, %s, %s)
                RETURNING id, created_at
                """,
                (username, email or None, password_hash, cafe_name),
            )
            row = cur.fetchone()
            return {
                "id": row[0],
                "username": username,
                "email": email,
                "passwordHash": password_hash,
                "cafeName": cafe_name,
                "googlePlaceId": "",
                "createdAt": row[1].isoformat(),
            }

# ---------------------------------------------------------------------------
# Data access — tables
# ---------------------------------------------------------------------------

def load_tables() -> list[dict]:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, owner_id, created_at FROM cafe_tables ORDER BY created_at"
                )
                return [
                    {
                        "id": row[0],
                        "name": row[1],
                        "ownerId": row[2],
                        "createdAt": row[3].isoformat() if row[3] else "",
                    }
                    for row in cur.fetchall()
                ]
    return read_json(TABLES_PATH, [])


def save_tables(tables: list[dict]) -> None:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM cafe_tables")
                existing = {row[0] for row in cur.fetchall()}
                new_ids = {t["id"] for t in tables}
                removed = existing - new_ids
                if removed:
                    cur.execute("DELETE FROM cafe_tables WHERE id = ANY(%s)", (list(removed),))
                for t in tables:
                    cur.execute(
                        """
                        INSERT INTO cafe_tables (id, name, owner_id, created_at)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
                        """,
                        (
                            t["id"],
                            t["name"],
                            t.get("ownerId"),
                            t.get("createdAt", datetime.now(timezone.utc).isoformat()),
                        ),
                    )
        return
    write_json(TABLES_PATH, tables)

# ---------------------------------------------------------------------------
# Data access — menu
# ---------------------------------------------------------------------------

def load_menu() -> dict:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT owner_id, data FROM menus")
                all_categories: list[dict] = []
                for owner_id, data in cur.fetchall():
                    for cat in (data or {}).get("categories", []):
                        cat_copy = dict(cat)
                        cat_copy["ownerId"] = owner_id
                        all_categories.append(cat_copy)
                return {"categories": all_categories}
    cached_menu = _get_cached_menu()
    if cached_menu is not None:
        return cached_menu
    menu = safe_read_json(MENU_PATH, {"categories": []})
    changed = False
    existing_ids: set[str] = set()
    for cat in menu.get("categories", []):
        if not cat.get("id"):
            cat["id"] = unique_id(normalize_id(cat.get("name", "category")), existing_ids)
            changed = True
        existing_ids.add(cat["id"])
    if changed:
        atomic_write_json(MENU_PATH, menu)
    _set_cached_menu(menu)
    return _clone_json_data(menu)


def save_menu(menu: dict) -> None:
    if USE_DB:
        by_owner: dict[int, list] = {}
        for cat in menu.get("categories", []):
            oid = cat.get("ownerId")
            if oid not in by_owner:
                by_owner[oid] = []
            cat_copy = {k: v for k, v in cat.items() if k != "ownerId"}
            by_owner[oid].append(cat_copy)
        with _get_conn() as conn:
            with conn.cursor() as cur:
                for oid, categories in by_owner.items():
                    cur.execute(
                        """
                        INSERT INTO menus (owner_id, data) VALUES (%s, %s)
                        ON CONFLICT (owner_id) DO UPDATE SET data = EXCLUDED.data
                        """,
                        (oid, Json({"categories": categories})),
                    )
        return
    atomic_write_json(MENU_PATH, menu)
    _set_cached_menu(menu)

# ---------------------------------------------------------------------------
# Data access — orders
# ---------------------------------------------------------------------------

def load_orders() -> list[dict]:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, owner_id, table_id, table_name, customer_name, "
                    "items, total, status, origin, created_at "
                    "FROM orders ORDER BY id"
                )
                return [
                    {
                        "id": row[0],
                        "ownerId": row[1],
                        "tableId": row[2],
                        "tableName": row[3],
                        "customerName": row[4],
                        "items": row[5] if isinstance(row[5], list) else [],
                        "total": float(row[6]) if row[6] is not None else 0.0,
                        "status": row[7] or "pending",
                        "origin": row[8] or "table",
                        "createdAt": row[9].isoformat() if row[9] else "",
                    }
                    for row in cur.fetchall()
                ]
    return read_json(ORDERS_PATH, [])


def save_orders(orders: list[dict]) -> None:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM orders")
                existing = {row[0] for row in cur.fetchall()}
                new_ids = {o["id"] for o in orders if isinstance(o.get("id"), int)}
                removed = existing - new_ids
                if removed:
                    cur.execute("DELETE FROM orders WHERE id = ANY(%s)", (list(removed),))
                for o in orders:
                    cur.execute(
                        """
                        INSERT INTO orders
                          (id, owner_id, table_id, table_name, customer_name,
                           items, total, status, origin, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            status = EXCLUDED.status,
                            items  = EXCLUDED.items,
                            total  = EXCLUDED.total
                        """,
                        (
                            o.get("id"),
                            o.get("ownerId"),
                            o.get("tableId"),
                            o.get("tableName"),
                            o.get("customerName", "Guest"),
                            Json(o.get("items", [])),
                            o.get("total", 0),
                            o.get("status", "pending"),
                            o.get("origin", "table"),
                            o.get("createdAt", datetime.now(timezone.utc).isoformat()),
                        ),
                    )
        return
    write_json(ORDERS_PATH, orders)


def place_order_in_db(order: dict) -> dict:
    """Insert a new order directly into DB and return with DB-generated ID."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO orders
                  (owner_id, table_id, table_name, customer_name,
                   items, total, status, origin, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    order.get("ownerId"),
                    order.get("tableId"),
                    order.get("tableName"),
                    order.get("customerName", "Guest"),
                    Json(order.get("items", [])),
                    order.get("total", 0),
                    order.get("status", "pending"),
                    order.get("origin", "table"),
                    order.get("createdAt", datetime.now(timezone.utc).isoformat()),
                ),
            )
            row = cur.fetchone()
            result = dict(order)
            result["id"] = row[0]
            return result


def _db_update_order_status(order_id: int, new_status: str) -> bool:
    """Efficiently update a single order's status in DB. Returns True if found."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE orders SET status = %s WHERE id = %s",
                (new_status, order_id),
            )
            return cur.rowcount > 0


def _db_get_order(order_id: int) -> dict | None:
    """Fetch a single order from DB by id."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, owner_id, table_id, table_name, customer_name, "
                "items, total, status, origin, created_at "
                "FROM orders WHERE id = %s",
                (order_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "ownerId": row[1],
                "tableId": row[2],
                "tableName": row[3],
                "customerName": row[4],
                "items": row[5] if isinstance(row[5], list) else [],
                "total": float(row[6]) if row[6] is not None else 0.0,
                "status": row[7] or "pending",
                "origin": row[8] or "table",
                "createdAt": row[9].isoformat() if row[9] else "",
            }


def _db_delete_order(order_id: int) -> bool:
    """Delete a single order from DB. Returns True if found."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM orders WHERE id = %s", (order_id,))
            return cur.rowcount > 0

# ---------------------------------------------------------------------------
# Data access — feedback
# ---------------------------------------------------------------------------

def load_feedback() -> list[dict]:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, owner_id, table_id, customer_name, rating, comment, created_at "
                    "FROM feedback ORDER BY id DESC"
                )
                return [
                    {
                        "id": row[0],
                        "ownerId": row[1],
                        "tableId": row[2],
                        "customerName": row[3],
                        "rating": row[4],
                        "comment": row[5] or "",
                        "createdAt": row[6].isoformat() if row[6] else "",
                    }
                    for row in cur.fetchall()
                ]
    return read_json(FEEDBACK_PATH, [])


def save_feedback_entry(entry: dict) -> dict:
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO feedback (owner_id, table_id, customer_name, rating, comment, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        entry.get("ownerId"),
                        entry.get("tableId"),
                        entry.get("customerName", "Guest"),
                        entry["rating"],
                        entry.get("comment", ""),
                        entry.get("createdAt", datetime.now(timezone.utc).isoformat()),
                    ),
                )
                row = cur.fetchone()
                result = dict(entry)
                result["id"] = row[0]
                return result
    feedbacks = read_json(FEEDBACK_PATH, [])
    entry["id"] = max((f.get("id", 0) for f in feedbacks), default=0) + 1
    feedbacks.append(entry)
    write_json(FEEDBACK_PATH, feedbacks)
    return entry

# ---------------------------------------------------------------------------
# Persistent "remember me" token system
# ---------------------------------------------------------------------------

_REMEMBER_COOKIE = "cafe_remember"
_REMEMBER_DAYS = 90

def _hash_token(raw: str) -> str:
    """SHA-256 hash a raw token string for safe DB storage."""
    import hashlib
    return hashlib.sha256(raw.encode()).hexdigest()


def create_remember_token(owner_id: int) -> str:
    """Create a persistent remember-me token, store it, and return the raw value."""
    raw = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw)
    expires = datetime.now(timezone.utc) + timedelta(days=_REMEMBER_DAYS)

    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                # Limit to 5 active tokens per owner to prevent abuse
                cur.execute(
                    "DELETE FROM remember_tokens WHERE owner_id = %s AND id NOT IN "
                    "(SELECT id FROM remember_tokens WHERE owner_id = %s ORDER BY created_at DESC LIMIT 4)",
                    (owner_id, owner_id),
                )
                cur.execute(
                    "INSERT INTO remember_tokens (owner_id, token_hash, expires_at) VALUES (%s, %s, %s)",
                    (owner_id, token_hash, expires),
                )
    else:
        tokens = read_json(TOKENS_PATH, [])
        # Prune expired + limit per owner
        now_iso = datetime.now(timezone.utc).isoformat()
        tokens = [t for t in tokens if t.get("expiresAt", "") > now_iso]
        owner_tokens = [t for t in tokens if t.get("ownerId") == owner_id]
        if len(owner_tokens) >= 5:
            oldest = sorted(owner_tokens, key=lambda t: t.get("createdAt", ""))[:len(owner_tokens) - 4]
            old_hashes = {t["tokenHash"] for t in oldest}
            tokens = [t for t in tokens if t.get("tokenHash") not in old_hashes]
        tokens.append({
            "ownerId": owner_id,
            "tokenHash": token_hash,
            "expiresAt": expires.isoformat(),
            "createdAt": datetime.now(timezone.utc).isoformat(),
        })
        write_json(TOKENS_PATH, tokens)

    return raw


def validate_remember_token(raw: str) -> dict | None:
    """Look up a raw token and return the owner dict if valid, else None."""
    if not raw:
        return None
    token_hash = _hash_token(raw)
    now = datetime.now(timezone.utc)

    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT owner_id, expires_at FROM remember_tokens WHERE token_hash = %s",
                    (token_hash,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                owner_id, expires_at = row[0], row[1]
                if expires_at and expires_at < now:
                    cur.execute("DELETE FROM remember_tokens WHERE token_hash = %s", (token_hash,))
                    return None
                # Fetch owner
                cur.execute(
                    "SELECT id, username, email, password_hash, cafe_name, google_place_id "
                    "FROM owners WHERE id = %s",
                    (owner_id,),
                )
                orow = cur.fetchone()
                if not orow:
                    return None
                return {
                    "id": orow[0], "username": orow[1], "email": orow[2],
                    "passwordHash": orow[3], "cafeName": orow[4] or "", "googlePlaceId": orow[5] or "",
                }
    else:
        tokens = read_json(TOKENS_PATH, [])
        now_iso = now.isoformat()
        entry = next(
            (t for t in tokens if t.get("tokenHash") == token_hash and t.get("expiresAt", "") > now_iso),
            None,
        )
        if not entry:
            return None
        owners = load_owners()
        return next((o for o in owners if o["id"] == entry["ownerId"]), None)


def revoke_remember_token(raw: str) -> None:
    """Delete a specific remember-me token (on logout)."""
    if not raw:
        return
    token_hash = _hash_token(raw)
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM remember_tokens WHERE token_hash = %s", (token_hash,))
    else:
        tokens = read_json(TOKENS_PATH, [])
        tokens = [t for t in tokens if t.get("tokenHash") != token_hash]
        write_json(TOKENS_PATH, tokens)


def revoke_all_tokens_for_owner(owner_id: int) -> None:
    """Revoke all remember-me tokens for an owner (e.g. password change)."""
    if USE_DB:
        with _get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM remember_tokens WHERE owner_id = %s", (owner_id,))
    else:
        tokens = read_json(TOKENS_PATH, [])
        tokens = [t for t in tokens if t.get("ownerId") != owner_id]
        write_json(TOKENS_PATH, tokens)


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
    return session.get("owner_username")


def logged_in_owner_id() -> int | None:
    return session.get("owner_id")


def login_required(view_func):
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
    return render_template("table_order.html", table=table,
                           cafe_name=cafe_name,
                           google_place_id=google_place_id)

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

        if owner and check_password_hash(owner["passwordHash"], password):
            _clear_failed_logins(ip)
            session.clear()
            session["owner_username"] = owner["username"]
            session["owner_id"] = owner["id"]
            session.permanent = True  # always keep session alive across browser restarts
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

        password_hash = generate_password_hash(password, method="scrypt")

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
        log_security("SIGNUP_SUCCESS", f"user={username!r}")
        return redirect(url_for("owner_dashboard"))

    return render_template("owner_signup.html")


@app.route("/owner/logout")
def owner_logout() -> Response:
    username = logged_in_owner()
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
            flash("Profile updated successfully.")

        elif action == "password":
            current_pw = str(request.form.get("current_password", ""))[:256]
            new_pw = str(request.form.get("new_password", ""))[:256]
            confirm_pw = str(request.form.get("confirm_password", ""))[:256]

            if not check_password_hash(owner["passwordHash"], current_pw):
                flash("Current password is incorrect.")
                return redirect(url_for("owner_profile"))

            if new_pw != confirm_pw:
                flash("New passwords do not match.")
                return redirect(url_for("owner_profile"))

            if not _is_strong_password(new_pw):
                flash("Password must be at least 8 characters with a letter and digit.")
                return redirect(url_for("owner_profile"))

            owner["passwordHash"] = generate_password_hash(new_pw, method="scrypt")
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
    table_id = str(payload.get("tableId", "")).strip()[:64] if payload.get("tableId") else None
    items = payload.get("items", [])

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
    return {"message": "Order placed successfully.", "order": order_record}, 201


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

    for o in orders:
        created = o.get("createdAt", "")[:10]
        daily[created] = round(daily[created] + float(o.get("total") or 0), 2)
        for it in o.get("items", []):
            item_counts[it.get("name", "?")] += it.get("quantity", 1)

    sorted_days = sorted(daily.keys())[-30:]
    revenue_by_day = [{"date": d, "revenue": daily[d]} for d in sorted_days]

    top_items = sorted(item_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_items_data = [{"name": n, "count": c} for n, c in top_items]

    total_revenue = round(sum(float(o.get("total") or 0) for o in orders), 2)
    total_orders = len(orders)
    avg_order = round(total_revenue / total_orders, 2) if total_orders else 0

    return {
        "revenueByDay": revenue_by_day,
        "topItems": top_items_data,
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

def _init_data_files() -> None:
    if not ORDERS_PATH.exists():
        write_json(ORDERS_PATH, [])
    if not OWNERS_PATH.exists():
        write_json(OWNERS_PATH, [])
    if not TABLES_PATH.exists():
        write_json(TABLES_PATH, [])
    if not MENU_PATH.exists():
        write_json(MENU_PATH, {"categories": []})
    if not FEEDBACK_PATH.exists():
        write_json(FEEDBACK_PATH, [])
    if not TOKENS_PATH.exists():
        write_json(TOKENS_PATH, [])


try:
    if USE_DB:
        _init_db()
    else:
        _init_data_files()
except Exception as exc:
    import sys as _sys
    print(f"WARNING: Could not initialise data store: {exc}", file=_sys.stderr, flush=True)
    if USE_DB:
        USE_DB = False
        print("WARNING: Falling back to JSON file storage.", file=_sys.stderr, flush=True)
        try:
            _init_data_files()
        except Exception as exc2:
            print(f"WARNING: Could not initialise JSON files either: {exc2}", file=_sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
