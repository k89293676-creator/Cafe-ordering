"""Centralised application configuration.

All environment-variable reads live here so the rest of the codebase
imports typed constants instead of sprinkling ``os.environ.get`` calls
throughout routes and services.
"""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # project root
DATA_DIR = Path(os.environ.get("DATA_DIR")) if os.environ.get("DATA_DIR") else BASE_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)

IS_PRODUCTION = (
    os.environ.get("IS_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}
    or os.environ.get("FLASK_ENV") == "production"
    or os.environ.get("RAILWAY_ENVIRONMENT") is not None
)

APP_VERSION = (
    os.environ.get("APP_VERSION")
    or os.environ.get("RAILWAY_GIT_COMMIT_SHA", "dev")[:12]
)
APP_START_TIME: float = 0.0  # set in create_app()

# ── Database ─────────────────────────────────────────────────────────────────
def _coerce_db_url(raw: str) -> str:
    if raw.startswith("postgres://"):
        return raw.replace("postgres://", "postgresql://", 1)
    return raw


_RAW_DB_URL = _coerce_db_url(os.environ.get("DATABASE_URL", ""))
_ALLOW_SQLITE_IN_PROD = os.environ.get("ALLOW_SQLITE_IN_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}

SQLALCHEMY_DATABASE_URI = (
    _RAW_DB_URL if _RAW_DB_URL else f"sqlite:///{DATA_DIR / 'app.db'}"
)

# Connection pool tuning — sized for a gunicorn/gevent worker. Override via env.
SQLALCHEMY_ENGINE_OPTIONS: dict = (
    {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "10")),
        "pool_timeout": int(os.environ.get("DB_POOL_TIMEOUT", "30")),
        # Named connect_args for PgBouncer in transaction mode:
        # application_name helps trace connections in pg_stat_activity.
        "connect_args": {"application_name": "cafe-ordering"},
    }
    if _RAW_DB_URL
    else {"pool_pre_ping": True}
)

REDIS_URL: str | None = os.environ.get("REDIS_URL") or None

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET", "")
TRUSTED_PROXIES = max(1, int(os.environ.get("TRUSTED_PROXIES", "1") or "1"))
SLOW_REQUEST_MS = int(os.environ.get("SLOW_REQUEST_MS", "1500") or "1500")

# ── Mail (SendGrid / SMTP) ────────────────────────────────────────────────────
MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.sendgrid.net")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
MAIL_USERNAME = os.environ.get("MAIL_USERNAME") or ("apikey" if os.environ.get("SENDGRID_API_KEY") else None)
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD") or os.environ.get("SENDGRID_API_KEY")
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_STORAGE_URI = REDIS_URL or "memory://"

# ── Idempotency / caching ─────────────────────────────────────────────────────
IDEMPOTENCY_TTL_SECONDS = int(os.environ.get("IDEMPOTENCY_TTL_SECONDS", "86400") or "86400")

# ── Content Security Policy ───────────────────────────────────────────────────
CSP: dict = {
    "default-src": "'self'",
    "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
    "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
    "img-src": [
        "'self'",
        "data:",
        "https://image.pollinations.ai",
        "https://*.unsplash.com",
        "https://images.unsplash.com",
        "https://*.googleusercontent.com",
        "blob:",
    ],
    "connect-src": ["'self'", "https://image.pollinations.ai"],
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri": "'self'",
}


class FlaskConfig:
    """Flask config dict — consumed by ``app.config.from_object``."""

    SECRET_KEY = SECRET_KEY
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = IS_PRODUCTION
    REMEMBER_COOKIE_DURATION = timedelta(days=30)
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = IS_PRODUCTION
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = SQLALCHEMY_ENGINE_OPTIONS
    MAIL_SERVER = MAIL_SERVER
    MAIL_PORT = MAIL_PORT
    MAIL_USE_TLS = MAIL_USE_TLS
    MAIL_USERNAME = MAIL_USERNAME
    MAIL_PASSWORD = MAIL_PASSWORD
    MAIL_DEFAULT_SENDER = MAIL_DEFAULT_SENDER
    COMPRESS_ALGORITHM = ["br", "gzip", "deflate"]
    COMPRESS_BR_LEVEL = 4
    COMPRESS_LEVEL = 6
    COMPRESS_MIN_SIZE = 500
