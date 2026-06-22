"""Centralised application configuration.

All environment-variable reads live here so the rest of the codebase
imports typed constants instead of sprinkling ``os.environ.get`` calls
throughout routes and services.

Fixes applied:
  Bug #4  — Duplicate SLOW_REQUEST_MS definition removed; single source of truth
              at module level, also exposed through FlaskConfig for app.config reads.
  Enhancement — SENTRY_DSN / SENTRY_TRACES_SAMPLE_RATE added.
  Enhancement — SESSION_COOKIE_NAME namespaced to avoid collisions with other apps.
"""
from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DATA_DIR")) if os.environ.get("DATA_DIR") else BASE_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)

IS_PRODUCTION = (
    os.environ.get("IS_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}
    or os.environ.get("FLASK_ENV") == "production"
    or os.environ.get("RAILWAY_ENVIRONMENT") is not None
    or os.environ.get("RENDER") is not None  # Render sets RENDER=true
)

APP_VERSION = (
    os.environ.get("APP_VERSION")
    or (os.environ.get("RAILWAY_GIT_COMMIT_SHA") or "")[:12]
    or (os.environ.get("RENDER_GIT_COMMIT") or "")[:12]
    or "dev"
)
APP_START_TIME: float = 0.0


# ── Database ──────────────────────────────────────────────────────────────────
def _coerce_db_url(raw: str) -> str:
    if raw.startswith("postgres://"):
        return raw.replace("postgres://", "postgresql://", 1)
    return raw


_RAW_DB_URL = _coerce_db_url(os.environ.get("DATABASE_URL", ""))
_ALLOW_SQLITE_IN_PROD = os.environ.get("ALLOW_SQLITE_IN_PRODUCTION", "").lower() in {"1", "true", "yes", "on"}

SQLALCHEMY_DATABASE_URI = (
    _RAW_DB_URL if _RAW_DB_URL else f"sqlite:///{DATA_DIR / 'app.db'}"
)

# Issue 1: Raise pool defaults so the app survives traffic bursts.
# total_connections = pool_size + max_overflow = 25 + 10 = 35 per process.
# With WEB_CONCURRENCY=4, peak demand is 4 × 35 = 140 — well within the
# Railway Postgres 500-connection limit. Tune via env vars for smaller DBs.
_DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "25"))      # was 5
_DB_MAX_OVERFLOW = int(os.environ.get("DB_MAX_OVERFLOW", "10")) # was 5
_DB_POOL_TIMEOUT = int(os.environ.get("DB_POOL_TIMEOUT", "30")) # was 20
_DB_STATEMENT_TIMEOUT_MS = int(os.environ.get("DB_STATEMENT_TIMEOUT_MS", "30000"))
_DB_CONNECT_TIMEOUT_S = int(os.environ.get("DB_CONNECT_TIMEOUT_S", "10"))

# Issue 6: slow-query threshold for the SQLAlchemy event-listener (separate
# from SLOW_REQUEST_MS which measures the full HTTP round-trip including
# Python serialisation).  200 ms is a sensible default for OLTP workloads;
# lower to 50 ms in staging to surface N+1 queries early.
SLOW_QUERY_MS: int = int(os.environ.get("SLOW_QUERY_MS", "200") or "200")

if _RAW_DB_URL:
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 1800,
        "pool_size": _DB_POOL_SIZE,
        "max_overflow": _DB_MAX_OVERFLOW,
        "pool_timeout": _DB_POOL_TIMEOUT,
        "connect_args": {
            "application_name": "cafe-ordering",
            "connect_timeout": _DB_CONNECT_TIMEOUT_S,
            "options": f"-c statement_timeout={_DB_STATEMENT_TIMEOUT_MS}ms",
        },
    }
else:
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

REDIS_URL: str | None = os.environ.get("REDIS_URL") or None
CDN_URL: str = (os.environ.get("CDN_URL") or "").rstrip("/")
RQ_REDIS_URL: str | None = os.environ.get("RQ_REDIS_URL") or REDIS_URL
RQ_DEFAULT_TIMEOUT: int = int(os.environ.get("RQ_DEFAULT_TIMEOUT", "300"))

SECRET_KEY = os.environ.get("SECRET_KEY") or os.environ.get("SESSION_SECRET", "")
TRUSTED_PROXIES = max(1, int(os.environ.get("TRUSTED_PROXIES", "1") or "1"))

# ── Single source of truth for SLOW_REQUEST_MS (Bug #4 fix) ──────────────────
SLOW_REQUEST_MS: int = int(os.environ.get("SLOW_REQUEST_MS", "1500") or "1500")

MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.sendgrid.net")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes", "on"}
MAIL_USERNAME = os.environ.get("MAIL_USERNAME") or ("apikey" if os.environ.get("SENDGRID_API_KEY") else None)
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD") or os.environ.get("SENDGRID_API_KEY")
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")

RATE_LIMIT_STORAGE_URI = REDIS_URL or "memory://"
IDEMPOTENCY_TTL_SECONDS = int(os.environ.get("IDEMPOTENCY_TTL_SECONDS", "86400") or "86400")

SESSION_TYPE = "redis" if REDIS_URL else "filesystem"
SESSION_PERMANENT = True
SESSION_USE_SIGNER = True
SESSION_KEY_PREFIX = "cafe:session:"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_FILE_DIR = str(DATA_DIR / ".flask_sessions")

# ── Sentry error tracking ─────────────────────────────────────────────────────
SENTRY_DSN: str = os.environ.get("SENTRY_DSN", "")
SENTRY_TRACES_SAMPLE_RATE: float = float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.05"))
SENTRY_PROFILES_SAMPLE_RATE: float = float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "0.01"))

CSP: dict = {
    "default-src": "'self'",
    "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
    "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
    "img-src": [
        "'self'", "data:", "https://image.pollinations.ai",
        "https://*.unsplash.com", "https://images.unsplash.com",
        "https://*.googleusercontent.com", "blob:",
    ],
    "connect-src": ["'self'", "https://image.pollinations.ai"],
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri": "'self'",
}


class FlaskConfig:
    """Flask config dict — consumed by ``app.config.from_object``."""

    SECRET_KEY = SECRET_KEY
    # Namespaced cookie name avoids collisions when multiple apps run on the same domain
    SESSION_COOKIE_NAME = "cafe_session"
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
    SESSION_TYPE = SESSION_TYPE
    SESSION_PERMANENT = SESSION_PERMANENT
    SESSION_USE_SIGNER = SESSION_USE_SIGNER
    SESSION_KEY_PREFIX = SESSION_KEY_PREFIX
    SESSION_FILE_DIR = SESSION_FILE_DIR
    # Issue 4: Tell Flask/Werkzeug to send long-lived Cache-Control headers for
    # static files in production (1 year). Cache-busting happens via the ?v=
    # query parameter appended by _safe_url_for(). Zero in development so
    # changes are visible immediately without a hard-refresh.
    SEND_FILE_MAX_AGE_DEFAULT = 31_536_000 if IS_PRODUCTION else 0
    # Expose slow-request threshold to app.config (Bug #4 fix — single definition)
    SLOW_REQUEST_MS = SLOW_REQUEST_MS
    # Issue 6: expose slow-query threshold so blueprints can read app.config
    SLOW_QUERY_MS = SLOW_QUERY_MS
    # Sentry
    SENTRY_DSN = SENTRY_DSN
    SENTRY_TRACES_SAMPLE_RATE = SENTRY_TRACES_SAMPLE_RATE
    STRIPE_SECRET_KEY = STRIPE_SECRET_KEY
    STRIPE_PRICE_STARTER = STRIPE_PRICE_STARTER
    STRIPE_PRICE_GROWTH = STRIPE_PRICE_GROWTH
    STRIPE_PRICE_PRO = STRIPE_PRICE_PRO
    STRIPE_CURRENCY = STRIPE_CURRENCY
    GEMINI_API_KEY = GEMINI_API_KEY


BILLING_STEPUP_REFUND_THRESHOLD = int(os.getenv("BILLING_STEPUP_REFUND_THRESHOLD", "500"))
BILLING_STEPUP_VOID_THRESHOLD = int(os.getenv("BILLING_STEPUP_VOID_THRESHOLD", "2000"))
BILLING_STEPUP_TTL_SECONDS = int(os.getenv("BILLING_STEPUP_TTL_SECONDS", "300"))
BILLING_REFUND_DAILY_CAP_PCT = int(os.getenv("BILLING_REFUND_DAILY_CAP_PCT", "30"))
BILLING_REFUND_VELOCITY_PER_HOUR = int(os.getenv("BILLING_REFUND_VELOCITY_PER_HOUR", "20"))
BILLING_DRAWER_VARIANCE_ALERT_PCT = int(os.getenv("BILLING_DRAWER_VARIANCE_ALERT_PCT", "2"))
BILLING_ENCRYPTION_KEY = os.getenv("BILLING_ENCRYPTION_KEY", "")

EXPORTS_MAX_ROWS = int(os.getenv("EXPORTS_MAX_ROWS", "50000"))
EXPORTS_RATE_LIMIT = os.getenv("EXPORTS_RATE_LIMIT", "30/hour")

WEBHOOK_MAX_ATTEMPTS = int(os.getenv("WEBHOOK_MAX_ATTEMPTS", "8"))
WEBHOOK_BASE_BACKOFF_SECONDS = int(os.getenv("WEBHOOK_BASE_BACKOFF_SECONDS", "5"))
WEBHOOK_MAX_BACKOFF_SECONDS = int(os.getenv("WEBHOOK_MAX_BACKOFF_SECONDS", "3600"))
WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10"))
WEBHOOK_POLL_SECONDS = int(os.getenv("WEBHOOK_POLL_SECONDS", "5"))
WEBHOOK_BATCH_SIZE = int(os.getenv("WEBHOOK_BATCH_SIZE", "10"))
WEBHOOK_SIGNATURE_HEADER = os.getenv("WEBHOOK_SIGNATURE_HEADER", "X-Cafe-Signature")
WEBHOOK_TIMESTAMP_HEADER = os.getenv("WEBHOOK_TIMESTAMP_HEADER", "X-Cafe-Timestamp")
DISABLE_WEBHOOK_WORKER = os.getenv("DISABLE_WEBHOOK_WORKER", "").lower() in {"1", "true", "yes"}

ALERT_SLACK_WEBHOOK = os.getenv("ALERT_SLACK_WEBHOOK", "")
ALERT_DISCORD_WEBHOOK = os.getenv("ALERT_DISCORD_WEBHOOK", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))

ERROR_LOG_MAX_BYTES = int(os.getenv("ERROR_LOG_MAX_BYTES", "5242880"))
ERROR_INMEM_RING_MAX = int(os.getenv("ERROR_INMEM_RING_MAX", "100"))

BACKUP_GPG_PASSPHRASE = os.getenv("BACKUP_GPG_PASSPHRASE", "")
BACKUP_UPLOAD_URL = os.getenv("BACKUP_UPLOAD_URL", "")
BACKUP_UPLOAD_AUTH_HEADER = os.getenv("BACKUP_UPLOAD_AUTH_HEADER", "")
BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "14"))
BACKUP_LABEL = os.getenv("BACKUP_LABEL", "cafe")

# ── Stripe subscription pricing ───────────────────────────────────────────────
STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_STARTER: str = os.getenv("STRIPE_PRICE_STARTER", "")
STRIPE_PRICE_GROWTH: str = os.getenv("STRIPE_PRICE_GROWTH", "")
STRIPE_PRICE_PRO: str = os.getenv("STRIPE_PRICE_PRO", "")
STRIPE_CURRENCY: str = os.getenv("STRIPE_CURRENCY", "gbp").lower()

CURRENCY_SYMBOLS: dict = {
    "gbp": "£",
    "usd": "$",
    "eur": "€",
    "inr": "₹",
    "aud": "A$",
    "cad": "C$",
    "sgd": "S$",
    "aed": "د.إ",
    "nzd": "NZ$",
}

# ── Gemini AI ─────────────────────────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

FEATURE_NEW_CHECKOUT = os.getenv("FEATURE_NEW_CHECKOUT", "").lower() in {"1", "true", "yes", "on"}
FEATURE_AI_SUGGESTIONS = os.getenv("FEATURE_AI_SUGGESTIONS", "").lower() in {"1", "true", "yes", "on"}
FEATURE_ANALYTICS_V2 = os.getenv("FEATURE_ANALYTICS_V2", "").lower() in {"1", "true", "yes", "on"}

RQ_QUEUE_NAME = os.getenv("RQ_QUEUE_NAME", "default")
OPS_HEALTH_TOKEN = os.getenv("OPS_HEALTH_TOKEN", "")
OWNER_SIGNUP_MODE = os.getenv("OWNER_SIGNUP_MODE", "approval")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")

VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_CLAIM_EMAIL = os.getenv("VAPID_CLAIM_EMAIL", "mailto:support@example.com")

SECURITY_CONTACT = os.getenv("SECURITY_CONTACT", "mailto:security@example.com")

CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5"))
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = float(os.getenv("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "30"))


def feature_enabled(name: str) -> bool:
    """Check if a feature flag is enabled by name."""
    import sys as _sys
    attr_name = f"FEATURE_{name.upper().replace('-', '_')}"
    return bool(getattr(_sys.modules[__name__], attr_name, False))
