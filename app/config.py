"""Centralised application configuration.

All environment-variable reads live here so the rest of the codebase
imports typed constants instead of sprinkling ``os.environ.get`` calls
throughout routes and services.
"""
from __future__ import annotations

import os
import sys
from datetime import timedelta
from pathlib import Path

# ── Ensure project root is on sys.path for lib_* imports ─────────────────────
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

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

# ── CDN / asset hosting ───────────────────────────────────────────────────────
# When CDN_URL is set (e.g. "https://cdn.example.com"), static asset URLs are
# rewritten to point at the CDN. Leave empty to serve assets from the origin.
CDN_URL: str = (os.environ.get("CDN_URL") or "").rstrip("/")

# ── RQ background worker ───────────────────────────────────────────────────────
# RQ_REDIS_URL defaults to REDIS_URL so no extra env var is needed in most cases.
RQ_REDIS_URL: str | None = os.environ.get("RQ_REDIS_URL") or REDIS_URL
RQ_DEFAULT_TIMEOUT: int = int(os.environ.get("RQ_DEFAULT_TIMEOUT", "300"))

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


# ══════════════════════════════════════════════════════════════════════════════
# Additional configuration variables
# ══════════════════════════════════════════════════════════════════════════════

# Billing security thresholds
BILLING_STEPUP_REFUND_THRESHOLD = int(os.getenv("BILLING_STEPUP_REFUND_THRESHOLD", "500"))
BILLING_STEPUP_VOID_THRESHOLD = int(os.getenv("BILLING_STEPUP_VOID_THRESHOLD", "2000"))
BILLING_STEPUP_TTL_SECONDS = int(os.getenv("BILLING_STEPUP_TTL_SECONDS", "300"))
BILLING_REFUND_DAILY_CAP_PCT = int(os.getenv("BILLING_REFUND_DAILY_CAP_PCT", "30"))
BILLING_REFUND_VELOCITY_PER_HOUR = int(os.getenv("BILLING_REFUND_VELOCITY_PER_HOUR", "20"))
BILLING_DRAWER_VARIANCE_ALERT_PCT = int(os.getenv("BILLING_DRAWER_VARIANCE_ALERT_PCT", "2"))
BILLING_ENCRYPTION_KEY = os.getenv("BILLING_ENCRYPTION_KEY", "")

# Export limits and rate limiting
EXPORTS_MAX_ROWS = int(os.getenv("EXPORTS_MAX_ROWS", "50000"))
EXPORTS_RATE_LIMIT = os.getenv("EXPORTS_RATE_LIMIT", "30/hour")

# Webhook retry queue configuration
WEBHOOK_MAX_ATTEMPTS = int(os.getenv("WEBHOOK_MAX_ATTEMPTS", "8"))
WEBHOOK_BASE_BACKOFF_SECONDS = int(os.getenv("WEBHOOK_BASE_BACKOFF_SECONDS", "5"))
WEBHOOK_MAX_BACKOFF_SECONDS = int(os.getenv("WEBHOOK_MAX_BACKOFF_SECONDS", "3600"))
WEBHOOK_TIMEOUT_SECONDS = int(os.getenv("WEBHOOK_TIMEOUT_SECONDS", "10"))
WEBHOOK_POLL_SECONDS = int(os.getenv("WEBHOOK_POLL_SECONDS", "5"))
WEBHOOK_BATCH_SIZE = int(os.getenv("WEBHOOK_BATCH_SIZE", "10"))
WEBHOOK_SIGNATURE_HEADER = os.getenv("WEBHOOK_SIGNATURE_HEADER", "X-Cafe-Signature")
WEBHOOK_TIMESTAMP_HEADER = os.getenv("WEBHOOK_TIMESTAMP_HEADER", "X-Cafe-Timestamp")
DISABLE_WEBHOOK_WORKER = os.getenv("DISABLE_WEBHOOK_WORKER", "").lower() in {"1", "true", "yes"}

# Alerting hub configuration
ALERT_SLACK_WEBHOOK = os.getenv("ALERT_SLACK_WEBHOOK", "")
ALERT_DISCORD_WEBHOOK = os.getenv("ALERT_DISCORD_WEBHOOK", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))

# Error tracking
ERROR_LOG_MAX_BYTES = int(os.getenv("ERROR_LOG_MAX_BYTES", "5242880"))
ERROR_INMEM_RING_MAX = int(os.getenv("ERROR_INMEM_RING_MAX", "100"))

# Backup configuration
BACKUP_GPG_PASSPHRASE = os.getenv("BACKUP_GPG_PASSPHRASE", "")
BACKUP_UPLOAD_URL = os.getenv("BACKUP_UPLOAD_URL", "")
BACKUP_UPLOAD_AUTH_HEADER = os.getenv("BACKUP_UPLOAD_AUTH_HEADER", "")
BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "14"))
BACKUP_LABEL = os.getenv("BACKUP_LABEL", "cafe")

# Feature flags
FEATURE_NEW_CHECKOUT = os.getenv("FEATURE_NEW_CHECKOUT", "").lower() in {"1", "true", "yes", "on"}
FEATURE_AI_SUGGESTIONS = os.getenv("FEATURE_AI_SUGGESTIONS", "").lower() in {"1", "true", "yes", "on"}
FEATURE_ANALYTICS_V2 = os.getenv("FEATURE_ANALYTICS_V2", "").lower() in {"1", "true", "yes", "on"}

# RQ configuration
RQ_QUEUE_NAME = os.getenv("RQ_QUEUE_NAME", "default")

# CDN configuration — already defined above as CDN_URL

# Operational health token
OPS_HEALTH_TOKEN = os.getenv("OPS_HEALTH_TOKEN", "")

# Owner signup mode
OWNER_SIGNUP_MODE = os.getenv("OWNER_SIGNUP_MODE", "approval")

# Twilio (SMS)
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")

# VAPID keys for push notifications
VAPID_PUBLIC_KEY = os.getenv("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.getenv("VAPID_PRIVATE_KEY", "")
VAPID_CLAIM_EMAIL = os.getenv("VAPID_CLAIM_EMAIL", "mailto:support@example.com")

# Performance tuning
SLOW_REQUEST_MS = int(os.getenv("SLOW_REQUEST_MS", "1500"))

# Security contact
SECURITY_CONTACT = os.getenv("SECURITY_CONTACT", "mailto:security@example.com")


def feature_enabled(name: str) -> bool:
    """Check if a feature flag is enabled by name (e.g. 'new_checkout')."""
    import sys as _sys
    attr_name = f"FEATURE_{name.upper().replace('-', '_')}"
    return bool(getattr(_sys.modules[__name__], attr_name, False))
