from __future__ import annotations

import base64
import csv
import io
import hashlib
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
    make_response,
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
ADMIN_KEYS_PATH = DATA_DIR / "admin_keys.json"

_orders_lock = threading.Lock()
_menu_lock = threading.Lock()
_tables_lock = threading.Lock()

# Boot time + version are surfaced via /health for uptime tracking on Railway.
APP_START_TIME = time.time()
APP_VERSION = os.environ.get("APP_VERSION") or os.environ.get("RAILWAY_GIT_COMMIT_SHA", "dev")[:12]

app = Flask(__name__, static_folder="static", template_folder="templates")
# Number of trusted reverse-proxy hops in front of this app. Behind Railway's
# edge the default of 1 is correct; if you place an extra L7 proxy / CDN in
# front (e.g. Cloudflare → Railway → app) bump TRUSTED_PROXIES to 2 so
# X-Forwarded-* headers are honoured for the right hop. Keeping this in env
# is what lets Talisman's HSTS + secure-cookie checks work behind the proxy.
_trusted_proxies = max(1, int(os.environ.get("TRUSTED_PROXIES", "1") or "1"))
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=_trusted_proxies,
    x_proto=_trusted_proxies,
    x_host=_trusted_proxies,
    x_prefix=_trusted_proxies,
)

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
    # Connection pool tuning. ``pool_pre_ping`` recycles dead sockets that
    # cloud Postgres providers (Railway, Render, Neon, …) silently drop after
    # a few minutes of idleness, which would otherwise surface as
    # ``OperationalError: server closed the connection unexpectedly`` on the
    # first request after a quiet period. Sized for a single gunicorn worker
    # with gevent — bump ``pool_size`` if you scale workers/threads up.
    SQLALCHEMY_ENGINE_OPTIONS=(
        {
            "pool_pre_ping": True,
            "pool_recycle": 1800,
            "pool_size": int(os.environ.get("DB_POOL_SIZE", "10")),
            "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", "10")),
            "pool_timeout": int(os.environ.get("DB_POOL_TIMEOUT", "30")),
        }
        if _raw_db_url
        else {"pool_pre_ping": True}
    ),
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

# ---------------------------------------------------------------------------
# In-process runtime primitives — no Redis/external services required.
# ---------------------------------------------------------------------------
from lib_runtime import (  # noqa: E402  (import after configure_logging on purpose)
    BackgroundTaskQueue,
    IdempotencyCache,
    ResponseCache,
    feature_enabled,
)
from lib_billing import (  # noqa: E402
    VALID_PAYMENT_METHODS,
    compute_bill_totals,
    compute_settlement,
    next_invoice_number,
    normalise_payments,
    summarise_payment_breakdown,
)
from lib_payments import (  # noqa: E402
    PROVIDER_GUIDES,
    PROVIDER_LABELS,
    SUPPORTED_PROVIDERS,
    PaymentProviderError,
    build_provider,
    decrypt_secret,
    detect_mode_from_key,
    encrypt_secret,
    mask_secret,
)
from lib_aggregators import (  # noqa: E402
    PLATFORM_GUIDES,
    PLATFORM_LABELS,
    SUPPORTED_PLATFORMS,
    AggregatorError,
    build_aggregator,
)

bg_tasks = BackgroundTaskQueue(name="cafe-bg")
idem_cache = IdempotencyCache(
    ttl_seconds=int(os.environ.get("IDEMPOTENCY_TTL_SECONDS", "86400") or "86400")
)
response_cache = ResponseCache()

# ---------------------------------------------------------------------------
# Sentry error tracking (optional). Enabled when SENTRY_DSN is configured.
# Lazily imported so the dependency stays optional in dev / CI.
# ---------------------------------------------------------------------------
_SENTRY_DSN = os.environ.get("SENTRY_DSN", "").strip()
if _SENTRY_DSN:
    try:
        import sentry_sdk  # type: ignore
        from sentry_sdk.integrations.flask import FlaskIntegration  # type: ignore
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration  # type: ignore

        sentry_sdk.init(
            dsn=_SENTRY_DSN,
            integrations=[FlaskIntegration(), SqlalchemyIntegration()],
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.0") or 0.0),
            profiles_sample_rate=float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "0.0") or 0.0),
            send_default_pii=False,
            release=APP_VERSION,
            environment=("production" if IS_PRODUCTION else "development"),
        )
        app.logger.info("Sentry initialised (release=%s)", APP_VERSION)
    except Exception as _sentry_err:  # pragma: no cover — Sentry must never crash the app
        app.logger.warning("Sentry init failed: %s", _sentry_err)

app.config.setdefault("COMPRESS_ALGORITHM", ["br", "gzip", "deflate"])
app.config.setdefault("COMPRESS_BR_LEVEL", 4)
app.config.setdefault("COMPRESS_LEVEL", 6)
app.config.setdefault("COMPRESS_MIN_SIZE", 500)
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
    # Multi-tenant onboarding & plan controls (managed via the multi_tenant
    # blueprint).  ``approval_status`` is the single source of truth for
    # whether an account may sign in: ``pending`` accounts are blocked, even
    # if ``is_active`` is true.  Plan limits override the per-tier defaults
    # in ``DEFAULT_PLAN_LIMITS`` when set; ``None`` means "use tier default";
    # ``0`` means "unlimited".
    approval_status = db.Column(db.Text, default="active", server_default="active", nullable=False)
    plan_tier = db.Column(db.Text, default="free", server_default="free", nullable=False)
    max_tables = db.Column(db.Integer, nullable=True)
    max_menu_items = db.Column(db.Integer, nullable=True)
    monthly_order_limit = db.Column(db.Integer, nullable=True)
    trial_ends_at = db.Column(db.DateTime(timezone=True), nullable=True)
    notes = db.Column(db.Text, default="", server_default="")
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
    # Billing config (per-owner). All optional — defaults make billing
    # work as a simple pay-what's-shown system, no tax or service charge.
    tax_rate_percent = db.Column(db.Numeric(5, 2), default=0, server_default="0")
    tax_label = db.Column(db.Text, default="GST", server_default="GST")
    gstin = db.Column(db.Text, default="", server_default="")
    service_charge_percent = db.Column(db.Numeric(5, 2), default=0, server_default="0")
    invoice_prefix = db.Column(db.Text, default="INV", server_default="INV")
    invoice_seq = db.Column(db.Integer, default=0, server_default="0")
    billing_address = db.Column(db.Text, default="", server_default="")
    billing_phone = db.Column(db.Text, default="", server_default="")
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class BillingLog(db.Model):
    """Append-only audit log for every billing action (settle / void /
    refund / discount adjustment / tax change).

    Read by /owner/billing/logs to give the owner a tamper-evident trail
    of who did what — essential for end-of-day cash reconciliation and
    for resolving disputes ('the customer says they paid but the system
    says unpaid'). Indexed on (owner_id, created_at desc) for fast
    paginated reads even after months of activity."""

    __tablename__ = "billing_logs"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True, index=True)
    invoice_number = db.Column(db.Text, default="")
    action = db.Column(db.Text, nullable=False)  # settled, voided, refunded, adjusted
    actor_owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    actor_username = db.Column(db.Text, default="")
    amount = db.Column(db.Numeric(10, 2), default=0)
    payment_method = db.Column(db.Text, default="")
    reason = db.Column(db.Text, default="")
    payload = db.Column(db.JSON, default=dict)  # full snapshot for forensics
    ip = db.Column(db.Text, default="")
    request_id = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), index=True)


class PaymentProviderCredential(db.Model):
    """Per-owner payment-gateway credentials.

    Owners configure their own Stripe / Razorpay keys at
    ``/owner/billing/payment-methods``. Secret values (``secret_key`` and
    ``webhook_secret``) are stored encrypted via ``lib_payments.encrypt_secret``;
    they never leave the database in plaintext after the initial save.
    Only one credential per (owner_id, provider) pair is allowed."""

    __tablename__ = "payment_credentials"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    provider = db.Column(db.Text, nullable=False)  # 'stripe' | 'razorpay'
    display_name = db.Column(db.Text, default="")
    public_key = db.Column(db.Text, default="")  # safe to read back as plaintext
    secret_key_enc = db.Column(db.Text, default="")  # encrypted
    webhook_secret_enc = db.Column(db.Text, default="")  # encrypted
    mode = db.Column(db.Text, default="test", server_default="test")  # 'test' | 'live'
    is_active = db.Column(db.Boolean, default=True, server_default="true")
    is_default = db.Column(db.Boolean, default=False, server_default="false")
    last_tested_at = db.Column(db.DateTime(timezone=True))
    last_test_status = db.Column(db.Text, default="")
    last_test_message = db.Column(db.Text, default="")
    verified_at = db.Column(db.DateTime(timezone=True))  # last successful test
    verified_fingerprint = db.Column(db.Text, default="")  # SHA-256 of verified secret
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                           onupdate=db.func.now())
    __table_args__ = (
        db.UniqueConstraint("owner_id", "provider", name="uq_payment_owner_provider"),
    )


class WebhookEventLog(db.Model):
    """Idempotency table for inbound provider webhooks.

    Providers retry until they get a 2xx — for some events (Stripe in
    particular) they will deliver the same event multiple times even
    after a successful response. We MUST refuse to settle a bill twice,
    so every event id is recorded once and re-deliveries become no-ops.
    Indexed on (provider, event_id) so the lookup at the top of the
    webhook handler is O(1)."""

    __tablename__ = "webhook_events"
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.Text, nullable=False)
    event_id = db.Column(db.Text, nullable=False)  # provider's event id (or hash)
    intent_id = db.Column(db.Text, default="", index=True)
    event_type = db.Column(db.Text, default="")
    received_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    processed = db.Column(db.Boolean, default=False, server_default="false")
    __table_args__ = (
        db.UniqueConstraint("provider", "event_id", name="uq_webhook_provider_event"),
    )


class OnlinePayment(db.Model):
    """Individual online-payment attempts against an Order.

    One Order may have several attempts (failed UPI, retried card, etc.)
    so we keep them all and use the latest succeeded one to settle. The
    ``raw`` JSON column captures the provider response for forensics —
    chargebacks always require this evidence."""

    __tablename__ = "online_payments"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    provider = db.Column(db.Text, nullable=False)
    intent_id = db.Column(db.Text, nullable=False, index=True)
    amount = db.Column(db.Numeric(10, 2), default=0)
    currency = db.Column(db.Text, default="INR", server_default="INR")
    status = db.Column(db.Text, default="pending", server_default="pending")
    # pending | succeeded | failed | refunded | cancelled
    customer_email = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    error_message = db.Column(db.Text, default="")
    raw = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                           onupdate=db.func.now())


class AggregatorPlatformCredential(db.Model):
    """Per-owner Swiggy/Zomato/Uber Eats partner credentials.

    Stored encrypted at rest (Fernet) — same encryption helpers as
    PaymentProviderCredential. The ``merchant_id`` (Swiggy Restaurant
    ID / Zomato res_id / Uber Eats Store UUID) is plaintext because
    the partner needs us to echo it back in API calls and it isn't
    secret on its own."""
    __tablename__ = "aggregator_credentials"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), index=True, nullable=False)
    platform = db.Column(db.Text, nullable=False)  # 'swiggy' | 'zomato' | 'ubereats'
    display_name = db.Column(db.Text, default="")
    api_key = db.Column(db.Text, default="")              # plaintext (often public-ish)
    secret_enc = db.Column(db.Text, default="")           # encrypted
    webhook_secret_enc = db.Column(db.Text, default="")   # encrypted
    merchant_id = db.Column(db.Text, default="")
    mode = db.Column(db.Text, default="test", server_default="test")
    is_active = db.Column(db.Boolean, default=True, server_default="true")
    auto_accept = db.Column(db.Boolean, default=False, server_default="false")
    last_tested_at = db.Column(db.DateTime(timezone=True))
    last_test_status = db.Column(db.Text, default="")
    last_test_message = db.Column(db.Text, default="")
    verified_at = db.Column(db.DateTime(timezone=True))
    verified_fingerprint = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                           onupdate=db.func.now())
    __table_args__ = (
        db.UniqueConstraint("owner_id", "platform", name="uq_aggregator_owner_platform"),
    )


class AggregatorOrder(db.Model):
    """Mirror of an aggregator-side order, linked to an internal Order row.

    The aggregator pushes a webhook with its own ``external_order_id``;
    we create a local ``Order`` for the kitchen + an ``AggregatorOrder``
    bridge row so reconciliation reports can group by platform.
    Lookup index on (platform, external_order_id) makes the webhook
    handler O(1)."""
    __tablename__ = "aggregator_orders"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("owners.id"), index=True, nullable=False)
    platform = db.Column(db.Text, nullable=False)
    external_order_id = db.Column(db.Text, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=True, index=True)
    customer_name = db.Column(db.Text, default="")
    customer_phone = db.Column(db.Text, default="")
    items_snapshot = db.Column(db.JSON, default=list)
    subtotal = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), default=0)
    currency = db.Column(db.Text, default="INR")
    aggregator_status = db.Column(db.Text, default="placed")
    pickup_eta_minutes = db.Column(db.Integer, default=0)
    rider_name = db.Column(db.Text, default="")
    rider_phone = db.Column(db.Text, default="")
    notes = db.Column(db.Text, default="")
    raw = db.Column(db.JSON, default=dict)
    accepted_at = db.Column(db.DateTime(timezone=True))
    rejected_at = db.Column(db.DateTime(timezone=True))
    rejected_reason = db.Column(db.Text, default="")
    food_ready_at = db.Column(db.DateTime(timezone=True))
    delivered_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                           onupdate=db.func.now())
    __table_args__ = (
        db.UniqueConstraint("platform", "external_order_id",
                             name="uq_aggregator_platform_external"),
    )


class OwnerLead(db.Model):
    """Pre-account 'request access' submissions from the public landing page.

    A lead is *not* an Owner — it has no password, no login, and grants no
    access. Superadmins review leads at ``/superadmin/leads`` and either
    approve (which provisions an Owner with a one-time temp password and
    emails it to the café owner) or reject (which marks the lead handled
    without creating any account).

    Kept deliberately separate from the existing ``approval_status='pending'``
    flow on Owner so that low-quality / spam submissions never pollute the
    real Owners table.
    """

    __tablename__ = "owner_leads"
    id = db.Column(db.Integer, primary_key=True)
    contact_name = db.Column(db.Text, nullable=False, default="")
    cafe_name = db.Column(db.Text, nullable=False, default="")
    email = db.Column(db.Text, nullable=False, default="")
    phone = db.Column(db.Text, default="")
    city = db.Column(db.Text, default="")
    table_count = db.Column(db.Integer, default=0)
    message = db.Column(db.Text, default="")
    source = db.Column(db.Text, default="landing")
    status = db.Column(db.Text, default="pending", server_default="pending", nullable=False)
    handled_by = db.Column(db.Integer, db.ForeignKey("owners.id"), nullable=True)
    handled_at = db.Column(db.DateTime(timezone=True), nullable=True)
    submitted_ip = db.Column(db.Text, default="")
    submitted_ua = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())


class SystemFlag(db.Model):
    """Global, single-row key/value flags for cross-tenant runtime toggles.

    Used today for the maintenance-mode banner. Kept deliberately schemaless
    (text value) so superadmins can toggle new flags without migrations.
    """

    __tablename__ = "system_flags"
    key = db.Column(db.Text, primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                           onupdate=db.func.now())


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
        # Billing extensions on orders. Defaults preserve existing behaviour
        # (every legacy row appears 'unpaid' until the owner settles it).
        add_column_if_missing("orders", "payment_status TEXT DEFAULT 'unpaid'", "payment_status")
        add_column_if_missing("orders", "payment_method TEXT DEFAULT ''", "payment_method")
        add_column_if_missing("orders", "discount NUMERIC(10,2) DEFAULT 0", "discount")
        add_column_if_missing("orders", "tax NUMERIC(10,2) DEFAULT 0", "tax")
        add_column_if_missing("orders", "service_charge NUMERIC(10,2) DEFAULT 0", "service_charge")
        add_column_if_missing("orders", "invoice_number TEXT DEFAULT ''", "invoice_number")
        add_column_if_missing("orders", "paid_at TIMESTAMP", "paid_at")
        add_column_if_missing("orders", "settled_by INTEGER", "settled_by")
        add_column_if_missing("orders", "payments_breakdown JSON", "payments_breakdown")
        add_column_if_missing("orders", "void_reason TEXT DEFAULT ''", "void_reason")
        add_column_if_missing("orders", "refund_amount NUMERIC(10,2) DEFAULT 0", "refund_amount")
        add_column_if_missing("orders", "refund_reason TEXT DEFAULT ''", "refund_reason")
        # Settings billing fields (for legacy rows that pre-date the new cols)
        add_column_if_missing("settings", "tax_rate_percent NUMERIC(5,2) DEFAULT 0", "tax_rate_percent")
        add_column_if_missing("settings", "tax_label TEXT DEFAULT 'GST'", "tax_label")
        add_column_if_missing("settings", "gstin TEXT DEFAULT ''", "gstin")
        add_column_if_missing("settings", "service_charge_percent NUMERIC(5,2) DEFAULT 0", "service_charge_percent")
        add_column_if_missing("settings", "invoice_prefix TEXT DEFAULT 'INV'", "invoice_prefix")
        add_column_if_missing("settings", "invoice_seq INTEGER DEFAULT 0", "invoice_seq")
        add_column_if_missing("settings", "billing_address TEXT DEFAULT ''", "billing_address")
        add_column_if_missing("settings", "billing_phone TEXT DEFAULT ''", "billing_phone")
        # Indexes that make the high-traffic billing screens stay fast
        # under load (open-tabs query, EOD report, audit log).
        for idx_sql in (
            "CREATE INDEX IF NOT EXISTS ix_orders_owner_paystatus ON orders(owner_id, payment_status)",
            "CREATE INDEX IF NOT EXISTS ix_orders_owner_paid_at ON orders(owner_id, paid_at)",
            "CREATE INDEX IF NOT EXISTS ix_orders_invoice_number ON orders(invoice_number)",
            "CREATE INDEX IF NOT EXISTS ix_billing_logs_owner_created ON billing_logs(owner_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS ix_payment_credentials_owner ON payment_credentials(owner_id)",
            "CREATE INDEX IF NOT EXISTS ix_online_payments_owner_order ON online_payments(owner_id, order_id)",
            "CREATE INDEX IF NOT EXISTS ix_online_payments_intent ON online_payments(intent_id)",
            "CREATE INDEX IF NOT EXISTS ix_webhook_events_provider_event ON webhook_events(provider, event_id)",
            "CREATE INDEX IF NOT EXISTS ix_aggregator_credentials_owner ON aggregator_credentials(owner_id)",
            "CREATE INDEX IF NOT EXISTS ix_aggregator_orders_owner_created ON aggregator_orders(owner_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS ix_aggregator_orders_external ON aggregator_orders(platform, external_order_id)",
        ):
            try:
                db.session.execute(text(idx_sql))
            except Exception as _exc:
                app.logger.warning("Index create skipped (%s): %s", idx_sql, _exc)
        db.session.commit()
        add_column_if_missing("owners", "is_superadmin BOOLEAN DEFAULT false", "is_superadmin")
        add_column_if_missing("owners", "totp_secret TEXT", "totp_secret")
        add_column_if_missing("owners", "totp_enabled BOOLEAN DEFAULT false", "totp_enabled")
        add_column_if_missing("owners", "phone TEXT DEFAULT ''", "phone")
        add_column_if_missing("owners", "cafe_id INTEGER", "cafe_id")
        add_column_if_missing("feedback", "order_id INTEGER", "order_id")
        add_column_if_missing("feedback", "cafe_id INTEGER", "cafe_id")
        # Multi-tenant control columns -------------------------------------
        add_column_if_missing("owners", "approval_status TEXT DEFAULT 'active'", "approval_status")
        add_column_if_missing("owners", "plan_tier TEXT DEFAULT 'free'", "plan_tier")
        add_column_if_missing("owners", "max_tables INTEGER", "max_tables")
        add_column_if_missing("owners", "max_menu_items INTEGER", "max_menu_items")
        add_column_if_missing("owners", "monthly_order_limit INTEGER", "monthly_order_limit")
        add_column_if_missing("owners", "trial_ends_at TIMESTAMP", "trial_ends_at")
        add_column_if_missing("owners", "notes TEXT DEFAULT ''", "notes")
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

_REQUEST_ID_HEADER = "X-Request-ID"
_SLOW_REQUEST_MS = int(os.environ.get("SLOW_REQUEST_MS", "1500") or "1500")


@app.before_request
def _assign_request_id() -> None:
    """Attach a correlation id to every request. Honour an upstream
    ``X-Request-ID`` header (e.g. set by Railway's edge / Cloudflare) so
    a single trace stitches across the proxy hop."""
    incoming = (request.headers.get(_REQUEST_ID_HEADER) or "").strip()
    # Reject pathological values; fall back to a fresh id.
    if incoming and len(incoming) <= 128 and all(c.isalnum() or c in "-_" for c in incoming):
        rid = incoming
    else:
        rid = secrets.token_hex(8)
    request.environ["request_id"] = rid
    request.environ["_t_start"] = time.perf_counter()
    # Session hijack protection: if the session was minted with a UA
    # fingerprint and the current request's UA hashes differently, the
    # cookie is being replayed from another browser — clear it. Sessions
    # without a fingerprint (older logins) pass through and will be
    # re-stamped on next ``_complete_login``.
    try:
        stored_fp = session.get("ua_fp")
        if stored_fp and stored_fp != _ua_fingerprint():
            log_security("SESSION_FINGERPRINT_MISMATCH",
                         f"owner_id={session.get('owner_id')!r} ip={_client_ip()}")
            session.clear()
    except Exception:  # pragma: no cover — never let session checks 500 a request
        pass


@app.after_request
def extra_security_headers(response: Response) -> Response:
    response.headers["Server"] = "CafePortal"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # Defence-in-depth: clickjacking, MIME sniffing, referrer leaks.
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # Echo the request correlation id so clients can quote it in bug reports.
    rid = request.environ.get("request_id")
    if rid:
        response.headers.setdefault(_REQUEST_ID_HEADER, rid)
    # Long-cache fingerprinted static assets, but never HTML responses.
    if request.path.startswith("/static/") and response.status_code == 200:
        response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
    # Per-request access log + slow-request warning. Skipped for SSE streams
    # whose duration is meaningless in this context.
    t0 = request.environ.get("_t_start")
    if t0 is not None and not request.path.startswith("/api/orders/stream"):
        dur_ms = (time.perf_counter() - t0) * 1000.0
        log_payload = {
            "event": "http.request",
            "rid": rid,
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "durationMs": round(dur_ms, 2),
            "ip": _client_ip() if "_client_ip" in globals() else request.remote_addr,
        }
        if dur_ms >= _SLOW_REQUEST_MS:
            app.logger.warning("slow_request %s", json.dumps(log_payload))
        elif response.status_code >= 500:
            app.logger.error("server_error %s", json.dumps(log_payload))
        else:
            app.logger.info("access %s", json.dumps(log_payload))
    # HSTS only when the request was HTTPS — never on plain HTTP, which
    # would lock developers out of localhost.
    is_https = (
        request.is_secure
        or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    )
    if is_https and (
        os.environ.get("IS_PRODUCTION", "").lower() == "true"
        or os.environ.get("RAILWAY_ENVIRONMENT")
    ):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
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


import collections as _collections

# Process-local ring buffer of recent security events for the superadmin
# audit viewer. Persists across requests within the same worker; survives
# until process restart. Capped to avoid unbounded memory growth.
SECURITY_EVENT_BUFFER: _collections.deque = _collections.deque(maxlen=2000)


def log_security(event: str, detail: str = "") -> None:
    ip = _client_ip()
    security_log.info("%s ip=%s %s", event, ip, detail)
    try:
        SECURITY_EVENT_BUFFER.append({
            "ts": time.time(),
            "event": event,
            "ip": ip,
            "detail": detail,
            "actor": (
                session.get("admin_owner_id")
                or session.get("_user_id")
                or None
            ),
        })
    except Exception:
        # Never let logging break the request.
        pass


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
        "approvalStatus": getattr(owner, "approval_status", "active") or "active",
        "planTier": getattr(owner, "plan_tier", "free") or "free",
        "maxTables": getattr(owner, "max_tables", None),
        "maxMenuItems": getattr(owner, "max_menu_items", None),
        "monthlyOrderLimit": getattr(owner, "monthly_order_limit", None),
        "trialEndsAt": _iso(getattr(owner, "trial_ends_at", None)),
        "notes": getattr(owner, "notes", "") or "",
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


# ---------------------------------------------------------------------------
# Admin access keys (server-stored secret keys per authorised owner)
# ---------------------------------------------------------------------------

_admin_keys_lock = threading.Lock()


def load_admin_keys() -> list[dict]:
    """Return all stored admin access keys (without plaintext)."""
    if not ADMIN_KEYS_PATH.exists():
        return []
    try:
        with open(ADMIN_KEYS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and "keys" in data:
            return list(data.get("keys") or [])
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _save_admin_keys(keys: list[dict]) -> None:
    with _admin_keys_lock:
        tmp = ADMIN_KEYS_PATH.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"keys": keys}, fh, indent=2)
        os.replace(tmp, ADMIN_KEYS_PATH)


def generate_admin_key_for_owner(owner_id: int, username: str = "") -> str:
    """Generate a new admin secret key for the given owner.

    The plaintext is returned (shown to the superadmin once); only a bcrypt
    hash is persisted on the server alongside the owner_id.
    """
    plaintext = secrets.token_urlsafe(32)
    key_hash = bcrypt.generate_password_hash(plaintext).decode("utf-8")
    keys = [k for k in load_admin_keys() if int(k.get("owner_id", -1)) != int(owner_id)]
    keys.append({
        "owner_id": int(owner_id),
        "username": username,
        "key_hash": key_hash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })
    _save_admin_keys(keys)
    return plaintext


def revoke_admin_key_for_owner(owner_id: int) -> bool:
    keys = load_admin_keys()
    new_keys = [k for k in keys if int(k.get("owner_id", -1)) != int(owner_id)]
    if len(new_keys) == len(keys):
        return False
    _save_admin_keys(new_keys)
    return True


def find_admin_key_owner(plaintext: str) -> int | None:
    """If plaintext matches a stored key, return the owner_id it belongs to."""
    if not plaintext:
        return None
    for record in load_admin_keys():
        key_hash = record.get("key_hash", "")
        if not key_hash:
            continue
        try:
            if bcrypt.check_password_hash(key_hash, plaintext):
                return int(record.get("owner_id"))
        except Exception:
            continue
    return None


def consume_admin_key(plaintext: str) -> int | None:
    """Single-use redeem: validate plaintext, remove it, return owner_id.

    Used by the owner-facing redeem page so a key can never be replayed once
    it has activated an account.
    """
    if not plaintext:
        return None
    keys = load_admin_keys()
    for idx, record in enumerate(keys):
        key_hash = record.get("key_hash", "")
        if not key_hash:
            continue
        try:
            if bcrypt.check_password_hash(key_hash, plaintext):
                owner_id = int(record.get("owner_id"))
                keys.pop(idx)
                _save_admin_keys(keys)
                return owner_id
        except Exception:
            continue
    return None


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
    # Enforce monthly order plan limit (silently skipped for orders that
    # have no owner_id, e.g. legacy demo data).
    owner_id = order.get("ownerId")
    if owner_id:
        from extensions.multi_tenant_bp import (
            enforce_quota as _enforce_quota,
            count_owner_orders_this_month,
            QuotaExceeded,
        )
        owner_obj = db.session.get(Owner, owner_id)
        if owner_obj is not None:
            current = count_owner_orders_this_month(owner_id)
            try:
                _enforce_quota(owner_obj, "monthly_order_limit", current)
            except QuotaExceeded as exc:
                from werkzeug.exceptions import HTTPException

                class _QuotaExceeded(HTTPException):
                    code = 402
                    description = exc.message
                raise _QuotaExceeded()

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


def _superadmin_key_configured() -> bool:
    return bool(os.environ.get("SUPERADMIN_KEY", "").strip())


def _superadmin_key_matches(provided: str) -> bool:
    expected = os.environ.get("SUPERADMIN_KEY", "")
    if not expected or not provided:
        return False
    import hmac as _hmac
    return _hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


# Session verification expires after this many seconds. Destructive actions
# also require a fresh per-request key from non-real-superadmin sessions.
SUPERADMIN_VERIFY_TTL = int(os.environ.get("SUPERADMIN_VERIFY_TTL", "600"))


def _superadmin_session_verified() -> bool:
    if not session.get("superadmin_key_verified"):
        return False
    try:
        ts = float(session.get("superadmin_key_verified_at", 0) or 0)
    except (TypeError, ValueError):
        ts = 0.0
    if time.time() - ts > SUPERADMIN_VERIFY_TTL:
        session.pop("superadmin_key_verified", None)
        session.pop("superadmin_key_verified_at", None)
        return False
    return True


def _is_real_superadmin(owner) -> bool:
    return bool(
        owner
        and getattr(owner, "is_superadmin", False)
        and getattr(owner, "is_active", True)
    )


def superadmin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        owner = logged_in_owner_obj()
        if _is_real_superadmin(owner):
            return view_func(*args, **kwargs)
        if (
            session.get("admin_authenticated")
            and _superadmin_session_verified()
            and _superadmin_key_configured()
        ):
            return view_func(*args, **kwargs)
        if session.get("admin_authenticated"):
            if not _superadmin_key_configured():
                log_security("SUPERADMIN_BLOCKED_NO_KEY", f"path={request.path}")
                return render_template(
                    "admin/error.html",
                    message="SUPERADMIN_KEY is not configured on this server. Set it in your hosting environment and redeploy.",
                ), 503
            session["superadmin_verify_next"] = request.full_path or request.path
            return redirect(url_for("superadmin_verify_key"))
        # No auth at all — send the visitor to a login page they can use.
        try:
            return redirect(url_for("admin.login"))
        except Exception:
            return redirect(url_for("owner_login"))
    return wrapper


def superadmin_destructive(view_func):
    """Per-request re-verification for destructive superadmin actions.

    Real superadmin owners pass through. Admin-elevated sessions must
    submit ``superadmin_key`` matching SUPERADMIN_KEY on the same POST,
    or they are sent to a confirmation page that re-submits the original
    form once the key is provided.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        owner = logged_in_owner_obj()
        if _is_real_superadmin(owner):
            return view_func(*args, **kwargs)
        if not _superadmin_key_configured():
            log_security("SUPERADMIN_DESTRUCTIVE_NO_KEY", f"action={request.endpoint}")
            abort(503)
        if request.method != "POST":
            abort(405)
        provided = str(request.form.get("superadmin_key", ""))
        if _superadmin_key_matches(provided):
            log_security(
                "SUPERADMIN_DESTRUCTIVE_OK",
                f"action={request.endpoint} admin_owner_id={session.get('admin_owner_id')}",
            )
            return view_func(*args, **kwargs)
        if provided:
            log_security(
                "SUPERADMIN_DESTRUCTIVE_DENIED",
                f"action={request.endpoint} admin_owner_id={session.get('admin_owner_id')}",
            )
        form_fields = [
            (k, v) for k, v in request.form.items()
            if k not in ("superadmin_key", "csrf_token")
        ]
        return render_template(
            "superadmin/confirm_action.html",
            action=request.endpoint or "this action",
            target_url=request.path,
            form_fields=form_fields,
            error=("Invalid SUPERADMIN_KEY." if provided else None),
        ), (401 if provided else 200)
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
# Per-table broadcast queues for the "At Your Service" customer page.
# Keyed by table_id (string from tables.json).
_sse_table_subs: dict[str, list] = {}
_sse_lock = threading.Lock()


def _local_dispatch_owner(owner_id: int, payload: str) -> None:
    with _sse_lock:
        entries = _sse_subscribers.get(owner_id, [])
        dead = []
        for entry in entries:
            try:
                if isinstance(entry, tuple):
                    q, ev = entry
                    q.append(payload)
                    ev.set()
                else:
                    entry.append(payload)
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


def _local_dispatch_customer(order_id: int, payload: str) -> None:
    with _sse_lock:
        entries = _sse_customer_subs.get(order_id, [])
        dead = []
        for entry in entries:
            try:
                if isinstance(entry, tuple):
                    q, ev = entry
                    q.append(payload)
                    ev.set()
                else:
                    entry.append(payload)
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


def _local_dispatch_table(table_id: str, payload: str) -> None:
    """Fan out a table-call SSE payload to every customer device watching
    this table_id (typically just one phone, but could be many)."""
    with _sse_lock:
        entries = _sse_table_subs.get(table_id, [])
        dead = []
        for entry in entries:
            try:
                if isinstance(entry, tuple):
                    q, ev = entry
                    q.append(payload)
                    ev.set()
                else:
                    entry.append(payload)
            except Exception:
                dead.append(entry)
        for entry in dead:
            entries.remove(entry)


# Optional Redis pub/sub fan-out for multi-worker deployments.
_REDIS_URL = os.environ.get("REDIS_URL")
_redis_client = None
_REDIS_OWNER_CHANNEL = "sse:owner"
_REDIS_CUSTOMER_CHANNEL = "sse:customer"
_REDIS_TABLE_CHANNEL = "sse:table"

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
                    pubsub.subscribe(
                        _REDIS_OWNER_CHANNEL,
                        _REDIS_CUSTOMER_CHANNEL,
                        _REDIS_TABLE_CHANNEL,
                    )
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
                            elif channel == _REDIS_TABLE_CHANNEL:
                                _local_dispatch_table(str(envelope["table_id"]), envelope["payload"])
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


def _notify_table_call(table_id: str, event_type: str, data: dict) -> None:
    """Push a table-call SSE event to the customer device(s) at this table.

    Used by the service-calls blueprint so the customer sees their call
    transition states (acknowledged / resolved / cancelled) instantly,
    without polling.
    """
    if not table_id:
        return
    payload = json.dumps({"type": event_type, "data": data})
    if _redis_client is not None:
        try:
            _redis_client.publish(
                _REDIS_TABLE_CHANNEL,
                json.dumps({"table_id": str(table_id), "payload": payload}),
            )
            return
        except Exception as exc:
            app.logger.warning("SSE redis publish failed (table): %s; using local.", exc)
    _local_dispatch_table(str(table_id), payload)


# Aliases requested by spec for explicit Redis-backed notifiers.
_notify_owner_redis = _notify_owner
_notify_order_status_redis = _notify_order_status


def _push_new_order(owner_id: int, customer_name: str, total: float) -> None:
    """Fire a Web Push notification to the owner for a new order (background thread)."""
    try:
        from extensions.push_bp import push_owner
        push_owner(
            owner_id,
            title="🆕 New order",
            body=f"{customer_name} — £{total:.2f}" if total else f"Order from {customer_name}",
            data={"type": "new_order"},
        )
    except Exception:
        pass


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

@app.route("/healthz")
@limiter.exempt
def health_check_alias():
    """Kubernetes/GCP-style alias for /health. Same payload, same status code.
    Kept so probes that hard-code ``/healthz`` (the test suite does) keep
    working alongside the canonical ``/health``."""
    return health_check()


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

    # ── DB connection pool ─────────────────────────────────────────────────
    try:
        pool = db.engine.pool
        pool_info: dict = {"ok": True}
        # SQLAlchemy QueuePool exposes these helpers; SQLite's NullPool does not.
        for attr in ("size", "checkedin", "checkedout", "overflow"):
            fn = getattr(pool, attr, None)
            if callable(fn):
                try:
                    pool_info[attr] = fn()
                except Exception:
                    pass
        checks["dbPool"] = pool_info
    except Exception as exc:
        checks["dbPool"] = {"ok": False, "error": str(exc)[:200]}

    # ── SSE subscribers ────────────────────────────────────────────────────
    try:
        sse_total = sum(len(v) for v in _sse_subscribers.values())
        checks["sseSubscribers"] = {
            "ok": True,
            "owners": len(_sse_subscribers),
            "connections": sse_total,
        }
    except Exception as exc:
        checks["sseSubscribers"] = {"ok": False, "error": str(exc)[:200]}

    # ── Maintenance mode flag ──────────────────────────────────────────────
    checks["maintenanceMode"] = {"ok": True, "enabled": _maintenance_mode_enabled()}

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


@app.route("/metrics/prom")
@limiter.exempt
def prometheus_metrics():
    """Minimal Prometheus text-format exposition. No new dependencies — emitted
    by hand because the only metrics we currently track are derived from the DB
    and the running process. Safe to expose publicly: counts only, no PII."""
    lines: list[str] = []

    def _emit(name: str, help_text: str, mtype: str, value, labels: str = "") -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name}{labels} {value}")

    _emit("cafe_uptime_seconds", "Process uptime in seconds.", "gauge",
          int(time.time() - APP_START_TIME))
    _emit("cafe_build_info", "Build info; value is always 1.", "gauge", 1,
          labels=f'{{version="{APP_VERSION}"}}')

    orders_today = active_orders = -1
    try:
        if _initialize_runtime_state(force=False):
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            orders_today = db.session.query(Order).filter(Order.created_at >= today_start).count()
            active_orders = db.session.query(Order).filter(
                Order.status.in_(("pending", "confirmed", "preparing", "ready"))
            ).count()
    except Exception as exc:
        app.logger.warning("Prometheus metrics query failed: %s", exc)

    if orders_today >= 0:
        _emit("cafe_orders_today", "Orders created since UTC midnight.", "gauge", orders_today)
    if active_orders >= 0:
        _emit("cafe_orders_active", "Orders not yet completed/cancelled.", "gauge", active_orders)

    try:
        sse_total = sum(len(v) for v in _sse_subscribers.values())
        _emit("cafe_sse_subscribers", "Currently connected SSE clients.", "gauge", sse_total)
    except Exception:
        pass

    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")


@app.route("/version")
@limiter.exempt
def version_endpoint():
    """Cheap, cache-friendly build identifier — handy for smoke tests after deploy."""
    return jsonify(
        version=APP_VERSION,
        commit=os.environ.get("RAILWAY_GIT_COMMIT_SHA", "")[:40] or None,
        branch=os.environ.get("RAILWAY_GIT_BRANCH") or None,
        deployedAt=os.environ.get("RAILWAY_DEPLOYMENT_CREATED_AT") or None,
        startedAt=datetime.fromtimestamp(APP_START_TIME, tz=timezone.utc).isoformat(),
    ), 200


@app.route("/robots.txt")
@limiter.exempt
def robots_txt():
    """Block search-engine indexing of authenticated/admin surfaces by default.
    Override with a real robots.txt in /static/ if you ever want public SEO."""
    body = (
        "User-agent: *\n"
        "Disallow: /owner/\n"
        "Disallow: /admin/\n"
        "Disallow: /superadmin/\n"
        "Disallow: /api/\n"
        "Disallow: /kitchen\n"
        "Allow: /\n"
    )
    return Response(body, mimetype="text/plain; charset=utf-8")


@app.route("/admin/runtime")
@limiter.limit("30 per minute")
def admin_runtime_stats():
    """Operational peek at the in-process queue + caches. Restricted to
    superadmins; safe to expose otherwise but unhelpful to most users.
    Tiny replacement for a Sidekiq/RQ dashboard since we run in-process."""
    if not session.get("is_superadmin") and request.headers.get("X-Admin-Key") != os.environ.get("SUPERADMIN_KEY", "__no__"):
        abort(403)
    return jsonify(
        bgTasks=bg_tasks.stats(),
        version=APP_VERSION,
        uptimeSeconds=int(time.time() - APP_START_TIME),
    ), 200


@app.route("/.well-known/security.txt")
@limiter.exempt
def security_txt():
    """RFC 9116 security disclosure contact. Override SECURITY_CONTACT to point
    at your own mailbox or HackerOne page."""
    contact = os.environ.get("SECURITY_CONTACT") or "mailto:security@example.com"
    expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = (
        f"Contact: {contact}\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
        "Canonical: https://" + (request.host or "example.com") + "/.well-known/security.txt\n"
    )
    return Response(body, mimetype="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route("/welcome")
@app.route("/for-owners")
@limiter.limit("60 per minute")
def owner_landing() -> str:
    """Public marketing page for café owners. Explains every feature of the
    tool and ends in a 'Request Access' form. Linked from the home page nav
    and from the email/WhatsApp template you send to prospects."""
    return render_template("landing.html")


@app.route("/welcome/request-access", methods=["POST"])
@limiter.limit("5 per hour; 30 per day")
def owner_lead_submit() -> Response:
    """Accept a 'request access' submission from the landing page.
    Lightly validated; heavy lifting (approval, account creation) is done
    later by a superadmin from /superadmin/leads."""
    contact_name = str(request.form.get("contact_name", "")).strip()[:120]
    cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
    email = str(request.form.get("email", "")).strip()[:254]
    phone = str(request.form.get("phone", "")).strip()[:30]
    city = str(request.form.get("city", "")).strip()[:120]
    table_count_raw = str(request.form.get("table_count", "")).strip()[:6]
    message = str(request.form.get("message", "")).strip()[:1000]
    # Honeypot field — any bot that auto-fills every input fails here
    # because real users never see/touch it.
    if str(request.form.get("website", "")).strip():
        return redirect(url_for("owner_landing") + "#thanks")

    if not contact_name or not cafe_name or not email:
        flash("Please share your name, café name and email so we can reach you.", "lead_error")
        return redirect(url_for("owner_landing") + "#request-access")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("That email address doesn't look right — please double-check.", "lead_error")
        return redirect(url_for("owner_landing") + "#request-access")

    try:
        table_count = int(table_count_raw) if table_count_raw.isdigit() else 0
        table_count = max(0, min(table_count, 9999))
    except ValueError:
        table_count = 0

    lead = OwnerLead(
        contact_name=contact_name,
        cafe_name=cafe_name,
        email=email.lower(),
        phone=phone,
        city=city,
        table_count=table_count,
        message=message,
        source="landing",
        submitted_ip=_client_ip()[:64],
        submitted_ua=(request.headers.get("User-Agent") or "")[:255],
    )
    db.session.add(lead)
    db.session.commit()
    log_security("OWNER_LEAD_SUBMITTED",
                 f"lead_id={lead.id} email={email!r} cafe={cafe_name!r}")

    # Fire-and-forget acknowledgement email (non-blocking — won't delay
    # the form response if SMTP is slow or unconfigured).
    def _send_lead_ack(to_addr: str, name: str, cafe: str) -> None:
        if not _mail_enabled():
            return
        try:
            mail.send(Message(
                subject=f"We got your request, {name} ☕",
                recipients=[to_addr],
                body=(
                    f"Hi {name},\n\n"
                    f"Thanks for requesting access for {cafe}. "
                    "Our team reviews new café applications within 1–2 business days "
                    "and will reach out at this address with your login link and a "
                    "short onboarding call.\n\n"
                    "If you'd like to fast-track approval, reply to this email with "
                    "your menu (PDF / photo / handwritten — anything works) and your "
                    "café's logo.\n\n"
                    "Talk soon,\n"
                    "The Cafe Ordering team"
                ),
            ))
        except Exception as exc:  # pragma: no cover
            app.logger.warning("Lead ack email failed: %s", exc)

    bg_tasks.submit(_send_lead_ack, email, contact_name, cafe_name,
                    _name="send_lead_ack")
    return redirect(url_for("owner_landing") + "#thanks")


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


# ---------------------------------------------------------------------------
# Maintenance mode
# ---------------------------------------------------------------------------

# Cheap process-local cache for the maintenance flag so the before_request
# hook doesn't hit the DB on every single request. We refresh at most once
# every MAINTENANCE_FLAG_TTL seconds; toggling the flag via the superadmin
# endpoint also forces an immediate refresh.
MAINTENANCE_FLAG_KEY = "maintenance_mode"
MAINTENANCE_FLAG_TTL = 5.0  # seconds
_maintenance_cache: dict = {"value": False, "ts": 0.0}


def _maintenance_mode_enabled(*, force_refresh: bool = False) -> bool:
    now = time.time()
    if not force_refresh and (now - _maintenance_cache["ts"]) < MAINTENANCE_FLAG_TTL:
        return bool(_maintenance_cache["value"])
    enabled = False
    try:
        if _DB_READY:
            row = db.session.get(SystemFlag, MAINTENANCE_FLAG_KEY)
            enabled = bool(row and (row.value or "").lower() in {"1", "true", "on", "yes"})
    except Exception:  # pragma: no cover — never block requests on a bad DB
        enabled = _maintenance_cache["value"]
    _maintenance_cache["value"] = enabled
    _maintenance_cache["ts"] = now
    return enabled


def _set_maintenance_mode(enabled: bool) -> None:
    row = db.session.get(SystemFlag, MAINTENANCE_FLAG_KEY)
    if row is None:
        row = SystemFlag(key=MAINTENANCE_FLAG_KEY, value=("true" if enabled else "false"))
        db.session.add(row)
    else:
        row.value = "true" if enabled else "false"
    db.session.commit()
    _maintenance_cache["value"] = enabled
    _maintenance_cache["ts"] = time.time()


# Endpoints that must remain reachable while maintenance mode is active so
# that operators can recover the system and probes keep working.
_MAINTENANCE_ALLOWED_ENDPOINTS = {
    "health_check",
    "readiness_check",
    "health_check_full",
    "public_metrics",
    "static",
    "owner_login",
    "owner_login_totp_verify",
    "owner_logout",
    "admin_login",
    "admin_logout",
    "maintenance_mode_toggle",
    "maintenance_mode_status",
}


@app.before_request
def _enforce_maintenance_mode():
    """Show a friendly maintenance page to non-superadmin traffic when toggled.

    Superadmins (and admin-elevated sessions) keep full access so they can
    finish migrations / debugging before flipping the flag back off.
    """
    endpoint = request.endpoint or ""
    if endpoint in _MAINTENANCE_ALLOWED_ENDPOINTS:
        return None
    # Always allow the superadmin namespace through so operators can toggle
    # the flag back even if they hit a stale tab.
    if endpoint.startswith("multi_tenant.") or endpoint.startswith("superadmin"):
        return None
    if not _maintenance_mode_enabled():
        return None
    # Let elevated operators bypass.
    try:
        owner = logged_in_owner_obj()
    except Exception:
        owner = None
    if (owner and getattr(owner, "is_superadmin", False)) or session.get("admin_authenticated"):
        return None
    if _wants_json():
        return jsonify(
            status="maintenance",
            description="The service is temporarily down for maintenance. Please try again shortly.",
        ), 503
    try:
        return render_template("maintenance.html"), 503
    except Exception:
        # Template may not exist on older deploys — fall back to plain text.
        return (
            "We're performing a quick maintenance — please try again in a minute.",
            503,
            {"Content-Type": "text/plain; charset=utf-8", "Retry-After": "60"},
        )


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
@limiter.limit("5 per minute; 50 per hour", methods=["POST"])
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
            flash("This account is suspended. If your administrator gave you "
                  "an access key, redeem it to reactivate your account.")
            return _no_store(app.make_response(render_template("owner_login.html")))

        if owner:
            from extensions.multi_tenant_bp import can_owner_login as _can_login
            ok, reason = _can_login(owner)
            if not ok:
                flash(reason)
                log_security("LOGIN_BLOCKED", f"user={owner.username!r} reason={reason!r}")
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


def _ua_fingerprint() -> str:
    """Stable, low-entropy hash of the requesting browser. Used to bind a
    session to the device that created it so a stolen cookie replayed from
    a different browser is rejected. Truncated SHA-256 keeps the cookie
    payload small while still giving collision resistance well beyond what
    a credential stuffer can brute force."""
    import hashlib
    ua = (request.headers.get("User-Agent") or "")[:512]
    return hashlib.sha256(ua.encode("utf-8", "ignore")).hexdigest()[:16]


def _complete_login(owner: Owner, remember_me: bool = False) -> None:
    session.clear()
    session["owner_username"] = owner.username
    session["owner_id"] = owner.id
    # Bind the session to the user-agent that performed the login. Validated
    # on every subsequent request in ``_assign_request_id`` (below). Old
    # sessions without ``ua_fp`` are grandfathered through for one rotation.
    session["ua_fp"] = _ua_fingerprint()
    session.permanent = True
    login_user(owner, remember=False)


@app.context_processor
def _inject_impersonation_state() -> dict:
    """Expose an ``is_impersonating`` flag + the impersonator's username to
    every template so layouts can render a persistent banner."""
    try:
        return {
            "is_impersonating": bool(session.get("impersonator_owner_id")),
            "impersonator_username": session.get("impersonator_username", ""),
        }
    except Exception:  # pragma: no cover
        return {"is_impersonating": False, "impersonator_username": ""}


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


@app.route("/owner/redeem-key", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def owner_redeem_key() -> str | Response:
    """Owner self-service: redeem an admin-issued access key.

    Activates the owner account that the key was generated for. Requires the
    owner's username + password so a stolen key alone can't take over an
    account, and consumes the key on success (single-use).
    """
    if request.method == "POST":
        identifier = str(request.form.get("identifier", "")).strip()[:128]
        password = str(request.form.get("password", ""))[:256]
        access_key = str(request.form.get("access_key", "")).strip()[:128]

        if not identifier or not password or not access_key:
            flash("Username, password and access key are all required.")
            return render_template("owner_redeem_key.html")

        owner = Owner.query.filter(
            (Owner.username == identifier) | (Owner.email == identifier)
        ).first()
        if not owner or not _password_matches(owner.password_hash, password):
            log_security("REDEEM_KEY_BAD_CREDENTIALS", f"identifier={identifier!r}")
            flash("Sign-in details didn't match. Try again.")
            return render_template("owner_redeem_key.html")

        # Validate first (non-destructive). Only consume on a perfect match
        # to the same owner — prevents one owner using another's key.
        target_owner_id = find_admin_key_owner(access_key)
        if target_owner_id is None or int(target_owner_id) != int(owner.id):
            log_security("REDEEM_KEY_MISMATCH", f"user={owner.username!r}")
            flash("That access key is not valid for this account.")
            return render_template("owner_redeem_key.html")

        # Single-use consume so the key cannot be replayed.
        consume_admin_key(access_key)
        owner.is_active = True
        db.session.commit()
        log_security("REDEEM_KEY_SUCCESS", f"user={owner.username!r}")
        flash("Access key accepted. Your account is now active — please sign in.")
        return redirect(url_for("owner_login"))

    return render_template("owner_redeem_key.html")


@app.route("/owner/signup", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def owner_signup() -> str | Response:
    if logged_in_owner():
        return redirect(url_for("owner_dashboard"))

    # Multi-tenant onboarding gate.  Three modes are supported:
    #   open         -- legacy behaviour: anyone can sign up and log in
    #   approval     -- account is created in 'pending' state and a superadmin
    #                   must approve before the owner may sign in
    #   invite_only  -- a valid invitation token is required to even submit
    from extensions.multi_tenant_bp import (
        signup_mode as _signup_mode,
        find_valid_invitation,
        consume_invitation,
        audit_log as _audit_log,
    )
    mode = _signup_mode()
    invite_token = (request.values.get("invite") or "").strip()
    invitation = find_valid_invitation(invite_token) if invite_token else None

    if mode == "invite_only" and not invitation:
        flash("Sign-ups are invite-only. Please use the invitation link sent to you.")
        return render_template("owner_signup.html",
                               signup_mode=mode, invite_token="",
                               invitation=None)

    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()[:64]
        email = str(request.form.get("email", "")).strip()[:254] or None
        cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
        password = str(request.form.get("password", ""))[:256]

        if not username or not password:
            flash("Username and password are required.")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{3,64}", username):
            flash("Username may only contain letters, digits, underscores, hyphens, and dots (3-64 chars).")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        if not _is_strong_password(password):
            flash("Password must be at least 8 characters with a letter and digit.")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        if Owner.query.filter_by(username=username).first():
            flash("That username is already taken.")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        if email and Owner.query.filter(Owner.email == email).first():
            flash("An account with that email already exists.")
            return render_template("owner_signup.html",
                                   signup_mode=mode, invite_token=invite_token,
                                   invitation=invitation)

        password_hash = _make_password_hash(password)
        new_owner = create_owner_in_db(username, email, password_hash, cafe_name)
        owner_model = db.session.get(Owner, new_owner["id"])

        # Apply onboarding policy.  Invitations always grant immediate access.
        if invitation is not None:
            owner_model.approval_status = "active"
            owner_model.plan_tier = invitation.plan_tier or "free"
            owner_model.cafe_id = invitation.cafe_id or owner_model.cafe_id
            db.session.commit()
            consume_invitation(invitation, owner_model)
            _complete_login(owner_model)
            log_security("SIGNUP_SUCCESS_INVITE", f"user={username!r}")
            _audit_log("OWNER_SIGNUP", owner_id=owner_model.id, actor_type="owner",
                       actor_id=owner_model.id, actor_label=username,
                       meta={"via": "invitation", "invitation_id": invitation.id})
            return redirect(url_for("owner_dashboard"))

        if mode == "approval":
            owner_model.approval_status = "pending"
            owner_model.is_active = False
            db.session.commit()
            log_security("SIGNUP_PENDING", f"user={username!r}")
            _audit_log("OWNER_SIGNUP", owner_id=owner_model.id, actor_type="owner",
                       actor_id=owner_model.id, actor_label=username,
                       meta={"via": "self_signup_pending"})
            flash("Your account has been created and is awaiting administrator "
                  "approval. You will be able to sign in once an administrator "
                  "approves your account.")
            return redirect(url_for("owner_login"))

        # Open mode -- legacy behaviour.
        _complete_login(owner_model)
        log_security("SIGNUP_SUCCESS", f"user={username!r}")
        _audit_log("OWNER_SIGNUP", owner_id=owner_model.id, actor_type="owner",
                   actor_id=owner_model.id, actor_label=username,
                   meta={"via": "open_signup"})
        return redirect(url_for("owner_dashboard"))

    return render_template("owner_signup.html",
                           signup_mode=mode, invite_token=invite_token,
                           invitation=invitation)


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

KITCHEN_ACTIVE_STATUSES = ("pending", "confirmed", "preparing", "ready")
KITCHEN_DEFAULT_LIMIT = 200
KITCHEN_MAX_LIMIT = 500


def _owner_table_names(owner_id: int) -> dict:
    """Return {table_id: name} for a single owner — SQL-side filter so we don't
    drag every other tenant's tables across the network on each kitchen poll."""
    rows = (CafeTable.query
            .filter(CafeTable.owner_id == owner_id)
            .with_entities(CafeTable.id, CafeTable.name)
            .all())
    return {tid: name for tid, name in rows}


@app.route("/kitchen")
@login_required
def kitchen_view():
    owner_id = logged_in_owner_id()
    table_names = _owner_table_names(owner_id)
    # Cap the initial render so a swamped kitchen doesn't try to paint
    # thousands of cards at once. The JSON feed below handles incremental
    # updates and a "load more" path can fetch deeper history if needed.
    orders = (Order.query
              .filter(Order.owner_id == owner_id,
                      Order.status.in_(KITCHEN_ACTIVE_STATUSES))
              .order_by(Order.created_at.asc())
              .limit(KITCHEN_DEFAULT_LIMIT)
              .all())
    orders_dicts = []
    for o in orders:
        od = _order_dict(o)
        od["tableName"] = table_names.get(o.table_id, o.table_name or o.table_id or "—")
        orders_dicts.append(od)
    return render_template("kitchen.html",
                           orders=orders_dicts,
                           owner_username=logged_in_owner())


# ---------------------------------------------------------------------------
# Owner Billing — overview, open tabs, settle, void, refund, EOD report,
# audit log, invoice. Designed to be safe under concurrent settles during
# rush hour: every state mutation goes through a SELECT FOR UPDATE +
# re-check pattern, every action is logged to billing_logs, and the
# overview is cached for 5s so repeated polling doesn't pound the DB.
# ---------------------------------------------------------------------------

def _settings_for(owner_id: int) -> Settings:
    s = db.session.get(Settings, owner_id)
    if not s:
        s = Settings(owner_id=owner_id)
        db.session.add(s)
        db.session.commit()
    return s


def _billing_log(*, owner_id: int, order_id: int | None, action: str,
                 amount: float = 0, payment_method: str = "",
                 reason: str = "", payload: dict | None = None,
                 invoice_number: str = "") -> None:
    """Append-only audit row. Intentionally swallows DB errors with a log
    line so a logging hiccup never blocks a customer-facing settle."""
    try:
        log_row = BillingLog(
            owner_id=owner_id,
            order_id=order_id,
            invoice_number=invoice_number or "",
            action=action,
            actor_owner_id=session.get("owner_id"),
            actor_username=session.get("owner_username") or "",
            amount=amount,
            payment_method=payment_method or "",
            reason=(reason or "")[:500],
            payload=payload or {},
            ip=_client_ip()[:64],
            request_id=request.environ.get("request_id", ""),
        )
        db.session.add(log_row)
        db.session.commit()
    except Exception as exc:  # pragma: no cover
        db.session.rollback()
        app.logger.warning("billing_log write failed: %s", exc)


def _bill_dict(order: Order) -> dict:
    """Order dict augmented with billing-specific fields used by templates."""
    base = _order_dict(order)
    base.update({
        "paymentStatus": order.payment_status or "unpaid",
        "paymentMethod": order.payment_method or "",
        "discount": float(order.discount or 0),
        "tax": float(order.tax or 0),
        "serviceCharge": float(order.service_charge or 0),
        "invoiceNumber": order.invoice_number or "",
        "paidAt": _iso(order.paid_at) if order.paid_at else None,
        "paymentsBreakdown": order.payments_breakdown if isinstance(order.payments_breakdown, list) else [],
        "voidReason": order.void_reason or "",
        "refundAmount": float(order.refund_amount or 0),
        "refundReason": order.refund_reason or "",
    })
    return base


def _today_window() -> tuple[datetime, datetime]:
    """Return [start_of_today_utc, now_utc) — used for the daily EOD
    report and the dashboard overview. Owners running across timezones
    can override with TZ env var; we keep it simple for v1."""
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, now


def _billing_overview(owner_id: int) -> dict:
    """Cheap aggregate for the billing dashboard tile-row. Cached 5s so
    a frantically-refreshing owner during a rush doesn't hammer the DB."""
    def _compute() -> dict:
        start, _now = _today_window()
        paid_today = (Order.query
                      .filter(Order.owner_id == owner_id,
                              Order.payment_status == "paid",
                              Order.paid_at >= start)
                      .all())
        revenue = sum(float(o.total or 0) - float(o.refund_amount or 0) for o in paid_today)
        tax_collected = sum(float(o.tax or 0) for o in paid_today)
        service_charge = sum(float(o.service_charge or 0) for o in paid_today)
        tips = sum(float(o.tip or 0) for o in paid_today)
        refunds = sum(float(o.refund_amount or 0) for o in paid_today)
        # Aggregate payment-mode totals across the day
        per_mode: dict[str, float] = {}
        for o in paid_today:
            for p in (o.payments_breakdown or []):
                if not isinstance(p, dict):
                    continue
                m = p.get("method", "other")
                per_mode[m] = round(per_mode.get(m, 0.0) + float(p.get("amount") or 0), 2)
        open_tabs = (Order.query
                     .filter(Order.owner_id == owner_id,
                             Order.payment_status == "unpaid",
                             Order.status != "cancelled")
                     .count())
        voided_today = (Order.query
                        .filter(Order.owner_id == owner_id,
                                Order.payment_status == "voided",
                                Order.updated_at >= start)
                        .count())
        return {
            "revenue": round(revenue, 2),
            "orders_paid": len(paid_today),
            "tax_collected": round(tax_collected, 2),
            "service_charge": round(service_charge, 2),
            "tips": round(tips, 2),
            "refunds": round(refunds, 2),
            "open_tabs": open_tabs,
            "voided_today": voided_today,
            "per_mode": per_mode,
            "as_of": datetime.now(timezone.utc).isoformat(),
        }
    return response_cache.get_or_set(f"billing_overview::{owner_id}", 5, _compute)


def _invalidate_billing_cache(owner_id: int) -> None:
    response_cache.invalidate_prefix(f"billing_overview::{owner_id}")


@app.route("/owner/billing")
@login_required
def owner_billing_overview():
    owner_id = logged_in_owner_id()
    settings = _settings_for(owner_id)
    overview = _billing_overview(owner_id)
    recent_paid = (Order.query
                   .filter(Order.owner_id == owner_id,
                           Order.payment_status == "paid")
                   .order_by(Order.paid_at.desc().nullslast())
                   .limit(10).all())
    return _no_store(app.make_response(render_template(
        "owner_billing/overview.html",
        overview=overview,
        recent_paid=[_bill_dict(o) for o in recent_paid],
        settings=settings,
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/billing/open")
@login_required
def owner_billing_open():
    owner_id = logged_in_owner_id()
    table_filter = (request.args.get("table") or "").strip()[:64]
    page = max(1, int(request.args.get("page", "1") or "1"))
    per_page = 50
    q = (Order.query
         .filter(Order.owner_id == owner_id,
                 Order.payment_status == "unpaid",
                 Order.status != "cancelled"))
    if table_filter:
        q = q.filter(Order.table_id == table_filter)
    total = q.count()
    rows = (q.order_by(Order.created_at.desc())
              .offset((page - 1) * per_page).limit(per_page).all())
    return _no_store(app.make_response(render_template(
        "owner_billing/open.html",
        orders=[_bill_dict(o) for o in rows],
        page=page, per_page=per_page, total=total,
        table_filter=table_filter,
        owner_username=logged_in_owner(),
    )))


def _load_owner_order(order_id: int, owner_id: int, *, lock: bool = False) -> Order:
    """Fetch + tenant-check + optional row lock. Always use lock=True for
    state-mutating endpoints so two cashiers can't double-settle the same
    bill during a rush. PostgreSQL only — falls back to plain query on
    SQLite (dev) where row locking is unsupported."""
    q = Order.query.filter_by(id=order_id, owner_id=owner_id)
    if lock and db.engine.dialect.name == "postgresql":
        q = q.with_for_update()
    order = q.one_or_none()
    if not order:
        abort(404)
    return order


@app.route("/owner/billing/orders/<int:order_id>")
@login_required
def owner_billing_order_detail(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id)
    settings = _settings_for(owner_id)
    totals = compute_bill_totals(
        subtotal=float(order.subtotal or 0),
        discount=float(order.discount or 0),
        service_charge_pct=0,
        service_charge_flat=float(order.service_charge or 0),
        tax_pct=0,
        tax_flat=float(order.tax or 0),
        tip=float(order.tip or 0),
    )
    return _no_store(app.make_response(render_template(
        "owner_billing/order_detail.html",
        order=_bill_dict(order),
        totals=totals,
        settings=settings,
        valid_methods=VALID_PAYMENT_METHODS,
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/billing/orders/<int:order_id>/adjust", methods=["POST"])
@login_required
def owner_billing_adjust(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Cannot adjust an already-settled bill. Issue a refund instead.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    settings = _settings_for(owner_id)
    try:
        discount = max(0.0, min(float(request.form.get("discount", 0) or 0), float(order.subtotal or 0)))
        service_charge_pct = float(request.form.get("service_charge_pct", settings.service_charge_percent or 0) or 0)
        tax_pct = float(request.form.get("tax_pct", settings.tax_rate_percent or 0) or 0)
        tip = max(0.0, float(request.form.get("tip", order.tip or 0) or 0))
    except ValueError:
        flash("Invalid number in adjustment form.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    totals = compute_bill_totals(
        subtotal=float(order.subtotal or 0),
        discount=discount,
        service_charge_pct=service_charge_pct,
        tax_pct=tax_pct,
        tip=tip,
    )
    order.discount = totals.discount
    order.service_charge = totals.service_charge
    order.tax = totals.tax
    order.tip = totals.tip
    order.total = totals.total
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="adjusted",
                 amount=totals.total,
                 payload={"discount": totals.discount, "service_charge": totals.service_charge,
                          "tax": totals.tax, "tip": totals.tip, "total": totals.total})
    _invalidate_billing_cache(owner_id)
    flash(f"Bill updated. New total ₹{totals.total:.2f}.", "billing_ok")
    return redirect(url_for("owner_billing_order_detail", order_id=order_id))


@app.route("/owner/billing/orders/<int:order_id>/settle", methods=["POST"])
@login_required
def owner_billing_settle(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status == "paid":
        flash("This bill is already settled.", "billing_info")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    if order.payment_status == "voided":
        flash("This bill is voided and cannot be settled.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    # Parse split-payment rows: form fields are payment_method[] and payment_amount[].
    methods = request.form.getlist("payment_method")
    amounts = request.form.getlist("payment_amount")
    refs = request.form.getlist("payment_reference") or [""] * len(methods)
    raw_payments = []
    for i, m in enumerate(methods):
        try:
            amt = float(amounts[i] or 0)
        except (ValueError, IndexError):
            amt = 0.0
        ref = refs[i] if i < len(refs) else ""
        raw_payments.append({"method": m, "amount": amt, "reference": ref})
    payments = normalise_payments(raw_payments)

    totals = compute_bill_totals(
        subtotal=float(order.subtotal or 0),
        discount=float(order.discount or 0),
        service_charge_pct=0, service_charge_flat=float(order.service_charge or 0),
        tax_pct=0, tax_flat=float(order.tax or 0),
        tip=float(order.tip or 0),
    )
    paid_amount, change_due, err = compute_settlement(totals, payments)
    if err:
        flash(err, "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    # Allocate invoice number (atomic update on settings row)
    settings = _settings_for(owner_id)
    invoice_no, new_seq = next_invoice_number(settings.invoice_prefix or "INV",
                                              int(settings.invoice_seq or 0))
    settings.invoice_seq = new_seq

    # Persist
    primary_method = max(payments, key=lambda p: p["amount"])["method"] if payments else ""
    order.payment_status = "paid"
    order.payment_method = primary_method
    order.payments_breakdown = payments
    order.invoice_number = invoice_no
    order.paid_at = datetime.now(timezone.utc)
    order.settled_by = owner_id
    order.updated_at = order.paid_at
    if order.status in ("pending", "preparing", "ready"):
        order.status = "served"
    db.session.commit()

    _billing_log(owner_id=owner_id, order_id=order.id, action="settled",
                 invoice_number=invoice_no, amount=totals.total,
                 payment_method=primary_method,
                 payload={"payments": payments, "change_due": change_due,
                          "paid_amount": paid_amount, "total": totals.total})
    _invalidate_billing_cache(owner_id)
    msg = f"Settled. Invoice {invoice_no}."
    if change_due > 0:
        msg += f" Change due: ₹{change_due:.2f}."
    flash(msg, "billing_ok")
    return redirect(url_for("owner_billing_invoice", order_id=order_id))


@app.route("/owner/billing/orders/<int:order_id>/void", methods=["POST"])
@login_required
def owner_billing_void(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status != "unpaid":
        flash("Only unpaid bills can be voided. Use refund for settled bills.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    reason = (request.form.get("reason") or "").strip()[:500]
    if not reason:
        flash("Voiding requires a reason for the audit log.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    order.payment_status = "voided"
    order.void_reason = reason
    order.status = "cancelled"
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="voided",
                 amount=float(order.total or 0), reason=reason)
    _invalidate_billing_cache(owner_id)
    flash(f"Bill #{order_id} voided.", "billing_ok")
    return redirect(url_for("owner_billing_open"))


@app.route("/owner/billing/orders/<int:order_id>/refund", methods=["POST"])
@login_required
def owner_billing_refund(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id, lock=True)
    if order.payment_status not in ("paid", "refunded"):
        flash("Only paid bills can be refunded.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    try:
        amount = float(request.form.get("amount", 0) or 0)
    except ValueError:
        flash("Invalid refund amount.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    reason = (request.form.get("reason") or "").strip()[:500]
    if amount <= 0:
        flash("Refund amount must be positive.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    already = float(order.refund_amount or 0)
    max_refundable = float(order.total or 0) - already
    if amount > max_refundable + 0.01:
        flash(f"Cannot refund ₹{amount:.2f} — only ₹{max_refundable:.2f} remains refundable.",
              "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))
    if not reason:
        flash("Refunds require a reason for the audit log.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    order.refund_amount = round(already + amount, 2)
    order.refund_reason = reason
    if abs(float(order.refund_amount) - float(order.total or 0)) < 0.01:
        order.payment_status = "refunded"
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id, action="refunded",
                 amount=amount, reason=reason,
                 invoice_number=order.invoice_number or "",
                 payload={"refund_amount_total": float(order.refund_amount),
                          "remaining": max(0.0, float(order.total or 0) - float(order.refund_amount))})
    _invalidate_billing_cache(owner_id)
    flash(f"Refunded ₹{amount:.2f}. Total refunded so far: ₹{float(order.refund_amount):.2f}.",
          "billing_ok")
    return redirect(url_for("owner_billing_order_detail", order_id=order_id))


@app.route("/owner/billing/invoice/<int:order_id>")
@login_required
def owner_billing_invoice(order_id: int):
    owner_id = logged_in_owner_id()
    order = _load_owner_order(order_id, owner_id)
    settings = _settings_for(owner_id)
    owner = db.session.get(Owner, owner_id)
    return render_template("owner_billing/invoice.html",
                           order=_bill_dict(order),
                           settings=settings,
                           owner=owner)


@app.route("/owner/billing/eod")
@login_required
def owner_billing_eod():
    owner_id = logged_in_owner_id()
    # Date filter — defaults to today (UTC). Owners can pick a past date.
    date_str = (request.args.get("date") or "").strip()
    try:
        if date_str:
            day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            day, _ = _today_window()
    except ValueError:
        day, _ = _today_window()
    end = day + timedelta(days=1)

    paid = (Order.query
            .filter(Order.owner_id == owner_id,
                    Order.payment_status.in_(("paid", "refunded")),
                    Order.paid_at >= day, Order.paid_at < end)
            .order_by(Order.paid_at.asc()).all())

    voided = (Order.query
              .filter(Order.owner_id == owner_id,
                      Order.payment_status == "voided",
                      Order.updated_at >= day, Order.updated_at < end)
              .all())

    flat_payments: list[dict] = []
    for o in paid:
        for p in (o.payments_breakdown or []):
            if isinstance(p, dict):
                flat_payments.append(p)
    by_mode = summarise_payment_breakdown(flat_payments)

    summary = {
        "date": day.strftime("%Y-%m-%d"),
        "orders": len(paid),
        "gross_revenue": round(sum(float(o.total or 0) for o in paid), 2),
        "discounts": round(sum(float(o.discount or 0) for o in paid), 2),
        "service_charge": round(sum(float(o.service_charge or 0) for o in paid), 2),
        "tax": round(sum(float(o.tax or 0) for o in paid), 2),
        "tips": round(sum(float(o.tip or 0) for o in paid), 2),
        "refunds": round(sum(float(o.refund_amount or 0) for o in paid), 2),
        "voided_count": len(voided),
        "voided_value": round(sum(float(o.total or 0) for o in voided), 2),
        "by_mode": by_mode,
    }
    summary["net_revenue"] = round(summary["gross_revenue"] - summary["refunds"], 2)

    return _no_store(app.make_response(render_template(
        "owner_billing/eod.html",
        summary=summary,
        paid=[_bill_dict(o) for o in paid],
        voided=[_bill_dict(o) for o in voided],
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/billing/eod.csv")
@login_required
def owner_billing_eod_csv():
    owner_id = logged_in_owner_id()
    date_str = (request.args.get("date") or "").strip()
    try:
        if date_str:
            day = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            day, _ = _today_window()
    except ValueError:
        day, _ = _today_window()
    end = day + timedelta(days=1)
    rows = (Order.query
            .filter(Order.owner_id == owner_id,
                    Order.payment_status.in_(("paid", "refunded")),
                    Order.paid_at >= day, Order.paid_at < end)
            .order_by(Order.paid_at.asc()).all())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["invoice_number", "order_id", "paid_at_utc", "table", "customer",
                "subtotal", "discount", "service_charge", "tax", "tip",
                "total", "refund_amount", "primary_method", "status"])
    for o in rows:
        w.writerow([
            o.invoice_number or "", o.id,
            o.paid_at.isoformat() if o.paid_at else "",
            o.table_name or "", o.customer_name or "",
            float(o.subtotal or 0), float(o.discount or 0),
            float(o.service_charge or 0), float(o.tax or 0),
            float(o.tip or 0), float(o.total or 0),
            float(o.refund_amount or 0),
            o.payment_method or "", o.payment_status or "",
        ])
    out = make_response(buf.getvalue())
    out.headers["Content-Type"] = "text/csv; charset=utf-8"
    out.headers["Content-Disposition"] = f'attachment; filename="eod-{day:%Y-%m-%d}.csv"'
    return out


@app.route("/owner/billing/logs")
@login_required
def owner_billing_logs():
    owner_id = logged_in_owner_id()
    page = max(1, int(request.args.get("page", "1") or "1"))
    per_page = 100
    action = (request.args.get("action") or "").strip().lower()
    q = BillingLog.query.filter_by(owner_id=owner_id)
    if action in ("settled", "voided", "refunded", "adjusted"):
        q = q.filter(BillingLog.action == action)
    total = q.count()
    logs = (q.order_by(BillingLog.created_at.desc())
              .offset((page - 1) * per_page).limit(per_page).all())
    return _no_store(app.make_response(render_template(
        "owner_billing/logs.html",
        logs=logs, page=page, per_page=per_page, total=total,
        action=action,
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/billing/settings", methods=["GET", "POST"])
@login_required
def owner_billing_settings():
    owner_id = logged_in_owner_id()
    settings = _settings_for(owner_id)
    if request.method == "POST":
        try:
            settings.tax_rate_percent = max(0.0, min(float(request.form.get("tax_rate_percent", 0) or 0), 100.0))
            settings.service_charge_percent = max(0.0, min(float(request.form.get("service_charge_percent", 0) or 0), 100.0))
        except ValueError:
            flash("Tax / service charge percent must be a number 0-100.", "billing_error")
            return redirect(url_for("owner_billing_settings"))
        settings.tax_label = (request.form.get("tax_label") or "GST").strip()[:32] or "GST"
        settings.gstin = (request.form.get("gstin") or "").strip()[:32]
        settings.invoice_prefix = re.sub(r"[^A-Za-z0-9_\-/]", "", (request.form.get("invoice_prefix") or "INV"))[:16] or "INV"
        settings.billing_address = (request.form.get("billing_address") or "").strip()[:500]
        settings.billing_phone = (request.form.get("billing_phone") or "").strip()[:30]
        db.session.commit()
        flash("Billing settings saved.", "billing_ok")
        return redirect(url_for("owner_billing_settings"))
    return _no_store(app.make_response(render_template(
        "owner_billing/settings.html",
        settings=settings,
        owner_username=logged_in_owner(),
    )))


# ---------------------------------------------------------------------------
# Owner-managed payment provider credentials
# ---------------------------------------------------------------------------
#
# Each owner brings their own Stripe / Razorpay account. Secrets are
# encrypted at rest (see ``lib_payments.encrypt_secret``) and never
# returned to the browser in plaintext — only a masked tail. The owner
# can:
#
#   * add / replace credentials per provider
#   * mark one provider as the default for online charges
#   * test the connection (calls the provider's API with the keys)
#   * delete a provider, which also tears down active webhooks on our side
#
# Customers then pay through the hosted payment page at
# ``/billing/pay/<order_id>`` and the provider notifies us via
# ``/billing/webhook/<provider>``, which auto-settles the bill.

def _provider_for_credential(cred: "PaymentProviderCredential"):
    return build_provider(
        cred.provider,
        public_key=cred.public_key,
        secret_key=decrypt_secret(cred.secret_key_enc),
        webhook_secret=decrypt_secret(cred.webhook_secret_enc),
        mode=cred.mode,
    )


def _default_payment_credential(owner_id: int) -> "PaymentProviderCredential | None":
    q = PaymentProviderCredential.query.filter_by(owner_id=owner_id, is_active=True)
    return (q.filter_by(is_default=True).first()
            or q.order_by(PaymentProviderCredential.updated_at.desc()).first())


def _secret_fingerprint(secret: str) -> str:
    """A short, non-reversible tag for a secret. Used to detect whether the
    currently-stored secret is the same one that was last verified — so we
    can require a fresh test after rotation before allowing live mode."""
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def _credential_view(cred: "PaymentProviderCredential") -> dict:
    try:
        secret_plain = decrypt_secret(cred.secret_key_enc) if cred.secret_key_enc else ""
    except Exception:  # noqa: BLE001 — encryption-key rotation case
        secret_plain = ""
    current_fp = _secret_fingerprint(secret_plain)
    is_verified = bool(cred.verified_at and cred.verified_fingerprint == current_fp and current_fp)
    guide = PROVIDER_GUIDES.get(cred.provider, {})
    return {
        "id": cred.id,
        "provider": cred.provider,
        "provider_label": PROVIDER_LABELS.get(cred.provider, cred.provider.title()),
        "display_name": cred.display_name or PROVIDER_LABELS.get(cred.provider, cred.provider),
        "public_key_masked": mask_secret(cred.public_key),
        "has_secret": bool(cred.secret_key_enc),
        "has_webhook": bool(cred.webhook_secret_enc),
        "mode": cred.mode,
        "is_active": bool(cred.is_active),
        "is_default": bool(cred.is_default),
        "is_verified": is_verified,
        "verified_at": cred.verified_at,
        "last_tested_at": cred.last_tested_at,
        "last_test_status": cred.last_test_status,
        "last_test_message": cred.last_test_message,
        "webhook_url": url_for("billing_webhook", provider=cred.provider, _external=True),
        "guide": guide,
    }


def _enforce_https_for_webhooks() -> bool:
    """Production deployments MUST receive webhooks over HTTPS — providers
    refuse to send them otherwise, but we also assert here so misconfigs
    surface as a 400 instead of a silent 'no payments arriving'."""
    return os.environ.get("FLASK_ENV", "").lower() == "production" or \
        bool(os.environ.get("RAILWAY_ENVIRONMENT"))


@app.route("/owner/billing/payment-methods")
@login_required
def owner_billing_payment_methods():
    owner_id = logged_in_owner_id()
    creds = (PaymentProviderCredential.query
             .filter_by(owner_id=owner_id)
             .order_by(PaymentProviderCredential.created_at.desc()).all())
    configured_providers = {c.provider for c in creds}
    available = [
        {"slug": p, "label": PROVIDER_LABELS.get(p, p.title()),
         "guide": PROVIDER_GUIDES.get(p, {})}
        for p in SUPPORTED_PROVIDERS if p not in configured_providers
    ]
    sample_webhook_url = url_for("billing_webhook", provider="<provider>", _external=True)
    return _no_store(app.make_response(render_template(
        "owner_billing/payment_methods.html",
        credentials=[_credential_view(c) for c in creds],
        available_providers=available,
        provider_labels=PROVIDER_LABELS,
        provider_guides=PROVIDER_GUIDES,
        sample_webhook_url=sample_webhook_url,
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/billing/payment-methods/save", methods=["POST"])
@login_required
@limiter.limit("20 per hour; 5 per minute")
def owner_billing_payment_methods_save():
    owner_id = logged_in_owner_id()
    provider = (request.form.get("provider") or "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        flash(f"Unsupported provider: {provider!r}.", "billing_error")
        return redirect(url_for("owner_billing_payment_methods"))

    cred = (PaymentProviderCredential.query
            .filter_by(owner_id=owner_id, provider=provider).first())
    is_new = cred is None
    if is_new:
        cred = PaymentProviderCredential(owner_id=owner_id, provider=provider)
        db.session.add(cred)

    cred.display_name = (request.form.get("display_name") or "").strip()[:80]
    # Only overwrite the public key if a non-empty, non-masked value was
    # submitted. Masked placeholder values like "rzp_••••wxyz" must never
    # be persisted — that was the v1 bug. We detect masking by the bullet
    # character, which never appears in a real provider key.
    submitted_public = (request.form.get("public_key") or "").strip()[:200]
    if submitted_public and "•" not in submitted_public:
        cred.public_key = submitted_public
    secret_key = (request.form.get("secret_key") or "").strip()
    webhook_secret = (request.form.get("webhook_secret") or "").strip()
    secret_changed = False
    if secret_key:
        cred.secret_key_enc = encrypt_secret(secret_key)
        secret_changed = True
    if webhook_secret:
        cred.webhook_secret_enc = encrypt_secret(webhook_secret)
    requested_mode = (request.form.get("mode") or "").strip().lower()
    desired_mode = cred.mode or "test"
    if requested_mode in ("test", "live"):
        desired_mode = requested_mode
    elif secret_key or cred.public_key:
        detected = detect_mode_from_key(
            provider, cred.public_key,
            secret_key or (decrypt_secret(cred.secret_key_enc) if cred.secret_key_enc else "")
        )
        if detected != "unknown":
            desired_mode = detected

    if not cred.public_key or not cred.secret_key_enc:
        flash(f"{PROVIDER_LABELS[provider]} requires both a key id and a secret.",
              "billing_error")
        db.session.rollback()
        return redirect(url_for("owner_billing_payment_methods"))

    desired_active = bool(request.form.get("is_active"))
    desired_default = bool(request.form.get("is_default"))

    # Production guard: never let an owner activate live mode against
    # un-verified credentials. Forcing a successful test_connection
    # against the saved keys before going live prevents the most common
    # support ticket — "I copied my live keys and now no payments work."
    if secret_changed:
        cred.verified_at = None
        cred.verified_fingerprint = ""
    if desired_mode == "live" and desired_active:
        try:
            current_secret = decrypt_secret(cred.secret_key_enc)
        except Exception:  # noqa: BLE001
            current_secret = ""
        current_fp = _secret_fingerprint(current_secret)
        already_verified = bool(
            cred.verified_at and cred.verified_fingerprint == current_fp and current_fp
        )
        if not already_verified:
            # Auto-test now and only activate if it passes.
            try:
                provider_obj = build_provider(
                    provider, public_key=cred.public_key,
                    secret_key=current_secret,
                    webhook_secret=(decrypt_secret(cred.webhook_secret_enc)
                                    if cred.webhook_secret_enc else ""),
                    mode=desired_mode,
                )
                msg = provider_obj.test_connection()
                cred.last_test_status = "ok"
                cred.last_test_message = msg[:500]
                cred.last_tested_at = datetime.now(timezone.utc)
                cred.verified_at = cred.last_tested_at
                cred.verified_fingerprint = current_fp
            except PaymentProviderError as exc:
                cred.last_test_status = "error"
                cred.last_test_message = str(exc)[:500]
                cred.last_tested_at = datetime.now(timezone.utc)
                desired_active = False  # refuse to activate
                flash(
                    f"Refusing to activate live mode — {provider.title()} rejected the keys: {exc}",
                    "billing_error",
                )

    cred.mode = desired_mode
    cred.is_active = desired_active

    if desired_default and desired_active:
        PaymentProviderCredential.query.filter(
            PaymentProviderCredential.owner_id == owner_id,
            PaymentProviderCredential.id != (cred.id or -1),
        ).update({"is_default": False})
        cred.is_default = True
    elif not desired_default:
        cred.is_default = False

    db.session.commit()
    _billing_log(
        owner_id=owner_id, order_id=None,
        action=f"payment_methods.{provider}.saved",
        amount=0, payment_method=provider,
        reason=f"credential {'created' if is_new else 'updated'}; mode={cred.mode}; active={cred.is_active}",
        payload={"provider": provider, "mode": cred.mode,
                 "is_active": cred.is_active, "is_default": cred.is_default,
                 "public_key_masked": mask_secret(cred.public_key),
                 "secret_rotated": secret_changed,
                 "webhook_rotated": bool(webhook_secret)},
    )
    flash(
        f"{PROVIDER_LABELS[provider]} saved ({cred.mode} mode, "
        f"{'active' if cred.is_active else 'disabled'}).",
        "billing_ok",
    )
    return redirect(url_for("owner_billing_payment_methods"))


@app.route("/owner/billing/payment-methods/<int:cred_id>/test", methods=["POST"])
@login_required
@limiter.limit("30 per hour; 5 per minute")
def owner_billing_payment_methods_test(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(id=cred_id, owner_id=owner_id).first_or_404()
    try:
        provider_obj = _provider_for_credential(cred)
        msg = provider_obj.test_connection()
        cred.last_test_status = "ok"
        cred.last_test_message = msg[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        try:
            cred.verified_fingerprint = _secret_fingerprint(decrypt_secret(cred.secret_key_enc))
            cred.verified_at = cred.last_tested_at
        except Exception:  # noqa: BLE001
            pass
        db.session.commit()
        _billing_log(owner_id=owner_id, order_id=None,
                     action=f"payment_methods.{cred.provider}.tested",
                     amount=0, payment_method=cred.provider,
                     reason="connection test ok",
                     payload={"provider": cred.provider, "mode": cred.mode})
        flash(msg, "billing_ok")
    except PaymentProviderError as exc:
        cred.last_test_status = "error"
        cred.last_test_message = str(exc)[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        db.session.commit()
        flash(f"Test failed: {exc}", "billing_error")
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("payment test crashed")
        flash(f"Unexpected error testing credentials: {exc}", "billing_error")
    return redirect(url_for("owner_billing_payment_methods"))


@app.route("/owner/billing/payment-methods/<int:cred_id>/delete", methods=["POST"])
@login_required
def owner_billing_payment_methods_delete(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(id=cred_id, owner_id=owner_id).first_or_404()
    provider = cred.provider
    db.session.delete(cred)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=None,
                 action=f"payment_methods.{provider}.deleted",
                 amount=0, payment_method=provider, reason="credential removed",
                 payload={"provider": provider})
    flash(f"{PROVIDER_LABELS.get(provider, provider).title()} credentials removed.", "billing_ok")
    return redirect(url_for("owner_billing_payment_methods"))


# ---------------------------------------------------------------------------
# Online charge flow — owner-side: create the intent for an open bill
# ---------------------------------------------------------------------------

@app.route("/owner/billing/orders/<int:order_id>/charge", methods=["POST"])
@login_required
def owner_billing_create_charge(order_id: int):
    owner_id = logged_in_owner_id()
    order = Order.query.filter_by(id=order_id, owner_id=owner_id).first_or_404()
    if (order.payment_status or "unpaid") == "paid":
        flash("This bill is already settled.", "billing_info")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    provider_name = (request.form.get("provider") or "").strip().lower()
    if provider_name:
        cred = PaymentProviderCredential.query.filter_by(
            owner_id=owner_id, provider=provider_name, is_active=True).first()
    else:
        cred = _default_payment_credential(owner_id)
    if cred is None:
        flash("Configure a payment provider first under Payment Methods.", "billing_error")
        return redirect(url_for("owner_billing_payment_methods"))

    settings = _settings_for(owner_id)
    totals = compute_bill_totals(
        subtotal=float(order.amount or 0),
        discount=float(order.discount or 0),
        service_charge_pct=float(settings.service_charge_percent or 0),
        tax_pct=float(settings.tax_rate_percent or 0),
    )
    amount_minor = int(round(totals.total * 100))
    if amount_minor <= 0:
        flash("Bill total is zero — nothing to charge.", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    try:
        provider = _provider_for_credential(cred)
        intent = provider.create_payment_intent(
            amount_minor=amount_minor,
            currency="INR",
            order_id=order.id,
            description=f"Order #{order.id} at {logged_in_owner() or 'Cafe'}",
            customer_email="",
            customer_phone=getattr(order, "customer_phone", "") or "",
            return_url=url_for("billing_pay_page", order_id=order.id, _external=True),
        )
    except PaymentProviderError as exc:
        flash(f"Could not start the online charge: {exc}", "billing_error")
        return redirect(url_for("owner_billing_order_detail", order_id=order_id))

    op = OnlinePayment(
        owner_id=owner_id, order_id=order.id, provider=cred.provider,
        intent_id=intent.intent_id, amount=totals.total, currency="INR",
        status="pending", customer_phone=(getattr(order, "customer_phone", "") or "")[:30],
        raw={"client_secret_present": bool(intent.client_secret),
             "checkout_url": intent.checkout_url, "extra": intent.raw},
    )
    db.session.add(op)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=order.id,
                 action="online_charge.created",
                 amount=totals.total, payment_method=cred.provider,
                 reason="payment intent created",
                 payload={"intent_id": intent.intent_id, "provider": cred.provider})
    flash("Payment link created. Share it with the customer.", "billing_ok")
    return redirect(url_for("billing_pay_page", order_id=order.id))


# ---------------------------------------------------------------------------
# Customer-facing hosted pay page + provider webhook
# ---------------------------------------------------------------------------

@app.route("/billing/pay/<int:order_id>")
def billing_pay_page(order_id: int):
    order = Order.query.get_or_404(order_id)
    op = (OnlinePayment.query
          .filter_by(order_id=order.id)
          .order_by(OnlinePayment.created_at.desc()).first())
    if op is None:
        return ("No active payment for this order.", 404)
    cred = PaymentProviderCredential.query.filter_by(
        owner_id=op.owner_id, provider=op.provider).first()
    if cred is None:
        return ("Payment provider is no longer configured.", 410)
    return _no_store(app.make_response(render_template(
        "owner_billing/customer_pay.html",
        order=order, payment=op, provider=op.provider,
        public_key=cred.public_key, mode=cred.mode,
        amount_minor=int(round(float(op.amount or 0) * 100)),
        currency=op.currency or "INR",
    )))


@app.route("/owner/billing/payment-methods/<int:cred_id>/delete", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_billing_payment_methods_delete(cred_id: int):
    """Two-step delete: requires the typed provider name as confirmation,
    so a stray click in the dashboard cannot wipe live keys."""
    owner_id = logged_in_owner_id()
    cred = PaymentProviderCredential.query.filter_by(
        id=cred_id, owner_id=owner_id).first_or_404()
    typed = (request.form.get("confirm_provider") or "").strip().lower()
    if typed != cred.provider:
        flash(f"Type '{cred.provider}' to confirm deletion.", "billing_error")
        return redirect(url_for("owner_billing_payment_methods"))
    provider = cred.provider
    db.session.delete(cred)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=None,
                 action=f"payment_methods.{provider}.deleted",
                 amount=0, payment_method=provider,
                 reason="credential removed by owner",
                 payload={"provider": provider})
    flash(f"{PROVIDER_LABELS.get(provider, provider)} credentials removed.", "billing_ok")
    return redirect(url_for("owner_billing_payment_methods"))


# ============================================================================
# Aggregator Platforms (Swiggy / Zomato / Uber Eats)
# ============================================================================

def _aggregator_for_credential(cred: "AggregatorPlatformCredential"):
    return build_aggregator(
        cred.platform,
        api_key=cred.api_key or "",
        secret=decrypt_secret(cred.secret_enc) if cred.secret_enc else "",
        webhook_secret=(decrypt_secret(cred.webhook_secret_enc)
                        if cred.webhook_secret_enc else ""),
        merchant_id=cred.merchant_id or "",
        mode=cred.mode or "test",
    )


def _aggregator_credential_view(cred: "AggregatorPlatformCredential") -> dict:
    try:
        secret_plain = decrypt_secret(cred.secret_enc) if cred.secret_enc else ""
    except Exception:  # noqa: BLE001
        secret_plain = ""
    current_fp = _secret_fingerprint(secret_plain)
    is_verified = bool(cred.verified_at and cred.verified_fingerprint == current_fp and current_fp)
    return {
        "id": cred.id,
        "platform": cred.platform,
        "platform_label": PLATFORM_LABELS.get(cred.platform, cred.platform.title()),
        "display_name": cred.display_name or PLATFORM_LABELS.get(cred.platform, cred.platform),
        "api_key_masked": mask_secret(cred.api_key),
        "merchant_id": cred.merchant_id or "",
        "has_secret": bool(cred.secret_enc),
        "has_webhook": bool(cred.webhook_secret_enc),
        "mode": cred.mode,
        "is_active": bool(cred.is_active),
        "auto_accept": bool(cred.auto_accept),
        "is_verified": is_verified,
        "verified_at": cred.verified_at,
        "last_tested_at": cred.last_tested_at,
        "last_test_status": cred.last_test_status,
        "last_test_message": cred.last_test_message,
        "webhook_url": url_for("aggregator_webhook", platform=cred.platform, _external=True),
        "guide": PLATFORM_GUIDES.get(cred.platform, {}),
    }


@app.route("/owner/aggregators")
@login_required
def owner_aggregators():
    owner_id = logged_in_owner_id()
    creds = (AggregatorPlatformCredential.query
             .filter_by(owner_id=owner_id)
             .order_by(AggregatorPlatformCredential.created_at.desc()).all())
    configured = {c.platform for c in creds}
    available = [
        {"slug": p, "label": PLATFORM_LABELS.get(p, p.title()),
         "guide": PLATFORM_GUIDES.get(p, {})}
        for p in SUPPORTED_PLATFORMS if p not in configured
    ]
    recent = (AggregatorOrder.query.filter_by(owner_id=owner_id)
              .order_by(AggregatorOrder.created_at.desc()).limit(50).all())
    return _no_store(app.make_response(render_template(
        "owner_aggregators/index.html",
        credentials=[_aggregator_credential_view(c) for c in creds],
        available_platforms=available,
        platform_labels=PLATFORM_LABELS,
        recent_orders=recent,
        owner_username=logged_in_owner(),
    )))


@app.route("/owner/aggregators/save", methods=["POST"])
@login_required
@limiter.limit("20 per hour; 5 per minute")
def owner_aggregators_save():
    owner_id = logged_in_owner_id()
    platform = (request.form.get("platform") or "").strip().lower()
    if platform not in SUPPORTED_PLATFORMS:
        flash(f"Unsupported platform: {platform!r}.", "billing_error")
        return redirect(url_for("owner_aggregators"))

    cred = (AggregatorPlatformCredential.query
            .filter_by(owner_id=owner_id, platform=platform).first())
    is_new = cred is None
    if is_new:
        cred = AggregatorPlatformCredential(owner_id=owner_id, platform=platform)
        db.session.add(cred)

    cred.display_name = (request.form.get("display_name") or "").strip()[:80]
    submitted_api = (request.form.get("api_key") or "").strip()[:200]
    if submitted_api and "•" not in submitted_api:
        cred.api_key = submitted_api
    cred.merchant_id = (request.form.get("merchant_id") or "").strip()[:120]
    secret = (request.form.get("secret") or "").strip()
    webhook_secret = (request.form.get("webhook_secret") or "").strip()
    secret_changed = False
    if secret:
        cred.secret_enc = encrypt_secret(secret)
        secret_changed = True
    if webhook_secret:
        cred.webhook_secret_enc = encrypt_secret(webhook_secret)
    requested_mode = (request.form.get("mode") or "").strip().lower()
    if requested_mode in ("test", "live"):
        cred.mode = requested_mode

    if not cred.api_key or not cred.secret_enc or not cred.merchant_id:
        flash(f"{PLATFORM_LABELS[platform]} requires API key, secret and merchant ID.",
              "billing_error")
        db.session.rollback()
        return redirect(url_for("owner_aggregators"))

    if secret_changed:
        cred.verified_at = None
        cred.verified_fingerprint = ""

    desired_active = bool(request.form.get("is_active"))
    cred.auto_accept = bool(request.form.get("auto_accept"))

    # Same live-mode safety net as payments: never activate live without
    # a fresh successful test against the partner API.
    if cred.mode == "live" and desired_active:
        try:
            current_secret = decrypt_secret(cred.secret_enc)
        except Exception:  # noqa: BLE001
            current_secret = ""
        current_fp = _secret_fingerprint(current_secret)
        already_verified = bool(
            cred.verified_at and cred.verified_fingerprint == current_fp and current_fp
        )
        if not already_verified:
            try:
                ag = build_aggregator(
                    platform, api_key=cred.api_key, secret=current_secret,
                    webhook_secret=(decrypt_secret(cred.webhook_secret_enc)
                                    if cred.webhook_secret_enc else ""),
                    merchant_id=cred.merchant_id, mode=cred.mode,
                )
                msg = ag.test_connection()
                cred.last_test_status = "ok"
                cred.last_test_message = msg[:500]
                cred.last_tested_at = datetime.now(timezone.utc)
                cred.verified_at = cred.last_tested_at
                cred.verified_fingerprint = current_fp
            except AggregatorError as exc:
                cred.last_test_status = "error"
                cred.last_test_message = str(exc)[:500]
                cred.last_tested_at = datetime.now(timezone.utc)
                desired_active = False
                flash(
                    f"Refusing to activate {PLATFORM_LABELS[platform]} live mode — "
                    f"partner rejected the keys: {exc}",
                    "billing_error",
                )

    cred.is_active = desired_active
    db.session.commit()
    _billing_log(
        owner_id=owner_id, order_id=None,
        action=f"aggregator.{platform}.saved",
        amount=0, payment_method=f"aggregator:{platform}",
        reason=f"credential {'created' if is_new else 'updated'}; mode={cred.mode}; active={cred.is_active}",
        payload={"platform": platform, "mode": cred.mode,
                 "is_active": cred.is_active, "auto_accept": cred.auto_accept,
                 "merchant_id": cred.merchant_id,
                 "api_key_masked": mask_secret(cred.api_key),
                 "secret_rotated": secret_changed,
                 "webhook_rotated": bool(webhook_secret)},
    )
    flash(f"{PLATFORM_LABELS[platform]} saved ({cred.mode} mode, "
          f"{'active' if cred.is_active else 'disabled'}).", "billing_ok")
    return redirect(url_for("owner_aggregators"))


@app.route("/owner/aggregators/<int:cred_id>/test", methods=["POST"])
@login_required
@limiter.limit("30 per hour; 5 per minute")
def owner_aggregators_test(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = AggregatorPlatformCredential.query.filter_by(
        id=cred_id, owner_id=owner_id).first_or_404()
    try:
        ag = _aggregator_for_credential(cred)
        msg = ag.test_connection()
        cred.last_test_status = "ok"
        cred.last_test_message = msg[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        try:
            cred.verified_fingerprint = _secret_fingerprint(decrypt_secret(cred.secret_enc))
            cred.verified_at = cred.last_tested_at
        except Exception:  # noqa: BLE001
            pass
        db.session.commit()
        flash(msg, "billing_ok")
    except AggregatorError as exc:
        cred.last_test_status = "error"
        cred.last_test_message = str(exc)[:500]
        cred.last_tested_at = datetime.now(timezone.utc)
        db.session.commit()
        flash(f"Test failed: {exc}", "billing_error")
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("aggregator test crashed")
        flash(f"Unexpected error: {exc}", "billing_error")
    return redirect(url_for("owner_aggregators"))


@app.route("/owner/aggregators/<int:cred_id>/delete", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_aggregators_delete(cred_id: int):
    owner_id = logged_in_owner_id()
    cred = AggregatorPlatformCredential.query.filter_by(
        id=cred_id, owner_id=owner_id).first_or_404()
    typed = (request.form.get("confirm_platform") or "").strip().lower()
    if typed != cred.platform:
        flash(f"Type '{cred.platform}' to confirm deletion.", "billing_error")
        return redirect(url_for("owner_aggregators"))
    platform = cred.platform
    db.session.delete(cred)
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=None,
                 action=f"aggregator.{platform}.deleted",
                 amount=0, payment_method=f"aggregator:{platform}",
                 reason="credential removed by owner", payload={"platform": platform})
    flash(f"{PLATFORM_LABELS.get(platform, platform)} disconnected.", "billing_ok")
    return redirect(url_for("owner_aggregators"))


@app.route("/owner/aggregators/orders/<int:agg_id>/<action>", methods=["POST"])
@login_required
@limiter.limit("120 per hour")
def owner_aggregator_order_action(agg_id: int, action: str):
    """Staff acks an aggregator order — accept/reject/ready. Pushes the
    state back to the partner and updates both the bridge row and the
    underlying internal Order so the kitchen ticket stays in sync."""
    owner_id = logged_in_owner_id()
    if action not in ("accept", "reject", "ready"):
        return ("bad action", 400)
    agg = AggregatorOrder.query.filter_by(id=agg_id, owner_id=owner_id).first_or_404()
    cred = AggregatorPlatformCredential.query.filter_by(
        owner_id=owner_id, platform=agg.platform, is_active=True).first()
    if cred is None:
        flash(f"{agg.platform} integration is not active.", "billing_error")
        return redirect(url_for("owner_aggregators"))
    reason = (request.form.get("reason") or "").strip()[:200]
    try:
        ag = _aggregator_for_credential(cred)
        ag.acknowledge_order(external_order_id=agg.external_order_id,
                             action=action, reason=reason)
    except AggregatorError as exc:
        flash(f"Partner rejected the {action}: {exc}", "billing_error")
        return redirect(url_for("owner_aggregators"))

    now = datetime.now(timezone.utc)
    if action == "accept":
        agg.accepted_at = now
        agg.aggregator_status = "accepted"
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o and o.status in ("pending", "new"):
                o.status = "preparing"
    elif action == "reject":
        agg.rejected_at = now
        agg.aggregator_status = "rejected"
        agg.rejected_reason = reason
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "cancelled"
    else:  # ready
        agg.food_ready_at = now
        agg.aggregator_status = "ready"
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "ready"
    db.session.commit()
    _billing_log(owner_id=owner_id, order_id=agg.order_id,
                 action=f"aggregator.{agg.platform}.{action}",
                 amount=float(agg.total or 0),
                 payment_method=f"aggregator:{agg.platform}",
                 reason=reason or f"order {action}",
                 payload={"external_order_id": agg.external_order_id,
                          "platform": agg.platform})
    flash(f"{PLATFORM_LABELS.get(agg.platform, agg.platform)} order #{agg.external_order_id} {action}ed.",
          "billing_ok")
    return redirect(url_for("owner_aggregators"))


def _settle_aggregator_order(cred: "AggregatorPlatformCredential",
                              event) -> "AggregatorOrder":
    """Idempotent upsert of an inbound aggregator order.

    Returns the AggregatorOrder row; creates a backing internal Order on
    the first NEW_ORDER event so the kitchen sees it immediately, and
    auto-accepts when ``cred.auto_accept`` is on. Subsequent events for
    the same external_order_id (cancellations, rider assignments,
    status updates) only mutate the existing rows."""
    owner_id = cred.owner_id
    agg = AggregatorOrder.query.filter_by(
        platform=cred.platform, external_order_id=event.external_order_id
    ).first()
    is_new = agg is None
    if is_new:
        agg = AggregatorOrder(
            owner_id=owner_id, platform=cred.platform,
            external_order_id=event.external_order_id,
        )
        db.session.add(agg)
    agg.customer_name = event.customer_name or agg.customer_name
    agg.customer_phone = event.customer_phone or agg.customer_phone
    agg.items_snapshot = event.items
    agg.subtotal = round(event.subtotal_minor / 100.0, 2) if event.subtotal_minor else agg.subtotal
    agg.total = round(event.total_minor / 100.0, 2) if event.total_minor else agg.total
    agg.currency = event.currency or agg.currency
    agg.aggregator_status = event.status
    agg.pickup_eta_minutes = event.pickup_eta_minutes or agg.pickup_eta_minutes
    if event.rider_name:
        agg.rider_name = event.rider_name
    if event.rider_phone:
        agg.rider_phone = event.rider_phone
    if event.notes:
        agg.notes = event.notes
    agg.raw = {"event_type": event.event_type, "object": event.raw}

    if event.status == "cancelled":
        agg.rejected_at = agg.rejected_at or datetime.now(timezone.utc)
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "cancelled"
    elif event.status == "delivered":
        agg.delivered_at = datetime.now(timezone.utc)
        if agg.order_id:
            o = Order.query.filter_by(id=agg.order_id, owner_id=owner_id).first()
            if o:
                o.status = "completed"
    elif is_new and event.status == "placed":
        # Mirror to internal Order so the kitchen workflow stays uniform
        # regardless of order source. Owner-id scoped; price already in
        # major units after the divide above.
        order = Order(
            owner_id=owner_id,
            customer_name=event.customer_name or f"{cred.platform} customer",
            customer_phone=event.customer_phone,
            items=event.items,
            subtotal=agg.subtotal, total=agg.total,
            status="pending",
            origin=cred.platform,
            notes=event.notes or "",
        )
        db.session.add(order)
        db.session.flush()
        agg.order_id = order.id

        if cred.auto_accept:
            try:
                ag = _aggregator_for_credential(cred)
                ag.acknowledge_order(external_order_id=event.external_order_id,
                                      action="accept")
                agg.accepted_at = datetime.now(timezone.utc)
                agg.aggregator_status = "accepted"
                order.status = "preparing"
            except AggregatorError as exc:
                app.logger.warning("auto-accept failed: %s", exc)
    return agg


@csrf.exempt
@app.route("/aggregators/webhook/<platform>", methods=["POST"])
@limiter.limit("600 per minute")
def aggregator_webhook(platform: str):
    """Inbound order push from Swiggy/Zomato/UberEats.

    Same defence-in-depth as the payment webhook: HTTPS-only in
    production, signature verified against every active credential
    until one matches, then deduped via WebhookEventLog before any
    state mutation. Returns 200 on duplicate so the partner stops
    retrying."""
    platform = (platform or "").lower()
    if platform not in SUPPORTED_PLATFORMS:
        return ("unsupported platform", 404)

    if _enforce_https_for_webhooks():
        scheme = (request.headers.get("X-Forwarded-Proto") or request.scheme or "").lower()
        if scheme != "https":
            app.logger.warning("Rejected %s aggregator webhook over %s", platform, scheme)
            return ("https required", 400)

    body = request.get_data(cache=True) or b""
    headers = {k: v for k, v in request.headers.items()}

    candidates = (AggregatorPlatformCredential.query
                  .filter_by(platform=platform, is_active=True).all())
    if not candidates:
        return ("no platform configured", 404)

    event = None
    matched_cred = None
    last_error = None
    for cred in candidates:
        try:
            ag = _aggregator_for_credential(cred)
            event = ag.parse_webhook(body, headers)
            matched_cred = cred
            break
        except AggregatorError as exc:
            last_error = str(exc)
            continue
    if event is None:
        app.logger.warning("Aggregator signature failed for %d %s creds: %s",
                            len(candidates), platform, last_error)
        # Audit row so owners can see attempted forgeries / misconfig.
        try:
            db.session.add(WebhookEventLog(
                provider=f"agg:{platform}", event_id=f"bad:{int(time.time()*1000)}",
                intent_id="", event_type="signature_invalid",
                processed=False,
            ))
            db.session.commit()
        except Exception:  # noqa: BLE001
            db.session.rollback()
        return ("signature invalid", 400)

    # Dedupe on (platform, external_order_id, event_type) — for
    # aggregators we want to *re-process* status updates (rider assigned
    # after new_order) but not duplicate retries of the same event.
    raw_event_id = ""
    if isinstance(event.raw, dict):
        raw_event_id = str(event.raw.get("event_id")
                            or event.raw.get("id") or "")
    if not raw_event_id:
        raw_event_id = hashlib.sha256(
            f"{event.event_type}:{event.external_order_id}:".encode("utf-8") + body
        ).hexdigest()
    try:
        seen = WebhookEventLog.query.filter_by(
            provider=f"agg:{platform}", event_id=raw_event_id).first()
        if seen is not None:
            return ("ok (duplicate)", 200)
        db.session.add(WebhookEventLog(
            provider=f"agg:{platform}", event_id=raw_event_id,
            intent_id=event.external_order_id,
            event_type=event.event_type, processed=False,
        ))
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return ("ok (duplicate)", 200)

    _settle_aggregator_order(matched_cred, event)
    WebhookEventLog.query.filter_by(
        provider=f"agg:{platform}", event_id=raw_event_id
    ).update({"processed": True})
    db.session.commit()
    return ("ok", 200)


@csrf.exempt
@app.route("/billing/webhook/<provider>", methods=["POST"])
@limiter.limit("600 per minute")  # generous; providers retry hard
def billing_webhook(provider: str):
    """Provider-side notification — verifies signature, updates order.

    We look up *which* owner the event belongs to via the matching
    OnlinePayment row (provider+intent_id is globally unique because
    provider IDs are universally unique). This avoids needing one
    webhook URL per owner."""
    provider = (provider or "").lower()
    if provider not in SUPPORTED_PROVIDERS:
        return ("unsupported provider", 404)

    # Block plaintext callbacks in production — every supported provider
    # requires HTTPS for live webhooks, and accepting them over HTTP would
    # let an on-path attacker forge a "succeeded" event for any open order.
    if _enforce_https_for_webhooks():
        forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").lower()
        scheme = forwarded_proto or request.scheme
        if scheme != "https":
            app.logger.warning("Rejected %s webhook over %s (production)",
                               provider, scheme)
            return ("https required", 400)

    body = request.get_data(cache=True) or b""
    sig_header = (request.headers.get("Stripe-Signature")
                  or request.headers.get("X-Razorpay-Signature")
                  or request.headers.get("X-Signature")
                  or "")

    # Try to find the credential by parsing the event metadata first; if
    # that's not possible, fall back to trying every credential for this
    # provider until one verifies. In production with one cafe per
    # webhook URL, the first match wins immediately.
    candidates = (PaymentProviderCredential.query
                  .filter_by(provider=provider, is_active=True).all())
    if not candidates:
        return ("no provider configured", 404)

    event = None
    matched_cred = None
    last_error = None
    for cred in candidates:
        try:
            p = _provider_for_credential(cred)
            event = p.parse_webhook(body, sig_header)
            matched_cred = cred
            break
        except PaymentProviderError as exc:
            last_error = str(exc)
            continue
    if event is None:
        app.logger.warning("Webhook signature failed for all %d %s credentials: %s",
                           len(candidates), provider, last_error)
        return ("signature invalid", 400)

    # Idempotency: providers retry until they get a 2xx, and Stripe in
    # particular delivers each event at-least-once. Without this guard
    # we would settle the same order twice and double-emit invoice
    # numbers. We use the provider's event_id when available, otherwise
    # a SHA-256 of the raw body — both are stable across redeliveries.
    raw_event_id = ""
    if isinstance(event.raw, dict):
        raw_event_id = str(event.raw.get("id") or
                           event.raw.get("event_id") or
                           event.raw.get("data", {}).get("id") or "")
    if not raw_event_id:
        raw_event_id = hashlib.sha256(body).hexdigest()
    try:
        seen = WebhookEventLog.query.filter_by(
            provider=provider, event_id=raw_event_id).first()
        if seen is not None:
            # Already processed — return 200 so the provider stops retrying.
            return ("ok (duplicate)", 200)
        db.session.add(WebhookEventLog(
            provider=provider, event_id=raw_event_id,
            intent_id=event.intent_id or "", event_type=event.event_type or "",
            processed=False,
        ))
        db.session.flush()
    except IntegrityError:
        # Concurrent delivery hit the unique constraint first — also a dupe.
        db.session.rollback()
        return ("ok (duplicate)", 200)

    op = (OnlinePayment.query
          .filter_by(provider=provider, intent_id=event.intent_id).first())
    if op is None:
        app.logger.info("Webhook event %s for unknown intent %s",
                        event.event_type, event.intent_id)
        return ("ok", 200)

    op.status = event.status
    op.raw = {"event_type": event.event_type, "object": event.raw}
    if event.status == "failed":
        op.error_message = (event.raw.get("last_payment_error", {}) or {}).get("message", "")[:500]
    db.session.add(op)

    if event.status == "succeeded":
        order = Order.query.filter_by(id=op.order_id, owner_id=op.owner_id).first()
        if order and (order.payment_status or "unpaid") != "paid":
            settings = _settings_for(order.owner_id)
            totals = compute_bill_totals(
                subtotal=float(order.amount or 0),
                discount=float(order.discount or 0),
                service_charge_pct=float(settings.service_charge_percent or 0),
                tax_pct=float(settings.tax_rate_percent or 0),
            )
            order.payment_status = "paid"
            order.payment_method = provider
            order.tax = totals.tax
            order.service_charge = totals.service_charge
            order.paid_at = datetime.now(timezone.utc)
            order.payments_breakdown = [{
                "method": provider, "amount": float(op.amount or totals.total),
                "reference": event.intent_id,
            }]
            if not order.invoice_number:
                inv, seq = next_invoice_number(settings.invoice_prefix or "INV",
                                               int(settings.invoice_seq or 0))
                order.invoice_number = inv
                settings.invoice_seq = seq
            db.session.add(order)
            _billing_log(owner_id=order.owner_id, order_id=order.id,
                         action="online_charge.settled",
                         amount=float(op.amount or totals.total),
                         payment_method=provider,
                         reason=f"webhook {event.event_type}",
                         payload={"intent_id": event.intent_id,
                                  "provider": provider,
                                  "credential_id": matched_cred.id if matched_cred else None})
            _invalidate_billing_cache(order.owner_id)
    # Mark the dedup row as fully processed so an ops dashboard can
    # distinguish "received but never finished" from "fully settled".
    WebhookEventLog.query.filter_by(
        provider=provider, event_id=raw_event_id
    ).update({"processed": True})
    db.session.commit()
    return ("ok", 200)


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
        _push_new_order(owner_id, new_record.get("customerName", "Guest"), new_record.get("total", 0))
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
    """Active-orders feed for the kitchen display.

    Query params:
      - ``limit`` (int, default 200, max 500): cap on rows returned.
      - ``since`` (ISO-8601 UTC timestamp, optional): when provided, return
        only orders whose ``updated_at`` is strictly newer. The client should
        pass back the previous response's ``fetchedAt`` for cheap delta polls.
      - ``include_completed`` (truthy, optional): when ``since`` is set, also
        include orders that just transitioned to ``completed`` / ``cancelled``
        so the kitchen UI can remove their cards. Without ``since`` we always
        return only active statuses.

    The query is served by ``ix_orders_owner_status_created`` (added in
    migration 003) so this stays cheap even with hundreds of thousands of
    historical orders.
    """
    owner_id = logged_in_owner_id()
    table_names = _owner_table_names(owner_id)

    # --- parse + clamp inputs --------------------------------------------
    try:
        limit = int(request.args.get("limit", KITCHEN_DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = KITCHEN_DEFAULT_LIMIT
    limit = max(1, min(limit, KITCHEN_MAX_LIMIT))

    since_raw = (request.args.get("since") or "").strip()
    since_dt = None
    if since_raw:
        try:
            # Accept both "...Z" and "+00:00" suffixes.
            since_dt = datetime.fromisoformat(since_raw.replace("Z", "+00:00"))
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            since_dt = None

    include_completed = str(request.args.get("include_completed", "")).strip().lower() in {
        "1", "true", "yes", "on"
    }

    # --- build query -----------------------------------------------------
    q = Order.query.filter(Order.owner_id == owner_id)
    if since_dt is not None and include_completed:
        # Delta poll: return anything that changed, including just-finished
        # orders so the client can remove them from the board.
        q = q.filter(Order.updated_at > since_dt)
    else:
        q = q.filter(Order.status.in_(KITCHEN_ACTIVE_STATUSES))
        if since_dt is not None:
            q = q.filter(Order.updated_at > since_dt)

    orders = q.order_by(Order.created_at.asc()).limit(limit).all()

    # --- shape payload ---------------------------------------------------
    now_ts = datetime.now(timezone.utc)
    payload = []
    for o in orders:
        d = _order_dict(o)
        d["tableName"] = table_names.get(o.table_id, o.table_name or "—")
        try:
            age_seconds = int((now_ts - o.created_at).total_seconds()) if o.created_at else 0
        except Exception:
            age_seconds = 0
        d["ageSeconds"] = max(0, age_seconds)
        payload.append(d)

    truncated = len(payload) >= limit
    return jsonify(
        orders=payload,
        fetchedAt=_iso(now_ts),
        count=len(payload),
        limit=limit,
        truncated=truncated,
        since=since_raw or None,
    )


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
@api_login_required
def orders_stream():
    owner_id = logged_in_owner_id()

    def generate():
        my_queue: list[str] = []
        my_event = threading.Event()
        _sub_entry = (my_queue, my_event)
        with _sse_lock:
            _sse_subscribers.setdefault(owner_id, []).append(_sub_entry)

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
                # Wake immediately when a notification arrives; fall back to heartbeat cadence
                _wait_secs = max(0.1, 25.0 - (time.time() - last_heartbeat))
                my_event.wait(timeout=_wait_secs)
                my_event.clear()
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                subs = _sse_subscribers.get(owner_id, [])
                try:
                    subs.remove(_sub_entry)
                except ValueError:
                    pass

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

    # Enforce per-tenant menu item quota when creating a brand new item.
    if not item_id:
        from extensions.multi_tenant_bp import (
            enforce_quota as _enforce_quota,
            count_owner_menu_items,
            QuotaExceeded,
        )
        owner_obj = db.session.get(Owner, owner_id) if owner_id else None
        if owner_obj is not None:
            try:
                _enforce_quota(owner_obj, "max_menu_items", count_owner_menu_items(owner_id))
            except QuotaExceeded as exc:
                flash(exc.message)
                return redirect(url_for("owner_dashboard") + "#menu")

    if item_id:
        item = next((i for i in category["items"] if i["id"] == item_id), None)
        if item:
            updates = {"name": name, "description": description, "price": price, "tags": tags,
                       "dietary_tags": dietary_tags, "image_url": image_url, "prep_time": prep_time}
            # When the owner overrides the image (URL, upload, or clears it),
            # reset the AI seed so the next auto-image is fresh and the cache
            # of any old AI image is invalidated.
            if image_url != item.get("image_url", ""):
                updates["image_seed"] = 0
            item.update(updates)
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
            "image_seed": 0,
        })
        flash(f"'{name}' added to menu.")

    save_menu(menu)
    return redirect(url_for("owner_dashboard") + "#menu")


@app.route("/owner/menu/upload-image", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def upload_menu_image() -> Response:
    """Upload an image file for a menu item.

    Accepts a multipart ``image`` field (jpg/jpeg/png), validates it with the
    same checks used elsewhere, saves it under ``static/uploads/menu/<owner_id>/``
    and returns ``{url: "..."}`` so the calling form can drop the URL into the
    item's ``itemImageUrl`` field.

    The owner-id namespace prevents one cafe from clobbering another's images.
    """
    owner_id = logged_in_owner_id()
    if not owner_id:
        return jsonify({"ok": False, "error": "Not signed in."}), 401

    uploaded = request.files.get("image")
    if not uploaded or not uploaded.filename:
        return jsonify({"ok": False, "error": "No file uploaded."}), 400

    # Reuse the existing 16 MB cap and the shared validator.
    file_bytes = uploaded.read(16 * 1024 * 1024)
    err, kind = validate_uploaded_file(uploaded, file_bytes)
    if err or kind != "image":
        return jsonify({"ok": False, "error": err or "Only JPG or PNG images are allowed."}), 400

    ext = Path((uploaded.filename or "").lower()).suffix
    if ext not in {".jpg", ".jpeg", ".png"}:
        return jsonify({"ok": False, "error": "Only JPG or PNG images are allowed."}), 400

    # Hash-based filename gives a stable URL and natural dedup; no PII leakage.
    import hashlib
    digest = hashlib.sha256(file_bytes).hexdigest()[:24]
    rel_dir = Path("static") / "uploads" / "menu" / str(owner_id)
    abs_dir = Path(app.root_path) / rel_dir
    abs_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{digest}{ext}"
    abs_path = abs_dir / filename
    if not abs_path.exists():
        with open(abs_path, "wb") as f:
            f.write(file_bytes)

    public_url = url_for("static", filename=f"uploads/menu/{owner_id}/{filename}")
    return jsonify({"ok": True, "url": public_url})


@app.route("/owner/menu/item/<item_id>/regen-image", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def regen_menu_item_image(item_id: str) -> Response:
    """Bump the item's ``image_seed`` so the auto-generated AI image rerolls.

    Also clears any custom ``image_url`` so the AI image takes effect again.
    Owners use this when they want a different AI picture for the same dish.
    """
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", item_id):
        abort(400)
    menu = load_menu()
    for category in menu.get("categories", []):
        if category.get("ownerId") != owner_id:
            continue
        item = next((i for i in category["items"] if i["id"] == item_id), None)
        if item:
            # Use seconds since epoch to guarantee a fresh seed each click,
            # and clear image_url so the regenerated AI image is what shows.
            item["image_seed"] = int(time.time())
            item["image_url"] = ""
            save_menu(menu)
            flash(f"New AI image generated for '{item['name']}'.")
            return redirect(url_for("owner_dashboard") + "#menu")
    flash("Item not found.")
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
    # Enforce per-tenant table quota.
    from extensions.multi_tenant_bp import (
        enforce_quota as _enforce_quota,
        count_owner_tables,
        QuotaExceeded,
    )
    owner_obj = db.session.get(Owner, owner_id) if owner_id else None
    if owner_obj is not None:
        try:
            _enforce_quota(owner_obj, "max_tables", count_owner_tables(owner_id))
        except QuotaExceeded as exc:
            flash(exc.message)
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


_QR_FONT_DIR = "/usr/share/fonts/truetype/dejavu"


def _qr_font(size: int, bold: bool = False):
    """Load DejaVu font at the requested size; fall back to PIL default."""
    from PIL import ImageFont
    path = f"{_QR_FONT_DIR}/DejaVuSans-Bold.ttf" if bold else f"{_QR_FONT_DIR}/DejaVuSans.ttf"
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _render_branded_table_qr(table_url: str, cafe_name: str, table_name: str,
                             brand_color: str, logo_url: str) -> "Image.Image":
    """Compose a branded, printable QR poster for a single table.

    Layout (720x1000):
      • Brand-coloured header with the cafe's logo/initial badge and name
      • Large "Table {name}" heading
      • High-error-correction QR code recoloured in the brand palette
      • "Scan to Order" call to action and a small footer line

    Falls back to safe defaults whenever a logo can't be loaded or the brand
    colour is malformed, so a poster always renders.
    """
    from PIL import Image, ImageDraw, ImageColor

    W, H = 720, 1000
    bg = (250, 250, 252)
    try:
        brand = ImageColor.getrgb(brand_color or "#4f46e5")
    except (ValueError, TypeError):
        brand = (79, 70, 229)
    # Pick legible foreground for the header band by luminance.
    header_fg = (255, 255, 255) if (brand[0] * 0.299 + brand[1] * 0.587 + brand[2] * 0.114) < 160 \
        else (20, 24, 40)

    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)

    # Header band
    d.rectangle([(0, 0), (W, 180)], fill=brand)

    # Logo: try to load owner's uploaded logo; otherwise draw an initial badge.
    badge_cx, badge_cy, badge_r = 100, 90, 56
    logo_drawn = False
    if logo_url and logo_url.startswith("/static/"):
        try:
            local_path = Path(app.root_path) / logo_url.lstrip("/")
            if local_path.is_file():
                logo_img = Image.open(local_path).convert("RGBA")
                size = badge_r * 2
                logo_img.thumbnail((size, size), Image.LANCZOS)
                # Circular mask for a polished badge look
                mask = Image.new("L", logo_img.size, 0)
                ImageDraw.Draw(mask).ellipse((0, 0, *logo_img.size), fill=255)
                circle_bg = Image.new("RGBA", (size, size), (255, 255, 255, 255))
                offset = ((size - logo_img.size[0]) // 2, (size - logo_img.size[1]) // 2)
                circle_bg.paste(logo_img, offset, logo_img)
                img.paste(circle_bg, (badge_cx - badge_r, badge_cy - badge_r),
                          mask.resize((size, size)))
                logo_drawn = True
        except Exception:
            logo_drawn = False
    if not logo_drawn:
        d.ellipse([(badge_cx - badge_r, badge_cy - badge_r),
                   (badge_cx + badge_r, badge_cy + badge_r)], fill=(255, 255, 255))
        initial = (cafe_name or "C").strip()[:1].upper() or "C"
        font_logo = _qr_font(64, bold=True)
        bbox = d.textbbox((0, 0), initial, font=font_logo)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        d.text((badge_cx - tw // 2 - bbox[0],
                badge_cy - th // 2 - bbox[1]),
               initial, fill=brand, font=font_logo)

    # Cafe name + tagline
    title_x = badge_cx + badge_r + 28
    name = (cafe_name or "Welcome").strip()[:28]
    d.text((title_x, 50), name, fill=header_fg, font=_qr_font(38, bold=True))
    d.text((title_x, 102), "Order at your table", fill=header_fg, font=_qr_font(20))

    # Table heading
    table_label = f"Table {table_name}".strip()
    font_table = _qr_font(54, bold=True)
    bbox = d.textbbox((0, 0), table_label, font=font_table)
    d.text(((W - (bbox[2] - bbox[0])) // 2, 218), table_label,
           fill=(20, 24, 40), font=font_table)

    # QR code (high error correction so the brand colour overlay still scans)
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=2,
    )
    qr.add_data(table_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color=brand, back_color="white").convert("RGB")
    qr_size = 480
    qr_img = qr_img.resize((qr_size, qr_size), Image.NEAREST)
    qx = (W - qr_size) // 2
    qy = 310
    pad = 22
    # White panel + thin brand border behind the QR for printable contrast
    d.rectangle([(qx - pad - 2, qy - pad - 2),
                 (qx + qr_size + pad + 2, qy + qr_size + pad + 2)], fill=brand)
    d.rectangle([(qx - pad, qy - pad),
                 (qx + qr_size + pad, qy + qr_size + pad)], fill=(255, 255, 255))
    img.paste(qr_img, (qx, qy))

    # CTA + footer
    cta = "Scan to Order"
    font_cta = _qr_font(34, bold=True)
    bbox = d.textbbox((0, 0), cta, font=font_cta)
    d.text(((W - (bbox[2] - bbox[0])) // 2, qy + qr_size + 50), cta,
           fill=brand, font=font_cta)

    foot = "Point your phone camera at the code to view the menu"
    font_foot = _qr_font(18)
    bbox = d.textbbox((0, 0), foot, font=font_foot)
    d.text(((W - (bbox[2] - bbox[0])) // 2, qy + qr_size + 100), foot,
           fill=(110, 114, 130), font=font_foot)

    return img


@app.route("/owner/tables/qr-posters.zip")
@login_required
def download_all_table_qr_posters() -> Response:
    """Bundle every owner table's branded QR poster into a single zip download.

    Useful when an owner is setting up a new floor and wants to print all
    posters at once instead of clicking each table individually.
    """
    import zipfile
    owner_id = logged_in_owner_id()
    tables = [t for t in load_tables() if t.get("ownerId") == owner_id]
    if not tables:
        flash("Add at least one table before downloading posters.")
        return redirect(url_for("owner_dashboard") + "#tables")

    owner = db.session.get(Owner, owner_id) if owner_id else None
    cafe_name = (owner.cafe_name if owner else None) or "Welcome"
    branding = load_settings(owner_id) if owner_id else {"logoUrl": "", "brandColor": "#4f46e5"}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for table in tables:
            table_url = url_for("table_order", table_id=table["id"], _external=True)
            poster = _render_branded_table_qr(
                table_url=table_url,
                cafe_name=cafe_name,
                table_name=table.get("name") or table["id"],
                brand_color=branding.get("brandColor", "#4f46e5"),
                logo_url=branding.get("logoUrl", ""),
            )
            png_buf = io.BytesIO()
            poster.save(png_buf, format="PNG", optimize=True)
            # Filenames keep the table id so they're unique even when names clash.
            safe_name = re.sub(r"[^a-zA-Z0-9_\-]+", "_", str(table.get("name") or table["id"]))[:40] or table["id"]
            zf.writestr(f"qr-{safe_name}-{table['id']}.png", png_buf.getvalue())
    buf.seek(0)

    safe_cafe = re.sub(r"[^a-zA-Z0-9_\-]+", "_", cafe_name)[:40] or "cafe"
    return Response(
        buf.read(),
        mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_cafe}-table-qr-posters.zip"'},
    )


@app.route("/owner/table/<table_id>/qr")
@login_required
def table_qr(table_id: str) -> Response:
    """Return a branded PNG poster for a table QR.

    The poster is sized for printing (720×1000) and reuses the cafe's logo,
    name and brand colour so each table gets a personalised hand-out instead
    of a bare QR square. Pass ``?plain=1`` to get the original raw QR PNG
    (e.g. for embedding in third-party menus).
    """
    owner_id = logged_in_owner_id()
    if not re.fullmatch(r"[a-zA-Z0-9\-]{1,64}", table_id):
        abort(400)
    tables = load_tables()
    table = next((t for t in tables if t["id"] == table_id), None)
    if not table or table.get("ownerId") != owner_id:
        abort(403)
    table_url = url_for("table_order", table_id=table_id, _external=True)

    if request.args.get("plain"):
        qr_img = qrcode.make(table_url)
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)
        return Response(buf.read(), mimetype="image/png")

    owner = db.session.get(Owner, owner_id) if owner_id else None
    cafe_name = (owner.cafe_name if owner else None) or "Welcome"
    branding = load_settings(owner_id) if owner_id else {"logoUrl": "", "brandColor": "#4f46e5"}
    poster = _render_branded_table_qr(
        table_url=table_url,
        cafe_name=cafe_name,
        table_name=table.get("name") or table_id,
        brand_color=branding.get("brandColor", "#4f46e5"),
        logo_url=branding.get("logoUrl", ""),
    )
    buf = io.BytesIO()
    poster.save(buf, format="PNG", optimize=True)
    buf.seek(0)
    return Response(buf.read(), mimetype="image/png",
                    headers={"Cache-Control": "private, max-age=60"})


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

@app.route("/superadmin/verify-key", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour", methods=["POST"])
def superadmin_verify_key():
    """Challenge an admin-authenticated session for the SUPERADMIN_KEY.

    Real superadmin owners never reach this page (they're already allowed
    by superadmin_required). Anyone else without an admin session is sent
    to the owner login.
    """
    if not session.get("admin_authenticated"):
        return redirect(url_for("owner_login"))
    if not _superadmin_key_configured():
        return render_template(
            "admin/error.html",
            message="SUPERADMIN_KEY is not configured on this server.",
        ), 503
    error = None
    if request.method == "POST":
        provided = str(request.form.get("key", ""))
        if _superadmin_key_matches(provided):
            session["superadmin_key_verified"] = True
            session["superadmin_key_verified_at"] = time.time()
            log_security("SUPERADMIN_KEY_OK", f"admin_owner_id={session.get('admin_owner_id')}")
            nxt = session.pop("superadmin_verify_next", "") or url_for("superadmin_dashboard")
            return redirect(nxt)
        error = "Invalid key. Please try again."
        log_security("SUPERADMIN_KEY_FAIL", f"admin_owner_id={session.get('admin_owner_id')}")
    return render_template("superadmin/verify_key.html", error=error), (200 if not error else 401)


@app.route("/superadmin/audit")
@superadmin_required
def superadmin_audit():
    """Browse the in-memory security audit ring buffer."""
    q = (request.args.get("q", "") or "").strip().lower()
    event_filter = (request.args.get("event", "") or "").strip()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 100

    events = list(SECURITY_EVENT_BUFFER)
    events.reverse()  # newest first

    if event_filter:
        events = [e for e in events if e.get("event", "").startswith(event_filter)]
    if q:
        events = [
            e for e in events
            if q in (e.get("event", "") + " " + e.get("detail", "") + " " + str(e.get("ip", ""))).lower()
        ]

    total = len(events)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    start = (page - 1) * per_page
    page_events = events[start:start + per_page]

    event_types = sorted({e.get("event", "") for e in SECURITY_EVENT_BUFFER if e.get("event")})
    return render_template(
        "superadmin/audit.html",
        events=page_events,
        total=total,
        page=page,
        pages=pages,
        per_page=per_page,
        q=q,
        event_filter=event_filter,
        event_types=event_types,
        buffer_capacity=SECURITY_EVENT_BUFFER.maxlen,
        verified_until=(
            float(session.get("superadmin_key_verified_at", 0) or 0) + SUPERADMIN_VERIFY_TTL
            if session.get("superadmin_key_verified") else None
        ),
    )


def _filtered_audit_events(q: str, event_filter: str) -> list[dict]:
    events = list(SECURITY_EVENT_BUFFER)
    events.reverse()
    if event_filter:
        events = [e for e in events if e.get("event", "").startswith(event_filter)]
    if q:
        events = [
            e for e in events
            if q in (e.get("event", "") + " " + e.get("detail", "") + " " + str(e.get("ip", ""))).lower()
        ]
    return events


@app.route("/superadmin/audit.json")
@superadmin_required
def superadmin_audit_json():
    q = (request.args.get("q", "") or "").strip().lower()
    event_filter = (request.args.get("event", "") or "").strip()
    events = _filtered_audit_events(q, event_filter)
    out = [
        {
            "ts": e.get("ts"),
            "iso": datetime.fromtimestamp(float(e.get("ts", 0)), tz=timezone.utc).isoformat(),
            "event": e.get("event", ""),
            "ip": e.get("ip", ""),
            "actor": e.get("actor"),
            "detail": e.get("detail", ""),
        }
        for e in events
    ]
    log_security("SUPERADMIN_AUDIT_EXPORT", f"format=json count={len(out)}")
    return jsonify(events=out, total=len(out))


@app.route("/superadmin/audit.csv")
@superadmin_required
def superadmin_audit_csv():
    import csv
    import io
    q = (request.args.get("q", "") or "").strip().lower()
    event_filter = (request.args.get("event", "") or "").strip()
    events = _filtered_audit_events(q, event_filter)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp_iso", "epoch", "event", "ip", "actor", "detail"])
    for e in events:
        ts = float(e.get("ts", 0) or 0)
        writer.writerow([
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            ts,
            e.get("event", ""),
            e.get("ip", ""),
            e.get("actor") if e.get("actor") is not None else "",
            e.get("detail", ""),
        ])
    log_security("SUPERADMIN_AUDIT_EXPORT", f"format=csv count={len(events)}")
    fname = "security-audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".csv"
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp


@app.route("/superadmin/verify-key/clear", methods=["POST"])
def superadmin_verify_key_clear():
    session.pop("superadmin_key_verified", None)
    session.pop("superadmin_verify_next", None)
    return redirect(url_for("admin.dashboard"))


@app.route("/superadmin")
@app.route("/superadmin/dashboard")
@superadmin_required
def superadmin_dashboard():
    from extensions.models import TableCall
    owners = Owner.query.order_by(Owner.created_at.desc()).all()
    cafes = Cafe.query.order_by(Cafe.created_at.desc()).all()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total)).filter_by(status="completed").scalar() or 0
    total_feedback = Feedback.query.count()
    avg_rating_row = db.session.query(db.func.avg(Feedback.rating)).scalar()
    avg_rating = round(float(avg_rating_row), 1) if avg_rating_row else 0.0
    open_calls = TableCall.query.filter_by(status="open").count()

    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(50).all()

    # ── Per-cafe stats for the cafes table ──────────────────────────────
    cafe_stats: dict[int, dict] = {}
    for cafe in cafes:
        cafe_owners = [o for o in owners if o.cafe_id == cafe.id]
        owner_ids = [o.id for o in cafe_owners]
        order_count = Order.query.filter(Order.owner_id.in_(owner_ids)).count() if owner_ids else 0
        rev = db.session.query(db.func.sum(Order.total)).filter(
            Order.owner_id.in_(owner_ids), Order.status == "completed"
        ).scalar() or 0 if owner_ids else 0
        cafe_stats[cafe.id] = {
            "owner_count": len(cafe_owners),
            "order_count": int(order_count),
            "revenue": round(float(rev), 0),
        }

    # ── Time-bucketed KPIs (today / 7-day / vs prior period) ────────────
    now_utc = datetime.now(timezone.utc)
    today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    week_ago = today_start - timedelta(days=7)
    two_weeks_ago = today_start - timedelta(days=14)

    def _count_orders(after, before=None):
        q = Order.query.filter(Order.created_at >= after)
        if before is not None:
            q = q.filter(Order.created_at < before)
        return q.count()

    def _sum_revenue(after, before=None):
        q = db.session.query(db.func.sum(Order.total)).filter(
            Order.created_at >= after, Order.status == "completed"
        )
        if before is not None:
            q = q.filter(Order.created_at < before)
        return float(q.scalar() or 0)

    orders_today = _count_orders(today_start)
    orders_yesterday = _count_orders(yesterday_start, today_start)
    orders_7d = _count_orders(week_ago)
    orders_prev_7d = _count_orders(two_weeks_ago, week_ago)
    revenue_today = _sum_revenue(today_start)
    revenue_7d = _sum_revenue(week_ago)
    revenue_prev_7d = _sum_revenue(two_weeks_ago, week_ago)
    new_owners_7d = sum(
        1 for o in owners
        if o.created_at and o.created_at.replace(tzinfo=timezone.utc) >= week_ago
    )

    def _pct(curr, prev):
        if prev == 0:
            return None if curr == 0 else 100.0
        return round((curr - prev) / prev * 100, 1)

    deltas = {
        "orders_today_vs_yesterday": _pct(orders_today, orders_yesterday),
        "orders_7d_vs_prev": _pct(orders_7d, orders_prev_7d),
        "revenue_7d_vs_prev": _pct(revenue_7d, revenue_prev_7d),
    }
    avg_ticket = round(float(total_revenue) / total_orders, 2) if total_orders else 0.0

    # ── 14-day order trend for sparkline ────────────────────────────────
    daily_series = []
    for i in range(13, -1, -1):
        day = today_start - timedelta(days=i)
        end = day + timedelta(days=1)
        cnt = _count_orders(day, end)
        daily_series.append({"date": day.strftime("%b %d"), "count": int(cnt)})

    # ── Top 5 cafes by completed revenue ────────────────────────────────
    top_cafes = sorted(
        cafes, key=lambda c: cafe_stats.get(c.id, {}).get("revenue", 0), reverse=True
    )[:5]
    top_cafes_data = [{
        "id": c.id, "name": c.name, "is_active": c.is_active,
        "revenue": cafe_stats.get(c.id, {}).get("revenue", 0),
        "orders": cafe_stats.get(c.id, {}).get("order_count", 0),
        "owners": cafe_stats.get(c.id, {}).get("owner_count", 0),
    } for c in top_cafes]

    # ── Pending attention list ──────────────────────────────────────────
    pending = []
    for o in owners:
        if not o.is_active:
            pending.append({"icon": "person-x-fill", "color": "warning",
                            "msg": f"Owner '{o.username}' is deactivated"})
    for c in cafes:
        if not c.is_active:
            pending.append({"icon": "shop-window", "color": "warning",
                            "msg": f"Cafe '{c.name}' is deactivated"})
        elif cafe_stats.get(c.id, {}).get("order_count", 0) == 0:
            pending.append({"icon": "exclamation-circle", "color": "info",
                            "msg": f"Cafe '{c.name}' has no orders yet"})
    if open_calls:
        pending.insert(0, {"icon": "bell-fill", "color": "danger",
                           "msg": f"{open_calls} open table-service call(s)"})

    # ── Recent security events (newest first, max 8) ────────────────────
    recent_security = list(SECURITY_EVENT_BUFFER)[-8:][::-1]

    # ── System health snapshot ──────────────────────────────────────────
    db_latency_ms = None
    try:
        t0 = time.time()
        db.session.execute(text("SELECT 1"))
        db_latency_ms = round((time.time() - t0) * 1000, 1)
    except Exception as exc:
        app.logger.warning("Superadmin DB ping failed: %s", exc)

    uptime_seconds = int(time.time() - APP_START_TIME)
    days, rem = divmod(uptime_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    uptime_str = (f"{days}d " if days else "") + f"{hours}h {minutes}m"

    health = {
        "version": APP_VERSION,
        "uptime": uptime_str,
        "db_latency_ms": db_latency_ms,
        "env": ("production" if os.environ.get("IS_PRODUCTION", "").lower() == "true"
                or os.environ.get("RAILWAY_ENVIRONMENT") else "development"),
        "events_buffered": len(SECURITY_EVENT_BUFFER),
        "verified_until": (
            float(session.get("superadmin_key_verified_at", 0) or 0) + SUPERADMIN_VERIFY_TTL
            if session.get("superadmin_key_verified") else None
        ),
    }

    return render_template(
        "superadmin/dashboard.html",
        owners=owners,
        cafes=cafes,
        cafe_stats=cafe_stats,
        total_orders=total_orders,
        total_revenue=round(float(total_revenue), 2),
        total_feedback=total_feedback,
        avg_rating=avg_rating,
        open_calls=open_calls,
        recent_orders=[_order_dict(o) for o in recent_orders],
        owner_count=len(owners),
        active_owner_count=sum(1 for o in owners if o.is_active),
        cafe_count=len(cafes),
        active_cafe_count=sum(1 for c in cafes if c.is_active),
        owner_username=logged_in_owner(),
        # ── Enhanced metrics ────────────────────────────────────────────
        orders_today=orders_today,
        orders_7d=orders_7d,
        revenue_today=round(revenue_today, 2),
        revenue_7d=round(revenue_7d, 2),
        new_owners_7d=new_owners_7d,
        avg_ticket=avg_ticket,
        deltas=deltas,
        daily_series=daily_series,
        top_cafes=top_cafes_data,
        pending=pending[:8],
        pending_total=len(pending),
        recent_security=recent_security,
        health=health,
    )


@app.route("/superadmin/leads")
@superadmin_required
def superadmin_leads():
    """Review queue for owner-access requests submitted via /welcome.
    Pending leads first; then handled (approved/rejected) for audit."""
    status_filter = (request.args.get("status") or "pending").strip().lower()
    if status_filter not in {"pending", "approved", "rejected", "all"}:
        status_filter = "pending"
    q = OwnerLead.query
    if status_filter != "all":
        q = q.filter(OwnerLead.status == status_filter)
    leads = q.order_by(OwnerLead.created_at.desc()).limit(500).all()
    counts = {
        "pending": OwnerLead.query.filter_by(status="pending").count(),
        "approved": OwnerLead.query.filter_by(status="approved").count(),
        "rejected": OwnerLead.query.filter_by(status="rejected").count(),
    }
    return render_template("superadmin/leads.html",
                           leads=leads, counts=counts,
                           status_filter=status_filter)


@app.route("/superadmin/leads/<int:lead_id>/approve", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_lead_approve(lead_id: int):
    """Approve a lead → provision an Owner with a one-time temp password
    and email it to the café owner. The lead row is kept for audit."""
    lead = db.session.get(OwnerLead, lead_id)
    if not lead or lead.status != "pending":
        abort(404)
    # Derive a sensible default username from the cafe name; superadmin can
    # rename later from the dashboard if needed.
    base = re.sub(r"[^a-z0-9]+", "_", (lead.cafe_name or "owner").lower()).strip("_")[:48] or "owner"
    candidate = base
    suffix = 1
    while Owner.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base}_{suffix}"[:64]
    if Owner.query.filter_by(email=lead.email).first():
        flash(f"An owner with email {lead.email} already exists — link them manually instead.",
              "lead_error")
        return redirect(url_for("superadmin_leads"))

    tmp_password = secrets.token_urlsafe(12)
    create_owner_in_db(
        username=candidate,
        email=lead.email,
        password_hash=_make_password_hash(tmp_password),
        cafe_name=lead.cafe_name,
    )
    lead.status = "approved"
    lead.handled_by = session.get("owner_id")
    lead.handled_at = datetime.now(timezone.utc)
    db.session.commit()

    login_url = url_for("owner_login", _external=True)

    def _send_invite(to_addr: str, name: str, cafe: str, uname: str, pw: str, url: str) -> None:
        if not _mail_enabled():
            return
        try:
            mail.send(Message(
                subject=f"Welcome aboard — {cafe} is ready ☕",
                recipients=[to_addr],
                body=(
                    f"Hi {name},\n\n"
                    f"Your café '{cafe}' has been approved. Here are your login details:\n\n"
                    f"Login URL : {url}\n"
                    f"Username  : {uname}\n"
                    f"Password  : {pw}\n\n"
                    "Please change this password the first time you sign in "
                    "(My Profile → Change Password) and turn on two-factor "
                    "authentication for extra safety.\n\n"
                    "Need help getting started? Just reply to this email.\n\n"
                    "Cheers,\n"
                    "The Cafe Ordering team"
                ),
            ))
        except Exception as exc:  # pragma: no cover
            app.logger.warning("Invite email failed: %s", exc)

    bg_tasks.submit(_send_invite, lead.email, lead.contact_name, lead.cafe_name,
                    candidate, tmp_password, login_url, _name="send_owner_invite")
    log_security("OWNER_LEAD_APPROVED", f"lead_id={lead.id} username={candidate!r}")
    flash(f"Approved. Owner '{candidate}' created. Temp password (also emailed): {tmp_password}",
          "lead_credentials")
    return redirect(url_for("superadmin_leads"))


@app.route("/superadmin/leads/<int:lead_id>/reject", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_lead_reject(lead_id: int):
    lead = db.session.get(OwnerLead, lead_id)
    if not lead or lead.status != "pending":
        abort(404)
    lead.status = "rejected"
    lead.handled_by = session.get("owner_id")
    lead.handled_at = datetime.now(timezone.utc)
    db.session.commit()
    log_security("OWNER_LEAD_REJECTED", f"lead_id={lead.id}")
    flash(f"Lead from {lead.email} marked as rejected.", "lead_info")
    return redirect(url_for("superadmin_leads"))


@app.route("/superadmin/cafes/create", methods=["POST"])
@superadmin_required
@superadmin_destructive
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
@superadmin_required
@superadmin_destructive
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
@superadmin_required
@superadmin_destructive
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
@superadmin_required
@superadmin_destructive
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
@superadmin_required
@superadmin_destructive
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
@superadmin_required
@superadmin_destructive
def superadmin_assign_cafe(owner_id: int):
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    cafe_id_str = request.form.get("cafe_id", "")
    owner.cafe_id = int(cafe_id_str) if cafe_id_str and cafe_id_str.isdigit() else None
    db.session.commit()
    flash(f"Owner '{owner.username}' assigned to cafe.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/cafes/<int:cafe_id>/rename", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_rename_cafe(cafe_id: int):
    cafe = db.session.get(Cafe, cafe_id)
    if not cafe:
        abort(404)
    new_name = str(request.form.get("name", "")).strip()[:200]
    if not new_name:
        flash("Cafe name cannot be empty.")
        return redirect(url_for("superadmin_dashboard"))
    cafe.name = new_name
    db.session.commit()
    flash(f"Cafe renamed to '{new_name}'.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/cafes/<int:cafe_id>/delete", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_delete_cafe(cafe_id: int):
    cafe = db.session.get(Cafe, cafe_id)
    if not cafe:
        abort(404)
    linked_owners = Owner.query.filter_by(cafe_id=cafe_id).count()
    if linked_owners:
        flash(f"Cannot delete '{cafe.name}' — {linked_owners} owner(s) still assigned. Reassign or delete them first.")
        return redirect(url_for("superadmin_dashboard"))
    db.session.delete(cafe)
    db.session.commit()
    flash(f"Cafe '{cafe.name}' deleted.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/owners/<int:owner_id>/delete", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_delete_owner(owner_id: int):
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot delete a superadmin account.")
        return redirect(url_for("superadmin_dashboard"))
    order_count = Order.query.filter_by(owner_id=owner_id).count()
    if order_count:
        flash(f"Cannot delete '{owner.username}' — {order_count} order(s) exist. Deactivate instead.")
        return redirect(url_for("superadmin_dashboard"))
    db.session.delete(owner)
    db.session.commit()
    flash(f"Owner '{owner.username}' deleted.")
    return redirect(url_for("superadmin_dashboard"))


@app.route("/superadmin/admin-keys", methods=["GET"])
@superadmin_required
def superadmin_admin_keys():
    keys = load_admin_keys()
    keys_by_owner = {int(k.get("owner_id", -1)): k for k in keys}
    owners = Owner.query.order_by(Owner.username).all()
    rows = []
    for owner in owners:
        record = keys_by_owner.get(int(owner.id))
        rows.append({
            "owner_id": owner.id,
            "username": owner.username,
            "email": owner.email,
            "is_superadmin": bool(owner.is_superadmin),
            "is_active": bool(owner.is_active),
            "has_key": record is not None,
            "generated_at": (record or {}).get("generated_at"),
        })
    new_key = session.pop("_new_admin_key", None)
    new_key_owner = session.pop("_new_admin_key_owner", None)
    return render_template(
        "superadmin/admin_keys.html",
        rows=rows,
        new_key=new_key,
        new_key_owner=new_key_owner,
        owner_username=logged_in_owner(),
    )


@app.route("/superadmin/admin-keys/generate", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_generate_admin_key():
    owner_id_raw = request.form.get("owner_id", "").strip()
    if not owner_id_raw.isdigit():
        flash("Please choose an authorised owner.", "danger")
        return redirect(url_for("superadmin_admin_keys"))
    owner = db.session.get(Owner, int(owner_id_raw))
    if not owner:
        flash("Owner not found.", "danger")
        return redirect(url_for("superadmin_admin_keys"))
    if not owner.is_active:
        flash(f"Owner '{owner.username}' is deactivated. Activate them first.", "danger")
        return redirect(url_for("superadmin_admin_keys"))
    plaintext = generate_admin_key_for_owner(owner.id, owner.username)
    log_security("ADMIN_KEY_GENERATED", f"by={logged_in_owner()} for_owner_id={owner.id}")
    session["_new_admin_key"] = plaintext
    session["_new_admin_key_owner"] = {"id": owner.id, "username": owner.username}
    flash(
        f"New admin access key generated for <strong>{owner.username}</strong>. "
        "Copy it now — it will not be shown again.",
        "success",
    )
    return redirect(url_for("superadmin_admin_keys"))


@app.route("/superadmin/admin-keys/revoke", methods=["POST"])
@superadmin_required
@superadmin_destructive
def superadmin_revoke_admin_key():
    owner_id_raw = request.form.get("owner_id", "").strip()
    if not owner_id_raw.isdigit():
        flash("Invalid owner.", "danger")
        return redirect(url_for("superadmin_admin_keys"))
    owner_id = int(owner_id_raw)
    if revoke_admin_key_for_owner(owner_id):
        log_security("ADMIN_KEY_REVOKED", f"by={logged_in_owner()} for_owner_id={owner_id}")
        flash("Admin access key revoked.", "success")
    else:
        flash("No key existed for that owner.", "info")
    return redirect(url_for("superadmin_admin_keys"))


@app.route("/superadmin/analytics")
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
@limiter.limit("10 per minute; 100 per hour")
def checkout() -> tuple[dict, int]:
    if not request.is_json:
        abort(400, description="JSON required.")
    # Idempotency: if the client supplied a key and we've already processed
    # the exact same request within the TTL, replay the original response
    # instead of placing a second order. Keys longer than 128 chars are
    # truncated defensively.
    _idem_key = (request.headers.get("Idempotency-Key") or "").strip()[:128]
    if _idem_key:
        cached = idem_cache.get("checkout", _idem_key)
        if cached is not None:
            cached_body, cached_status = cached
            return cached_body, cached_status
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
        _push_new_order(owner_id, customer_name, order_record.get("total", 0))

    log_security("ORDER_PLACED", f"table={table_id!r} total={order_record['total']}")
    # Email is now non-blocking — a slow SMTP call no longer holds the
    # customer's HTTP connection open. Same for the owner's web-push above.
    bg_tasks.submit(_send_order_confirmation, order_record, _name="send_order_confirmation")
    response_payload = {
        "message": "Order placed. Pay at counter.",
        "order": order_record,
        "pickupCode": order_record["pickupCode"],
        "paymentMethod": "pay_at_counter",
    }
    # Cache the response under the supplied Idempotency-Key so a retry of the
    # same request returns the same order instead of creating a duplicate.
    _idem_key = (request.headers.get("Idempotency-Key") or "").strip()[:128]
    if _idem_key:
        idem_cache.set("checkout", _idem_key, (response_payload, 201))
    return response_payload, 201


@app.route("/api/orders", methods=["GET"])
@limiter.limit("60 per minute")
@api_login_required
def orders_api() -> tuple[dict, int]:
    """Paginated, owner-scoped orders feed.

    Previous implementation called ``load_orders()`` with no arguments — which
    materialised every order in the system into memory and then filtered in
    Python. That scaled linearly with global order volume on every poll and
    leaked one tenant's row count to another's request latency. Now we push
    both ownership and pagination down to the database so the new
    ``ix_orders_owner_status_created`` index can serve the query.

    Query params (both optional):
      - ``limit``  — 1..500, default 100
      - ``offset`` — >=0, default 0
    """
    owner_id = logged_in_owner_id()

    try:
        limit = int(request.args.get("limit", "100"))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = int(request.args.get("offset", "0"))
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    orders = load_orders(owner_id=owner_id, limit=limit, offset=offset)
    return {"orders": orders, "limit": limit, "offset": offset, "count": len(orders)}, 200


@app.route("/api/orders/<int:order_id>", methods=["GET"])
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
@limiter.limit("30 per minute")
def customer_order_stream(order_id: int) -> Response:
    order = _db_get_order(order_id)
    if not order:
        abort(404, description="Order not found.")
    initial_status = order.get("status", "pending")

    my_queue: list[str] = []
    my_event = threading.Event()
    _sub_entry = (my_queue, my_event)
    with _sse_lock:
        _sse_customer_subs.setdefault(order_id, []).append(_sub_entry)

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
                # Wake immediately when a status update arrives
                _wait_secs = max(0.1, 25.0 - (time.time() - last_heartbeat))
                my_event.wait(timeout=_wait_secs)
                my_event.clear()
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                subs = _sse_customer_subs.get(order_id, [])
                try:
                    subs.remove(_sub_entry)
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
