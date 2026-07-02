"""Application factory.

Usage::

    from app import create_app
    flask_app = create_app()

Backward compatibility (tests, wsgi.py, extensions that do ``from app import db``)::

    import app as flask_app
    flask_app.app          # Flask instance
    flask_app.db           # SQLAlchemy instance

Issue #1 — Circular import guard:
  ``db`` (and other extension singletons) are imported from ``app.extensions``
  at the TOP of this module so they are available as ``app.db`` the moment
  Python starts executing this package — before ``create_app()`` is called.
  A ``_CREATE_APP_IN_PROGRESS`` flag prevents re-entrant factory calls that
  can occur when a blueprint imported inside ``create_app()`` does
  ``from app import ...`` while this module is still being initialised.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_login import logout_user
from werkzeug.middleware.proxy_fix import ProxyFix

from app import config as _cfg

log = logging.getLogger("cafe.app")

# ── Issue #1: Circular import guard ──────────────────────────────────────────
# Import extension singletons EARLY so ``from app import db`` succeeds even
# when Python is still executing this module (re-entrant import scenario).
# All models and blueprints must import from ``app.extensions``, not from
# ``app``, to avoid the re-entrancy entirely — but this guards the legacy path.
from app.extensions import db  # noqa: E402 — must be before create_app

_CREATE_APP_IN_PROGRESS = False  # re-entrancy guard

# ── Global state ─────────────────────────────────────────────────────────────
_DB_READY = False
_DB_INIT_ERROR = ""
_DB_INIT_LOCK = threading.Lock()
_DB_INIT_LAST_ATTEMPT: float = 0.0

_REQUEST_ID_HEADER = "X-Request-ID"

# ── Issue 6: slow-query monitoring ────────────────────────────────────────────
# Guard prevents duplicate listener registrations when create_app() is called
# more than once (e.g. test suite running multiple factory invocations).
_SLOW_QUERY_REGISTERED = False


def _register_slow_query_listener() -> None:
    """Register a one-time SQLAlchemy Engine-class event for slow-query logging.

    Using the Engine *class* (not an instance) means the listener fires on
    every engine created in this process — including the one Flask-SQLAlchemy
    creates lazily after db.init_app().  The listener stacks perf_counter
    timestamps on conn.info so it is gevent-safe and re-entrant.
    """
    global _SLOW_QUERY_REGISTERED
    if _SLOW_QUERY_REGISTERED:
        return
    _SLOW_QUERY_REGISTERED = True

    import time as _time
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "before_cursor_execute")
    def _sq_before(conn, cursor, stmt, params, ctx, exec_many):
        conn.info.setdefault("_sq_t", []).append(_time.perf_counter())

    @event.listens_for(Engine, "after_cursor_execute")
    def _sq_after(conn, cursor, stmt, params, ctx, exec_many):
        stack = conn.info.get("_sq_t")
        if not stack:
            return
        elapsed_ms = (_time.perf_counter() - stack.pop(-1)) * 1000
        if elapsed_ms >= _cfg.SLOW_QUERY_MS:
            msg = "slow_query durationMs=%.1f stmt=%.200s"
            try:
                from flask import current_app
                current_app.logger.warning(msg, elapsed_ms, stmt)
            except RuntimeError:
                log.warning(msg, elapsed_ms, stmt)


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
            from app.utils.db_init import _init_db, _make_superadmin_if_missing
            _init_db()
            _make_superadmin_if_missing()
            _DB_READY = True
            _DB_INIT_ERROR = ""
            return True
        except Exception as exc:
            _DB_INIT_ERROR = str(exc)
            log.exception("Database initialization failed; will retry.")
            return False


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application.

    Issue #1: guarded against re-entrant calls that can occur when a blueprint
    imported inside this function does ``from app import X`` while this module
    is still being initialised.
    """
    global _CREATE_APP_IN_PROGRESS
    if _CREATE_APP_IN_PROGRESS:
        raise RuntimeError(
            "create_app() called recursively — circular import detected. "
            "Ensure all blueprints import from 'app.extensions', not from 'app'."
        )
    _CREATE_APP_IN_PROGRESS = True
    try:
        return _create_app_impl(test_config)
    finally:
        _CREATE_APP_IN_PROGRESS = False


def _create_app_impl(test_config: dict | None = None) -> Flask:
    """Internal factory implementation — call via create_app()."""
    from pathlib import Path
    _PROJECT_ROOT = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(_PROJECT_ROOT / "templates"),
        static_folder=str(_PROJECT_ROOT / "static"),
    )

    # ── Config ────────────────────────────────────────────────────────────────
    app.config.from_object(_cfg.FlaskConfig)
    if not app.config.get("SECRET_KEY"):
        if _cfg.IS_PRODUCTION:
            raise RuntimeError("SECRET_KEY env var is required in production.")
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        log.warning("Using ephemeral SECRET_KEY (dev mode).")
    if test_config:
        app.config.update(test_config)

    # ── Proxy fix ─────────────────────────────────────────────────────────────
    app.wsgi_app = ProxyFix(  # type: ignore[assignment]
        app.wsgi_app,
        x_for=_cfg.TRUSTED_PROXIES,
        x_proto=1,
        x_host=1,
        x_prefix=1,
    )

    # ── Extensions ────────────────────────────────────────────────────────────
    from app.extensions import (
        bcrypt, compress, csrf, db, limiter, login_manager,
        mail, migrate, session_store,
    )

    # Pre-flight: validate that the DB URL is parseable before calling init_app.
    # db.init_app() raises an opaque "Could not parse SQLAlchemy URL" error;
    # this block surfaces the actual URL prefix so it can be debugged quickly.
    _db_uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if not _db_uri:
        raise RuntimeError(
            "SQLALCHEMY_DATABASE_URI is empty. Set DATABASE_URL to a valid "
            "postgresql:// URL in your Render/Railway environment variables."
        )
    try:
        import sqlalchemy as _sa_url_check
        _sa_url_check.engine.make_url(_db_uri)
    except Exception as _url_exc:
        _scheme = _db_uri.split("://")[0] if "://" in _db_uri else repr(_db_uri[:40])
        raise RuntimeError(
            f"DATABASE_URL cannot be parsed as a valid SQLAlchemy URL "
            f"(received scheme/prefix: {_scheme!r}). "
            f"In Render: go to your web service → Environment → DATABASE_URL "
            f"and ensure it starts with postgresql:// pointing to your Postgres instance. "
            f"If you see a bare DSN string (host=... dbname=...) instead of a URL, "
            f"convert it to the URL format."
        ) from _url_exc
    db.init_app(app)
    _register_slow_query_listener()  # Issue 6: slow-query event listener
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    mail.init_app(app)
    compress.init_app(app)
    csrf.init_app(app)

    limiter.init_app(app)
    if _cfg.REDIS_URL:
        app.config["RATELIMIT_STORAGE_URI"] = _cfg.REDIS_URL
    else:
        app.config.setdefault("RATELIMIT_STORAGE_URI", "memory://")

    login_manager.login_view = "web_auth.owner_login"  # type: ignore[assignment]
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    # ── Issue #10: Distributed tracing ────────────────────────────────────────
    # Registered HERE — before blueprints and before_request hooks — so that
    # g.trace_id is populated as the very first before_request action. Any
    # code called by later before_request hooks can then call get_trace_id().
    try:
        from app.middleware.tracing import init_tracing
        init_tracing(app)
        log.info("Distributed tracing middleware registered.")
    except Exception as _tracing_exc:
        log.warning("Tracing middleware failed to init: %s", _tracing_exc)

    # ── Issue #5: Server-side session store (Flask-Session) ───────────────────
    # Initialised HERE — before db.create_all() and blueprints — so the
    # session interface is active from the very first request. Using the
    # singleton from app.extensions keeps the init_app() pattern consistent
    # with every other extension and avoids inline flask_session imports.
    if session_store is not None:
        if _cfg.REDIS_URL:
            try:
                import redis as _redis
                _redis_client = _redis.from_url(
                    _cfg.REDIS_URL,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                _redis_client.ping()  # fail fast rather than at first request
                app.config["SESSION_REDIS"] = _redis_client
                app.config["SESSION_TYPE"] = "redis"
                session_store.init_app(app)
                log.info("Server-side sessions backed by Redis.")
            except ImportError:
                log.warning("flask-session or redis not installed; using cookie sessions.")
            except Exception as _sess_exc:
                log.warning(
                    "Redis session setup failed (%s); falling back to filesystem sessions.",
                    _sess_exc,
                )
                # Explicit fallback so the session interface is always initialised.
                try:
                    import os as _sess_os
                    _sess_os.makedirs(_cfg.SESSION_FILE_DIR, exist_ok=True)
                    app.config["SESSION_TYPE"] = "filesystem"
                    session_store.init_app(app)
                    log.info(
                        "Server-side sessions backed by filesystem (%s) [Redis fallback].",
                        _cfg.SESSION_FILE_DIR,
                    )
                except Exception as _fs_exc:
                    log.warning("Filesystem session fallback failed (%s); using cookie sessions.", _fs_exc)
        else:
            try:
                import os as _sess_os
                _sess_os.makedirs(_cfg.SESSION_FILE_DIR, exist_ok=True)
                app.config["SESSION_TYPE"] = "filesystem"
                session_store.init_app(app)
                log.info("Server-side sessions backed by filesystem (%s).", _cfg.SESSION_FILE_DIR)
            except Exception as _sess_exc:
                log.warning("Filesystem session setup failed (%s); using cookie sessions.", _sess_exc)

    # ── Talisman (security headers) ────────────────────────────────────────────
    # force_https is intentionally False: Railway (and most PaaS) terminate
    # TLS at the edge and forward requests to the container over plain HTTP.
    # If force_https=True, Talisman issues a 301 redirect on every plain-HTTP
    # request — including Railway's own internal health-check probe — causing
    # the health check to fail permanently.  HSTS headers are still sent so
    # browsers enforce HTTPS on subsequent user-facing requests.
    if _cfg.IS_PRODUCTION:
        try:
            from flask_talisman import Talisman
            Talisman(
                app,
                force_https=False,
                strict_transport_security=True,
                strict_transport_security_max_age=31536000,
                strict_transport_security_include_subdomains=True,
                content_security_policy=None,
                referrer_policy="strict-origin-when-cross-origin",
                feature_policy={
                    "geolocation": "'none'",
                    "camera": "'none'",
                    "microphone": "'none'",
                },
            )
            log.info("Talisman security headers enabled (force_https=False; TLS terminated at edge)")
        except ImportError:
            log.warning("Flask-Talisman not installed; security headers disabled")

    @login_manager.user_loader
    def load_user(user_id: str):
        from app.services.auth import load_owner_user
        return load_owner_user(user_id)

    # ── Create tables ─────────────────────────────────────────────────────────
    # Wrapped in try/except: migrations run via flask db upgrade in release.sh,
    # so create_all() is only a safety net. A transient DB error here must not
    # crash the entire app — requests will fail gracefully via _initialize_runtime_state.
    try:
        with app.app_context():
            db.create_all()
    except Exception as _create_exc:
        log.warning("db.create_all() failed at startup (will retry on first request): %s", _create_exc)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from app.api.v1.health import bp as health_bp
    from app.api.v1.menu import bp as menu_bp
    from app.api.v1.orders import bp as orders_bp
    from app.api.v1.kitchen import bp as kitchen_bp
    from app.api.v1.feedback import bp as feedback_bp
    from app.api.v1.payments import bp as payments_bp
    from app.api.v1.webhooks import bp as webhooks_bp
    from app.api.v1.stats import bp as stats_bp
    from app.api.v1.billing_summary import bp as billing_summary_bp
    from app.web.public import bp as public_bp
    from app.web.auth import bp as auth_bp
    from app.web.owner import bp as owner_bp
    from app.web.owner_menu import bp as owner_menu_bp
    from app.web.analytics import bp as analytics_bp
    from app.web.inventory import bp as inventory_bp
    from app.web.superadmin import bp as superadmin_bp
    from app.web.billing_subscription import bp as billing_subscription_bp
    from app.web.onboarding import bp as onboarding_bp
    from admin.routes import admin_bp

    for bp in (
        health_bp, menu_bp, orders_bp, kitchen_bp, feedback_bp,
        payments_bp, webhooks_bp, stats_bp, billing_summary_bp,
        public_bp, auth_bp, owner_bp, owner_menu_bp,
        analytics_bp, inventory_bp, superadmin_bp,
        billing_subscription_bp, onboarding_bp,
        admin_bp,
    ):
        app.register_blueprint(bp)

    # ── Background job queue (RQ) ─────────────────────────────────────────────
    from app.tasks import init_queue
    init_queue(_cfg.RQ_REDIS_URL)

    # ── CDN helper — Jinja2 global ────────────────────────────────────────────
    _cdn_base = _cfg.CDN_URL  # "" → serve from origin

    def cdn_url(path: str) -> str:
        """Return *path* prefixed with CDN_URL when configured."""
        if _cdn_base:
            return _cdn_base + path
        return path

    app.jinja_env.globals["cdn_url"] = cdn_url

    # ── Currency symbol — Jinja2 global ───────────────────────────────────────
    _currency_code = _cfg.STRIPE_CURRENCY or "gbp"
    app.jinja_env.globals["currency_symbol"] = _cfg.CURRENCY_SYMBOLS.get(
        _currency_code.lower(), _currency_code.upper()
    )

    # ── Safe url_for: legacy endpoint-name aliases + graceful BuildError ──────
    # The template was written against the original monolith where all routes
    # had flat names.  After decomposition, endpoints are prefixed with their
    # blueprint name (e.g. kitchen_view → web_owner.kitchen).  A safe wrapper
    # (a) resolves the old names to the new ones and (b) returns '#' for any
    # endpoint that has not been migrated yet so template rendering never 500s.
    _ENDPOINT_ALIASES: dict[str, str] = {
        # ── Web owner blueprint ───────────────────────────────────────────
        "owner_dashboard":                "web_owner.owner_dashboard",
        "owner_panel":                    "web_owner.owner_dashboard",   # legacy alias
        "kitchen_view":                   "web_owner.kitchen",
        "owner_profile":                  "web_owner.owner_profile",
        "owner_tables":                   "web_owner.owner_tables",
        "create_table":                   "web_owner.owner_add_table",
        "delete_table":                   "web_owner.owner_delete_table",
        "rename_table":                   "web_owner.owner_rename_table",
        # ── Web auth blueprint ────────────────────────────────────────────
        "owner_logout":                   "web_auth.owner_logout",
        "owner_login":                    "web_auth.owner_login",
        "owner_signup":                   "web_auth.owner_signup",
        "owner_landing":                  "web_public.owner_landing",
        "owner_redeem_key":               "web_auth.owner_redeem_key",
        # Legacy TOTP route name used by pre-refactor templates
        "owner_login_otp":                "web_auth.owner_login_totp_verify",
        "owner_login_totp_verify":        "web_auth.owner_login_totp_verify",
        # ── Web analytics blueprint ───────────────────────────────────────
        "owner_analytics":                "web_analytics.owner_analytics",
        "export_orders_csv":              "web_analytics.export_orders_csv",
        # ── Web inventory blueprint ───────────────────────────────────────
        "inventory_view":                 "web_inventory.owner_inventory",
        "add_ingredient":                 "web_inventory.owner_add_ingredient",
        "update_ingredient":              "web_inventory.owner_update_ingredient",
        "delete_ingredient":              "web_inventory.owner_delete_ingredient",
        # ── Web superadmin blueprint ──────────────────────────────────────
        "superadmin_dashboard":           "web_superadmin.superadmin_dashboard",
        "superadmin_verify_key":          "web_superadmin.superadmin_verify_key",
        "superadmin_toggle_owner":        "web_superadmin.superadmin_toggle_owner",
        "superadmin_delete_owner":        "web_superadmin.superadmin_delete_owner",
        "superadmin_approve_owner":       "web_superadmin.superadmin_approve_owner",
        "superadmin_generate_admin_key":  "web_superadmin.superadmin_generate_admin_key",
        "superadmin_revoke_admin_key":    "web_superadmin.superadmin_generate_admin_key",  # same form
        "superadmin_leads":               "web_superadmin.superadmin_leads",
        "superadmin_security_log":        "web_superadmin.superadmin_security_log",
        # ── Web owner_menu blueprint ──────────────────────────────────────
        "owner_menu":                     "web_owner_menu.owner_menu",
        "create_menu_category":           "web_owner_menu.owner_add_category",
        "delete_menu_category":           "web_owner_menu.owner_delete_category",
        "save_menu_item":                 "web_owner_menu.owner_add_item",
        "delete_menu_item":               "web_owner_menu.owner_delete_item",
        "toggle_menu_item_availability":  "web_owner_menu.owner_toggle_item",
        "update_menu":                    "web_owner_menu.owner_import_menu",
        # ── Web public blueprint ──────────────────────────────────────────
        "table_order":                    "web_public.table_order",
        "home":                           "web_public.home",
        # ── Extension blueprints ──────────────────────────────────────────
        "tables_overview_view":           "tables_overview.view",
        # ── Billing blueprint ─────────────────────────────────────────────
        "owner_billing_overview":                  "billing.owner_billing_overview",
        "owner_billing_open":                      "billing.owner_billing_open",
        "owner_billing_order_detail":              "billing.owner_billing_order_detail",
        "owner_billing_adjust":                    "billing.owner_billing_adjust",
        "owner_billing_add_item":                  "billing.owner_billing_add_item",
        "owner_billing_remove_item":               "billing.owner_billing_remove_item",
        "owner_billing_settle":                    "billing.owner_billing_settle",
        "owner_billing_void":                      "billing.owner_billing_void",
        "owner_billing_refund":                    "billing.owner_billing_refund",
        "owner_billing_invoice":                   "billing.owner_billing_invoice",
        "owner_billing_eod":                       "billing.owner_billing_eod",
        "owner_billing_eod_csv":                   "billing.owner_billing_eod_csv",
        "owner_billing_refunds":                   "billing.owner_billing_refunds",
        "owner_billing_aging":                     "billing.owner_billing_aging",
        "owner_billing_drawer":                    "billing.owner_billing_drawer",
        "owner_billing_health":                    "billing.owner_billing_health",
        "owner_billing_health_json":               "billing.owner_billing_health_json",
        "owner_billing_logs":                      "billing.owner_billing_logs",
        "owner_billing_settings":                  "billing.owner_billing_settings",
        "owner_billing_payment_methods":           "billing.owner_billing_payment_methods",
        "owner_billing_payment_methods_save":      "billing.owner_billing_payment_methods_save",
        "owner_billing_payment_methods_test":      "billing.owner_billing_payment_methods_test",
        "owner_billing_payment_methods_rotate_webhook": "billing.owner_billing_payment_methods_rotate_webhook",
        "owner_billing_payment_methods_delete":    "billing.owner_billing_payment_methods_delete",
        "owner_billing_create_charge":             "billing.owner_billing_create_charge",
        "billing_pay_page":                        "billing.billing_pay_page",
        "billing_pay_status":                      "billing.billing_pay_status",
        "billing_pay_razorpay_verify":             "billing.billing_pay_razorpay_verify",
        # ── Aggregators blueprint ─────────────────────────────────────────
        "owner_aggregators":                       "aggregators.owner_aggregators",
        "owner_aggregators_save":                  "aggregators.owner_aggregators_save",
        "owner_aggregators_test":                  "aggregators.owner_aggregators_test",
        "owner_aggregators_delete":                "aggregators.owner_aggregators_delete",
        "owner_aggregator_order_action":           "aggregators.owner_aggregator_order_action",
        # ── Integrations hub blueprint ────────────────────────────────────
        "owner_integrations_hub":                  "integrations.owner_integrations_hub",
        "owner_integrations_test_all":             "integrations.owner_integrations_test_all",
        "owner_integrations_checklist_json":       "integrations.owner_integrations_checklist_json",
        # ── Superadmin extras ─────────────────────────────────────────────
        "superadmin_analytics":                    "web_superadmin.superadmin_analytics",
        # ── New owner routes ──────────────────────────────────────────────
        "reorder_view":                            "web_owner.reorder_view",
        "owner_customers":                         "web_owner.owner_customers",
        "download_all_table_qr_posters":           "web_owner.download_all_table_qr_posters",
        "table_qr":                               "web_owner.table_qr",
        # ── Inventory extras ──────────────────────────────────────────────
        "import_inventory_csv":                    "web_inventory.import_inventory_csv",
        "export_inventory_csv":                    "web_inventory.export_inventory_csv",
        "restock_ingredient":                      "web_inventory.restock_ingredient",
        # ── Menu extras ───────────────────────────────────────────────────
        "export_menu_csv":                         "web_owner_menu.export_menu_csv",
        "save_menu_item":                          "web_owner_menu.save_menu_item",
        "owner_upload_item_image":                 "web_owner_menu.owner_upload_item_image",
        # ── Daily report PDF ──────────────────────────────────────────────
        "daily_report_pdf":                        "billing.owner_billing_eod",
    }

    from werkzeug.routing import BuildError as _BuildError

    def _safe_url_for(endpoint: str, **values):  # type: ignore[override]
        """url_for() that resolves legacy monolith endpoint names and returns
        '#' instead of raising BuildError for not-yet-migrated endpoints.

        Issue 4: injects ?v=<APP_VERSION> into static asset URLs so that the
        long-lived Cache-Control: max-age=31536000 header (set via
        SEND_FILE_MAX_AGE_DEFAULT) is safe — a new deploy changes the version
        string, busting every cached asset without renaming files.
        """
        from flask import url_for as _uf
        resolved = _ENDPOINT_ALIASES.get(endpoint, endpoint)
        # Issue 4: append cache-busting version to static URLs only.
        if resolved == "static" and "v" not in values and _cfg.APP_VERSION:
            values["v"] = _cfg.APP_VERSION
        try:
            return _uf(resolved, **values)
        except _BuildError:
            return "#"

    app.jinja_env.globals["url_for"] = _safe_url_for

    # ── External blueprints (existing extensions/) ────────────────────────────
    try:
        from extensions import init_extensions
        init_extensions(app)
    except ImportError:
        pass
    except Exception as exc:
        log.warning("extensions.init_extensions failed: %s", exc)

    # ── CSRF exempt for API routes ────────────────────────────────────────────
    try:
        from flask_wtf.csrf import CSRFProtect
        for bp in (health_bp, menu_bp, orders_bp, kitchen_bp, feedback_bp, webhooks_bp):
            csrf.exempt(bp)
    except Exception:
        pass

    # ── Before-request: request ID, session fingerprinting ───────────────────
    @app.before_request
    def _assign_request_id() -> None:
        incoming = (request.headers.get(_REQUEST_ID_HEADER) or "").strip()
        if incoming and len(incoming) <= 128 and all(c.isalnum() or c in "-_" for c in incoming):
            rid = incoming
        else:
            rid = secrets.token_hex(8)
        request.environ["request_id"] = rid
        request.environ["_t_start"] = time.perf_counter()
        try:
            stored_fp = session.get("ua_fp")
            if stored_fp:
                from app.services.auth import _ua_fingerprint
                if stored_fp != _ua_fingerprint():
                    from app.utils.security import log_security
                    log_security("SESSION_FINGERPRINT_MISMATCH",
                                 f"owner_id={session.get('owner_id')!r}")
                    # Only clear owner-session keys. session.clear() would also wipe
                    # admin_authenticated, admin_owner_id, and admin_via_superadmin,
                    # logging out admins whenever a UA string fluctuates (proxy headers,
                    # browser minor updates, etc.).
                    for _k in (
                        "owner_username", "owner_id", "ua_fp",
                        "pending_totp_owner_id", "pending_totp_remember",
                    ):
                        session.pop(_k, None)
        except Exception:
            pass

    @app.before_request
    def _ensure_db_ready():
        if not _DB_READY and not request.path.startswith("/health") and not request.path.startswith("/healthz"):
            _initialize_runtime_state()

    # ── After-request: security headers, logging ──────────────────────────────
    @app.after_request
    def _security_headers(response):
        from flask import Response as FlaskResponse
        response.headers["Server"] = "CafePortal"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()"
        )
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if "Content-Security-Policy" not in response.headers:
            ct = (response.content_type or "").lower()
            if "html" in ct or ct == "":
                response.headers["Content-Security-Policy"] = (
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
                    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
                    "img-src 'self' data: blob: https://image.pollinations.ai "
                    "https://*.unsplash.com https://images.unsplash.com https://*.googleusercontent.com; "
                    "connect-src 'self' https://image.pollinations.ai; "
                    "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
                )
        rid = request.environ.get("request_id")
        if rid:
            response.headers.setdefault(_REQUEST_ID_HEADER, rid)
        if request.path.startswith("/static/") and response.status_code == 200:
            response.headers.setdefault("Cache-Control", "public, max-age=31536000, immutable")
        t0 = request.environ.get("_t_start")
        if t0 is not None and not request.path.startswith("/api/orders/stream") and not request.path.startswith("/api/v1/orders/stream"):
            dur_ms = (time.perf_counter() - t0) * 1000.0
            log_payload = {
                "event": "http.request",
                "rid": rid,
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "durationMs": round(dur_ms, 2),
            }
            if dur_ms >= _cfg.SLOW_REQUEST_MS:
                app.logger.warning("slow_request %s", __import__("json").dumps(log_payload))
            elif response.status_code >= 500:
                app.logger.error("server_error %s", __import__("json").dumps(log_payload))
        is_https = (
            request.is_secure
            or request.headers.get("X-Forwarded-Proto", "").lower() == "https"
        )
        if is_https and _cfg.IS_PRODUCTION:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    # ── Error handlers ────────────────────────────────────────────────────────
    from app.utils.serializers import _wants_json, _safe_redirect_target

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

    @app.errorhandler(429)
    def err_rate_limit(e):
        from app.utils.security import log_security
        log_security("RATE_LIMIT_HIT", f"path={request.path}")
        if _wants_json():
            return jsonify(description="Too many requests."), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def err_server_error(e):
        if _wants_json():
            return jsonify(description="Internal server error."), 500
        try:
            return render_template("errors/500.html"), 500
        except Exception:
            return "Internal server error", 500

    try:
        from flask_wtf.csrf import CSRFError

        @app.errorhandler(CSRFError)
        def err_csrf(e):
            from app.utils.security import log_security
            log_security("CSRF_VIOLATION", f"path={request.path}")
            from flask import flash
            flash("Your session has expired. Please try again.")
            return redirect(_safe_redirect_target(request.referrer, url_for("web_public.home"))), 302
    except ImportError:
        pass

    # ── SSE Redis pub/sub (optional) ──────────────────────────────────────────
    if not (test_config or {}).get("TESTING"):
        from app.services.notifications import init_redis_pubsub
        init_redis_pubsub()

    # ── Run DB init on first real request ─────────────────────────────────────
    with app.app_context():
        _initialize_runtime_state(force=True)

    _cfg.APP_START_TIME = time.time()
    return app


# ── Backward-compatible module-level exports ──────────────────────────────────
# ``import app as flask_app; flask_app.app; flask_app.db`` must still work.
# Python resolves the *package* before ``app.py`` so these names are exposed
# here on the package itself.
# NOTE: ``db`` is already imported at the TOP of this module (Issue #1 fix).
# The duplicate import that used to live here has been removed.

app = create_app()

# Re-export all models at package level for legacy ``from app import Owner`` usage.
from app.models import (  # noqa: E402, F401
    AggregatorOrder,
    AggregatorPlatformCredential,
    AuditLog,
    BillingLog,
    Cafe,
    CafeTable,
    CashDrawerCount,
    Customer,
    Employee,
    Feedback,
    Ingredient,
    Invitation,
    Menu,
    OnlinePayment,
    Order,
    OrderEmployeeAssignment,
    Owner,
    OwnerLead,
    PaymentProviderCredential,
    RememberToken,
    Settings,
    SystemFlag,
    TableCall,
    WebhookEventLog,
)

# Legacy helpers re-exported for any extension still importing from ``app``.
from app.services.auth import (  # noqa: E402, F401
    logged_in_owner,
    logged_in_owner_id,
    logged_in_owner_obj,
    create_remember_token,
    validate_remember_token,
    revoke_remember_token,
    revoke_all_tokens_for_owner,
    _make_password_hash,
    _password_matches,
)
from app.services.menu import load_menu, save_menu, load_owner_menu, save_owner_menu  # noqa: E402, F401
from app.services.tables import (  # noqa: E402, F401
    load_tables,
    save_tables,
    load_owner_tables,
    load_settings,
    save_settings,
)
from app.services.orders import (  # noqa: E402, F401
    load_orders,
    place_order_in_db,
    compute_order_summary,
    _db_update_order_status,
    _db_get_order,
    _db_delete_order,
    save_feedback_entry,
)
from app.services.notifications import (  # noqa: E402, F401
    _notify_owner,
    _notify_order_status,
    _notify_table_call,
    _push_new_order,
)
from app.utils.security import (  # noqa: E402, F401
    log_security,
    validate_uploaded_file,
    login_required,
    api_login_required,
    superadmin_required,
    SECURITY_EVENT_BUFFER,
)
from app.utils.serializers import (  # noqa: E402, F401
    _safe_text,
    _iso,
    _parse_dt,
    _wants_json,
    _no_store,
    _safe_redirect_target,
)

# ── Flask CLI commands ────────────────────────────────────────────────────────
import click as _click  # noqa: E402 — Flask bundles click


@app.cli.command("sync-schema")
def cli_sync_schema() -> None:
    """Idempotent CREATE TABLE IF NOT EXISTS + ADD COLUMN pass.

    Used by scripts/release.sh as a safety net after flask db upgrade
    to catch any model additions that don't yet have a migration.
    """
    from app.extensions import db as _db
    with app.app_context():
        _db.create_all()
    _click.echo("sync-schema OK")


# ── Legacy compatibility exports for admin/routes.py _store() usage ──────────
from app.config import DATA_DIR  # noqa: E402, F401
from app.extensions import limiter  # noqa: E402, F401
from sqlalchemy import text  # noqa: E402, F401
from app.services.auth import (  # noqa: E402, F401
    load_owners,
    create_owner_in_db,
    find_admin_key_owner,
    _load_admin_keys_from_db as load_admin_keys,
)

USE_DB: bool = True

# Legacy JSON-file path constants (admin status page compatibility)
OWNERS_PATH = _cfg.DATA_DIR / "owners.json"
ORDERS_PATH = _cfg.DATA_DIR / "orders.json"
MENU_PATH = _cfg.DATA_DIR / "menu.json"
TABLES_PATH = _cfg.DATA_DIR / "tables.json"
FEEDBACK_PATH = _cfg.DATA_DIR / "feedback.json"
