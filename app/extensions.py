"""Flask extension singletons.

Initialised here without an app object; bound to a real app inside
``create_app()`` via ``ext.init_app(app)``.  Importing from this module
never triggers app creation, so it is safe to use in models, services, and
blueprints without causing circular imports.

All extensions that were previously wired inline inside ``create_app()``
(Flask-Session, tracing) belong here so every module can import a single
canonical object instead of relying on the package-level ``app`` namespace.
"""
from __future__ import annotations

from flask_bcrypt import Bcrypt
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
mail = Mail()
login_manager = LoginManager()
compress = Compress()
csrf = CSRFProtect()

# Limiter is configured with storage_uri at init_app time.
limiter = Limiter(key_func=get_remote_address)

# ── Flask-Session (Issue #5) ───────────────────────────────────────────────
# Server-side session store. SESSION_TYPE / SESSION_REDIS are set in
# app.config before session_store.init_app(app) is called in create_app().
# If flask-session is not installed the attribute is None and create_app()
# skips server-side sessions gracefully, falling back to signed cookies.
try:
    from flask_session import Session as _FlaskSession
    session_store: "_FlaskSession | None" = _FlaskSession()
except ImportError:  # pragma: no cover — flask-session is in requirements.txt
    session_store = None  # type: ignore[assignment]
