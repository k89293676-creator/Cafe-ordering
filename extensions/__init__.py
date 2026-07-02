"""Extensions package: new feature blueprints layered on top of the core app.

This package is the seam where we gradually decompose the monolith.
New features live here in small, focused modules and are wired into the
Flask app via :func:`init_extensions`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


def init_extensions(app: "Flask") -> None:
    """Register every extension blueprint and ensure new tables exist."""
    # Local imports keep startup fast and avoid circular imports.
    try:
        from . import models as _models  # noqa: F401  (migrated → app.models)
    except ImportError:
        pass
    try:
        from . import mt_models as _mt_models  # noqa: F401  (migrated → app.models.auth / staff)
    except ImportError:
        pass

    blueprints_to_try = [
        ("service_calls_bp", "bp"),
        ("sales_dashboard_bp", "bp"),
        ("menu_engineering_bp", "bp"),
        ("ltv_bp", "bp"),
        ("employees_bp", "bp"),
        ("superadmin_extras_bp", "bp"),
        ("customers_bp", "bp"),
        ("push_bp", "bp"),
        ("multi_tenant_bp", "bp"),
        ("tables_overview_bp", "bp"),
        ("exports_bp", "bp"),
        # ── New feature blueprints ────────────────────────────────────────
        ("billing_bp", "bp"),
        ("aggregators_bp", "bp"),
        ("integrations_bp", "bp"),
        ("metrics_bp", "bp"),
    ]
    for module_name, bp_attr in blueprints_to_try:
        try:
            mod = __import__(f"extensions.{module_name}", fromlist=[bp_attr])
            bp = getattr(mod, bp_attr)
            if bp.name not in app.blueprints:
                app.register_blueprint(bp)
        except (ImportError, AttributeError, Exception) as exc:
            app.logger.warning("extensions: failed to register %s: %s", module_name, exc)

    # Ensure the new tables exist even if alembic hasn't run yet.
    from app.extensions import db
    try:
        with app.app_context():
            db.create_all()
    except Exception as exc:
        app.logger.warning("extensions: deferred create_all failed: %s", exc)


# Backward compat alias
register_extensions = init_extensions
