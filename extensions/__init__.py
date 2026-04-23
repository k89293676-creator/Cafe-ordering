"""Extensions package: new feature blueprints layered on top of the legacy
monolithic ``app.py``.

This package is the seam where we are gradually decomposing the monolith.
New features live here in small, focused modules and are wired into the
Flask app via :func:`register_extensions`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from flask import Flask


def register_extensions(app: "Flask") -> None:
    """Register every extension blueprint and ensure new tables exist."""
    # Local imports keep startup fast and avoid circular imports with app.py.
    from . import models  # noqa: F401  (registers SQLAlchemy models)
    from . import mt_models  # noqa: F401  (multi-tenant models: Invitation, AuditLog)
    from .service_calls_bp import bp as service_calls_bp
    from .sales_dashboard_bp import bp as sales_dashboard_bp
    from .menu_engineering_bp import bp as menu_engineering_bp
    from .ltv_bp import bp as ltv_bp
    from .employees_bp import bp as employees_bp
    from .superadmin_extras_bp import bp as superadmin_extras_bp
    from .customers_bp import bp as customers_bp
    from .push_bp import bp as push_bp
    from .multi_tenant_bp import bp as multi_tenant_bp
    from .tables_overview_bp import bp as tables_overview_bp

    for bp in (
        service_calls_bp,
        sales_dashboard_bp,
        menu_engineering_bp,
        ltv_bp,
        employees_bp,
        superadmin_extras_bp,
        customers_bp,
        push_bp,
        multi_tenant_bp,
        tables_overview_bp,
    ):
        if bp.name not in app.blueprints:
            app.register_blueprint(bp)

    # Ensure the new tables exist even if the operator hasn't run alembic yet.
    # This is safe: ``create_all`` is idempotent and only creates missing tables.
    from app import db  # local import to avoid circular import at module load
    try:
        with app.app_context():
            db.create_all()
    except Exception as exc:  # pragma: no cover - defensive
        app.logger.warning("extensions: deferred create_all failed: %s", exc)
