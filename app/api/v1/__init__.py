"""API v1 blueprint registration.

All JSON endpoints live under ``/api/v1/`` for explicit versioning.
Legacy unversioned paths (``/api/menu``, ``/api/checkout``, etc.) are
preserved via backward-compat redirects registered in ``create_app()``.
"""
from __future__ import annotations

from flask import Blueprint

from app.api.v1.health import bp as health_bp
from app.api.v1.menu import bp as menu_bp
from app.api.v1.orders import bp as orders_bp
from app.api.v1.kitchen import bp as kitchen_bp
from app.api.v1.feedback import bp as feedback_bp

v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def register_v1(app):
    """Register all v1 sub-blueprints onto the Flask app."""
    for bp in (health_bp, menu_bp, orders_bp, kitchen_bp, feedback_bp):
        app.register_blueprint(bp)
