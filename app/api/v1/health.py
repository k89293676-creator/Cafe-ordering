"""Health, readiness and metrics endpoints — /api/v1/health, /api/v1/metrics."""
from __future__ import annotations

import os
import time

from flask import Blueprint, jsonify, current_app
from sqlalchemy import text

from app.extensions import db, limiter

bp = Blueprint("api_v1_health", __name__)

# Module-level start time (set once at import).
_START_TIME = time.time()


@bp.route("/api/v1/health")
@bp.route("/health")
@limiter.exempt
def health_check():
    from app.config import APP_VERSION
    return jsonify(
        status="ok",
        version=APP_VERSION,
        uptimeSeconds=int(time.time() - _START_TIME),
    ), 200


@bp.route("/api/v1/ready")
@bp.route("/readyz")
@limiter.exempt
def readiness_check():
    from app.config import APP_VERSION
    from lib_payments import encrypt_secret, decrypt_secret
    checks: dict = {}
    overall_ok = True
    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["database"] = {"ok": False, "error": str(exc)[:200]}
    try:
        db.session.execute(text("SELECT verified_at, verified_fingerprint FROM payment_credentials LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM webhook_events LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM aggregator_credentials LIMIT 0"))
        checks["schema"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["schema"] = {"ok": False, "error": str(exc)[:200], "hint": "migrations may not have run"}
    try:
        probe = encrypt_secret("healthz-probe")
        assert decrypt_secret(probe) == "healthz-probe"
        checks["encryption"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["encryption"] = {"ok": False, "error": str(exc)[:200]}
    status = 200 if overall_ok else 503
    return jsonify(ok=overall_ok, checks=checks, version=APP_VERSION,
                   uptime_seconds=int(time.time() - _START_TIME)), status


@bp.route("/api/v1/version")
@bp.route("/version")
@limiter.exempt
def version_endpoint():
    from app.config import APP_VERSION
    return jsonify(
        version=APP_VERSION,
        commit=os.environ.get("RAILWAY_GIT_COMMIT_SHA", "")[:40] or None,
        branch=os.environ.get("RAILWAY_GIT_BRANCH") or None,
        deployedAt=os.environ.get("RAILWAY_DEPLOYMENT_CREATED_AT") or None,
        startedAt=__import__("datetime").datetime.fromtimestamp(
            _START_TIME, tz=__import__("datetime").timezone.utc
        ).isoformat(),
    ), 200


@bp.route("/api/v1/metrics")
@bp.route("/metrics")
def public_metrics():
    from app.models import Order, Feedback, Owner
    try:
        total_orders = db.session.query(db.func.count(Order.id)).scalar() or 0
        total_owners = db.session.query(db.func.count(Owner.id)).scalar() or 0
        avg_rating = db.session.query(db.func.avg(Feedback.rating)).scalar()
        avg_rating = round(float(avg_rating), 2) if avg_rating else 0.0
    except Exception:
        total_orders = total_owners = 0
        avg_rating = 0.0
    return jsonify(
        orders=total_orders,
        owners=total_owners,
        averageRating=avg_rating,
        uptimeSeconds=int(time.time() - _START_TIME),
    ), 200


@bp.route("/healthz")
@limiter.exempt
def healthz():
    return ("ok", 200, {"Content-Type": "text/plain"})


@bp.route("/robots.txt")
@limiter.exempt
def robots_txt():
    body = (
        "User-agent: *\n"
        "Disallow: /owner/\n"
        "Disallow: /admin/\n"
        "Disallow: /superadmin/\n"
        "Disallow: /api/\n"
        "Disallow: /kitchen\n"
        "Allow: /\n"
    )
    from flask import Response
    return Response(body, mimetype="text/plain; charset=utf-8")


@bp.route("/.well-known/security.txt")
@limiter.exempt
def security_txt():
    from flask import Response
    import datetime as _dt
    contact = os.environ.get("SECURITY_CONTACT") or "mailto:security@example.com"
    expires = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    from flask import request
    body = (
        f"Contact: {contact}\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
        f"Canonical: https://{request.host}/.well-known/security.txt\n"
    )
    return Response(body, mimetype="text/plain; charset=utf-8")
