"""Health, readiness, metrics and ops endpoints."""
from __future__ import annotations

import hmac
import os
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from sqlalchemy import text, func

from app.extensions import db, limiter

bp = Blueprint("api_v1_health", __name__)

_START_TIME = time.time()


# ── Liveness ──────────────────────────────────────────────────────────────────

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


@bp.route("/healthz")
@limiter.exempt
def healthz():
    return ("ok", 200, {"Content-Type": "text/plain"})


# ── Readiness ─────────────────────────────────────────────────────────────────

@bp.route("/api/v1/ready")
@bp.route("/readyz")
@limiter.exempt
def readiness_check():
    from app.config import APP_VERSION
    checks: dict = {}
    overall_ok = True

    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["database"] = {"ok": False, "error": str(exc)[:200]}

    try:
        db.session.execute(text("SELECT 1 FROM payment_credentials LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM webhook_events LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM aggregator_credentials LIMIT 0"))
        checks["schema"] = {"ok": True}
    except Exception as exc:
        checks["schema"] = {"ok": False, "error": str(exc)[:200], "hint": "run flask db upgrade"}
        overall_ok = False

    try:
        from lib_payments import encrypt_secret, decrypt_secret
        probe = encrypt_secret("healthz-probe")
        assert decrypt_secret(probe) == "healthz-probe"
        checks["encryption"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["encryption"] = {"ok": False, "error": str(exc)[:200]}

    status = 200 if overall_ok else 503
    return jsonify(
        ok=overall_ok,
        checks=checks,
        version=APP_VERSION,
        uptime_seconds=int(time.time() - _START_TIME),
    ), status


# ── Version ───────────────────────────────────────────────────────────────────

@bp.route("/api/v1/version")
@bp.route("/version")
@limiter.exempt
def version_endpoint():
    from app.config import APP_VERSION
    import datetime as _dt
    return jsonify(
        version=APP_VERSION,
        commit=os.environ.get("RAILWAY_GIT_COMMIT_SHA", "")[:40] or None,
        branch=os.environ.get("RAILWAY_GIT_BRANCH") or None,
        deployedAt=os.environ.get("RAILWAY_DEPLOYMENT_CREATED_AT") or None,
        startedAt=_dt.datetime.fromtimestamp(
            _START_TIME, tz=_dt.timezone.utc
        ).isoformat(),
    ), 200


# ── Ops health (bearer-token-protected, per-section) ─────────────────────────

@bp.route("/api/ops/health")
@limiter.exempt
def ops_health():
    """Deep per-section health check for post-deploy probes.

    Protected by OPS_HEALTH_TOKEN bearer token when configured.
    Returns 200 with ``ok=true`` only when all critical sections pass.
    """
    expected_token = os.environ.get("OPS_HEALTH_TOKEN", "")
    if expected_token:
        auth_header = request.headers.get("Authorization", "")
        provided = auth_header.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(provided.encode(), expected_token.encode()):
            return jsonify(ok=False, error="Unauthorized"), 401

    started = time.time()
    sections: dict = {}
    overall_ok = True

    # Database
    try:
        db.session.execute(text("SELECT 1"))
        sections["database"] = {"ok": True}
    except Exception as exc:
        sections["database"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Redis (optional — only flagged critical if configured)
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            import redis as _redis
            r = _redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.time()
            r.ping()
            sections["redis"] = {"ok": True, "latency_ms": round((time.time() - t0) * 1000, 2)}
        except Exception as exc:
            sections["redis"] = {"ok": False, "error": str(exc)[:200]}
            overall_ok = False
    else:
        sections["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # Encryption round-trip
    try:
        from lib_payments import encrypt_secret, decrypt_secret
        probe = encrypt_secret("ops-probe")
        assert decrypt_secret(probe) == "ops-probe"
        sections["encryption"] = {"ok": True}
    except Exception as exc:
        sections["encryption"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Admin key configured
    admin_key_set = bool(os.environ.get("ADMIN_SECRET_KEY"))
    sections["admin_key"] = {"ok": admin_key_set, "note": "Set ADMIN_SECRET_KEY" if not admin_key_set else None}

    # Disk writability
    try:
        from app.config import DATA_DIR
        probe_path = DATA_DIR / ".ops_health_probe.tmp"
        probe_path.write_text("ok", encoding="utf-8")
        probe_path.unlink(missing_ok=True)
        sections["disk"] = {"ok": True, "path": str(DATA_DIR)}
    except Exception as exc:
        sections["disk"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    status_code = 200 if overall_ok else 503
    return jsonify(
        ok=overall_ok,
        sections=sections,
        uptime_seconds=int(time.time() - _START_TIME),
        elapsed_ms=round((time.time() - started) * 1000, 1),
        checked_at=datetime.now(timezone.utc).isoformat(),
    ), status_code


# ── Metrics — JSON (api/v1) + Prometheus text (/metrics) ────────────────────

def _collect_metrics() -> dict:
    """Collect current metrics as a plain dict (shared by both endpoints)."""
    from app.models import Order, Feedback, Owner
    try:
        order_counts: dict = {}
        rows = db.session.query(Order.status, func.count(Order.id)).group_by(Order.status).all()
        for status, cnt in rows:
            order_counts[status or "unknown"] = cnt
        total_orders = sum(order_counts.values())
        total_owners = db.session.query(func.count(Owner.id)).scalar() or 0
        avg_rating_raw = db.session.query(func.avg(Feedback.rating)).scalar()
        avg_rating = round(float(avg_rating_raw), 4) if avg_rating_raw else 0.0
    except Exception:
        order_counts = {}
        total_orders = total_owners = 0
        avg_rating = 0.0
    return {
        "uptime_seconds": int(time.time() - _START_TIME),
        "total_orders": total_orders,
        "order_counts": order_counts,
        "total_owners": total_owners,
        "average_rating": avg_rating,
    }


@bp.route("/api/v1/metrics")
def api_metrics_json():
    """JSON metrics for dashboards."""
    m = _collect_metrics()
    return jsonify(
        orders=m["total_orders"],
        ordersByStatus=m["order_counts"],
        owners=m["total_owners"],
        averageRating=m["average_rating"],
        uptimeSeconds=m["uptime_seconds"],
    ), 200


@bp.route("/metrics")
@limiter.exempt
def prometheus_metrics():
    """Prometheus-compatible text metrics.

    Returns Prometheus exposition format (text/plain; version=0.0.4).
    Falls back to JSON when Accept: application/json is explicitly requested.
    """
    accept = request.headers.get("Accept", "")
    if "application/json" in accept and "text/plain" not in accept:
        return api_metrics_json()

    try:
        from prometheus_client import (
            CollectorRegistry,
            Gauge,
            generate_latest,
            CONTENT_TYPE_LATEST,
        )

        reg = CollectorRegistry()
        m = _collect_metrics()

        Gauge(
            "cafe_uptime_seconds",
            "Seconds since the Flask application started",
            registry=reg,
        ).set(m["uptime_seconds"])

        orders_g = Gauge(
            "cafe_orders_total",
            "Total orders by status",
            ["status"],
            registry=reg,
        )
        for status, cnt in m["order_counts"].items():
            orders_g.labels(status=status).set(cnt)

        Gauge(
            "cafe_owners_total",
            "Total registered owner accounts",
            registry=reg,
        ).set(m["total_owners"])

        Gauge(
            "cafe_feedback_average_rating",
            "Average customer feedback rating (1-5)",
            registry=reg,
        ).set(m["average_rating"])

        return Response(generate_latest(reg), mimetype=CONTENT_TYPE_LATEST)

    except ImportError:
        # prometheus_client not installed — fall back to Prometheus text hand-rolled
        m = _collect_metrics()
        lines = [
            "# HELP cafe_uptime_seconds Seconds since the Flask application started.",
            "# TYPE cafe_uptime_seconds gauge",
            f"cafe_uptime_seconds {m['uptime_seconds']}",
            "# HELP cafe_orders_total Total orders by status.",
            "# TYPE cafe_orders_total gauge",
        ]
        for status, cnt in m["order_counts"].items():
            lines.append(f'cafe_orders_total{{status="{status}"}} {cnt}')
        lines += [
            "# HELP cafe_owners_total Total registered owner accounts.",
            "# TYPE cafe_owners_total gauge",
            f"cafe_owners_total {m['total_owners']}",
            "# HELP cafe_feedback_average_rating Average customer feedback rating.",
            "# TYPE cafe_feedback_average_rating gauge",
            f"cafe_feedback_average_rating {m['average_rating']}",
        ]
        body = "\n".join(lines) + "\n"
        return Response(body, mimetype="text/plain; version=0.0.4; charset=utf-8")


# ── Static well-known files ───────────────────────────────────────────────────

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
    return Response(body, mimetype="text/plain; charset=utf-8")


@bp.route("/.well-known/security.txt")
@limiter.exempt
def security_txt():
    import datetime as _dt
    contact = os.environ.get("SECURITY_CONTACT") or "mailto:security@example.com"
    expires = (
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = (
        f"Contact: {contact}\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
        f"Canonical: https://{request.host}/.well-known/security.txt\n"
    )
    return Response(body, mimetype="text/plain; charset=utf-8")
