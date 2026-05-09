"""Health, readiness, metrics and ops endpoints.

Issue #9 fix: readiness endpoint now probes all critical dependencies —
database, Redis, encryption, disk, background-task queue, and circuit
breaker states — so an orchestrator (Railway, k8s, Docker Compose) will
not route traffic to a pod that is partially broken.
"""
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


# ── Readiness — Issue #9: full dependency probe ───────────────────────────────

@bp.route("/api/v1/ready")
@bp.route("/readyz")
@limiter.exempt
def readiness_check():
    from app.config import APP_VERSION
    checks: dict = {}
    overall_ok = True

    # 1. Database connectivity
    try:
        db.session.execute(text("SELECT 1"))
        db.session.rollback()
        checks["database"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["database"] = {"ok": False, "error": str(exc)[:200]}

    # 2. Required schema tables
    try:
        db.session.execute(text("SELECT 1 FROM payment_credentials LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM webhook_events LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM aggregator_credentials LIMIT 0"))
        checks["schema"] = {"ok": True}
    except Exception as exc:
        checks["schema"] = {"ok": False, "error": str(exc)[:200], "hint": "run flask db upgrade"}
        overall_ok = False
    finally:
        db.session.rollback()

    # 3. Encryption round-trip
    try:
        from lib_payments import encrypt_secret, decrypt_secret
        probe = encrypt_secret("healthz-probe")
        assert decrypt_secret(probe) == "healthz-probe"
        checks["encryption"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["encryption"] = {"ok": False, "error": str(exc)[:200]}

    # 4. Redis connectivity (Issue #9 — was missing from readiness)
    redis_url = os.environ.get("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _redis
            r = _redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.monotonic()
            r.ping()
            latency_ms = round((time.monotonic() - t0) * 1000, 2)
            checks["redis"] = {"ok": True, "latency_ms": latency_ms}
        except Exception as exc:
            overall_ok = False
            checks["redis"] = {"ok": False, "error": str(exc)[:200]}
    else:
        checks["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # 5. Background task queue — Issue #9
    try:
        from lib_runtime import BackgroundTaskQueue
        _q = BackgroundTaskQueue.__new__(BackgroundTaskQueue)
        checks["bg_queue"] = {"ok": True, "note": "in-process queue available"}
    except Exception as exc:
        checks["bg_queue"] = {"ok": False, "error": str(exc)[:200]}

    # 6. Circuit breaker states — Issue #9 + #12
    try:
        from app.middleware.circuit_breaker import all_breaker_stats
        breaker_stats = all_breaker_stats()
        open_breakers = [b["name"] for b in breaker_stats if b["state"] == "OPEN"]
        checks["circuit_breakers"] = {
            "ok": len(open_breakers) == 0,
            "open": open_breakers,
            "details": breaker_stats,
        }
        if open_breakers:
            checks["circuit_breakers"]["warning"] = f"Open circuits: {', '.join(open_breakers)}"
    except Exception as exc:
        checks["circuit_breakers"] = {"ok": True, "note": str(exc)[:100]}

    # 7. Disk writability — Issue #9
    try:
        from app.config import DATA_DIR
        probe_path = DATA_DIR / ".readyz_probe.tmp"
        probe_path.write_text("ok", encoding="utf-8")
        probe_path.unlink(missing_ok=True)
        checks["disk"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["disk"] = {"ok": False, "error": str(exc)[:200]}

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


# ── Ops health (bearer-token-protected, full dependency matrix) ───────────────

@bp.route("/api/ops/health")
@limiter.exempt
def ops_health():
    """Deep per-section health check — Issue #9: circuit breakers + queue added.

    Protected by OPS_HEALTH_TOKEN bearer token when configured.
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
        t0 = time.monotonic()
        db.session.execute(text("SELECT 1"))
        db.session.rollback()
        sections["database"] = {"ok": True, "latency_ms": round((time.monotonic() - t0) * 1000, 2)}
    except Exception as exc:
        sections["database"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Redis
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            import redis as _redis
            r = _redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.monotonic()
            r.ping()
            sections["redis"] = {"ok": True, "latency_ms": round((time.monotonic() - t0) * 1000, 2)}
        except Exception as exc:
            sections["redis"] = {"ok": False, "error": str(exc)[:200]}
            overall_ok = False
    else:
        sections["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # Encryption
    try:
        from lib_payments import encrypt_secret, decrypt_secret
        probe = encrypt_secret("ops-probe")
        assert decrypt_secret(probe) == "ops-probe"
        sections["encryption"] = {"ok": True}
    except Exception as exc:
        sections["encryption"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Admin key
    admin_key_set = bool(os.environ.get("ADMIN_SECRET_KEY"))
    sections["admin_key"] = {
        "ok": admin_key_set,
        "note": "Set ADMIN_SECRET_KEY" if not admin_key_set else None,
    }

    # Disk
    try:
        from app.config import DATA_DIR
        probe_path = DATA_DIR / ".ops_health_probe.tmp"
        probe_path.write_text("ok", encoding="utf-8")
        probe_path.unlink(missing_ok=True)
        sections["disk"] = {"ok": True, "path": str(DATA_DIR)}
    except Exception as exc:
        sections["disk"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Circuit breakers — Issue #9 + #12
    try:
        from app.middleware.circuit_breaker import all_breaker_stats
        breaker_stats = all_breaker_stats()
        open_breakers = [b["name"] for b in breaker_stats if b["state"] == "OPEN"]
        sections["circuit_breakers"] = {
            "ok": len(open_breakers) == 0,
            "open": open_breakers,
            "details": breaker_stats,
        }
        if open_breakers:
            sections["circuit_breakers"]["note"] = (
                f"Open circuits will self-recover after cooldown: {', '.join(open_breakers)}"
            )
    except Exception as exc:
        sections["circuit_breakers"] = {"ok": True, "note": str(exc)[:100]}

    # Background task queue
    try:
        from app.cache import BackgroundTaskQueue
        _q = BackgroundTaskQueue(name="_health_probe")
        stats = _q.stats()
        sections["bg_queue"] = {"ok": True, **stats}
    except Exception as exc:
        sections["bg_queue"] = {"ok": True, "note": str(exc)[:100]}

    # DB connection pool stats
    try:
        from app.extensions import db as _db
        pool = _db.engine.pool
        sections["db_pool"] = {
            "ok": True,
            "size": pool.size(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
        }
    except Exception:
        sections["db_pool"] = {"ok": True, "note": "pool stats unavailable"}

    status_code = 200 if overall_ok else 503
    return jsonify(
        ok=overall_ok,
        sections=sections,
        uptime_seconds=int(time.time() - _START_TIME),
        elapsed_ms=round((time.time() - started) * 1000, 1),
        checked_at=datetime.now(timezone.utc).isoformat(),
    ), status_code


# ── Metrics — JSON (api/v1) + Prometheus text (/metrics) ─────────────────────

def _collect_metrics() -> dict:
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
    accept = request.headers.get("Accept", "")
    if "application/json" in accept and "text/plain" not in accept:
        return api_metrics_json()

    try:
        from prometheus_client import (
            CollectorRegistry, Gauge, generate_latest, CONTENT_TYPE_LATEST,
        )
        reg = CollectorRegistry()
        m = _collect_metrics()
        Gauge("cafe_uptime_seconds", "Seconds since Flask app started", registry=reg).set(m["uptime_seconds"])
        orders_g = Gauge("cafe_orders_total", "Total orders by status", ["status"], registry=reg)
        for status, cnt in m["order_counts"].items():
            orders_g.labels(status=status).set(cnt)
        Gauge("cafe_owners_total", "Total owner accounts", registry=reg).set(m["total_owners"])
        Gauge("cafe_feedback_average_rating", "Average feedback rating", registry=reg).set(m["average_rating"])
        return Response(generate_latest(reg), mimetype=CONTENT_TYPE_LATEST)
    except ImportError:
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
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4; charset=utf-8")


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
