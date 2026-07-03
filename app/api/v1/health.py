"""Health, readiness, metrics and ops endpoints.

Issue #9 fix: readiness endpoint now probes all critical dependencies —
database, Redis, encryption, disk, background-task queue, and circuit
breaker states — so an orchestrator (Railway, k8s, Docker Compose) will
not route traffic to a pod that is partially broken.

Health check fixes:
  Fix #1 — Uptime: use _cfg.APP_START_TIME (set in create_app) rather than
             a module-level time.time() call that reflects module import time,
             not actual server start time.
  Fix #2 — BackgroundTaskQueue in readyz/ops_health: use the module-level
             _bg_queue singleton from app.cache instead of calling __new__()
             which produces a broken uninitialised instance.
  Fix #3 — Encryption probe in /readyz: made non-fatal (warn only); lib_payments
             may not be installed on all deployments and missing it should not
             block traffic — the probe is still run and reported.
  Fix #4 — /readyz schema check: also validates that webhook_events.status
             column exists (migration 007) so a partially-migrated DB is caught.
"""
from __future__ import annotations

import hmac
import os
import time
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from sqlalchemy import text, func

from app.extensions import db, limiter
from app import config as _cfg

bp = Blueprint("api_v1_health", __name__)

# Module-level sentinel — used ONLY as fallback when APP_START_TIME is 0.0
# (i.e. during tests or before create_app finishes). In production the
# authoritative value is _cfg.APP_START_TIME set at the end of create_app().
_MODULE_LOAD_TIME = time.time()


def _uptime_seconds() -> int:
    """Return seconds since the app started (create_app completed)."""
    t = _cfg.APP_START_TIME or _MODULE_LOAD_TIME
    return max(0, int(time.time() - t))


# ── Liveness — must never depend on DB or Redis ───────────────────────────────

@bp.route("/api/v1/health")
@bp.route("/health")
@limiter.exempt
def health_check():
    """Liveness probe — returns 200 as long as the Python process is alive."""
    return jsonify(
        status="ok",
        version=_cfg.APP_VERSION,
        uptime_seconds=_uptime_seconds(),
    ), 200


@bp.route("/healthz")
@limiter.exempt
def healthz():
    """Minimal liveness probe used by Railway and Docker HEALTHCHECK.

    Intentionally returns plain text with no DB / Redis dependency so that
    container orchestrators can distinguish a live-but-degraded container
    (healthz=200, readyz=503) from a dead one (healthz=503).
    """
    return ("ok", 200, {"Content-Type": "text/plain; charset=utf-8"})


# ── Readiness — full dependency probe ─────────────────────────────────────────

@bp.route("/api/v1/ready")
@bp.route("/readyz")
@bp.route("/ready")
@limiter.exempt
def readiness_check():
    """Readiness probe — returns 503 until all critical dependencies are up.

    Railway routes traffic here only after this returns 200; a 503 keeps
    the previous container alive while the new one warms up.
    """
    checks: dict = {}
    overall_ok = True

    # 1. Database connectivity (critical)
    try:
        db.session.execute(text("SELECT 1"))
        db.session.rollback()
        checks["database"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["database"] = {"ok": False, "error": str(exc)[:200]}

    # 2. Required schema tables + critical column existence (critical)
    try:
        db.session.execute(text("SELECT 1 FROM payment_credentials LIMIT 0"))
        db.session.execute(text("SELECT 1 FROM aggregator_credentials LIMIT 0"))
        # Verify webhook_events has the retry columns from migration 007
        db.session.execute(text("SELECT status, next_attempt_at FROM webhook_events LIMIT 0"))
        checks["schema"] = {"ok": True}
    except Exception as exc:
        checks["schema"] = {
            "ok": False,
            "error": str(exc)[:200],
            "hint": "run: flask db upgrade (migrations 006 + 007 may be pending)",
        }
        overall_ok = False
    finally:
        db.session.rollback()

    # 3. Encryption round-trip (warn-only — lib_payments may not be installed)
    try:
        from lib_payments import encrypt_secret, decrypt_secret  # type: ignore
        probe = encrypt_secret("healthz-probe")
        assert decrypt_secret(probe) == "healthz-probe"
        checks["encryption"] = {"ok": True}
    except ImportError:
        checks["encryption"] = {"ok": True, "skipped": True, "note": "lib_payments not installed"}
    except Exception as exc:
        # Non-fatal: encryption failing degrades payment flows but doesn't block health
        checks["encryption"] = {"ok": True, "warning": str(exc)[:200]}

    # 4. Redis connectivity (critical when REDIS_URL is set)
    redis_url = os.environ.get("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _redis
            r = _redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.monotonic()
            r.ping()
            checks["redis"] = {"ok": True, "latency_ms": round((time.monotonic() - t0) * 1000, 2)}
        except Exception as exc:
            overall_ok = False
            checks["redis"] = {"ok": False, "error": str(exc)[:200]}
    else:
        checks["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # 5. Background task queue — use module-level singleton (Fix #2)
    try:
        from app.cache import _bg_queue
        q_stats = _bg_queue.stats()
        checks["bg_queue"] = {"ok": True, **q_stats}
    except Exception as exc:
        checks["bg_queue"] = {"ok": True, "note": str(exc)[:100]}

    # 6. Circuit breaker states
    try:
        from app.middleware.circuit_breaker import all_breaker_stats
        breaker_stats = all_breaker_stats()
        open_breakers = [b["name"] for b in breaker_stats if b["state"] == "OPEN"]
        checks["circuit_breakers"] = {
            "ok": len(open_breakers) == 0,
            "open": open_breakers,
        }
        if open_breakers:
            checks["circuit_breakers"]["warning"] = (
                f"Open circuits (self-recover after cooldown): {', '.join(open_breakers)}"
            )
    except Exception as exc:
        checks["circuit_breakers"] = {"ok": True, "note": str(exc)[:100]}

    # 7. Disk writability (critical — session files, backups)
    try:
        from app.config import DATA_DIR
        probe_path = DATA_DIR / ".readyz_probe.tmp"
        probe_path.write_text("ok", encoding="utf-8")
        probe_path.unlink(missing_ok=True)
        checks["disk"] = {"ok": True}
    except Exception as exc:
        overall_ok = False
        checks["disk"] = {"ok": False, "error": str(exc)[:200]}

    # 8. DB connection-pool utilisation — Issue 1.
    # A saturated pool means all new requests will block for up to
    # pool_timeout seconds then raise OperationalError.  Alert before that.
    try:
        pool = db.engine.pool
        pool_used = pool.checkedout()
        pool_cap = pool.size() + pool.overflow()
        pool_full = pool_used >= pool_cap
        checks["db_pool"] = {
            "ok": not pool_full,
            "size": pool.size(),
            "max_overflow": pool.overflow(),
            "checked_out": pool_used,
            "capacity": pool_cap,
        }
        if pool_full:
            overall_ok = False
            checks["db_pool"]["error"] = (
                "DB connection pool exhausted — all connections in use. "
                "Raise DB_POOL_SIZE or scale down WEB_CONCURRENCY."
            )
    except Exception as exc:
        checks["db_pool"] = {"ok": True, "note": str(exc)[:100]}

    # 9. Webhook dead-letter queue depth — Issue 7.
    # A growing dead-letter queue means the retry worker is not running or
    # the downstream webhook endpoints are persistently rejecting events.
    try:
        from sqlalchemy import text as _sqtext
        _dead = db.session.execute(
            _sqtext("SELECT COUNT(*) FROM outbound_webhooks WHERE status = 'dead'")
        ).scalar() or 0
        _pending = db.session.execute(
            _sqtext(
                "SELECT COUNT(*) FROM outbound_webhooks "
                "WHERE status IN ('pending', 'retrying')"
            )
        ).scalar() or 0
        checks["webhook_queue"] = {
            "ok": _dead < 100,
            "pending": _pending,
            "dead": _dead,
        }
        if _dead >= 100:
            checks["webhook_queue"]["warning"] = (
                f"{_dead} events in the dead-letter queue. "
                "POST /api/ops/webhooks/<id>/requeue to retry individual events."
            )
        db.session.rollback()
    except Exception as exc:
        checks["webhook_queue"] = {"ok": True, "note": str(exc)[:100]}

    status = 200 if overall_ok else 503
    return jsonify(
        ok=overall_ok,
        checks=checks,
        version=_cfg.APP_VERSION,
        uptime_seconds=_uptime_seconds(),
    ), status


# ── Version ───────────────────────────────────────────────────────────────────

@bp.route("/api/v1/version")
@bp.route("/version")
@limiter.exempt
def version_endpoint():
    return jsonify(
        version=_cfg.APP_VERSION,
        commit=os.environ.get("RAILWAY_GIT_COMMIT_SHA", "")[:40] or None,
        branch=os.environ.get("RAILWAY_GIT_BRANCH") or None,
        deployedAt=os.environ.get("RAILWAY_DEPLOYMENT_CREATED_AT") or None,
        startedAt=datetime.fromtimestamp(
            _cfg.APP_START_TIME or _MODULE_LOAD_TIME, tz=timezone.utc
        ).isoformat(),
        uptime_seconds=_uptime_seconds(),
    ), 200


# ── Ops health (bearer-token-protected, full dependency matrix) ───────────────

@bp.route("/api/ops/health")
@bp.route("/health/full")
@limiter.exempt
def ops_health():
    """Deep per-section health check — requires OPS_HEALTH_TOKEN when configured."""
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
        sections["database"] = {
            "ok": True,
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        }
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
            sections["redis"] = {
                "ok": True,
                "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            }
        except Exception as exc:
            sections["redis"] = {"ok": False, "error": str(exc)[:200]}
            overall_ok = False
    else:
        sections["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # Encryption (warn-only)
    try:
        from lib_payments import encrypt_secret, decrypt_secret  # type: ignore
        probe = encrypt_secret("ops-probe")
        assert decrypt_secret(probe) == "ops-probe"
        sections["encryption"] = {"ok": True}
    except ImportError:
        sections["encryption"] = {"ok": True, "skipped": True, "note": "lib_payments not installed"}
    except Exception as exc:
        sections["encryption"] = {"ok": False, "error": str(exc)[:200]}
        overall_ok = False

    # Admin key
    admin_key_set = bool(
        os.environ.get("ADMIN_SECRET_KEY") or os.environ.get("SUPERADMIN_KEY")
    )
    sections["admin_key"] = {
        "ok": admin_key_set,
        "note": "Set ADMIN_SECRET_KEY or SUPERADMIN_KEY" if not admin_key_set else None,
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

    # Circuit breakers
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
                f"Open circuits self-recover after cooldown: {', '.join(open_breakers)}. "
                "Or reset manually via POST /api/v1/admin/circuit-breakers/<name>/reset"
            )
    except Exception as exc:
        sections["circuit_breakers"] = {"ok": True, "note": str(exc)[:100]}

    # Background task queue — Fix #2: use singleton
    try:
        from app.cache import _bg_queue
        q_stats = _bg_queue.stats()
        sections["bg_queue"] = {"ok": True, **q_stats}
    except Exception as exc:
        sections["bg_queue"] = {"ok": True, "note": str(exc)[:100]}

    # DB connection pool stats
    try:
        pool = db.engine.pool
        sections["db_pool"] = {
            "ok": True,
            "size": pool.size(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
        }
    except Exception:
        sections["db_pool"] = {"ok": True, "note": "pool stats unavailable"}

    # Webhook retry queue depth
    try:
        from app.models.billing import WebhookEventLog
        pending = (
            db.session.query(func.count(WebhookEventLog.id))
            .filter(WebhookEventLog.status.in_(["pending", "failed"]))
            .scalar()
        ) or 0
        dead = (
            db.session.query(func.count(WebhookEventLog.id))
            .filter(WebhookEventLog.status == "dead")
            .scalar()
        ) or 0
        sections["webhook_queue"] = {
            "ok": dead < 50,  # alert if > 50 permanently dead events
            "pending": pending,
            "dead": dead,
            "note": (
                f"{dead} dead events need manual retry or discard"
                if dead >= 50 else None
            ),
        }
        db.session.rollback()
    except Exception:
        sections["webhook_queue"] = {"ok": True, "note": "unavailable"}

    status_code = 200 if overall_ok else 503
    return jsonify(
        ok=overall_ok,
        sections=sections,
        uptime_seconds=_uptime_seconds(),
        elapsed_ms=round((time.time() - started) * 1000, 1),
        checked_at=datetime.now(timezone.utc).isoformat(),
    ), status_code


# ── Metrics ───────────────────────────────────────────────────────────────────

def _collect_metrics() -> dict:
    from app.models import Order, Feedback, Owner
    try:
        rows = (
            db.session.query(Order.status, func.count(Order.id))
            .group_by(Order.status)
            .all()
        )
        order_counts = {status or "unknown": cnt for status, cnt in rows}
        total_orders = sum(order_counts.values())
        total_owners = db.session.query(func.count(Owner.id)).scalar() or 0
        avg_rating_raw = db.session.query(func.avg(Feedback.rating)).scalar()
        avg_rating = round(float(avg_rating_raw), 4) if avg_rating_raw else 0.0
    except Exception:
        order_counts, total_orders, total_owners, avg_rating = {}, 0, 0, 0.0
    return {
        "uptime_seconds": _uptime_seconds(),
        "total_orders": total_orders,
        "order_counts": order_counts,
        "total_owners": total_owners,
        "average_rating": avg_rating,
    }


@bp.route("/api/v1/metrics")
@limiter.limit("30 per minute")
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
@bp.route("/metrics/prom")
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
        ]
        return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4; charset=utf-8")


# ── Well-known static files ───────────────────────────────────────────────────

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
