from __future__ import annotations

import os
import platform
import secrets
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder=None,
)

# ---------------------------------------------------------------------------
# In-memory brute-force protection for admin login
# ---------------------------------------------------------------------------
import threading as _admin_threading
_login_attempts: dict = {}  # {ip: [timestamp, ...]}
_login_lock = _admin_threading.Lock()
_MAX_ATTEMPTS = 10  # max failed attempts in window
_ATTEMPT_WINDOW = 300  # seconds


def _check_login_rate(ip: str) -> bool:
    """Return True if the IP is within the allowed rate. Return False to block."""
    import time as _t
    now = _t.time()
    with _login_lock:
        attempts = [ts for ts in _login_attempts.get(ip, []) if now - ts < _ATTEMPT_WINDOW]
        _login_attempts[ip] = attempts
        if len(attempts) >= _MAX_ATTEMPTS:
            return False
        return True


def _record_failed_login(ip: str) -> None:
    import time as _t
    with _login_lock:
        _login_attempts.setdefault(ip, []).append(_t.time())



def _store():
    import app as _app
    return _app


def _admin_key() -> str:
    return os.environ.get("ADMIN_SECRET_KEY", "")


def _key_match(key: str) -> tuple[bool, int | None]:
    """Return (matched, owner_id). owner_id is None for legacy env-based key."""
    if not key:
        return (False, None)
    secret = _admin_key()
    if secret and secrets.compare_digest(secret, key):
        return (True, None)
    try:
        store = _store()
        owner_id = store.find_admin_key_owner(key)
        if owner_id is not None:
            return (True, owner_id)
    except Exception:
        pass
    return (False, None)


def _key_valid(key: str) -> bool:
    matched, _ = _key_match(key)
    return matched


def _has_any_admin_key() -> bool:
    if _admin_key():
        return True
    try:
        return bool(_store().load_admin_keys())
    except Exception:
        return False


def _logged_in_superadmin():
    """Return the currently logged-in superadmin Owner, or None.

    This unifies the legacy admin-key auth with the modern owner login so a
    superadmin user automatically has access to the /admin/* DevOps panel
    without needing to enter a separate admin key.
    """
    try:
        store = _store()
        owner = store.logged_in_owner_obj()
        if owner and getattr(owner, "is_superadmin", False) and getattr(owner, "is_active", True):
            return owner
    except Exception:
        return None
    return None


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1) Already authenticated to admin via legacy key flow.
        if session.get("admin_authenticated"):
            return f(*args, **kwargs)
        # 2) Logged-in superadmin owner — auto-elevate (resolves admin/superadmin conflict).
        sa_owner = _logged_in_superadmin()
        if sa_owner is not None:
            session["admin_authenticated"] = True
            session["admin_owner_id"] = sa_owner.id
            session["admin_via_superadmin"] = True
            return f(*args, **kwargs)
        # 3) Header-based admin key (machine clients).
        key = request.headers.get("X-Admin-Key", "")
        matched, owner_id = _key_match(key)
        if matched:
            try:
                _store().log_security("ADMIN_LOGIN_OK", f"owner_id={owner_id} ip={request.remote_addr}")
            except Exception: pass
            session["admin_authenticated"] = True
            if owner_id is not None:
                session["admin_owner_id"] = owner_id
            return f(*args, **kwargs)
        return redirect(url_for("admin.login"))
    return decorated



@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    # Logged-in superadmin owner gets straight in (no key needed).
    sa_owner = _logged_in_superadmin()
    if sa_owner is not None:
        session["admin_authenticated"] = True
        session["admin_owner_id"] = sa_owner.id
        session["admin_via_superadmin"] = True
        return redirect(url_for("admin.dashboard"))
    if not _has_any_admin_key():
        return render_template(
            "admin/error.html",
            message=(
                "No admin access key has been configured. Sign in as a superadmin "
                "owner from the main login page, or set the ADMIN_SECRET_KEY "
                "environment variable."
            ),
        ), 503
    if session.get("admin_authenticated"):
        return redirect(url_for("admin.dashboard"))
    client_ip = request.remote_addr or "unknown"
    if request.method == "POST" and not _check_login_rate(client_ip):
        return render_template("admin/login.html", error="Too many attempts. Please wait 5 minutes."), 429
    error = None
    if request.method == "POST":
        key = request.form.get("key", "")
        matched, owner_id = _key_match(key)
        if matched:
            try:
                _store().log_security("ADMIN_LOGIN_OK", f"owner_id={owner_id} ip={client_ip}")
            except Exception: pass
            session["admin_authenticated"] = True
            if owner_id is not None:
                session["admin_owner_id"] = owner_id
            session.permanent = True
            return redirect(url_for("admin.dashboard"))
        error = "Invalid admin key. Please try again."
        _record_failed_login(client_ip)
        try:
            _store().log_security("ADMIN_LOGIN_FAIL", f"ip={client_ip}")
        except Exception: pass
    return render_template("admin/login.html", error=error)


@admin_bp.route("/logout")
def logout():
    session.pop("admin_authenticated", None)
    session.pop("admin_owner_id", None)
    session.pop("admin_via_superadmin", None)
    session.pop("superadmin_key_verified", None)
    session.pop("superadmin_verify_next", None)
    return redirect(url_for("admin.login"))


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    store = _store()
    owners = store.load_owners()
    stats = _global_stats(store)
    cafes = _get_cafes(store)
    orders_24h = _orders_24h(store)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "admin/dashboard.html",
        owners=owners,
        cafes=cafes,
        total_owners=len(owners),
        active_owners=sum(1 for o in owners if o.get("isActive", True)),
        total_orders=stats["total_orders"],
        total_revenue=stats["total_revenue"],
        orders_24h=orders_24h,
        now=now,
    )


@admin_bp.route("/owners")
@admin_required
def owners():
    store = _store()
    all_owners = store.load_owners()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template("admin/owners.html", owners=all_owners, now=now)


@admin_bp.route("/owners/<int:owner_id>/reset", methods=["POST"])
@admin_required
def reset_password(owner_id: int):
    store = _store()
    from app import Owner, db, revoke_all_tokens_for_owner
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    tmp_password = secrets.token_urlsafe(12)
    new_hash = store._make_password_hash(tmp_password)
    owner.password_hash = new_hash
    db.session.commit()
    revoke_all_tokens_for_owner(owner_id)
    flash(f"Password for <strong>{owner.username}</strong> reset. Temp: <code>{tmp_password}</code>", "password_reset")
    return redirect(url_for("admin.owners"))


@admin_bp.route("/owners/<int:owner_id>/toggle", methods=["POST"])
@admin_required
def toggle_owner(owner_id: int):
    from app import Owner, db
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot deactivate a superadmin.")
        return redirect(url_for("admin.owners"))
    owner.is_active = not owner.is_active
    db.session.commit()
    status_word = "activated" if owner.is_active else "deactivated"
    flash(f"Owner <strong>{owner.username}</strong> has been {status_word}.", "success")
    return redirect(url_for("admin.owners"))


@admin_bp.route("/owners/create", methods=["POST"])
@admin_required
def create_owner():
    import re
    store = _store()
    from app import Owner, db, create_owner_in_db
    username = str(request.form.get("username", "")).strip()[:64]
    email = str(request.form.get("email", "")).strip()[:254] or None
    cafe_name = str(request.form.get("cafe_name", "")).strip()[:200]
    password = str(request.form.get("password", ""))[:256]
    cafe_id_str = request.form.get("cafe_id", "")
    cafe_id = int(cafe_id_str) if cafe_id_str and cafe_id_str.isdigit() else None

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("admin.dashboard"))
    if not re.fullmatch(r"[a-zA-Z0-9_\-\.]{3,64}", username):
        flash("Invalid username — letters, numbers, _ - . only, 3–64 chars.", "danger")
        return redirect(url_for("admin.dashboard"))
    if Owner.query.filter_by(username=username).first():
        flash(f"Username '{username}' already exists.", "danger")
        return redirect(url_for("admin.dashboard"))
    pw_hash = store._make_password_hash(password)
    create_owner_in_db(username, email, pw_hash, cafe_name, cafe_id)
    flash(f"Owner <strong>{username}</strong> created successfully.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/analytics")
@admin_required
def analytics():
    store = _store()
    stats = _global_stats(store)
    top_items = _top_items(store)
    daily = _daily_revenue(store)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "admin/analytics.html",
        stats=stats,
        top_items=top_items,
        daily=daily,
        now=now,
    )


def _get_cafes(store) -> list:
    try:
        from app import Cafe
        return [{"id": c.id, "name": c.name} for c in Cafe.query.order_by(Cafe.name).all()]
    except Exception:
        return []


def _orders_24h(store) -> int:
    try:
        from datetime import timedelta
        from app import Order, db
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        return Order.query.filter(Order.created_at >= cutoff).count()
    except Exception:
        return 0


def _global_stats(store) -> dict:
    orders = store.load_orders()
    active = [o for o in orders if o.get("status") != "cancelled"]
    total_rev = sum(float(o.get("total", 0)) for o in active)
    return {"total_orders": len(active), "total_revenue": round(total_rev, 2)}


def _top_items(store, limit: int = 10) -> list[dict]:
    orders = store.load_orders()
    counts: dict[str, int] = {}
    for order in orders:
        if order.get("status") == "cancelled":
            continue
        for item in order.get("items", []):
            name = item.get("name", "Unknown")
            counts[name] = counts.get(name, 0) + int(item.get("quantity", 1))
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"name": name, "quantity": quantity} for name, quantity in sorted_items]


def _daily_revenue(store, days: int = 14) -> list[dict]:
    from datetime import timedelta
    orders = store.load_orders()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    daily: dict[str, float] = {}
    for order in orders:
        if order.get("status") == "cancelled":
            continue
        timestamp = order.get("createdAt", "")
        if timestamp < cutoff:
            continue
        day = timestamp[:10]
        daily[day] = daily.get(day, 0.0) + float(order.get("total", 0))
    return [{"date": day, "revenue": round(value, 2)} for day, value in sorted(daily.items())]


@admin_bp.route("/status")
@admin_required
def status():
    store = _store()
    data_dir = store.DATA_DIR

    try:
        disk = shutil.disk_usage(str(data_dir))
        disk_total_gb = round(disk.total / 1e9, 1)
        disk_used_gb = round(disk.used / 1e9, 1)
        disk_free_gb = round(disk.free / 1e9, 1)
        disk_pct = round(disk.used / disk.total * 100, 1) if disk.total else 0
    except Exception:
        disk_total_gb = disk_used_gb = disk_free_gb = disk_pct = None

    db_ok = False
    db_msg = "SQLAlchemy storage"
    if store.USE_DB:
        try:
            store.db.session.execute(store.text("SELECT 1"))
            db_ok = True
            db_msg = "Database connected"
        except Exception as exc:
            db_msg = f"Database error: {exc}"

    file_stats = []
    for label, path in [
        ("owners.json", store.OWNERS_PATH),
        ("orders.json", store.ORDERS_PATH),
        ("menu.json", store.MENU_PATH),
        ("tables.json", store.TABLES_PATH),
        ("feedback.json", store.FEEDBACK_PATH),
    ]:
        try:
            size = os.path.getsize(str(path))
            file_stats.append({"name": label, "size_kb": round(size / 1024, 1), "exists": True})
        except FileNotFoundError:
            file_stats.append({"name": label, "size_kb": 0, "exists": False})

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "admin/status.html",
        disk_total_gb=disk_total_gb,
        disk_used_gb=disk_used_gb,
        disk_free_gb=disk_free_gb,
        disk_pct=disk_pct,
        db_ok=db_ok,
        db_msg=db_msg,
        file_stats=file_stats,
        use_db=store.USE_DB,
        server_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        now=now,
    )


# ---------------------------------------------------------------------------
# DevOps tools
# ---------------------------------------------------------------------------

_DEVOPS_RECENT_HEALTH: list[dict] = []
_DEVOPS_RECENT_HEALTH_MAX = 25


def _system_metrics() -> dict:
    """Best-effort host metrics. Returns whatever is available; never raises."""
    metrics: dict = {
        "host": socket.gethostname(),
        "python": sys.version.split(" ")[0],
        "platform": f"{platform.system()} {platform.release()}",
        "pid": os.getpid(),
    }
    try:
        import psutil  # type: ignore
        proc = psutil.Process(os.getpid())
        with proc.oneshot():
            mem_info = proc.memory_info()
            create_time = proc.create_time()
        vmem = psutil.virtual_memory()
        try:
            load1, load5, load15 = os.getloadavg()
            metrics["loadAvg"] = {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)}
        except (AttributeError, OSError):
            pass
        metrics.update({
            "cpuPercent": psutil.cpu_percent(interval=0.1),
            "cpuCount": psutil.cpu_count(logical=True),
            "memoryTotalMb": round(vmem.total / 1e6, 0),
            "memoryUsedPercent": vmem.percent,
            "processRssMb": round(mem_info.rss / 1e6, 1),
            "processUptimeSeconds": int(time.time() - create_time),
            "psutilAvailable": True,
        })
    except ImportError:
        metrics["psutilAvailable"] = False
    except Exception as exc:  # noqa: BLE001
        metrics["psutilError"] = str(exc)[:200]
    return metrics


def _run_health_check() -> dict:
    """Aggregate liveness/readiness/full health signals into one result."""
    store = _store()
    started = time.time()
    checks: dict = {}

    # DB ping
    try:
        store.db.session.execute(store.text("SELECT 1"))
        checks["database"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        checks["database"] = {"ok": False, "error": str(exc)[:200]}

    # Disk writability
    try:
        probe = store.DATA_DIR / ".admin_devops_probe.tmp"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        checks["disk"] = {"ok": True, "path": str(store.DATA_DIR)}
    except Exception as exc:  # noqa: BLE001
        checks["disk"] = {"ok": False, "error": str(exc)[:200]}

    # Disk free
    try:
        usage = shutil.disk_usage(str(store.DATA_DIR))
        checks["diskUsage"] = {
            "ok": (usage.free / usage.total) > 0.05 if usage.total else True,
            "freePercent": round((usage.free / usage.total) * 100, 1) if usage.total else None,
            "freeGb": round(usage.free / 1e9, 2),
        }
    except Exception as exc:  # noqa: BLE001
        checks["diskUsage"] = {"ok": False, "error": str(exc)[:200]}

    # Redis (optional)
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            import redis  # type: ignore
            client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            t0 = time.time()
            client.ping()
            checks["redis"] = {"ok": True, "latencyMs": round((time.time() - t0) * 1000, 2)}
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = {"ok": False, "error": str(exc)[:200]}
    else:
        checks["redis"] = {"ok": True, "skipped": True, "note": "REDIS_URL not configured"}

    # Admin key configured
    checks["adminKey"] = {"ok": _has_any_admin_key()}

    overall_ok = all(c.get("ok") for c in checks.values())
    return {
        "ok": overall_ok,
        "elapsedMs": round((time.time() - started) * 1000, 1),
        "ranAt": datetime.now(timezone.utc).isoformat(),
        "ranBy": session.get("admin_owner_id"),
        "checks": checks,
    }


def _record_health(result: dict) -> None:
    _DEVOPS_RECENT_HEALTH.insert(0, {
        "ranAt": result.get("ranAt"),
        "ok": bool(result.get("ok")),
        "elapsedMs": result.get("elapsedMs"),
        "failing": [name for name, info in (result.get("checks") or {}).items() if not info.get("ok")],
    })
    del _DEVOPS_RECENT_HEALTH[_DEVOPS_RECENT_HEALTH_MAX:]


def _safe_env_summary() -> list[dict]:
    """Show whether sensitive env vars are configured, never their values."""
    keys = [
        "ADMIN_SECRET_KEY", "DATABASE_URL", "REDIS_URL", "SECRET_KEY",
        "MAIL_USERNAME", "MAIL_PASSWORD", "FLASK_ENV", "IS_PRODUCTION",
        "RAILWAY_ENVIRONMENT", "PORT",
    ]
    summary = []
    for key in keys:
        val = os.environ.get(key)
        sensitive = any(s in key for s in ("KEY", "PASSWORD", "URL", "SECRET"))
        summary.append({
            "key": key,
            "set": bool(val),
            "value": (val if (val and not sensitive) else None),
        })
    return summary


def _is_safe_redirect(target: str) -> bool:
    return bool(target) and target.startswith("/admin/")


@admin_bp.route("/devops")
@admin_required
def devops():
    store = _store()
    metrics = _system_metrics()
    env_summary = _safe_env_summary()
    last_health = _DEVOPS_RECENT_HEALTH[0] if _DEVOPS_RECENT_HEALTH else None
    app_info = {
        "version": getattr(store, "APP_VERSION", "unknown"),
        "uptimeSeconds": int(time.time() - getattr(store, "APP_START_TIME", time.time())),
        "useDb": getattr(store, "USE_DB", False),
        "dataDir": str(getattr(store, "DATA_DIR", "")),
    }
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "admin/devops.html",
        metrics=metrics,
        env_summary=env_summary,
        last_health=last_health,
        recent_health=list(_DEVOPS_RECENT_HEALTH),
        app_info=app_info,
        admin_owner_id=session.get("admin_owner_id"),
        now=now,
    )


@admin_bp.route("/devops/health", methods=["GET", "POST"])
@admin_required
def devops_health():
    """Run the aggregated health check.

    GET returns JSON for AJAX/probes; POST updates the page-level cache and
    redirects back to the DevOps view with a flash message.
    """
    result = _run_health_check()
    _record_health(result)
    if request.method == "POST":
        flash(
            ("All systems healthy." if result["ok"]
             else "Health check found issues — see DevOps panel for details."),
            "success" if result["ok"] else "danger",
        )
        return redirect(url_for("admin.devops"))
    return jsonify(result), (200 if result["ok"] else 503)


@admin_bp.route("/devops/clear-rate-limits", methods=["POST"])
@admin_required
def devops_clear_rate_limits():
    """Reset Flask-Limiter storage (best-effort). Useful after a burst of 429s."""
    store = _store()
    cleared = False
    try:
        limiter = getattr(store, "limiter", None)
        if limiter is not None and getattr(limiter, "storage", None):
            try:
                limiter.storage.reset()
                cleared = True
            except Exception:
                # In-memory storage may not implement reset()
                if hasattr(limiter, "_storage") and hasattr(limiter._storage, "storage"):
                    limiter._storage.storage.clear()
                    cleared = True
    except Exception as exc:  # noqa: BLE001
        flash(f"Could not clear rate limit storage: {exc}", "danger")
        return redirect(url_for("admin.devops"))
    try:
        store.log_security("DEVOPS_CLEAR_RATE_LIMITS",
                           f"by_owner_id={session.get('admin_owner_id')}")
    except Exception:
        pass
    flash("Rate-limit storage cleared." if cleared else "Nothing to clear.", "success" if cleared else "info")
    return redirect(url_for("admin.devops"))


# ---------------------------------------------------------------------------
# Rate-limited admin login (brute-force protection)
# ---------------------------------------------------------------------------
# Wrap the existing login view so rapid wrong-key attempts are throttled.
# We patch it after the fact to avoid touching the original function body.

_orig_login = login  # type: ignore  # noqa: F821  — defined above


def _login_rate_limited(*args, **kwargs):
    try:
        from app import limiter
        return limiter.limit("15 per minute; 60 per hour")(lambda: _orig_login(*args, **kwargs))()
    except Exception:
        return _orig_login(*args, **kwargs)


# ---------------------------------------------------------------------------
# DevOps: live metrics JSON (AJAX endpoint — no page reload needed)
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/metrics.json")
@admin_required
def devops_metrics_json():
    """Return current system metrics as JSON for the auto-refresh panel."""
    metrics = _system_metrics()
    store = _store()
    app_info = {
        "version": getattr(store, "APP_VERSION", "unknown"),
        "uptimeSeconds": int(time.time() - getattr(store, "APP_START_TIME", time.time())),
        "useDb": getattr(store, "USE_DB", False),
        "dataDir": str(getattr(store, "DATA_DIR", "")),
    }
    return jsonify(metrics=metrics, app_info=app_info, now=datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# DevOps: database pool stats
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/db-stats.json")
@admin_required
def devops_db_stats():
    """Return connection pool statistics from SQLAlchemy."""
    store = _store()
    stats: dict = {"available": False}
    try:
        engine = store.db.engine
        pool = engine.pool
        stats = {
            "available": True,
            "poolSize": getattr(pool, "size", lambda: None)() if callable(getattr(pool, "size", None)) else getattr(pool, "_pool", {}).qsize() if hasattr(getattr(pool, "_pool", None), "qsize") else "n/a",
            "checkedOut": pool.checkedout() if hasattr(pool, "checkedout") else "n/a",
            "overflow": pool.overflow() if hasattr(pool, "overflow") else "n/a",
            "checkedIn": pool.checkedin() if hasattr(pool, "checkedin") else "n/a",
            "dialect": engine.dialect.name,
            "driverVersion": str(getattr(engine.dialect, "driver", "unknown")),
        }
    except Exception as exc:
        stats["error"] = str(exc)[:200]
    return jsonify(stats)


# ---------------------------------------------------------------------------
# DevOps: recent security events (tail last N lines from security logger)
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/security-events.json")
@admin_required
def devops_security_events():
    """Return the most recent security log entries from memory."""
    store = _store()
    events = []
    try:
        # Walk the security_log's handlers to find our MemoryHandler or the list
        import logging
        sec_log = logging.getLogger("cafe.security")
        # Try to read from the in-memory ring buffer if we store them
        ring = getattr(store, "_security_event_ring", None)
        if ring:
            events = list(ring)[-100:]
        else:
            # Collect from last rotating-file log if available
            log_file = os.environ.get("LOG_FILE")
            if log_file:
                import pathlib
                p = pathlib.Path(log_file)
                if p.exists():
                    with open(p, "r", errors="replace") as fh:
                        lines = fh.readlines()
                    events = [l.strip() for l in lines[-100:] if "SECURITY" in l.upper() or "security" in l]
    except Exception:
        pass
    return jsonify(events=events, count=len(events))


# ---------------------------------------------------------------------------
# DevOps: prune old resolved table calls
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/prune-resolved", methods=["POST"])
@admin_required
def devops_prune_resolved():
    """Delete resolved table calls older than 30 days to keep the DB lean."""
    store = _store()
    deleted = 0
    try:
        from datetime import timedelta
        from extensions.models import TableCall
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        q = (
            store.db.session.query(TableCall)
            .filter(TableCall.status == "resolved")
            .filter(TableCall.resolved_at < cutoff)
        )
        deleted = q.count()
        q.delete(synchronize_session=False)
        store.db.session.commit()
        store.log_security("DEVOPS_PRUNE_RESOLVED",
                           f"deleted={deleted} cutoff={cutoff.date()} by_owner_id={session.get('admin_owner_id')}")
    except Exception as exc:
        flash(f"Prune failed: {exc}", "danger")
        return redirect(url_for("admin.devops"))
    flash(f"Pruned {deleted} resolved call(s) older than 30 days.", "success")
    return redirect(url_for("admin.devops"))


# ---------------------------------------------------------------------------
# DevOps: export recent orders as CSV
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/export-orders.csv")
@admin_required
def devops_export_orders():
    """Download a CSV of all orders from the last 7 days for diagnostics."""
    import csv
    import io
    from datetime import timedelta
    store = _store()
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        from app import Order
        orders = Order.query.filter(Order.created_at >= cutoff).order_by(Order.created_at.desc()).all()
    except Exception:
        orders = []
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["id", "owner_id", "status", "total", "customer_name", "table_id", "created_at"])
    for o in orders:
        w.writerow([o.id, o.owner_id, o.status, o.total,
                    getattr(o, "customer_name", ""), getattr(o, "table_id", ""),
                    o.created_at.isoformat() if o.created_at else ""])
    out.seek(0)
    fname = f"orders_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    from flask import Response as _Response
    return _Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )


# ---------------------------------------------------------------------------
# DevOps: git info (deployment version panel)
# ---------------------------------------------------------------------------

@admin_bp.route("/devops/git-info.json")
@admin_required
def devops_git_info():
    """Return current git ref, commit hash, and deploy time."""
    import subprocess
    info: dict = {}
    try:
        info["commit"] = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, timeout=5
        ).strip()
        info["branch"] = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True, timeout=5
        ).strip()
        info["subject"] = subprocess.check_output(
            ["git", "log", "-1", "--format=%s"], text=True, timeout=5
        ).strip()[:120]
        info["date"] = subprocess.check_output(
            ["git", "log", "-1", "--format=%ci"], text=True, timeout=5
        ).strip()
    except Exception as exc:
        info["error"] = str(exc)[:200]
    info["appVersion"] = os.environ.get("APP_VERSION", "unknown")
    return jsonify(info)
