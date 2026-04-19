from __future__ import annotations

import os
import secrets
import shutil
import time
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash

admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder=None,
)

# ---------------------------------------------------------------------------
# Helpers — lazy-import to avoid circular dependency with app.py
# ---------------------------------------------------------------------------

def _store():
    import app as _app  # noqa: PLC0415
    return _app


def _admin_key() -> str:
    return os.environ.get("ADMIN_SECRET_KEY", "")


def _key_valid(key: str) -> bool:
    secret = _admin_key()
    return bool(secret) and bool(key) and secrets.compare_digest(secret, key)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("admin_authenticated"):
            return f(*args, **kwargs)
        key = request.args.get("key", "") or request.headers.get("X-Admin-Key", "")
        if _key_valid(key):
            session["admin_authenticated"] = True
            return f(*args, **kwargs)
        return redirect(url_for("admin.login"))
    return decorated


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if not _admin_key():
        return render_template("admin/error.html",
                               message="ADMIN_SECRET_KEY is not configured on this server."), 503
    if session.get("admin_authenticated"):
        return redirect(url_for("admin.dashboard"))
    error = None
    if request.method == "POST":
        key = request.form.get("key", "")
        if _key_valid(key):
            session["admin_authenticated"] = True
            session.permanent = True
            return redirect(url_for("admin.dashboard"))
        error = "Invalid admin key. Please try again."
    return render_template("admin/login.html", error=error)


@admin_bp.route("/logout")
def logout():
    session.pop("admin_authenticated", None)
    return redirect(url_for("admin.login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    store = _store()
    owners = store.load_owners()
    stats = _global_stats(store)
    return render_template(
        "admin/dashboard.html",
        owners=owners,
        total_owners=len(owners),
        active_owners=sum(1 for o in owners if o.get("isActive", True)),
        total_orders=stats["total_orders"],
        total_revenue=stats["total_revenue"],
    )


# ---------------------------------------------------------------------------
# Owners management
# ---------------------------------------------------------------------------

@admin_bp.route("/owners")
@admin_required
def owners():
    store = _store()
    all_owners = store.load_owners()
    return render_template("admin/owners.html", owners=all_owners)


@admin_bp.route("/owners/<int:owner_id>/reset", methods=["POST"])
@admin_required
def reset_password(owner_id: int):
    store = _store()
    tmp_password = secrets.token_urlsafe(12)
    new_hash = generate_password_hash(tmp_password)

    if store.USE_DB:
        with store._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE owners SET password_hash = %s WHERE id = %s RETURNING username",
                    (new_hash, owner_id),
                )
                row = cur.fetchone()
                if not row:
                    abort(404)
                username = row[0]
        # Revoke all remember tokens for security
        store.revoke_all_tokens_for_owner(owner_id)
    else:
        all_owners = store.load_owners()
        owner = next((o for o in all_owners if o["id"] == owner_id), None)
        if not owner:
            abort(404)
        username = owner["username"]
        owner["passwordHash"] = new_hash
        store.save_owners(all_owners)
        store.revoke_all_tokens_for_owner(owner_id)

    flash(f"Password for <strong>{username}</strong> reset. Temporary password: <code>{tmp_password}</code>", "password_reset")
    return redirect(url_for("admin.owners"))


@admin_bp.route("/owners/<int:owner_id>/toggle", methods=["POST"])
@admin_required
def toggle_owner(owner_id: int):
    store = _store()

    if store.USE_DB:
        with store._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE owners SET is_active = NOT is_active WHERE id = %s RETURNING username, is_active",
                    (owner_id,),
                )
                row = cur.fetchone()
                if not row:
                    abort(404)
                username, is_active = row[0], row[1]
    else:
        all_owners = store.load_owners()
        owner = next((o for o in all_owners if o["id"] == owner_id), None)
        if not owner:
            abort(404)
        owner["isActive"] = not owner.get("isActive", True)
        is_active = owner["isActive"]
        username = owner["username"]
        store.save_owners(all_owners)

    status_word = "activated" if is_active else "deactivated"
    flash(f"Owner <strong>{username}</strong> has been {status_word}.", "success")
    return redirect(url_for("admin.owners"))


# ---------------------------------------------------------------------------
# Global analytics
# ---------------------------------------------------------------------------

@admin_bp.route("/analytics")
@admin_required
def analytics():
    store = _store()
    stats = _global_stats(store)
    top_items = _top_items(store)
    daily = _daily_revenue(store)
    return render_template(
        "admin/analytics.html",
        stats=stats,
        top_items=top_items,
        daily=daily,
    )


def _global_stats(store) -> dict:
    if store.USE_DB:
        with store._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), COALESCE(SUM(total), 0) FROM orders WHERE status != 'cancelled'"
                )
                row = cur.fetchone()
                return {"total_orders": row[0] or 0, "total_revenue": float(row[1] or 0)}
    else:
        orders = store.read_json(store.ORDERS_PATH, [])
        active = [o for o in orders if o.get("status") != "cancelled"]
        total_rev = sum(float(o.get("total", 0)) for o in active)
        return {"total_orders": len(active), "total_revenue": round(total_rev, 2)}


def _top_items(store, limit: int = 10) -> list[dict]:
    if store.USE_DB:
        with store._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        item->>'name'  AS item_name,
                        SUM((item->>'quantity')::int) AS qty
                    FROM orders,
                         jsonb_array_elements(items) AS item
                    WHERE status != 'cancelled'
                    GROUP BY item_name
                    ORDER BY qty DESC
                    LIMIT %s
                """, (limit,))
                return [{"name": r[0], "quantity": int(r[1])} for r in cur.fetchall()]
    else:
        orders = store.read_json(store.ORDERS_PATH, [])
        counts: dict[str, int] = {}
        for o in orders:
            if o.get("status") == "cancelled":
                continue
            for item in o.get("items", []):
                name = item.get("name", "Unknown")
                counts[name] = counts.get(name, 0) + int(item.get("quantity", 1))
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"name": n, "quantity": q} for n, q in sorted_items]


def _daily_revenue(store, days: int = 14) -> list[dict]:
    if store.USE_DB:
        with store._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT DATE(created_at) AS day, COALESCE(SUM(total), 0) AS rev
                    FROM orders
                    WHERE status != 'cancelled'
                      AND created_at >= NOW() - (%s * INTERVAL '1 day')
                    GROUP BY day
                    ORDER BY day
                """, (days,))
                return [{"date": str(r[0]), "revenue": float(r[1])} for r in cur.fetchall()]
    else:
        orders = store.read_json(store.ORDERS_PATH, [])
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        daily: dict[str, float] = {}
        for o in orders:
            if o.get("status") == "cancelled":
                continue
            ts = o.get("createdAt", "")
            if ts < cutoff:
                continue
            day = ts[:10]
            daily[day] = daily.get(day, 0.0) + float(o.get("total", 0))
        return [{"date": d, "revenue": round(v, 2)} for d, v in sorted(daily.items())]


# ---------------------------------------------------------------------------
# System status
# ---------------------------------------------------------------------------

@admin_bp.route("/status")
@admin_required
def status():
    store = _store()
    data_dir = store.DATA_DIR

    # Disk usage
    try:
        disk = shutil.disk_usage(str(data_dir))
        disk_total_gb = round(disk.total / 1e9, 1)
        disk_used_gb = round(disk.used / 1e9, 1)
        disk_free_gb = round(disk.free / 1e9, 1)
        disk_pct = round(disk.used / disk.total * 100, 1) if disk.total else 0
    except Exception:
        disk_total_gb = disk_used_gb = disk_free_gb = disk_pct = None

    # DB status
    db_ok = False
    db_msg = "JSON file storage (no DATABASE_URL)"
    if store.USE_DB:
        try:
            with store._get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            db_ok = True
            db_msg = "PostgreSQL connected"
        except Exception as exc:
            db_msg = f"PostgreSQL error: {exc}"

    # Data file sizes
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
    )
