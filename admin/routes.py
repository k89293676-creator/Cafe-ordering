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
admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin",
    template_folder=None,
)


def _store():
    import app as _app
    return _app


def _admin_key() -> str:
    return os.environ.get("ADMIN_SECRET_KEY", "")


def _key_valid(key: str) -> bool:
    secret = _admin_key()
    return bool(secret) and bool(key) and secrets.compare_digest(secret, key)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("admin_authenticated"):
            return f(*args, **kwargs)
        key = request.headers.get("X-Admin-Key", "")
        if _key_valid(key):
            session["admin_authenticated"] = True
            return f(*args, **kwargs)
        return redirect(url_for("admin.login"))
    return decorated


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


@admin_bp.route("/")
@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    store = _store()
    owners = store.load_owners()
    stats = _global_stats(store)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "admin/dashboard.html",
        owners=owners,
        total_owners=len(owners),
        active_owners=sum(1 for o in owners if o.get("isActive", True)),
        total_orders=stats["total_orders"],
        total_revenue=stats["total_revenue"],
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
