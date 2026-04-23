"""Multi-tenant control plane: superadmin onboarding, plans, quotas,
impersonation, audit log and per-tenant export/delete.

All routes here are mounted under ``/superadmin/mt/*`` to avoid colliding
with the legacy ``admin_bp`` ``/admin/*`` routes, while still being
protected by the same superadmin gate (a logged-in Owner with
``is_superadmin=True``).

Helpers exposed for use by ``app.py``:

* :func:`signup_mode`       -- returns ``open|approval|invite_only``
* :func:`audit_log`         -- record a tenant-scoped action
* :func:`enforce_quota`     -- raise an HTTP 402 when an owner exceeds plan limits
* :func:`hash_invite_token` -- shared token hashing
* :func:`is_impersonating`  -- session helper
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import login_user

bp = Blueprint("multi_tenant", __name__, url_prefix="/superadmin/mt")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

VALID_PLAN_TIERS = ("free", "starter", "pro", "enterprise")
DEFAULT_PLAN_LIMITS: dict[str, dict[str, int]] = {
    "free": {"max_tables": 5, "max_menu_items": 30, "monthly_order_limit": 200},
    "starter": {"max_tables": 15, "max_menu_items": 100, "monthly_order_limit": 2000},
    "pro": {"max_tables": 50, "max_menu_items": 500, "monthly_order_limit": 20000},
    "enterprise": {"max_tables": 0, "max_menu_items": 0, "monthly_order_limit": 0},  # 0 = unlimited
}


def signup_mode() -> str:
    """Return the configured signup mode.

    ``open``         -- legacy: anyone can register and log in immediately.
    ``approval``     -- accounts are created with ``approval_status='pending'``
                        and cannot log in until a superadmin approves them.
    ``invite_only``  -- a valid (unused, unexpired) invite token is required.

    Default: ``approval`` -- safe, opt-in onboarding for production SaaS.
    """
    raw = (os.environ.get("OWNER_SIGNUP_MODE") or "approval").strip().lower()
    if raw not in {"open", "approval", "invite_only"}:
        return "approval"
    return raw


def hash_invite_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def superadmin_only(view_func):
    """Unified superadmin guard.

    Historically this module had a local check that only granted access when
    the logged-in owner had ``is_superadmin=True``. That excluded admin-elevated
    sessions which had verified ``SUPERADMIN_KEY`` (the legacy /admin -> /superadmin
    flow). To unify authorization across the app, this decorator now delegates
    to ``app.superadmin_required`` (lazy import keeps startup circular-import
    safe). All ``@superadmin_only`` decorations therefore behave identically to
    ``@superadmin_required`` elsewhere in the codebase.
    """

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        from app import superadmin_required
        return superadmin_required(view_func)(*args, **kwargs)

    return wrapper


# Backwards-compatible alias so new code can import the canonical name from
# this module too.
superadmin_required = superadmin_only


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def audit_log(
    action: str,
    *,
    owner_id: int | None = None,
    actor_type: str = "system",
    actor_id: int | None = None,
    actor_label: str = "",
    target: str = "",
    meta: dict | None = None,
    ip: str = "",
) -> None:
    """Record a tenant-scoped audit event.  Never raises."""
    try:
        from app import db
        from .mt_models import AuditLog
        entry = AuditLog(
            owner_id=owner_id,
            actor_type=actor_type or "system",
            actor_id=actor_id,
            actor_label=actor_label or "",
            action=action,
            target=target or "",
            meta=meta or {},
            ip=ip or "",
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:  # pragma: no cover - never break the user request
        try:
            from app import db as _db
            _db.session.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Quota enforcement
# ---------------------------------------------------------------------------

class QuotaExceeded(Exception):
    def __init__(self, message: str, kind: str):
        super().__init__(message)
        self.message = message
        self.kind = kind


def _owner_limit(owner, kind: str) -> int:
    """Return the active integer limit for ``kind`` (``0`` means unlimited)."""
    explicit = getattr(owner, kind, None)
    if explicit is not None:
        try:
            return int(explicit)
        except (TypeError, ValueError):
            pass
    tier = (getattr(owner, "plan_tier", "") or "free").lower()
    defaults = DEFAULT_PLAN_LIMITS.get(tier, DEFAULT_PLAN_LIMITS["free"])
    return int(defaults.get(kind, 0))


def enforce_quota(owner, kind: str, current_count: int) -> None:
    """Raise :class:`QuotaExceeded` if creating one more would exceed the limit.

    ``kind`` must be one of ``max_tables`` / ``max_menu_items`` /
    ``monthly_order_limit``.  ``current_count`` is the count *before* the new
    record is added.
    """
    limit = _owner_limit(owner, kind)
    if limit <= 0:
        return  # 0 = unlimited
    if current_count + 1 > limit:
        nice = {
            "max_tables": "tables",
            "max_menu_items": "menu items",
            "monthly_order_limit": "orders this month",
        }.get(kind, kind)
        raise QuotaExceeded(
            f"Plan limit reached: {limit} {nice}. Contact your administrator to upgrade.",
            kind,
        )


def count_owner_tables(owner_id: int) -> int:
    from app import CafeTable
    return CafeTable.query.filter_by(owner_id=owner_id).count()


def count_owner_menu_items(owner_id: int) -> int:
    from app import Menu, db
    record = db.session.get(Menu, owner_id)
    if not record or not record.data:
        return 0
    total = 0
    for cat in (record.data.get("categories") or []):
        total += len(cat.get("items") or [])
    return total


def count_owner_orders_this_month(owner_id: int) -> int:
    from app import Order
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return Order.query.filter(
        Order.owner_id == owner_id,
        Order.created_at >= month_start,
    ).count()


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

IMPERSONATION_KEY = "impersonator_owner_id"


def is_impersonating() -> bool:
    return bool(session.get(IMPERSONATION_KEY))


def begin_impersonation(superadmin_owner, target_owner) -> None:
    """Switch the current session to act as ``target_owner`` while remembering
    the original superadmin so the operator can stop impersonating later.

    NOTE: ``superadmin_owner`` may be Flask-Login's ``current_user`` proxy,
    which gets re-bound by ``login_user(target_owner)`` inside
    :func:`_complete_login`.  We therefore snapshot the SA's id and username
    into local primitives BEFORE re-binding so the impersonation marker we
    write to the session points to the SA, not the target.
    """
    from app import _complete_login
    sa_id = int(superadmin_owner.id)
    sa_username = str(superadmin_owner.username)
    _complete_login(target_owner, remember_me=False)
    # _complete_login() clears the session; set the marker afterwards from
    # the snapshot so it isn't overwritten.
    session[IMPERSONATION_KEY] = sa_id
    session["impersonator_username"] = sa_username


def end_impersonation() -> int | None:
    sa_id = session.get(IMPERSONATION_KEY)
    session.pop(IMPERSONATION_KEY, None)
    session.pop("impersonator_username", None)
    return sa_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _current_sa():
    from app import logged_in_owner_obj
    return logged_in_owner_obj()


def _ip() -> str:
    try:
        from app import _client_ip
        return _client_ip()
    except Exception:
        return request.remote_addr or ""


def _serialize_owner(owner) -> dict:
    return {
        "id": owner.id,
        "username": owner.username,
        "email": owner.email,
        "cafeName": owner.cafe_name,
        "cafeId": owner.cafe_id,
        "isActive": bool(owner.is_active),
        "isSuperadmin": bool(getattr(owner, "is_superadmin", False)),
        "approvalStatus": getattr(owner, "approval_status", "active") or "active",
        "planTier": getattr(owner, "plan_tier", "free") or "free",
        "maxTables": getattr(owner, "max_tables", None),
        "maxMenuItems": getattr(owner, "max_menu_items", None),
        "monthlyOrderLimit": getattr(owner, "monthly_order_limit", None),
        "trialEndsAt": getattr(owner, "trial_ends_at", None).isoformat()
        if getattr(owner, "trial_ends_at", None) else None,
        "notes": getattr(owner, "notes", "") or "",
        "createdAt": owner.created_at.isoformat() if owner.created_at else None,
    }


def _is_trial_expired(owner) -> bool:
    end = getattr(owner, "trial_ends_at", None)
    if not end:
        return False
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > end


def can_owner_login(owner) -> tuple[bool, str]:
    """Gate used by /owner/login to enforce approval + trial state."""
    if not owner.is_active:
        return False, "This account is suspended."
    status = (getattr(owner, "approval_status", "active") or "active").lower()
    if status == "pending":
        return False, "Your account is awaiting administrator approval."
    if status == "rejected":
        return False, "Your account application was declined."
    if _is_trial_expired(owner):
        return False, "Your trial has expired. Please contact your administrator."
    return True, ""


# ---------------------------------------------------------------------------
# Onboarding -- pending owners
# ---------------------------------------------------------------------------

@bp.route("/pending")
@superadmin_only
def pending_owners():
    from app import Owner
    pending = Owner.query.filter_by(approval_status="pending").order_by(Owner.created_at.desc()).all()
    return render_template("admin/pending_owners.html", pending=pending,
                           signup_mode=signup_mode())


@bp.route("/owners/<int:owner_id>/approve", methods=["POST"])
@superadmin_only
def approve_owner(owner_id: int):
    from app import Owner, db
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    owner.approval_status = "active"
    owner.is_active = True
    plan = (request.form.get("plan_tier") or "free").lower()
    if plan in VALID_PLAN_TIERS:
        owner.plan_tier = plan
    db.session.commit()
    sa = _current_sa()
    audit_log("OWNER_APPROVED", owner_id=owner.id, actor_type="superadmin",
              actor_id=getattr(sa, "id", None), actor_label=getattr(sa, "username", ""),
              meta={"plan": owner.plan_tier}, ip=_ip())
    flash(f"Approved @{owner.username} ({owner.plan_tier}).", "success")
    return redirect(url_for("multi_tenant.pending_owners"))


@bp.route("/owners/<int:owner_id>/reject", methods=["POST"])
@superadmin_only
def reject_owner(owner_id: int):
    from app import Owner, db
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Cannot reject a superadmin.", "danger")
        return redirect(url_for("multi_tenant.pending_owners"))
    owner.approval_status = "rejected"
    owner.is_active = False
    db.session.commit()
    sa = _current_sa()
    audit_log("OWNER_REJECTED", owner_id=owner.id, actor_type="superadmin",
              actor_id=getattr(sa, "id", None), actor_label=getattr(sa, "username", ""),
              ip=_ip())
    flash(f"Rejected @{owner.username}.", "warning")
    return redirect(url_for("multi_tenant.pending_owners"))


# ---------------------------------------------------------------------------
# Plan + quota editing
# ---------------------------------------------------------------------------

@bp.route("/owners/<int:owner_id>/plan", methods=["GET", "POST"])
@superadmin_only
def edit_plan(owner_id: int):
    from app import Owner, db
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)

    if request.method == "POST":
        plan = (request.form.get("plan_tier") or "free").lower()
        if plan not in VALID_PLAN_TIERS:
            flash("Invalid plan tier.", "danger")
            return redirect(url_for("multi_tenant.edit_plan", owner_id=owner_id))

        def _opt_int(name: str) -> int | None:
            raw = (request.form.get(name) or "").strip()
            if raw == "":
                return None
            try:
                value = int(raw)
                return value if value >= 0 else 0
            except ValueError:
                return None

        def _opt_dt(name: str):
            raw = (request.form.get(name) or "").strip()
            if not raw:
                return None
            try:
                return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return None

        previous = {
            "plan_tier": owner.plan_tier,
            "max_tables": owner.max_tables,
            "max_menu_items": owner.max_menu_items,
            "monthly_order_limit": owner.monthly_order_limit,
            "trial_ends_at": owner.trial_ends_at.isoformat() if owner.trial_ends_at else None,
        }
        owner.plan_tier = plan
        owner.max_tables = _opt_int("max_tables")
        owner.max_menu_items = _opt_int("max_menu_items")
        owner.monthly_order_limit = _opt_int("monthly_order_limit")
        owner.trial_ends_at = _opt_dt("trial_ends_at")
        owner.notes = (request.form.get("notes") or "")[:2000]
        db.session.commit()
        sa = _current_sa()
        audit_log("OWNER_PLAN_UPDATED", owner_id=owner.id, actor_type="superadmin",
                  actor_id=getattr(sa, "id", None), actor_label=getattr(sa, "username", ""),
                  meta={"previous": previous, "current": {
                      "plan_tier": owner.plan_tier,
                      "max_tables": owner.max_tables,
                      "max_menu_items": owner.max_menu_items,
                      "monthly_order_limit": owner.monthly_order_limit,
                      "trial_ends_at": owner.trial_ends_at.isoformat() if owner.trial_ends_at else None,
                  }}, ip=_ip())
        flash(f"Plan updated for @{owner.username}.", "success")
        return redirect(url_for("multi_tenant.edit_plan", owner_id=owner_id))

    usage = {
        "tables": count_owner_tables(owner_id),
        "menu_items": count_owner_menu_items(owner_id),
        "orders_this_month": count_owner_orders_this_month(owner_id),
    }
    limits = {
        "max_tables": _owner_limit(owner, "max_tables"),
        "max_menu_items": _owner_limit(owner, "max_menu_items"),
        "monthly_order_limit": _owner_limit(owner, "monthly_order_limit"),
    }
    return render_template("admin/owner_plan.html", owner=owner, usage=usage,
                           limits=limits, plan_tiers=VALID_PLAN_TIERS,
                           defaults=DEFAULT_PLAN_LIMITS)


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

@bp.route("/owners/<int:owner_id>/impersonate", methods=["POST"])
@superadmin_only
def impersonate(owner_id: int):
    from app import Owner, db
    sa = _current_sa()
    target = db.session.get(Owner, owner_id)
    if not target:
        abort(404)
    if target.is_superadmin and target.id != sa.id:
        flash("Refusing to impersonate another superadmin.", "danger")
        return redirect(url_for("superadmin_dashboard"))
    if not target.is_active or (getattr(target, "approval_status", "active") or "active") != "active":
        flash("Cannot impersonate a non-active owner. Approve or reactivate first.", "danger")
        return redirect(url_for("superadmin_dashboard"))

    audit_log("IMPERSONATION_START", owner_id=target.id, actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username,
              target=f"owner:{target.id}", ip=_ip())
    begin_impersonation(sa, target)
    flash(f"You are now viewing the app as @{target.username}.", "info")
    return redirect(url_for("owner_dashboard"))


@bp.route("/stop-impersonating", methods=["POST", "GET"])
def stop_impersonating():
    """Restore the original superadmin session.

    NOTE: We deliberately avoid calling ``_complete_login`` here because that
    helper calls ``session.clear()``, which would wipe ``admin_authenticated``
    and ``superadmin_key_verified`` — the two flags that admin-elevated
    operators rely on to access ``/superadmin``. Clearing them caused the
    operator to be bounced back to ``/admin`` after every impersonation.

    Instead we directly re-authenticate the original SA owner and preserve
    those elevation flags.
    """
    from app import Owner, db
    sa_id = end_impersonation()
    if not sa_id:
        return redirect(url_for("owner_login"))
    sa = db.session.get(Owner, sa_id)
    if not sa:
        return redirect(url_for("owner_login"))

    audit_log("IMPERSONATION_END", actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username, ip=_ip())

    # Re-bind the SA's owner identity without clearing the session.
    session["owner_username"] = sa.username
    session["owner_id"] = sa.id
    session.permanent = True
    # Do NOT pop admin_authenticated / superadmin_key_verified — keep the
    # operator's elevation intact.
    login_user(sa, remember=False)

    flash("Impersonation ended.", "success")
    return redirect(url_for("superadmin_dashboard"))


# ---------------------------------------------------------------------------
# Maintenance mode toggle
# ---------------------------------------------------------------------------

@bp.route("/maintenance", methods=["GET"], endpoint="maintenance_mode_status")
@superadmin_only
def maintenance_status():
    """Return the current maintenance flag state. JSON for API callers."""
    from app import _maintenance_mode_enabled
    enabled = _maintenance_mode_enabled(force_refresh=True)
    return jsonify({"ok": True, "enabled": enabled}), 200


@bp.route("/maintenance", methods=["POST"], endpoint="maintenance_mode_toggle")
@superadmin_only
def maintenance_toggle():
    """Toggle the maintenance-mode flag.

    Accepts ``enabled=true|false`` via JSON body or form. While the flag is on,
    non-superadmin requests are served a maintenance page (see
    ``app._enforce_maintenance_mode``). Superadmins themselves keep full
    access so they can finish whatever they're doing before flipping it back.
    """
    from app import _set_maintenance_mode, _maintenance_mode_enabled
    payload = request.get_json(silent=True) or request.form or {}
    raw = str(payload.get("enabled", "")).strip().lower()
    if raw not in {"true", "false", "1", "0", "on", "off", "yes", "no"}:
        return jsonify({"ok": False, "error": "Body must include enabled=true|false."}), 400
    enabled = raw in {"true", "1", "on", "yes"}
    _set_maintenance_mode(enabled)

    sa = _current_sa()
    audit_log(
        "MAINTENANCE_TOGGLE",
        actor_type="superadmin",
        actor_id=getattr(sa, "id", None),
        actor_label=getattr(sa, "username", ""),
        meta={"enabled": enabled},
        ip=_ip(),
    )
    return jsonify({"ok": True, "enabled": _maintenance_mode_enabled(force_refresh=True)}), 200


# ---------------------------------------------------------------------------
# Per-tenant export and delete
# ---------------------------------------------------------------------------

@bp.route("/owners/<int:owner_id>/export.json")
@superadmin_only
def export_owner(owner_id: int):
    from app import (
        Owner, CafeTable, Menu, Order, Feedback, Settings, Ingredient, db,
    )
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)

    def _row(obj, fields):
        out = {}
        for f in fields:
            v = getattr(obj, f, None)
            if isinstance(v, datetime):
                v = v.isoformat()
            out[f] = v
        return out

    payload = {
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "owner": _serialize_owner(owner),
        "tables": [
            _row(t, ["id", "name", "cafe_id", "created_at"])
            for t in CafeTable.query.filter_by(owner_id=owner_id).all()
        ],
        "menu": (db.session.get(Menu, owner_id).data
                 if db.session.get(Menu, owner_id) else {"categories": []}),
        "ingredients": [
            _row(i, ["id", "name", "unit", "stock", "low_stock_threshold",
                     "menu_item_id", "qty_per_order", "created_at"])
            for i in Ingredient.query.filter_by(owner_id=owner_id).all()
        ],
        "orders": [
            {
                **_row(o, ["id", "table_id", "table_name", "customer_name",
                           "customer_email", "customer_phone", "subtotal",
                           "tip", "total", "status", "pickup_code", "origin",
                           "notes", "created_at", "updated_at"]),
                "items": o.items,
                "modifiers": o.modifiers,
            }
            for o in Order.query.filter_by(owner_id=owner_id)
            .order_by(Order.created_at.desc()).all()
        ],
        "feedback": [
            _row(f, ["id", "order_id", "table_id", "customer_name", "rating",
                     "comment", "created_at"])
            for f in Feedback.query.filter_by(owner_id=owner_id).all()
        ],
        "settings": (
            {
                "logo_url": db.session.get(Settings, owner_id).logo_url,
                "brand_color": db.session.get(Settings, owner_id).brand_color,
            } if db.session.get(Settings, owner_id) else None
        ),
    }
    sa = _current_sa()
    audit_log("OWNER_EXPORTED", owner_id=owner_id, actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username, ip=_ip())
    body = json.dumps(payload, indent=2, default=str)
    resp = Response(body, mimetype="application/json")
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="owner-{owner_id}-{owner.username}.json"'
    )
    return resp


@bp.route("/owners/<int:owner_id>/delete", methods=["POST"])
@superadmin_only
def delete_owner(owner_id: int):
    from app import (
        Owner, CafeTable, Menu, Order, Feedback, Settings, Ingredient,
        RememberToken, db,
    )
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    if owner.is_superadmin:
        flash("Refusing to delete a superadmin.", "danger")
        return redirect(url_for("superadmin_dashboard"))

    confirm = (request.form.get("confirm_username") or "").strip()
    if confirm != owner.username:
        flash("Confirmation username does not match.", "danger")
        return redirect(url_for("superadmin_dashboard"))

    sa = _current_sa()
    snapshot = _serialize_owner(owner)

    # Delete dependent rows that may not have ON DELETE CASCADE on legacy rows.
    Order.query.filter_by(owner_id=owner_id).delete(synchronize_session=False)
    Feedback.query.filter_by(owner_id=owner_id).delete(synchronize_session=False)
    CafeTable.query.filter_by(owner_id=owner_id).delete(synchronize_session=False)
    Ingredient.query.filter_by(owner_id=owner_id).delete(synchronize_session=False)
    RememberToken.query.filter_by(owner_id=owner_id).delete(synchronize_session=False)
    menu = db.session.get(Menu, owner_id)
    if menu:
        db.session.delete(menu)
    settings = db.session.get(Settings, owner_id)
    if settings:
        db.session.delete(settings)
    db.session.delete(owner)
    db.session.commit()
    audit_log("OWNER_DELETED", actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username,
              meta={"deleted": snapshot}, ip=_ip())
    flash(f"Deleted @{owner.username} and all associated data.", "success")
    return redirect(url_for("superadmin_dashboard"))


# ---------------------------------------------------------------------------
# Audit log views
# ---------------------------------------------------------------------------

@bp.route("/owners/<int:owner_id>/audit")
@superadmin_only
def owner_audit(owner_id: int):
    from app import Owner, db
    from .mt_models import AuditLog
    owner = db.session.get(Owner, owner_id)
    if not owner:
        abort(404)
    entries = (AuditLog.query
               .filter_by(owner_id=owner_id)
               .order_by(AuditLog.created_at.desc())
               .limit(500).all())
    return render_template("admin/owner_audit.html", owner=owner, entries=entries)


@bp.route("/audit")
@superadmin_only
def global_audit():
    from .mt_models import AuditLog
    entries = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return render_template("admin/owner_audit.html", owner=None, entries=entries)


# ---------------------------------------------------------------------------
# Invitations
# ---------------------------------------------------------------------------

@bp.route("/invitations")
@superadmin_only
def invitations_list():
    from .mt_models import Invitation
    from app import Owner, db
    invites = Invitation.query.order_by(Invitation.created_at.desc()).limit(200).all()
    creator_ids = {i.created_by_owner_id for i in invites if i.created_by_owner_id}
    creators = {o.id: o.username for o in Owner.query.filter(Owner.id.in_(creator_ids)).all()} if creator_ids else {}
    issued = session.pop("_just_issued_invite", None)
    return render_template("admin/invitations.html", invites=invites,
                           creators=creators, issued=issued,
                           plan_tiers=VALID_PLAN_TIERS,
                           signup_mode=signup_mode())


@bp.route("/invitations/create", methods=["POST"])
@superadmin_only
def create_invitation():
    from app import db
    from .mt_models import Invitation
    sa = _current_sa()
    email = (request.form.get("email") or "").strip()[:254]
    note = (request.form.get("note") or "").strip()[:500]
    plan = (request.form.get("plan_tier") or "free").lower()
    if plan not in VALID_PLAN_TIERS:
        plan = "free"
    days = (request.form.get("expires_days") or "14").strip()
    try:
        expire_days = max(1, min(365, int(days)))
    except ValueError:
        expire_days = 14

    plaintext = secrets.token_urlsafe(24)
    inv = Invitation(
        token_hash=hash_invite_token(plaintext),
        email=email,
        note=note,
        plan_tier=plan,
        created_by_owner_id=sa.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=expire_days),
    )
    db.session.add(inv)
    db.session.commit()
    audit_log("INVITATION_CREATED", actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username,
              meta={"id": inv.id, "email": email, "plan": plan, "expires_days": expire_days},
              ip=_ip())
    invite_url = url_for("owner_signup", invite=plaintext, _external=True)
    session["_just_issued_invite"] = {
        "id": inv.id,
        "token": plaintext,
        "url": invite_url,
        "email": email,
        "plan": plan,
        "expires_at": inv.expires_at.isoformat(),
    }
    return redirect(url_for("multi_tenant.invitations_list"))


@bp.route("/invitations/<int:invite_id>/revoke", methods=["POST"])
@superadmin_only
def revoke_invitation(invite_id: int):
    from app import db
    from .mt_models import Invitation
    inv = db.session.get(Invitation, invite_id)
    if not inv:
        abort(404)
    if inv.used_at:
        flash("That invitation has already been redeemed.", "warning")
        return redirect(url_for("multi_tenant.invitations_list"))
    inv.revoked_at = datetime.now(timezone.utc)
    db.session.commit()
    sa = _current_sa()
    audit_log("INVITATION_REVOKED", actor_type="superadmin",
              actor_id=sa.id, actor_label=sa.username,
              meta={"id": inv.id}, ip=_ip())
    flash("Invitation revoked.", "success")
    return redirect(url_for("multi_tenant.invitations_list"))


def find_valid_invitation(plaintext: str):
    """Return the Invitation row if the token is valid, otherwise ``None``."""
    if not plaintext:
        return None
    from .mt_models import Invitation
    inv = Invitation.query.filter_by(token_hash=hash_invite_token(plaintext)).first()
    if not inv:
        return None
    if inv.used_at or inv.revoked_at:
        return None
    if inv.expires_at:
        end = inv.expires_at
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > end:
            return None
    return inv


def consume_invitation(inv, owner) -> None:
    from app import db
    inv.used_at = datetime.now(timezone.utc)
    inv.used_by_owner_id = owner.id
    db.session.commit()
    audit_log("INVITATION_REDEEMED", owner_id=owner.id, actor_type="owner",
              actor_id=owner.id, actor_label=owner.username,
              meta={"invitation_id": inv.id, "plan": inv.plan_tier})


# ---------------------------------------------------------------------------
# Quick read-only API used by the Owners table
# ---------------------------------------------------------------------------

@bp.route("/api/owners-summary")
@superadmin_only
def owners_summary():
    from app import Owner
    owners = Owner.query.order_by(Owner.created_at.desc()).all()
    return jsonify([_serialize_owner(o) for o in owners])
