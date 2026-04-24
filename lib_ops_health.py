"""Production-grade operational health check.

Exposes a single secure endpoint — ``/api/ops/health`` — that returns
per-section health for every item shown in the owner sidebar
(Inventory, Billing, Payment Methods, Food Delivery aggregators,
Reorder, Analytics, Sales Dashboard, Menu Engineering, Customer LTV,
Employees, Tables Overview, Table Calls, Customers, Export CSV,
Daily PDF Report).

Designed for uptime monitors / SRE dashboards / GitHub Actions
post-deploy verification. Each section reports:

- ``ok`` — boolean
- ``rows`` / ``count`` / ``configured`` — at-a-glance signal
- ``error`` — short string when degraded (truncated to 200 chars)
- ``hint`` — what to look at when not OK

The endpoint is protected by a constant-time token compare against
the ``OPS_HEALTH_TOKEN`` env var. If the token is unset the endpoint
returns ``503`` with an "ops-token-not-configured" hint instead of
silently exposing internal state.

Always returns ``200`` with JSON body when the token is valid; the
``ok`` field on the body indicates overall health. This separation
matters: load balancers should not flap the deployment because
"customers haven't signed up yet" — the workflow / monitor decides
what to do with the signal.
"""
from __future__ import annotations

import hmac
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, abort, current_app, jsonify, request
from sqlalchemy import text

bp = Blueprint("ops_health", __name__)


# ---------------------------------------------------------------------------
# Token gate
# ---------------------------------------------------------------------------

def _expected_token() -> str:
    """Resolve the ops-health token. Falls back through a tiny chain so
    the endpoint works on a fresh deploy without any extra config:

    1. ``OPS_HEALTH_TOKEN`` — the canonical env var.
    2. ``HEALTHCHECK_TOKEN`` — common alias used by some monitors.
    3. Empty string when neither is set; the request will be refused.
    """
    return (
        os.environ.get("OPS_HEALTH_TOKEN")
        or os.environ.get("HEALTHCHECK_TOKEN")
        or ""
    ).strip()


def _provided_token() -> str:
    """Read the token from ``Authorization: Bearer …`` or ``?token=…``.
    Header is preferred — query params land in access logs."""
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.args.get("token") or request.headers.get("X-Ops-Token") or "").strip()


def _token_ok() -> bool:
    expected = _expected_token()
    provided = _provided_token()
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))


# ---------------------------------------------------------------------------
# Section probes
# ---------------------------------------------------------------------------

def _safe(fn):
    """Run ``fn`` and return ``{ok, ...}`` — never raises."""
    try:
        result = fn() or {}
        result.setdefault("ok", True)
        return result
    except Exception as exc:  # noqa: BLE001 - top-level boundary
        current_app.logger.warning("ops-health probe failed: %s", exc)
        return {"ok": False, "error": str(exc)[:200]}


def _section_inventory() -> dict[str, Any]:
    from app import Ingredient, db
    total = db.session.query(Ingredient).count()
    low = (
        db.session.query(Ingredient)
        .filter(Ingredient.stock <= Ingredient.low_stock_threshold)
        .count()
    )
    out_of_stock = db.session.query(Ingredient).filter(Ingredient.stock <= 0).count()
    return {
        "rows": total,
        "lowStock": low,
        "outOfStock": out_of_stock,
        "hint": "low/out-of-stock counts; trip restock when lowStock > 0",
    }


def _section_billing() -> dict[str, Any]:
    from app import Order, db
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    paid_today = (
        db.session.query(Order)
        .filter(Order.created_at >= today_start, Order.payment_status == "paid")
        .count()
    )
    unpaid_open = (
        db.session.query(Order)
        .filter(Order.payment_status == "unpaid",
                Order.status.in_(("confirmed", "preparing", "ready", "completed")))
        .count()
    )
    return {
        "paidToday": paid_today,
        "unpaidOpen": unpaid_open,
        "hint": "unpaidOpen reflects orders waiting for settlement",
    }


def _section_payment_methods() -> dict[str, Any]:
    from app import db
    try:
        from lib_payments import SUPPORTED_PROVIDERS  # noqa: F401
    except Exception:
        SUPPORTED_PROVIDERS = ()  # type: ignore[assignment]
    row = db.session.execute(
        text(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN COALESCE(verified_at, NULL) IS NOT NULL THEN 1 ELSE 0 END) AS verified "
            "FROM payment_credentials"
        )
    ).first()
    total = int(row.total or 0) if row else 0
    verified = int(row.verified or 0) if row else 0
    return {
        "configured": total,
        "verified": verified,
        "supportedProviders": list(SUPPORTED_PROVIDERS),
        "needsSetup": total == 0,
        "hint": "verify ratio < 1 means at least one provider failed health probe",
    }


def _section_food_delivery() -> dict[str, Any]:
    from app import db
    try:
        from lib_integrations import SUPPORTED_PLATFORMS  # type: ignore
    except Exception:
        try:
            from lib_payments import SUPPORTED_PLATFORMS  # type: ignore
        except Exception:
            SUPPORTED_PLATFORMS = ()  # type: ignore[assignment]
    row = db.session.execute(
        text("SELECT COUNT(*) AS total FROM aggregator_credentials")
    ).first()
    total = int(row.total or 0) if row else 0
    last24 = datetime.now(timezone.utc) - timedelta(hours=24)
    orders_row = db.session.execute(
        text("SELECT COUNT(*) AS c FROM aggregator_orders WHERE received_at >= :since"),
        {"since": last24},
    ).first()
    return {
        "configured": total,
        "supportedPlatforms": list(SUPPORTED_PLATFORMS),
        "ordersLast24h": int(orders_row.c or 0) if orders_row else 0,
        "needsSetup": total == 0,
        "hint": "ordersLast24h == 0 with platforms configured may indicate webhook drift",
    }


def _section_reorder() -> dict[str, Any]:
    from app import Order, db
    last7 = datetime.now(timezone.utc) - timedelta(days=7)
    reorder_count = (
        db.session.query(Order)
        .filter(Order.origin == "reorder", Order.created_at >= last7)
        .count()
    )
    return {"reorderLast7d": reorder_count}


def _section_analytics() -> dict[str, Any]:
    from app import Order, db
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "ordersToday": db.session.query(Order).filter(Order.created_at >= today_start).count(),
    }


def _section_sales_dashboard() -> dict[str, Any]:
    from app import db
    bp_present = "sales_dashboard" in current_app.blueprints
    last7 = datetime.now(timezone.utc) - timedelta(days=7)
    last7_orders = db.session.execute(
        text("SELECT COUNT(*) FROM orders WHERE created_at >= :since"),
        {"since": last7},
    ).scalar() or 0
    return {"blueprintLoaded": bp_present, "ordersLast7d": int(last7_orders)}


def _section_menu_engineering() -> dict[str, Any]:
    from app import db
    bp_present = "menu_engineering" in current_app.blueprints
    cat_count = db.session.execute(text("SELECT COUNT(*) FROM categories")).scalar() or 0
    return {"blueprintLoaded": bp_present, "categories": int(cat_count)}


def _section_customer_ltv() -> dict[str, Any]:
    from app import Order, db
    bp_present = "ltv" in current_app.blueprints
    last30 = datetime.now(timezone.utc) - timedelta(days=30)
    distinct_customers = (
        db.session.query(Order.customer_email)
        .filter(Order.created_at >= last30, Order.customer_email != "")
        .distinct()
        .count()
    )
    return {"blueprintLoaded": bp_present, "uniqueCustomersLast30d": distinct_customers}


def _section_employees() -> dict[str, Any]:
    from app import db
    bp_present = "employees" in current_app.blueprints
    total = db.session.execute(text("SELECT COUNT(*) FROM employees")).scalar() or 0
    active = db.session.execute(
        text("SELECT COUNT(*) FROM employees WHERE is_active = TRUE")
    ).scalar() or 0
    return {"blueprintLoaded": bp_present, "total": int(total), "active": int(active)}


def _section_tables_overview() -> dict[str, Any]:
    from app import db
    bp_present = "tables_overview" in current_app.blueprints
    total = db.session.execute(text("SELECT COUNT(*) FROM tables")).scalar() or 0
    return {"blueprintLoaded": bp_present, "tables": int(total)}


def _section_table_calls() -> dict[str, Any]:
    from app import db
    bp_present = "service_calls" in current_app.blueprints
    open_calls = db.session.execute(
        text("SELECT COUNT(*) FROM table_calls WHERE status = 'open'")
    ).scalar() or 0
    last24 = datetime.now(timezone.utc) - timedelta(hours=24)
    last24_count = db.session.execute(
        text("SELECT COUNT(*) FROM table_calls WHERE created_at >= :since"),
        {"since": last24},
    ).scalar() or 0
    return {
        "blueprintLoaded": bp_present,
        "openCalls": int(open_calls),
        "callsLast24h": int(last24_count),
    }


def _section_customers() -> dict[str, Any]:
    from app import db
    bp_present = "customers" in current_app.blueprints
    total = db.session.execute(text("SELECT COUNT(*) FROM customers")).scalar() or 0
    return {"blueprintLoaded": bp_present, "registered": int(total)}


def _section_exports() -> dict[str, Any]:
    """Smoke-check: the route is registered. Cannot actually invoke
    here without a real owner session — the goal is to flag a missing
    route after a refactor, not to download CSVs from the monitor."""
    routes = {r.endpoint for r in current_app.url_map.iter_rules()}
    return {
        "exportOrdersCsv": "export_orders_csv" in routes,
        "dailyReportPdf": "daily_report_pdf" in routes,
        "salesDashboardCsv": "exports.sales_dashboard_csv" in routes,
        "menuEngineeringCsv": "exports.menu_engineering_csv" in routes,
        "ltvCsv": "exports.ltv_csv" in routes,
        "employeesCsv": "exports.employees_performance_csv" in routes,
    }


SECTION_PROBES: dict[str, Any] = {
    "inventory": _section_inventory,
    "billing": _section_billing,
    "paymentMethods": _section_payment_methods,
    "foodDelivery": _section_food_delivery,
    "reorder": _section_reorder,
    "analytics": _section_analytics,
    "salesDashboard": _section_sales_dashboard,
    "menuEngineering": _section_menu_engineering,
    "customerLtv": _section_customer_ltv,
    "employees": _section_employees,
    "tablesOverview": _section_tables_overview,
    "tableCalls": _section_table_calls,
    "customers": _section_customers,
    "exports": _section_exports,
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route("/api/ops/health")
def ops_health():
    """Comprehensive per-section health probe.

    Auth: ``Authorization: Bearer <OPS_HEALTH_TOKEN>``.

    Status codes:

    - ``200`` — token OK and probe ran (overall ``ok`` is in the body).
    - ``401`` — missing or invalid token.
    - ``503`` — token not configured on the server.
    """
    if not _expected_token():
        return jsonify(
            ok=False,
            error="ops-token-not-configured",
            hint="set OPS_HEALTH_TOKEN env var to enable this endpoint",
        ), 503
    if not _token_ok():
        # Same body for both "missing" and "wrong" — don't help an attacker
        # distinguish the two.
        return jsonify(ok=False, error="unauthorized"), 401

    started = time.time()
    only_param = (request.args.get("only") or "").strip().lower()
    requested = {s.strip() for s in only_param.split(",") if s.strip()} if only_param else None

    sections: dict[str, Any] = {}
    overall_ok = True
    for name, probe in SECTION_PROBES.items():
        if requested is not None and name.lower() not in requested:
            continue
        result = _safe(probe)
        if not result.get("ok", True):
            overall_ok = False
        sections[name] = result

    payload = {
        "ok": overall_ok,
        "service": "cafe-ordering-saas",
        "checkedAt": datetime.now(timezone.utc).isoformat(),
        "elapsedMs": round((time.time() - started) * 1000, 2),
        "sections": sections,
    }
    # Add deploy metadata so post-deploy CI can verify the right SHA is live.
    commit = (
        os.environ.get("RAILWAY_GIT_COMMIT_SHA")
        or os.environ.get("GIT_COMMIT")
        or os.environ.get("SOURCE_VERSION")
        or ""
    )
    if commit:
        payload["commit"] = commit[:40]
    deploy_id = os.environ.get("RAILWAY_DEPLOYMENT_ID")
    if deploy_id:
        payload["deployId"] = deploy_id
    return jsonify(payload), 200


def register(app) -> None:
    """Idempotently register the blueprint with the Flask app."""
    if bp.name not in app.blueprints:
        app.register_blueprint(bp)
