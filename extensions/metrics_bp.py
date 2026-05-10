"""Prometheus-compatible metrics endpoint for production monitoring.

Exposes /metrics with application-level gauges and counters in the
Prometheus text exposition format (version 0.0.4). Secured by a
Bearer token (METRICS_TOKEN env var); returns 403 if the token is
absent or wrong so the endpoint is safe to expose on a public port.

Performance & Scaling:
- Uses a lightweight in-process aggregation so there is no separate
  push-gateway required for small deployments.
- For multi-worker setups (gunicorn) each worker independently serves
  metrics; a scraper should add a ``worker`` label in the job config.
- The endpoint itself is O(DB queries) — keep the scrape interval at
  ≥15s to avoid hammering the DB.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, request

from app.extensions import db

bp = Blueprint("metrics", __name__)

_START_TIME = time.time()


def _token_ok() -> bool:
    token = os.environ.get("METRICS_TOKEN", "")
    if not token:
        return True  # no token configured → open (dev mode)
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {token}"


def _gauge(name: str, value, labels: dict | None = None, help_text: str = "") -> str:
    label_str = ""
    if labels:
        kv = ",".join(f'{k}="{v}"' for k, v in labels.items())
        label_str = f"{{{kv}}}"
    lines = []
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} gauge")
    lines.append(f"{name}{label_str} {value}")
    return "\n".join(lines)


def _counter(name: str, value, help_text: str = "") -> str:
    lines = []
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} counter")
    lines.append(f"{name}_total {value}")
    return "\n".join(lines)


@bp.route("/metrics")
def metrics():
    if not _token_ok():
        return Response("Forbidden", status=403, mimetype="text/plain")

    parts: list[str] = []
    parts.append(_gauge("cafe_uptime_seconds", round(time.time() - _START_TIME, 1),
                        help_text="Seconds since this worker process started."))

    try:
        from app.models import Order, Owner, Ingredient
        from sqlalchemy import text

        now = datetime.now(timezone.utc)
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        since_1h = now - timedelta(hours=1)

        total_orders = db.session.query(db.func.count(Order.id)).scalar() or 0
        parts.append(_counter("cafe_orders", total_orders, "Total orders ever created."))

        orders_today = (db.session.query(db.func.count(Order.id))
                        .filter(Order.created_at >= today).scalar() or 0)
        parts.append(_gauge("cafe_orders_today", orders_today,
                            help_text="Orders created since midnight UTC."))

        open_tabs = (db.session.query(db.func.count(Order.id))
                     .filter(Order.payment_status == "unpaid",
                             Order.status != "cancelled").scalar() or 0)
        parts.append(_gauge("cafe_open_tabs", open_tabs,
                            help_text="Currently open unpaid bills."))

        pending_orders = (db.session.query(db.func.count(Order.id))
                          .filter(Order.status.in_(("pending", "preparing"))).scalar() or 0)
        parts.append(_gauge("cafe_pending_orders", pending_orders,
                            help_text="Orders in pending or preparing state."))

        revenue_today = float(
            db.session.query(db.func.coalesce(db.func.sum(Order.total), 0))
            .filter(Order.payment_status == "paid", Order.paid_at >= today).scalar() or 0)
        parts.append(_gauge("cafe_revenue_today_rupees", round(revenue_today, 2),
                            help_text="Total revenue (paid orders) since midnight UTC."))

        active_owners = (db.session.query(db.func.count(Owner.id))
                         .filter(Owner.is_active == True).scalar() or 0)
        parts.append(_gauge("cafe_active_owners", active_owners,
                            help_text="Number of active owner accounts."))

        low_stock = (db.session.query(db.func.count(Ingredient.id))
                     .filter(Ingredient.stock <= Ingredient.low_stock_threshold).scalar() or 0)
        parts.append(_gauge("cafe_low_stock_ingredients", low_stock,
                            help_text="Ingredients at or below low-stock threshold."))

        orders_1h = (db.session.query(db.func.count(Order.id))
                     .filter(Order.created_at >= since_1h).scalar() or 0)
        parts.append(_gauge("cafe_orders_last_1h", orders_1h,
                            help_text="Orders created in the last 60 minutes."))

    except Exception as exc:
        parts.append(f"# SCRAPE_ERROR {exc}")

    try:
        pool = db.engine.pool
        parts.append(_gauge("cafe_db_pool_checkedout", getattr(pool, "checkedout", lambda: 0)(),
                            help_text="DB connections currently checked out."))
        parts.append(_gauge("cafe_db_pool_size", getattr(pool, "size", lambda: 0)(),
                            help_text="DB connection pool configured size."))
    except Exception:
        pass

    output = "\n\n".join(parts) + "\n"
    return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")
