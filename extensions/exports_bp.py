"""CSV exports for the analytics-heavy sections of the owner dashboard.

The legacy ``/owner/export.csv`` and ``/owner/report/daily`` cover orders +
PDF day-roll, but the Sales Dashboard, Menu Engineering, Customer LTV, and
Employee Performance sections only render JSON — owners had to copy/paste
to Excel. That's a friction point in market-grade SaaS, so this blueprint
exposes per-section CSV downloads with sensible safety rails:

- Owner login required — never anonymous.
- Owner-scoped queries — multi-tenancy can never leak rows across cafés.
- ``Cache-Control: no-store, private`` — CSVs often contain customer email
  / phone, so we forbid intermediate caches.
- CSV-injection guard on every cell so a row title like ``=cmd|' /C calc'``
  cannot execute when opened in Excel.
- Hard row cap (configurable via ``EXPORTS_MAX_ROWS``) to keep memory
  bounded on Railway's free tier.
- Safe filenames — slugified ``cafe`` name + ISO date, no path bytes.
"""
from __future__ import annotations

import csv
import io
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from flask import Blueprint, Response, abort, request
from sqlalchemy import func

from app import (
    Order,
    Owner,
    db,
    limiter,
    logged_in_owner_id,
    login_required,
)
from ._helpers import parse_date_range, safe_float
from .models import Employee, OrderEmployeeAssignment

bp = Blueprint("exports", __name__)


MAX_ROWS = int(os.environ.get("EXPORTS_MAX_ROWS", "50000"))
RATE_LIMIT = os.environ.get("EXPORTS_RATE_LIMIT", "30 per hour")

# Cells that begin with these characters can be interpreted as formulas by
# Excel/LibreOffice/Numbers. Prefix with a single quote to neutralise.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize(value) -> str:
    """Stringify ``value`` and neutralise CSV-injection vectors."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in _FORMULA_PREFIXES:
        s = "'" + s
    return s


def _slug(value: str | None, fallback: str = "cafe") -> str:
    raw = (value or fallback).strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return cleaned[:40] or fallback


def _csv_response(filename: str, header: list[str], rows: Iterable[list]) -> Response:
    """Build a hardened CSV ``Response``.

    Wraps each cell with :func:`_sanitize`, enforces ``MAX_ROWS``, and emits
    ``no-store`` so customer PII isn't accidentally cached upstream.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    written = 0
    for row in rows:
        if written >= MAX_ROWS:
            writer.writerow(["…", f"truncated at {MAX_ROWS} rows; refine date range"])
            break
        writer.writerow([_sanitize(c) for c in row])
        written += 1
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename)[:120] or "export.csv"
    if not safe_name.lower().endswith(".csv"):
        safe_name += ".csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename={safe_name}",
            "Cache-Control": "no-store, private, max-age=0",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


def _cafe_slug() -> str:
    owner_id = logged_in_owner_id()
    owner = db.session.get(Owner, owner_id) if owner_id else None
    return _slug(getattr(owner, "cafe_name", None) or "cafe")


# ---------------------------------------------------------------------------
# Sales Dashboard CSV — daily revenue / orders / avg ticket
# ---------------------------------------------------------------------------

@bp.route("/owner/reports/sales-dashboard.csv")
@login_required
@limiter.limit(RATE_LIMIT)
def sales_dashboard_csv():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(
        request.args.get("start"), request.args.get("end"), default_days=30
    )
    bucket = func.date(Order.created_at)
    rows = (
        db.session.query(
            bucket.label("day"),
            func.count(Order.id).label("orders"),
            func.sum(Order.total).label("revenue"),
            func.sum(Order.tip).label("tips"),
        )
        .filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .group_by(bucket)
        .order_by(bucket.asc())
        .all()
    )

    def _gen():
        for r in rows:
            day = r.day.isoformat() if hasattr(r.day, "isoformat") else str(r.day)
            orders = int(r.orders or 0)
            revenue = round(safe_float(r.revenue), 2)
            tips = round(safe_float(r.tips), 2)
            avg = round(revenue / orders, 2) if orders else 0
            yield [day, orders, f"{revenue:.2f}", f"{tips:.2f}", f"{avg:.2f}"]

    filename = f"sales-{_cafe_slug()}-{start_dt.date()}_{end_dt.date()}.csv"
    return _csv_response(
        filename,
        ["date", "orders", "revenue", "tips", "avgTicket"],
        _gen(),
    )


# ---------------------------------------------------------------------------
# Menu Engineering CSV — popularity vs. profitability
# ---------------------------------------------------------------------------

@bp.route("/owner/reports/menu-engineering.csv")
@login_required
@limiter.limit(RATE_LIMIT)
def menu_engineering_csv():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(
        request.args.get("start"), request.args.get("end"), default_days=30
    )

    completed = (
        Order.query.filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .all()
    )

    by_item: dict[str, dict] = defaultdict(lambda: {
        "name": "", "qty": 0, "revenue": 0.0, "category": "",
    })
    for o in completed:
        items = o.items or []
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            iid = str(it.get("id") or it.get("name") or "")
            if not iid:
                continue
            qty = int(it.get("quantity", it.get("qty", 1)) or 1)
            price = safe_float(it.get("price"))
            rec = by_item[iid]
            rec["name"] = it.get("name") or rec["name"] or iid
            rec["category"] = it.get("category") or rec["category"]
            rec["qty"] += qty
            rec["revenue"] += price * qty

    if not by_item:
        return _csv_response(
            f"menu-engineering-{_cafe_slug()}-{start_dt.date()}_{end_dt.date()}.csv",
            ["item", "category", "quantity", "revenue", "share", "quadrant"],
            [],
        )

    total_qty = sum(r["qty"] for r in by_item.values()) or 1
    total_rev = sum(r["revenue"] for r in by_item.values()) or 1
    median_qty = sorted(r["qty"] for r in by_item.values())[len(by_item) // 2]
    median_rev = sorted(r["revenue"] for r in by_item.values())[len(by_item) // 2]

    def _quadrant(qty: int, rev: float) -> str:
        # Classic menu-engineering matrix.
        if qty >= median_qty and rev >= median_rev:
            return "star"
        if qty >= median_qty and rev < median_rev:
            return "plowhorse"
        if qty < median_qty and rev >= median_rev:
            return "puzzle"
        return "dog"

    def _gen():
        for rec in sorted(by_item.values(), key=lambda r: -r["revenue"]):
            yield [
                rec["name"],
                rec["category"] or "uncategorised",
                rec["qty"],
                f"{rec['revenue']:.2f}",
                f"{rec['revenue'] / total_rev * 100:.1f}%",
                _quadrant(rec["qty"], rec["revenue"]),
            ]

    return _csv_response(
        f"menu-engineering-{_cafe_slug()}-{start_dt.date()}_{end_dt.date()}.csv",
        ["item", "category", "quantity", "revenue", "share", "quadrant"],
        _gen(),
    )


# ---------------------------------------------------------------------------
# Customer LTV CSV
# ---------------------------------------------------------------------------

@bp.route("/owner/reports/ltv.csv")
@login_required
@limiter.limit(RATE_LIMIT)
def ltv_csv():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(
        request.args.get("start"), request.args.get("end"), default_days=365
    )
    rows = (
        Order.query.filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .order_by(Order.created_at.asc())
        .all()
    )

    by_customer: dict[str, dict] = defaultdict(lambda: {
        "name": "Guest", "email": "", "phone": "",
        "orders": 0, "revenue": 0.0,
        "first": None, "last": None,
    })
    for o in rows:
        email = (o.customer_email or "").strip().lower()
        phone = (o.customer_phone or "").strip()
        name = (o.customer_name or "Guest").strip() or "Guest"
        key = f"e:{email}" if email else (f"p:{phone}" if phone else f"n:{name.lower()}|t:{o.table_id or ''}")
        rec = by_customer[key]
        rec["name"] = name
        rec["email"] = email or rec["email"]
        rec["phone"] = phone or rec["phone"]
        rec["orders"] += 1
        rec["revenue"] += safe_float(o.total)
        ts = o.created_at
        if ts:
            if rec["first"] is None or ts < rec["first"]:
                rec["first"] = ts
            if rec["last"] is None or ts > rec["last"]:
                rec["last"] = ts

    now = datetime.now(timezone.utc)

    def _gen():
        for rec in sorted(by_customer.values(), key=lambda r: -r["revenue"]):
            avg = rec["revenue"] / rec["orders"] if rec["orders"] else 0
            days_active = ((rec["last"] - rec["first"]).days + 1) if (rec["first"] and rec["last"]) else 1
            monthly = (rec["revenue"] / days_active) * 30 if days_active else 0
            projected = monthly * 12
            since_last = (now - rec["last"]).days if rec["last"] else ""
            yield [
                rec["name"], rec["email"], rec["phone"],
                rec["orders"], f"{rec['revenue']:.2f}", f"{avg:.2f}",
                rec["first"].date().isoformat() if rec["first"] else "",
                rec["last"].date().isoformat() if rec["last"] else "",
                since_last,
                f"{projected:.2f}",
            ]

    return _csv_response(
        f"customer-ltv-{_cafe_slug()}-{start_dt.date()}_{end_dt.date()}.csv",
        ["name", "email", "phone", "orders", "revenue", "avgTicket",
         "firstSeen", "lastSeen", "daysSinceLastVisit", "projectedLtv"],
        _gen(),
    )


# ---------------------------------------------------------------------------
# Employee performance CSV
# ---------------------------------------------------------------------------

@bp.route("/owner/reports/employees-performance.csv")
@login_required
@limiter.limit(RATE_LIMIT)
def employees_performance_csv():
    owner_id = logged_in_owner_id()
    if not owner_id:
        abort(401)
    start_dt, end_dt = parse_date_range(
        request.args.get("start"), request.args.get("end"), default_days=30
    )

    emps = Employee.query.filter_by(owner_id=owner_id).all()
    base = {
        e.id: {"id": e.id, "name": e.name, "role": e.role,
               "orders": 0, "revenue": 0.0, "tips": 0.0, "items": 0}
        for e in emps
    }
    rows = (
        db.session.query(OrderEmployeeAssignment, Order)
        .join(Order, Order.id == OrderEmployeeAssignment.order_id)
        .filter(
            Order.owner_id == owner_id,
            Order.status == "completed",
            Order.created_at >= start_dt,
            Order.created_at <= end_dt,
        )
        .all()
    )
    for assn, order in rows:
        rec = base.get(assn.employee_id)
        if not rec:
            continue
        rec["orders"] += 1
        rec["revenue"] += safe_float(order.total)
        rec["tips"] += safe_float(order.tip)
        rec["items"] += len(order.items or [])

    def _gen():
        for rec in sorted(base.values(), key=lambda r: -r["revenue"]):
            avg = rec["revenue"] / rec["orders"] if rec["orders"] else 0
            tip_pct = (rec["tips"] / rec["revenue"] * 100) if rec["revenue"] else 0
            yield [
                rec["id"], rec["name"], rec["role"],
                rec["orders"], f"{rec['revenue']:.2f}", f"{rec['tips']:.2f}",
                rec["items"], f"{avg:.2f}", f"{tip_pct:.1f}%",
            ]

    return _csv_response(
        f"employee-performance-{_cafe_slug()}-{start_dt.date()}_{end_dt.date()}.csv",
        ["employeeId", "name", "role", "orders", "revenue", "tips",
         "itemsServed", "avgTicket", "tipPct"],
        _gen(),
    )
