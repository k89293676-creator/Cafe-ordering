"""Regression tests for the owner dashboard bug-fix batch.

Covers the 12-bug python-dev handoff:
  * GET /owner/dashboard renders 200 with the per-owner currency symbol
    and no dead ``href="#"`` navigation links (only intentional JS-toggle
    placeholders with ``onclick`` are allowed — those are not failed
    ``url_for`` fallbacks from ``_safe_url_for``).
  * GET /api/owner/analytics/day-orders?date=TODAY returns the
    ``{date, orders:[...], hours, totals}`` shape, excludes
    cancelled/voided, and honours the ``date`` param.
  * GET /api/v1/stats/today revenue excludes cancelled/voided and matches
    the dashboard's ``revenue_today`` logic (naive local-day start).

Each test seeds its own owner so failures point at one feature, and the
DB is the shared session-scoped SQLite file from conftest.
"""
from __future__ import annotations

import datetime as _dt
import re


# ---------------------------------------------------------------------------
# Helpers (duplicated, not imported, so this file runs standalone like
# test_critical_endpoints.py / test_ops_and_exports.py).
# ---------------------------------------------------------------------------

def _login(app, client, *, username, email, currency="gbp"):
    import app as flask_app
    with app.app_context():
        existing = flask_app.Owner.query.filter_by(username=username).first()
        if existing:
            # Keep currency deterministic for symbol assertions.
            if (existing.currency or "gbp").lower() != currency.lower():
                existing.currency = currency.lower()
                flask_app.db.session.commit()
            owner_id = existing.id
            symbol = existing.currencySymbol
        else:
            owner = flask_app.Owner(
                username=username,
                email=email,
                password_hash=flask_app._make_password_hash("pw12345!"),
                cafe_name=f"{username} cafe",
                is_active=True,
                currency=currency.lower(),
            )
            flask_app.db.session.add(owner)
            flask_app.db.session.commit()
            owner_id = owner.id
            symbol = owner.currencySymbol
    with client.session_transaction() as sess:
        sess["owner_id"] = owner_id
        sess["_user_id"] = str(owner_id)
        sess["_fresh"] = True
    return owner_id, symbol


def _seed_orders(app, owner_id, *, now=None):
    """Seed 2 valid today + 1 cancelled today + 1 old order.

    Returns (valid_total, cancelled_total) for revenue assertions.
    """
    import app as flask_app
    now = now or _dt.datetime.now()
    old = now - _dt.timedelta(days=2)
    with app.app_context():
        # Clear any prior orders for this owner so the test is repeatable
        # even when the session DB is reused across test files.
        flask_app.Order.query.filter_by(owner_id=owner_id).delete()
        flask_app.db.session.commit()
        rows = [
            flask_app.Order(
                owner_id=owner_id, status="completed", total=100.0,
                items=[{"id": "m1", "name": "Espresso",
                        "price": 100.0, "quantity": 1}],
                customer_name="Valid-A", table_id="T1", created_at=now,
            ),
            flask_app.Order(
                owner_id=owner_id, status="pending", total=50.0,
                items=[], customer_name="Valid-B", table_id="T1",
                created_at=now,
            ),
            flask_app.Order(
                owner_id=owner_id, status="cancelled", total=999.0,
                items=[], customer_name="Cancelled-C", table_id="T1",
                created_at=now,
            ),
            flask_app.Order(
                owner_id=owner_id, status="completed", total=777.0,
                items=[], customer_name="Old-D", table_id="T1",
                created_at=old,
            ),
        ]
        for r in rows:
            flask_app.db.session.add(r)
        flask_app.db.session.commit()
    return 150.0, 999.0


# ---------------------------------------------------------------------------
# 1. Dashboard renders with currency symbol and no dead links.
# ---------------------------------------------------------------------------

def test_owner_dashboard_renders_with_currency_symbol(app, client):
    owner_id, symbol = _login(
        app, client, username="dash_reg_owner",
        email="dash_reg@x.com", currency="gbp")
    assert symbol == "£"

    r = client.get("/owner/dashboard")
    assert r.status_code == 200, r.data[:500]
    html = r.data.decode("utf-8", errors="replace")

    # Per-owner currency symbol must be rendered (KPI cards use it).
    assert symbol in html, "dashboard missing per-owner currency symbol"
    # Formatted revenue KPI uses the symbol too (e.g. £0.00 on empty cafe).
    assert "£" in html

    # No dead href="#" navigation links: the only allowed href="#" anchors
    # are intentional JS toggles that carry an onclick handler (e.g. the
    # "Reviews coming soon" placeholder). A bare href="#" without onclick
    # means _safe_url_for failed to resolve an endpoint — the regression
    # the alias batch fixed.
    dead = []
    for m in re.finditer(r'<a[^>]*href="#"[^>]*>', html):
        tag = m.group(0)
        if "onclick" not in tag:
            dead.append(tag[:200])
    assert not dead, f"dashboard has dead href='#' links: {dead!r}"

    # Key sidebar destinations must resolve to real URLs (not "#").
    for needle in ("/owner/dashboard", "/owner/tables",
                   "/owner/menu", "/owner/billing"):
        assert needle in html, f"dashboard missing nav link {needle}"


def test_owner_dashboard_requires_auth(client):
    r = client.get("/owner/dashboard", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


# ---------------------------------------------------------------------------
# 2. Day-orders drill-down shape.
# ---------------------------------------------------------------------------

def test_day_orders_returns_orders_shape(app, client):
    owner_id, _sym = _login(
        app, client, username="dayorders_reg_owner",
        email="dayorders_reg@x.com")
    valid_total, _cancelled = _seed_orders(app, owner_id)

    today = _dt.date.today().isoformat()
    r = client.get(f"/api/owner/analytics/day-orders?date={today}")
    assert r.status_code == 200, r.data[:500]
    body = r.get_json()
    assert body is not None
    assert body.get("date") == today
    assert isinstance(body.get("orders"), list)
    assert isinstance(body.get("hours"), list) and len(body["hours"]) == 24
    assert isinstance(body.get("totals"), dict)

    # Cancelled orders excluded → exactly the 2 valid today orders.
    assert len(body["orders"]) == 2, body
    for o in body["orders"]:
        assert "id" in o and "total" in o and "status" in o
        assert o["status"] not in ("cancelled", "voided")
        # Drill-down contract: both camelCase and snake_case aliases.
        assert o.get("createdAt") and o.get("created_at")
        assert o.get("created_at") == o.get("createdAt")
        assert ("table" in o) and ("tableName" in o or "tableId" in o)

    totals = body["totals"]
    assert totals["orders"] == 2
    assert abs(float(totals["revenue"]) - valid_total) < 0.01
    # Per-hour buckets must sum back to the totals.
    assert sum(h["orders"] for h in body["hours"]) == totals["orders"]
    assert abs(sum(float(h["revenue"]) for h in body["hours"])
               - float(totals["revenue"])) < 0.01


def test_day_orders_rejects_bad_date(app, client):
    _login(app, client, username="dayorders_baddate",
           email="dayorders_baddate@x.com")
    r = client.get("/api/owner/analytics/day-orders?date=not-a-date")
    assert r.status_code == 400
    assert "Invalid date" in (r.get_json() or {}).get("error", "")


def test_day_orders_requires_auth(client):
    r = client.get("/api/owner/analytics/day-orders",
                   follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


# ---------------------------------------------------------------------------
# 3. /api/v1/stats/today revenue excludes cancelled + matches dashboard.
# ---------------------------------------------------------------------------

def test_stats_today_revenue_excludes_cancelled(app, client):
    owner_id, symbol = _login(
        app, client, username="stats_reg_owner",
        email="stats_reg@x.com", currency="gbp")
    valid_total, cancelled_total = _seed_orders(app, owner_id)

    r = client.get("/api/v1/stats/today")
    assert r.status_code == 200, r.data[:500]
    body = r.get_json()
    assert body is not None
    for key in ("orders", "revenue", "pending", "avg_order",
                "currency", "currency_symbol"):
        assert key in body, f"stats/today missing key: {key}"

    # Revenue excludes the £999 cancelled order (and the old £777 order).
    assert abs(float(body["revenue"]) - valid_total) < 0.01
    assert float(body["revenue"]) != pytest_approx_including_cancelled(
        valid_total, cancelled_total)
    assert body["currency"] == "gbp"
    assert body["currency_symbol"] == symbol == "£"
    # avg_order = revenue / non-cancelled-today count (2 orders → 75.0).
    assert body["avg_order"] == round(valid_total / 2, 2)

    # Dashboard must render the SAME revenue figure (same "today" definition
    # + same cancelled/voided exclusion on both sides).
    dash = client.get("/owner/dashboard")
    assert dash.status_code == 200
    html = dash.data.decode("utf-8", errors="replace")
    expected = f"{symbol}{valid_total:.2f}"
    assert expected in html, (
        f"dashboard HTML missing revenue {expected!r} — "
        "dashboard/API today-revenue logic diverged")


def pytest_approx_including_cancelled(valid, cancelled):
    """Helper: revenue value we must NOT see (i.e. bug if cancelled added)."""
    return valid + cancelled


def test_stats_today_requires_auth(client):
    r = client.get("/api/v1/stats/today")
    assert r.status_code in (401, 403)
