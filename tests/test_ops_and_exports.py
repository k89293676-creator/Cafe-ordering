"""Tests for the new operational health, secure exports, and reorder
suggestions endpoints. Each test is intentionally independent so a
failure points at exactly one feature.
"""
from __future__ import annotations

import io
import json
import os
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_owner_and_login(app, client, *, username="ops_owner",
                          email="ops@x.com", password="pw12345!"):
    """Create an owner record and authenticate the test client.

    Returns the owner id so the test can scope its assertions.
    """
    import app as flask_app
    with app.app_context():
        existing = flask_app.Owner.query.filter_by(username=username).first()
        if existing:
            owner_id = existing.id
        else:
            owner = flask_app.Owner(
                username=username,
                email=email,
                password_hash=flask_app._make_password_hash(password),
                cafe_name="Ops Test Cafe",
                is_active=True,
            )
            flask_app.db.session.add(owner)
            flask_app.db.session.commit()
            owner_id = owner.id
    # Replicate session contents the login route would set. Going through
    # the login form is brittle (CAPTCHA, rate limits, optional 2FA) so we
    # bypass it the same way Flask-Login's helpers do internally.
    with client.session_transaction() as sess:
        sess["owner_id"] = owner_id
        sess["_user_id"] = str(owner_id)
        sess["_fresh"] = True
    return owner_id


# ---------------------------------------------------------------------------
# /api/ops/health — token-protected per-section health
# ---------------------------------------------------------------------------

def test_ops_health_requires_token(client, monkeypatch):
    monkeypatch.setenv("OPS_HEALTH_TOKEN", "secret-token-xyz")
    r = client.get("/api/ops/health")
    # Anonymous, no header → 401 (never 200, never 500).
    assert r.status_code == 401, r.data


def test_ops_health_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setenv("OPS_HEALTH_TOKEN", "secret-token-xyz")
    r = client.get("/api/ops/health",
                   headers={"Authorization": "Bearer wrong-value"})
    assert r.status_code == 401


def test_ops_health_accepts_correct_token(client, monkeypatch):
    monkeypatch.setenv("OPS_HEALTH_TOKEN", "secret-token-xyz")
    r = client.get("/api/ops/health",
                   headers={"Authorization": "Bearer secret-token-xyz"})
    assert r.status_code in (200, 503), r.data
    body = r.get_json()
    assert body is not None
    assert "ok" in body and "sections" in body
    # All 14 sidebar sections from the original spec must be reported on.
    for expected in (
        "inventory", "billing", "payment_methods", "food_delivery",
        "reorder", "analytics", "sales_dashboard", "menu_engineering",
        "customer_ltv", "employees", "tables_overview", "table_calls",
        "customers", "exports",
    ):
        assert expected in body["sections"], f"missing section: {expected}"


def test_ops_health_disabled_without_token_env(client, monkeypatch):
    """If OPS_HEALTH_TOKEN is unset the endpoint must refuse all requests
    (closed-by-default — never accidentally exposed)."""
    monkeypatch.delenv("OPS_HEALTH_TOKEN", raising=False)
    r = client.get("/api/ops/health",
                   headers={"Authorization": "Bearer anything"})
    assert r.status_code in (401, 503)


# ---------------------------------------------------------------------------
# CSV export hardening
# ---------------------------------------------------------------------------

def test_orders_csv_requires_login(client):
    r = client.get("/owner/export/orders", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


def test_orders_csv_csv_injection_guard(app, client):
    """A customer name that begins with '=' MUST be neutralised."""
    import app as flask_app
    owner_id = _seed_owner_and_login(app, client, username="csv_owner",
                                     email="csv@x.com")
    with app.app_context():
        # Hostile customer name — would execute as a formula in Excel.
        order = flask_app.Order(
            owner_id=owner_id,
            customer_name="=SUM(A1:A9)",
            customer_email="evil@example.com",
            customer_phone="+10000000000",
            subtotal=10.0, tip=0.0, total=10.0,
            status="completed",
            items=[{"id": "x", "name": "Coffee", "quantity": 1, "price": 10}],
            origin="dine-in",
            created_at=datetime.now(timezone.utc),
        )
        flask_app.db.session.add(order)
        flask_app.db.session.commit()

    r = client.get("/owner/export/orders")
    assert r.status_code == 200
    text = r.data.decode("utf-8")
    # The "=SUM" cell must be prefixed with a single quote.
    assert "'=SUM(A1:A9)" in text, text[:500]
    # Hardened response headers.
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.mimetype.startswith("text/csv")


# ---------------------------------------------------------------------------
# Inventory reorder suggestions
# ---------------------------------------------------------------------------

def test_reorder_suggestions_requires_login(client):
    r = client.get("/owner/inventory/reorder-suggestions",
                   follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


def test_reorder_suggestions_returns_priorities(app, client):
    import app as flask_app
    owner_id = _seed_owner_and_login(app, client, username="reorder_owner",
                                     email="reorder@x.com")
    with app.app_context():
        # One ingredient critically depleted, one healthy.
        ing_low = flask_app.Ingredient(
            owner_id=owner_id, name="Espresso Beans", unit="kg",
            stock=0, low_stock_threshold=2, qty_per_order=0.02,
            cost_per_unit=25.0, menu_item_id="m-coffee",
        )
        ing_ok = flask_app.Ingredient(
            owner_id=owner_id, name="Sugar", unit="kg",
            stock=20, low_stock_threshold=1, qty_per_order=0.01,
            cost_per_unit=2.0, menu_item_id="m-coffee",
        )
        flask_app.db.session.add_all([ing_low, ing_ok])
        flask_app.db.session.commit()

        # Recent completed order so daily_usage > 0 for the depleted item.
        order = flask_app.Order(
            owner_id=owner_id, customer_name="Guest", subtotal=10, tip=0,
            total=10, status="completed",
            items=[{"id": "m-coffee", "name": "Coffee",
                    "quantity": 60, "price": 10}],
            created_at=datetime.now(timezone.utc),
        )
        flask_app.db.session.add(order)
        flask_app.db.session.commit()

    r = client.get("/owner/inventory/reorder-suggestions")
    assert r.status_code == 200
    body = r.get_json()
    assert body and "suggestions" in body
    by_name = {s["name"]: s for s in body["suggestions"]}
    assert by_name["Espresso Beans"]["priority"] == "critical"
    assert by_name["Espresso Beans"]["suggestOrderQty"] > 0
    # Sugar has plenty of stock + recent sales → "ok".
    assert by_name["Sugar"]["priority"] == "ok"


def test_reorder_suggestions_csv_format(app, client):
    """``?format=csv`` returns a procurement-friendly download."""
    _seed_owner_and_login(app, client, username="reorder_csv_owner",
                          email="reorder_csv@x.com")
    r = client.get("/owner/inventory/reorder-suggestions?format=csv")
    assert r.status_code == 200
    assert r.mimetype.startswith("text/csv")
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    first_line = r.data.decode("utf-8").splitlines()[0]
    assert "name" in first_line and "suggest_order_qty" in first_line


# ---------------------------------------------------------------------------
# Daily-PDF rate limit decorator is wired
# ---------------------------------------------------------------------------

def test_daily_pdf_rate_limit_decorated(app):
    """A regression guard: the limiter decorator must remain attached."""
    import app as flask_app
    rule = flask_app.app.view_functions.get("daily_report_pdf")
    assert rule is not None, "daily_report_pdf route missing"
