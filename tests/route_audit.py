"""Hit every endpoint as the appropriate role and report pass/fail.

This is an *audit* harness — it deliberately uses minimum-viable payloads
to exercise the perimeter (auth, CSRF, basic happy-path response). It is
not a substitute for unit tests of business logic. Run via:

    pytest tests/route_audit.py -v -s
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
from typing import Any

# Force a clean test environment BEFORE importing app
os.environ.setdefault("SECRET_KEY", "test-route-audit")
os.environ["DATABASE_URL"] = "sqlite:////tmp/cafe_audit.sqlite"
os.environ["SUPERADMIN_KEY"] = "audit-superadmin-key"
os.environ["RATELIMIT_ENABLED"] = "false"
# Wipe any old DB so the test starts clean
try:
    os.unlink("/tmp/cafe-ordering-audit.sqlite")
except OSError:
    pass

# Reset DB
try:
    os.unlink("/tmp/cafe_audit.sqlite")
except OSError:
    pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import (  # noqa: E402
    app, db, Owner, Order, CafeTable, Menu, Feedback,
    _make_password_hash, limiter,
)

# Disable CSRF + rate limiting in the test client
app.config["WTF_CSRF_ENABLED"] = False
app.config["TESTING"] = True
app.config["RATELIMIT_ENABLED"] = False
limiter.enabled = False


def _seed():
    """Set up: 1 real superadmin owner, 1 regular owner, 1 table+menu+order."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        sa = Owner(
            username="root",
            email="root@cafeportal.test",
            password_hash=_make_password_hash("RootPass1!"),
            cafe_name="HQ Cafe",
            is_active=True,
            is_superadmin=True,
        )
        ow = Owner(
            username="cafeowner",
            email="owner@cafeportal.test",
            password_hash=_make_password_hash("OwnerPass1!"),
            cafe_name="Main Street Brews",
            is_active=True,
            is_superadmin=False,
        )
        db.session.add_all([sa, ow])
        db.session.commit()
        sa_id, ow_id = sa.id, ow.id

        # A table + a menu (Menu is a single JSON-blob row per owner) + an order.
        # CafeTable's PK is `id` (text), referenced as table_id elsewhere.
        t = CafeTable(id="T1", owner_id=ow_id, name="Table 1")
        menu = Menu(owner_id=ow_id, data={
            "categories": [
                {"id": "coffee", "name": "Coffee", "ownerId": ow_id, "items": [
                    {"id": "m1", "name": "Espresso", "description": "Single shot",
                     "price": 120.0, "available": True},
                    {"id": "m2", "name": "Latte", "description": "With milk",
                     "price": 180.0, "available": True},
                ]},
            ],
        })
        db.session.add_all([t, menu])
        db.session.commit()
        o = Order(
            owner_id=ow_id,
            status="pending",
            total=120.0,
            items=[{"id": "m1", "name": "Espresso", "price": 120.0, "quantity": 1}],
            customer_name="Walk-in",
            table_id="T1",
        )
        db.session.add(o)
        db.session.commit()
        return {
            "superadmin_id": sa_id, "superadmin_username": "root",
            "owner_id": ow_id, "owner_username": "cafeowner",
            "table_id": "T1", "menu_item_id": "m1", "category_id": "coffee",
            "order_id": o.id,
        }


def _client_as(role: str, ctx: dict):
    """Return a logged-in test client for the requested role."""
    c = app.test_client()
    if role == "superadmin":
        with c.session_transaction() as s:
            s["owner_id"] = ctx["superadmin_id"]
            s["owner_username"] = ctx["superadmin_username"]
            s["_user_id"] = str(ctx["superadmin_id"])  # flask-login
            s["is_superadmin"] = True
            s["admin_authenticated"] = True
            s["admin_owner_id"] = ctx["superadmin_id"]
            s["superadmin_verified_at"] = time.time()
    elif role == "owner":
        with c.session_transaction() as s:
            s["owner_id"] = ctx["owner_id"]
            s["owner_username"] = ctx["owner_username"]
            s["_user_id"] = str(ctx["owner_id"])
    # customer = no session
    return c


# ---- Endpoint matrix --------------------------------------------------------
# (method, path_template, role, expected_status_set, payload_factory)
# expected_status: set of acceptable statuses (200, 302, 303, 400, 404 are all
# meaningful "the perimeter responded" answers; 5xx is always a bug).
TWO_HUNDRED_OR_REDIRECT = {200, 201, 202, 204, 301, 302, 303, 304}
OK_OR_NOT_FOUND = TWO_HUNDRED_OR_REDIRECT | {400, 404, 422}


def matrix(ctx):
    oid = ctx["order_id"]
    tid = ctx["table_id"]
    mid = ctx["menu_item_id"]
    cid = ctx["category_id"]
    own = ctx["owner_id"]

    return [
        # --- public / customer ----------------------------------------------
        ("GET", "/", "customer", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/health", "customer", {200}, None),
        ("GET", "/healthz", "customer", {200}, None),
        ("GET", "/ready", "customer", {200, 503}, None),
        ("GET", "/readyz", "customer", {200, 503}, None),
        ("GET", "/health/full", "customer", {200, 503}, None),
        ("GET", "/version", "customer", {200}, None),
        ("GET", "/metrics", "customer", {200}, None),
        ("GET", "/metrics/prom", "customer", {200}, None),
        ("GET", "/robots.txt", "customer", {200}, None),
        ("GET", "/.well-known/security.txt", "customer", {200}, None),
        ("GET", "/welcome", "customer", TWO_HUNDRED_OR_REDIRECT, None),
        ("POST", "/welcome/request-access", "customer", OK_OR_NOT_FOUND,
         lambda: {"name": "Test", "email": "x@y.com", "phone": "1234567890",
                  "cafe_name": "X", "city": "Y", "message": "hi"}),
        ("GET", f"/table/{tid}", "customer", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/api/menu", "customer", {200, 400}, None),
        ("POST", "/api/order-preview", "customer", OK_OR_NOT_FOUND,
         lambda: {"items": [{"id": mid, "quantity": 1}], "table_id": tid}),
        ("POST", "/api/checkout", "customer", OK_OR_NOT_FOUND,
         lambda: {"items": [{"id": mid, "quantity": 1}], "table_id": tid,
                  "customer_name": "Audit", "payment_method": "cash"}),
        ("GET", "/api/orders", "customer", {200, 400, 401, 403}, None),
        ("GET", f"/api/orders/{oid}", "customer", {200, 401, 403, 404}, None),
        ("POST", f"/api/orders/{oid}/cancel", "customer", OK_OR_NOT_FOUND | {401, 403}, lambda: {}),
        ("POST", "/api/feedback", "customer", OK_OR_NOT_FOUND,
         lambda: {"order_id": oid, "rating": 5, "comment": "good"}),
        ("GET", "/api/feedback/summary", "customer", {200, 400, 401, 403}, None),

        # --- owner login flow (no session) -----------------------------------
        ("GET", "/owner/login", "customer", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/signup", "customer", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/redeem-key", "customer", TWO_HUNDRED_OR_REDIRECT, None),

        # --- owner (logged in as regular owner) ------------------------------
        ("GET", "/owner/dashboard", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/profile", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/open", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", f"/owner/billing/orders/{oid}", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", f"/owner/billing/invoice/{oid}", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/eod", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/eod.csv", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/logs", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/settings", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/billing/payment-methods", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/aggregators", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/inventory", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/inventory/export", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/reorder", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/analytics", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/customers", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/export/orders", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/export/menu", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/menu/download", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/report/daily", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", f"/owner/order/{oid}/receipt", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", f"/owner/table/{tid}/bill", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", f"/owner/table/{tid}/qr", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/tables/qr-posters.zip", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/2fa/setup", "owner", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/owner/logout", "owner", TWO_HUNDRED_OR_REDIRECT, None),

        # owner POSTs (mutating, but harmless on isolated test DB)
        ("POST", f"/owner/order/{oid}/status", "owner", OK_OR_NOT_FOUND,
         lambda: {"status": "preparing"}),
        ("POST", "/owner/menu/category", "owner", OK_OR_NOT_FOUND,
         lambda: {"name": "Pastries"}),
        ("POST", "/owner/table", "owner", OK_OR_NOT_FOUND,
         lambda: {"name": "Table 2"}),

        # --- kitchen API (owner-authed) --------------------------------------
        ("GET", "/api/kitchen/orders", "owner", {200, 400, 401, 403}, None),
        ("GET", "/api/owner/analytics/day-orders", "owner", {200, 400, 401, 403}, None),
        # SSE streams skipped — they block forever

        # --- admin / superadmin ----------------------------------------------
        ("GET", "/admin/runtime", "superadmin", {200, 403}, None),
        ("GET", "/superadmin", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/leads", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/audit", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/audit.json", "superadmin", {200, 400}, None),
        ("GET", "/superadmin/audit.csv", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/devops", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/devops/aggregators", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/devops/schema", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/devops/schema.json", "superadmin", {200}, None),
        ("GET", "/superadmin/admin-keys", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/analytics", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),
        ("GET", "/superadmin/last-error", "superadmin", TWO_HUNDRED_OR_REDIRECT, None),

        # --- security perimeter (negative tests) -----------------------------
        ("GET", "/owner/dashboard", "customer", {302, 401, 403}, None),
        ("GET", "/superadmin", "customer", {302, 401, 403}, None),
        ("GET", "/superadmin", "owner", {302, 401, 403}, None),
        ("GET", "/admin/runtime", "customer", {302, 401, 403}, None),
        ("GET", "/admin/runtime", "owner", {302, 401, 403}, None),
    ]


def test_audit_every_endpoint():
    ctx = _seed()
    failures: list[str] = []
    passes = 0
    skipped = 0

    for method, path, role, expected, payload_fn in matrix(ctx):
        c = _client_as(role, ctx)
        payload = payload_fn() if payload_fn else None
        try:
            if method == "GET":
                resp = c.get(path, follow_redirects=False)
            elif method == "POST":
                if payload is not None and isinstance(payload, dict) and any(
                    k in path for k in ("/api/", "/checkout", "/order-preview", "/feedback", "/cancel")
                ):
                    resp = c.post(path, json=payload, follow_redirects=False)
                else:
                    resp = c.post(path, data=payload or {}, follow_redirects=False)
            else:
                skipped += 1
                continue
            status = resp.status_code
            if status in expected:
                passes += 1
                print(f"PASS [{role:10s}] {method:4s} {path:55s} -> {status}")
            else:
                body_snippet = resp.get_data(as_text=True)[:200].replace("\n", " ")
                failures.append(
                    f"FAIL [{role:10s}] {method:4s} {path:55s} -> {status}  body={body_snippet!r}"
                )
                print(failures[-1])
        except Exception as exc:  # noqa: BLE001
            failures.append(
                f"CRASH [{role:10s}] {method:4s} {path:55s} -> {type(exc).__name__}: {exc}"
            )
            print(failures[-1])

    print()
    print(f"=== AUDIT SUMMARY: {passes} passed, {len(failures)} failed, {skipped} skipped ===")
    if failures:
        print("\nFailures:")
        for f in failures:
            print(" ", f)
        # Don't `assert` — we want to *see* every failure, not stop at the first.
        # Pytest -v -s will print them; the test itself fails so CI knows.
        assert False, f"{len(failures)} endpoint(s) failed"


if __name__ == "__main__":
    test_audit_every_endpoint()
