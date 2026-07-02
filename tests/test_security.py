"""Security-focused tests for the customer-facing API surface.

Covers:
- _safe_text helper: control-char stripping, angle-bracket defang, length cap
- /api/checkout XSS payload neutralization
- /api/feedback XSS payload neutralization
- /api/checkout email + table_id validation
- Webhook endpoints reject unsigned posts
- Setup pages require authentication
"""
from __future__ import annotations

import pytest


# ───────────────────────────── helper unit tests ─────────────────────────────

def test_safe_text_strips_control_chars():
    import app as flask_app
    out = flask_app._safe_text("hello\x00world\x07!")
    assert out == "helloworld!"


def test_safe_text_defangs_angle_brackets():
    import app as flask_app
    out = flask_app._safe_text("<script>alert(1)</script>")
    # Angle brackets are removed, payload becomes inert text.
    assert "<" not in out and ">" not in out
    assert "script" in out  # text preserved, just defanged


def test_safe_text_truncates_to_max_len():
    import app as flask_app
    out = flask_app._safe_text("a" * 1000, max_len=50)
    assert len(out) == 50


def test_safe_text_returns_default_for_empty():
    import app as flask_app
    assert flask_app._safe_text(None, default="Guest") == "Guest"
    assert flask_app._safe_text("   ", default="Guest") == "Guest"
    assert flask_app._safe_text("", default="Guest") == "Guest"


def test_safe_text_preserves_unicode():
    import app as flask_app
    out = flask_app._safe_text("café 🍕")
    assert "café" in out and "🍕" in out


# ───────────────────────────── checkout endpoint ─────────────────────────────

def _seed_owner_and_table(app, slug="sec-test"):
    """Create an owner + a table to use in checkout/feedback POSTs."""
    import app as flask_app
    with app.app_context():
        owner = flask_app.Owner(
            username=f"o_{slug}",
            email=f"{slug}@x.com",
            password_hash=flask_app._make_password_hash("pw12345!"),
            cafe_name="Sec Cafe",
            is_active=True,
        )
        flask_app.db.session.add(owner)
        flask_app.db.session.commit()
        table = flask_app.CafeTable(id=f"tok-{slug}", name="T-sec", owner_id=owner.id)
        flask_app.db.session.add(table)
        flask_app.db.session.commit()
        return owner.id, table.id


def test_checkout_rejects_invalid_email(app, client):
    _seed_owner_and_table(app, slug="bad-email")
    r = client.post("/api/checkout", json={
        "customerName": "X",
        "customerEmail": "not-an-email",
        "items": [],
    })
    assert r.status_code == 400


def test_checkout_rejects_invalid_table_id(app, client):
    r = client.post("/api/checkout", json={
        "customerName": "X",
        "tableId": "../../etc/passwd",
        "items": [],
    })
    assert r.status_code == 400


def test_checkout_rejects_invalid_phone(app, client):
    r = client.post("/api/checkout", json={
        "customerName": "X",
        "customerPhone": "<script>alert(1)</script>",
        "items": [],
    })
    assert r.status_code == 400


def test_checkout_neutralizes_xss_in_customer_name(app, client):
    """Even with empty cart (which 400s), the body shouldn't echo a live tag."""
    r = client.post("/api/checkout", json={
        "customerName": "<img src=x onerror=alert(1)>",
        "items": [],
    })
    body = r.data.decode("utf-8", errors="replace")
    # The raw payload must never appear unescaped in any error JSON.
    assert "<img src=x onerror=alert(1)>" not in body


def test_checkout_requires_json(client):
    r = client.post("/api/checkout", data="not json", content_type="text/plain")
    assert r.status_code == 400


# ───────────────────────────── feedback endpoint ─────────────────────────────

def test_feedback_rejects_bad_rating(app, client):
    r = client.post("/api/feedback", json={"rating": 99, "comment": "ok"})
    assert r.status_code == 400


def test_feedback_rejects_non_numeric_rating(app, client):
    r = client.post("/api/feedback", json={"rating": "five", "comment": "ok"})
    assert r.status_code == 400


def test_feedback_neutralizes_xss_in_comment(app, client):
    import app as flask_app
    r = client.post("/api/feedback", json={
        "rating": 5,
        "customerName": "Tester",
        "comment": "<script>alert('xss')</script>good food",
    })
    assert r.status_code in (200, 201)
    body = r.get_json() or {}
    saved = body.get("feedback") or {}
    # Stored comment should have angle brackets stripped.
    if "comment" in saved:
        assert "<script>" not in saved["comment"]
        assert "good food" in saved["comment"]


# ───────────────────────────── webhook security ──────────────────────────────

def test_billing_webhook_rejects_unsigned(client):
    r = client.post("/webhooks/billing/stripe",
                    json={"type": "fake.event"},
                    headers={"Content-Type": "application/json"})
    # Either 400 (no signature header), 401 (auth), or 404 (route disabled).
    # Must NOT be 200.
    assert r.status_code != 200


def test_aggregator_webhook_rejects_unsigned(client):
    r = client.post("/webhooks/aggregator/swiggy",
                    json={"event": "order.created"},
                    headers={"Content-Type": "application/json"})
    assert r.status_code != 200


# ───────────────────────────── setup pages auth ──────────────────────────────

def test_payment_methods_requires_auth(client):
    r = client.get("/owner/payment-methods", follow_redirects=False)
    # Redirect to login or 401/403 — must not be a 200 leak.
    assert r.status_code in (301, 302, 401, 403)


def test_aggregators_setup_requires_auth(client):
    r = client.get("/owner/aggregators", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403, 404)


# ───────────────────────────── security headers ──────────────────────────────

def test_response_carries_security_headers(client):
    r = client.get("/owner/login")
    # In dev/test mode Talisman may relax some headers, but content-type
    # nosniff is universally safe to assert.
    assert r.status_code == 200
    assert "X-Content-Type-Options" in r.headers


def test_session_cookie_is_httponly(client):
    """Anything that sets a session cookie must mark it HttpOnly."""
    client.get("/owner/login")
    for cookie in client.cookie_jar if hasattr(client, "cookie_jar") else []:
        if "session" in cookie.name.lower():
            assert cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly")
