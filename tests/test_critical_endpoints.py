"""Coverage-broadening smoke tests for the sidebar's "real" pages.

Each test seeds the minimum data needed and asserts:
  1. the endpoint exists,
  2. the auth gate works,
  3. the happy path returns a sensible status code.

We deliberately keep assertions broad (status-code ranges, JSON shape)
because the goal here is to catch *regressions* — a route disappearing,
a template crashing, an N+1 wrecking response time — not to pin down
every byte of the response. Pixel-perfect template tests live elsewhere.

Style notes:
  * Each test asks for its own seeded owner so a failure points at one
    test, not a chain.
  * Helpers from ``test_ops_and_exports`` are duplicated (not imported)
    so the two files can run independently in any order — pytest's
    collection order isn't always alphabetical.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Local helpers (intentionally duplicated — see module docstring).
# ---------------------------------------------------------------------------

def _login(app, client, *, username, email):
    import app as flask_app
    with app.app_context():
        existing = flask_app.Owner.query.filter_by(username=username).first()
        if existing:
            owner_id = existing.id
        else:
            owner = flask_app.Owner(
                username=username,
                email=email,
                password_hash=flask_app._make_password_hash("pw12345!"),
                cafe_name=f"{username} cafe",
                is_active=True,
            )
            flask_app.db.session.add(owner)
            flask_app.db.session.commit()
            owner_id = owner.id
    with client.session_transaction() as sess:
        sess["owner_id"] = owner_id
        sess["_user_id"] = str(owner_id)
        sess["_fresh"] = True
    return owner_id


# ---------------------------------------------------------------------------
# Auth gates: every owner page must reject anonymous traffic.
# ---------------------------------------------------------------------------

def test_owner_pages_require_auth(client):
    """Lock down every owner-only page in one go.

    Adding a new sidebar item should be a one-line addition to this
    list — not a forgotten security hole.
    """
    paths = [
        "/owner/dashboard",
        "/owner/inventory",
        "/owner/inventory/reorder-suggestions",
        "/owner/integrations",
        "/owner/integrations/checklist.json",
        "/owner/billing",
        "/owner/customers",
        "/owner/export/orders",
        "/owner/report/daily",
    ]
    for path in paths:
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (301, 302, 401, 403), \
            f"{path} returned {r.status_code} — unauth gate is broken"


# ---------------------------------------------------------------------------
# Inventory page renders for an authenticated owner.
# ---------------------------------------------------------------------------

def test_inventory_view_renders(app, client):
    import app as flask_app
    owner_id = _login(app, client, username="inv_owner", email="inv@x.com")
    with app.app_context():
        ing = flask_app.Ingredient(
            owner_id=owner_id, name="Milk", unit="L",
            stock=10, low_stock_threshold=2, qty_per_order=0.2,
            cost_per_unit=0.5,
        )
        flask_app.db.session.add(ing)
        flask_app.db.session.commit()
    r = client.get("/owner/inventory")
    assert r.status_code == 200
    assert b"Milk" in r.data or b"milk" in r.data.lower()


# ---------------------------------------------------------------------------
# Reorder suggestions: works even when the owner has no ingredients yet.
# ---------------------------------------------------------------------------

def test_reorder_suggestions_empty_inventory_is_ok(app, client):
    """A brand-new cafe with zero ingredients must not crash this page."""
    _login(app, client, username="reorder_empty",
           email="reorder_empty@x.com")
    r = client.get("/owner/inventory/reorder-suggestions")
    assert r.status_code == 200
    body = r.get_json()
    assert body and body["totalIngredients"] == 0
    assert body["suggestions"] == []
    assert body["estimatedReorderCost"] == 0


# ---------------------------------------------------------------------------
# Export — the empty-cafe edge case (was a 500 before the row-cap fix).
# ---------------------------------------------------------------------------

def test_orders_csv_empty_cafe(app, client):
    _login(app, client, username="csv_empty", email="csv_empty@x.com")
    r = client.get("/owner/export/orders")
    assert r.status_code == 200
    assert r.mimetype.startswith("text/csv")
    # Header row must always be present, even with zero data rows.
    first_line = r.data.decode("utf-8").splitlines()[0]
    assert "id" in first_line and "status" in first_line


# ---------------------------------------------------------------------------
# IP login lockout: cross-worker logic must work without Redis configured.
# ---------------------------------------------------------------------------

def test_ip_lockout_thresholds(app, monkeypatch):
    """5 failed attempts → locked out; clear() removes it."""
    import app as flask_app
    # Force the in-memory codepath so this test never depends on a live
    # Redis instance.
    monkeypatch.setattr(flask_app, "_failed_login_redis", lambda: None)
    ip = "203.0.113.42"  # TEST-NET-3
    flask_app._clear_failed_logins(ip)
    assert flask_app._is_ip_locked_out(ip) is False
    for _ in range(flask_app._MAX_FAIL_ATTEMPTS):
        flask_app._record_failed_login(ip)
    assert flask_app._is_ip_locked_out(ip) is True
    flask_app._clear_failed_logins(ip)
    assert flask_app._is_ip_locked_out(ip) is False


def test_ip_lockout_redis_path_uses_pipeline(app, monkeypatch):
    """When Redis is configured, INCR + EXPIRE(NX) must be issued atomically."""
    import app as flask_app

    calls = {"incr": 0, "expire": 0, "pipeline": 0}

    class _FakePipe:
        def __init__(self):
            self.ops = []
        def incr(self, key):
            calls["incr"] += 1
            self.ops.append(("incr", key))
            return self
        def expire(self, key, ttl, nx=False):
            calls["expire"] += 1
            self.ops.append(("expire", key, ttl, nx))
            return self
        def execute(self):
            return [1, True]

    class _FakeRedis:
        def pipeline(self):
            calls["pipeline"] += 1
            return _FakePipe()
        def get(self, key):
            return "0"
        def delete(self, key):
            return 1

    monkeypatch.setattr(flask_app, "_failed_login_redis", lambda: _FakeRedis())
    flask_app._record_failed_login("198.51.100.7")
    assert calls == {"incr": 1, "expire": 1, "pipeline": 1}


# ---------------------------------------------------------------------------
# Admin keys storage now uses portalocker via safe_read_json /
# atomic_write_json — verify it round-trips without losing rows.
# ---------------------------------------------------------------------------

def test_admin_keys_round_trip(app, tmp_path, monkeypatch):
    import app as flask_app
    fake_path = tmp_path / "admin_keys.json"
    monkeypatch.setattr(flask_app, "ADMIN_KEYS_PATH", fake_path)
    flask_app._save_admin_keys([
        {"owner_id": 1, "username": "alice", "key_hash": "h1"},
        {"owner_id": 2, "username": "bob",   "key_hash": "h2"},
    ])
    out = flask_app.load_admin_keys()
    assert {row["username"] for row in out} == {"alice", "bob"}
    # Empty list overwrite must work too — this caught a bug where the
    # empty case left the previous file in place.
    flask_app._save_admin_keys([])
    assert flask_app.load_admin_keys() == []


# ---------------------------------------------------------------------------
# Modular blueprints surface their main pages without crashing.
# ---------------------------------------------------------------------------

def test_sales_dashboard_owner_page(app, client):
    _login(app, client, username="sales_owner", email="sales@x.com")
    r = client.get("/owner/dashboard/sales", follow_redirects=False)
    # Either 200 (template renders) or 302 if the blueprint chooses to
    # redirect (e.g. to a default date range). Anything else is a regression.
    assert r.status_code in (200, 302)


def test_menu_engineering_owner_page(app, client):
    _login(app, client, username="me_owner", email="me@x.com")
    r = client.get("/owner/reports/menu-engineering", follow_redirects=False)
    assert r.status_code in (200, 302)


def test_employees_owner_page(app, client):
    _login(app, client, username="emp_owner", email="emp@x.com")
    r = client.get("/owner/employees", follow_redirects=False)
    assert r.status_code in (200, 302)


def test_customers_owner_page(app, client):
    _login(app, client, username="cust_owner", email="cust@x.com")
    r = client.get("/owner/customers", follow_redirects=False)
    assert r.status_code in (200, 302)


def test_tables_overview_owner_page(app, client):
    _login(app, client, username="tov_owner", email="tov@x.com")
    r = client.get("/owner/tables/overview", follow_redirects=False)
    assert r.status_code in (200, 302)


def test_ltv_owner_page(app, client):
    _login(app, client, username="ltv_owner", email="ltv@x.com")
    r = client.get("/owner/reports/ltv", follow_redirects=False)
    assert r.status_code in (200, 302)


# ---------------------------------------------------------------------------
# Ephemeral table state (notes / cleaning) survives a get-after-set,
# even on the in-memory codepath (no REDIS_URL).
# ---------------------------------------------------------------------------

def test_table_state_set_get_inmem(app, monkeypatch):
    from extensions import tables_overview_bp as tov
    monkeypatch.setattr(tov, "_table_state_redis", None)

    tov._set_note(99, "T7", "Birthday — slow service")
    assert tov._get_note(99, "T7") == "Birthday — slow service"
    tov._set_note(99, "T7", "")
    assert tov._get_note(99, "T7") == ""

    assert tov._is_cleaning(99, "T8") is False
    tov._set_cleaning(99, "T8", True)
    assert tov._is_cleaning(99, "T8") is True
    tov._set_cleaning(99, "T8", False)
    assert tov._is_cleaning(99, "T8") is False
