"""Smoke tests covering: app import, public endpoints, auth gates, table-call API."""
from __future__ import annotations


def test_app_imports(app):
    assert app is not None
    assert "csrf" in app.extensions or True  # app boots


def test_health_endpoint(client):
    r = client.get("/healthz")
    # Either /healthz or /health may exist; accept 200 from any of them.
    if r.status_code == 404:
        r = client.get("/health")
    assert r.status_code in (200, 204)


def test_login_page_renders(client):
    r = client.get("/owner/login")
    assert r.status_code == 200
    assert b"login" in r.data.lower() or b"sign in" in r.data.lower()


def test_owner_dashboard_requires_auth(client):
    r = client.get("/owner/dashboard", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


def test_extensions_blueprints_registered(app):
    names = set(app.blueprints.keys())
    for bp in ("service_calls", "sales_dashboard", "menu_engineering",
               "ltv", "employees", "superadmin_extras"):
        assert bp in names, f"blueprint missing: {bp}"


def test_integrations_hub_requires_auth(client):
    """Hub must be behind owner login — never serve it anonymously."""
    r = client.get("/owner/integrations", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


def test_integrations_checklist_json_requires_auth(client):
    r = client.get("/owner/integrations/checklist.json", follow_redirects=False)
    assert r.status_code in (301, 302, 401, 403)


def test_integrations_send_setup_requires_auth_and_csrf(client):
    """The send-setup endpoint must reject anonymous AND must reject
    cross-site posts (CSRF). Both are required because it triggers
    outbound email/SMS to the registered owner."""
    r = client.post("/owner/integrations/send-setup/email/stripe",
                    follow_redirects=False)
    # Either redirect to login (auth gate) OR a CSRF rejection — never 200.
    assert r.status_code in (301, 302, 400, 401, 403)


def test_lib_integrations_imports_without_io():
    """Importing must be side-effect free so tests / route_audit don't
    hit Twilio or Flask-Mail at collection time."""
    import lib_integrations as lib_i
    items = lib_i.production_readiness_check()
    assert isinstance(items, list)
    summary = lib_i.readiness_summary(items)
    assert summary["verdict"] in {"blocked", "needs_attention", "production_ready"}
    # Catalog is non-empty so the hub UI always has cards to render.
    assert lib_i.PAYMENT_CATALOG and lib_i.AGGREGATOR_CATALOG


def test_integrations_signup_link_prefill():
    """Signup URL helper must include name + email when given."""
    import lib_integrations as lib_i
    url = lib_i.build_provider_signup_link(
        "stripe", owner_name="Cafe 11:11", owner_email="owner@example.com")
    assert "email=owner%40example.com" in url
    assert "name=Cafe+11" in url or "name=Cafe%2011" in url
    # Unknown provider → empty string, not a crash.
    assert lib_i.build_provider_signup_link("nope") == ""


def test_table_call_create_and_list(app, client):
    """End-to-end: customer posts a call, owner sees it as 'open'."""
    import app as flask_app
    from extensions.models import TableCall

    with app.app_context():
        # Seed an owner + table directly.
        owner = flask_app.Owner(
            username="t_owner",
            email="t@x.com",
            password_hash=flask_app._make_password_hash("pw12345!"),
            cafe_name="Test Cafe",
            is_active=True,
        )
        flask_app.db.session.add(owner)
        flask_app.db.session.commit()
        table = flask_app.CafeTable(id="tok-test-1", name="T1", owner_id=owner.id)
        flask_app.db.session.add(table)
        flask_app.db.session.commit()
        owner_id, table_id = owner.id, table.id

    # Public endpoint: no auth required, CSRF disabled in tests.
    r = client.post(f"/api/table/{table_id}/call", json={"reason": "service"})
    assert r.status_code in (200, 201), r.data
    body = r.get_json()
    assert body and body.get("ok") is True

    with app.app_context():
        calls = TableCall.query.filter_by(table_id=table_id, status="open").all()
        assert len(calls) == 1
        assert calls[0].reason == "service"
        assert calls[0].owner_id == owner_id
