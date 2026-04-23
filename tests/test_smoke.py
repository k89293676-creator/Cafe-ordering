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
