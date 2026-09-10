"""Regression tests for the owner menu JSON upload fix (python-dev handoff).

Covers ``app/web/owner_menu.py`` import + export hardening:
  * valid JSON import -> 302 + menu saved, categories/items present
  * BOM (utf-8-sig) JSON import succeeds
  * non-JSON file rejected with "Only JSON"
  * invalid schema (categories not list) rejected, no corrupt save
  * duplicate item IDs deduped (stored ids unique)
  * export CSV has no-store header + injection cells sanitized

Each test seeds its own owner so failures point at one feature, and the
DB is the shared session-scoped SQLite file from conftest.
"""
from __future__ import annotations

import io
import json


# ---------------------------------------------------------------------------
# Helpers (duplicated, not imported, so this file runs standalone like
# test_owner_dashboard.py / test_critical_endpoints.py).
# ---------------------------------------------------------------------------

def _login(app, client, *, username, email, currency="gbp"):
    import app as flask_app
    with app.app_context():
        existing = flask_app.Owner.query.filter_by(username=username).first()
        if existing:
            if (existing.currency or "gbp").lower() != currency.lower():
                existing.currency = currency.lower()
                flask_app.db.session.commit()
            owner_id = existing.id
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
    with client.session_transaction() as sess:
        sess["owner_id"] = owner_id
        sess["_user_id"] = str(owner_id)
        sess["_fresh"] = True
    return owner_id


def _post_menu_file(client, payload_bytes, filename="menu.json",
                    mimetype="application/json", follow=False):
    data = {
        "menu_file": (io.BytesIO(payload_bytes), filename, mimetype),
    }
    return client.post(
        "/owner/menu/import",
        data=data,
        content_type="multipart/form-data",
        follow_redirects=follow,
    )


def _load_menu(app, owner_id):
    import app as flask_app
    with app.app_context():
        return flask_app.load_owner_menu(owner_id)


def _save_menu(app, owner_id, menu):
    import app as flask_app
    with app.app_context():
        flask_app.save_owner_menu(owner_id, menu)


# ---------------------------------------------------------------------------
# 1. Valid JSON import -> 302 + menu saved.
# ---------------------------------------------------------------------------

def test_valid_json_import_saves_menu(app, client):
    owner_id = _login(
        app, client, username="menu_valid_owner",
        email="menu_valid@x.com")
    # Start clean so the assertion proves the import wrote the menu.
    _save_menu(app, owner_id, {"categories": []})

    payload = {
        "categories": [
            {
                "id": "cat-1",
                "name": "Drinks",
                "items": [
                    {"id": "item-1", "name": "Espresso", "price": 2.5,
                     "description": "Strong coffee", "available": True},
                    {"id": "item-2", "name": "Latte", "price": 3.0,
                     "description": "", "available": False},
                ],
            },
            {
                "id": "cat-2",
                "name": "Food",
                "items": [
                    {"id": "item-3", "name": "Croissant", "price": 1.75,
                     "description": "Buttery", "available": True},
                ],
            },
        ]
    }
    r = _post_menu_file(
        client, json.dumps(payload).encode("utf-8"), follow=False)
    assert r.status_code == 302, r.data[:500]
    assert "/owner/menu" in r.headers.get("Location", "")

    menu = _load_menu(app, owner_id)
    assert isinstance(menu.get("categories"), list)
    assert len(menu["categories"]) == 2
    names = [c.get("name") for c in menu["categories"]]
    assert "Drinks" in names and "Food" in names
    drinks = next(c for c in menu["categories"] if c.get("name") == "Drinks")
    assert len(drinks.get("items", [])) == 2
    item_names = {i.get("name") for i in drinks["items"]}
    assert item_names == {"Espresso", "Latte"}


# ---------------------------------------------------------------------------
# 2. BOM (utf-8-sig) JSON import succeeds.
# ---------------------------------------------------------------------------

def test_bom_json_import_succeeds(app, client):
    owner_id = _login(
        app, client, username="menu_bom_owner",
        email="menu_bom@x.com")
    _save_menu(app, owner_id, {"categories": []})

    payload = {
        "categories": [
            {
                "id": "cat-bom",
                "name": "BOM Drinks",
                "items": [
                    {"id": "bom-item-1", "name": "Flat White",
                     "price": 3.5, "description": "Smooth",
                     "available": True},
                ],
            }
        ]
    }
    raw = b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8")
    r = _post_menu_file(client, raw, follow=False)
    assert r.status_code == 302, r.data[:500]

    menu = _load_menu(app, owner_id)
    assert len(menu.get("categories", [])) == 1
    assert menu["categories"][0].get("name") == "BOM Drinks"
    assert menu["categories"][0]["items"][0].get("name") == "Flat White"


# ---------------------------------------------------------------------------
# 3. Non-JSON file rejected with "Only JSON".
# ---------------------------------------------------------------------------

def test_non_json_file_rejected_with_only_json(app, client):
    owner_id = _login(
        app, client, username="menu_nonjson_owner",
        email="menu_nonjson@x.com")
    _save_menu(app, owner_id, {"categories": []})

    # Minimal valid PNG so magic-byte validation passes as "image",
    # which the import route must then reject with "Only JSON".
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    r = _post_menu_file(
        client, png_bytes, filename="evil.png",
        mimetype="image/png", follow=True)
    assert r.status_code == 200, r.data[:500]
    assert b"Only JSON" in r.data, r.data[:1000]

    menu = _load_menu(app, owner_id)
    assert menu.get("categories") == []


# ---------------------------------------------------------------------------
# 4. Invalid schema (categories not list) rejected, no corrupt save.
# ---------------------------------------------------------------------------

def test_invalid_schema_rejected_no_corrupt_save(app, client):
    owner_id = _login(
        app, client, username="menu_badschema_owner",
        email="menu_badschema@x.com")
    good = {
        "categories": [
            {"id": "keep-cat", "name": "KeepMe", "items": [
                {"id": "keep-item", "name": "KeepItem", "price": 1.0,
                 "description": "", "available": True},
            ]},
        ]
    }
    _save_menu(app, owner_id, good)

    bad = json.dumps({"categories": "not-a-list"}).encode("utf-8")
    r = _post_menu_file(client, bad, follow=True)
    assert r.status_code == 200, r.data[:500]
    assert b"Invalid menu JSON" in r.data, r.data[:1000]

    menu = _load_menu(app, owner_id)
    # Must NOT have saved the corrupt blob.
    assert isinstance(menu.get("categories"), list), menu
    assert len(menu["categories"]) == 1
    assert menu["categories"][0].get("name") == "KeepMe"


# ---------------------------------------------------------------------------
# 5. Duplicate item IDs deduped (stored ids unique).
# ---------------------------------------------------------------------------

def test_duplicate_item_ids_deduped(app, client):
    owner_id = _login(
        app, client, username="menu_dedupe_owner",
        email="menu_dedupe@x.com")
    _save_menu(app, owner_id, {"categories": []})

    payload = {
        "categories": [
            {
                "id": "cat-dup",
                "name": "DupCat",
                "items": [
                    {"id": "dup-id", "name": "Item A", "price": 1.0,
                     "description": "", "available": True},
                    {"id": "dup-id", "name": "Item B", "price": 2.0,
                     "description": "", "available": True},
                ],
            }
        ]
    }
    r = _post_menu_file(
        client, json.dumps(payload).encode("utf-8"), follow=False)
    assert r.status_code == 302, r.data[:500]

    menu = _load_menu(app, owner_id)
    ids = [
        item.get("id")
        for cat in menu.get("categories", [])
        for item in cat.get("items", [])
    ]
    assert len(ids) == 2, menu
    assert len(set(ids)) == 2, f"duplicate ids not deduped: {ids!r}"
    # At most one row may keep the colliding id; the other is regenerated.
    assert ids.count("dup-id") <= 1


# ---------------------------------------------------------------------------
# 6. Export CSV has no-store header + injection cells sanitized.
# ---------------------------------------------------------------------------

def test_export_csv_no_store_and_injection_sanitized(app, client):
    owner_id = _login(
        app, client, username="menu_export_owner",
        email="menu_export@x.com")
    _save_menu(app, owner_id, {
        "categories": [
            {"id": "cat-x", "name": "Drinks", "items": [
                {"id": "x1", "name": "=SUM(A1:A9)", "price": 10.0,
                 "description": "+2+2 cmd", "available": True},
                {"id": "x2", "name": "Normal Coffee", "price": 2.0,
                 "description": "plain", "available": True},
            ]},
        ]
    })

    r = client.get("/owner/export/menu")
    assert r.status_code == 200, r.data[:500]
    assert r.mimetype.startswith("text/csv")
    assert r.headers.get("Cache-Control", "").startswith("no-store")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"

    text = r.data.decode("utf-8")
    # Formula cells must be neutralised with a leading single quote.
    assert "'=SUM(A1:A9)" in text, text[:1000]
    assert "'+2+2" in text or "'+2" in text or "'+2+2 cmd" in text, text[:1000]
