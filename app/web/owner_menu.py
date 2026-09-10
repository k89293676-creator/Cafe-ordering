"""Owner menu management routes."""
from __future__ import annotations

import json
import logging
import math
import uuid

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.menu import load_owner_menu, save_owner_menu
from app.services.tables import load_settings
from app.utils.security import login_required, validate_uploaded_file
from app.utils.serializers import _safe_text

log = logging.getLogger(__name__)

bp = Blueprint("web_owner_menu", __name__)

# ── Import validation caps ───────────────────────────────────────────────────
MAX_CATEGORIES = 200
MAX_ITEMS_PER_CATEGORY = 500
MAX_NAME_LEN = 100
MAX_DESC_LEN = 500
MAX_PRICE = 99999.99

# Cells beginning with these chars can execute as formulas in Excel.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value) -> str:
    """Stringify *value* and neutralise CSV-injection vectors (mirrors extensions/exports_bp)."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in _FORMULA_PREFIXES:
        s = "'" + s
    return s


def _reject_json_constant(value: str):
    """json.parse_constant hook — reject NaN/Infinity (strict JSON)."""
    raise ValueError(f"Invalid JSON constant: {value}")


def _validate_imported_menu(menu: dict) -> dict:
    """Validate an imported menu blob. Raises ValueError with a user-facing message."""
    if not isinstance(menu, dict):
        raise ValueError("Expected a JSON object with 'categories' key.")
    if "categories" not in menu:
        raise ValueError("Expected a JSON object with 'categories' key.")
    categories = menu.get("categories")
    if not isinstance(categories, list):
        raise ValueError("Expected 'categories' to be a list.")
    if len(categories) > MAX_CATEGORIES:
        raise ValueError(f"Too many categories (max {MAX_CATEGORIES}).")
    for idx, cat in enumerate(categories):
        if not isinstance(cat, dict):
            raise ValueError(f"Category #{idx + 1} must be an object.")
        if "items" not in cat or cat.get("items") is None:
            cat["items"] = []
        items = cat.get("items")
        if not isinstance(items, list):
            raise ValueError(
                f"Category '{cat.get('name', '?')}' items must be a list."
            )
        if len(items) > MAX_ITEMS_PER_CATEGORY:
            raise ValueError(
                f"Too many items in category '{cat.get('name', '?')}' "
                f"(max {MAX_ITEMS_PER_CATEGORY})."
            )
        raw_cat_name = cat.get("name", "")
        if not isinstance(raw_cat_name, str):
            raise ValueError(f"Category #{idx + 1} name must be a string.")
        if len(raw_cat_name) > MAX_NAME_LEN:
            raise ValueError(
                f"Category name too long (max {MAX_NAME_LEN} chars)."
            )
        for j, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Item #{j + 1} in category '{raw_cat_name}' must be an object."
                )
            iname = item.get("name", "")
            if not isinstance(iname, str):
                raise ValueError(f"Item #{j + 1} name must be a string.")
            if len(iname) > MAX_NAME_LEN:
                raise ValueError(
                    f"Item name too long (max {MAX_NAME_LEN} chars)."
                )
            desc = item.get("description", "")
            if desc is None:
                desc = ""
                item["description"] = ""
            if not isinstance(desc, str):
                raise ValueError(f"Item '{iname}' description must be a string.")
            if len(desc) > MAX_DESC_LEN:
                raise ValueError(
                    f"Item '{iname}' description too long (max {MAX_DESC_LEN} chars)."
                )
            price = item.get("price", 0)
            if isinstance(price, str):
                price = price.strip()
                try:
                    price = float(price)
                except (TypeError, ValueError):
                    raise ValueError(f"Item '{iname}' price must be a number.")
                item["price"] = price
            if isinstance(price, bool) or not isinstance(price, (int, float)):
                raise ValueError(f"Item '{iname}' price must be a number.")
            try:
                price_f = float(price)
            except (TypeError, ValueError):
                raise ValueError(f"Item '{iname}' price must be a number.")
            if not math.isfinite(price_f):
                raise ValueError(f"Item '{iname}' price must be finite.")
            if not (0 <= price_f <= MAX_PRICE):
                raise ValueError(
                    f"Item '{iname}' price must be between 0 and {MAX_PRICE}."
                )
            item["price"] = round(price_f, 2)
    return menu


@bp.route("/owner/menu")
@login_required
def owner_menu():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    menu = load_owner_menu(owner_id)
    settings = load_settings(owner_id)
    return render_template("owner_menu.html", owner=owner, menu=menu, settings=settings)


@bp.route("/owner/menu/add-category", methods=["POST"])
@bp.route("/owner/menu/category", methods=["POST"])
@login_required
@limiter.limit("30 per hour")
def owner_add_category():
    owner_id = logged_in_owner_id()
    name = _safe_text(request.form.get("name"), max_len=100)
    if not name:
        flash("Category name is required.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    menu = load_owner_menu(owner_id)
    categories = menu.get("categories", [])
    categories.append({"id": str(uuid.uuid4()), "name": name, "items": [], "ownerId": owner_id})
    menu["categories"] = categories
    save_owner_menu(owner_id, menu)
    flash(f"Category '{name}' added.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


@bp.route("/owner/menu/category/<category_id>/delete", methods=["POST"])
@login_required
def owner_delete_category(category_id: str):
    owner_id = logged_in_owner_id()
    menu = load_owner_menu(owner_id)
    menu["categories"] = [c for c in menu.get("categories", []) if c.get("id") != category_id]
    save_owner_menu(owner_id, menu)
    flash("Category deleted.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


@bp.route("/owner/menu/category/<category_id>/add-item", methods=["POST"])
@login_required
@limiter.limit("50 per hour")
def owner_add_item(category_id: str):
    owner_id = logged_in_owner_id()
    name = _safe_text(request.form.get("name"), max_len=100)
    description = _safe_text(request.form.get("description"), max_len=500)
    try:
        price = round(float(request.form.get("price", "0")), 2)
        if price < 0:
            price = 0.0
    except (TypeError, ValueError):
        price = 0.0

    available = request.form.get("available", "1") != "0"
    if not name:
        flash("Item name is required.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))

    menu = load_owner_menu(owner_id)
    for cat in menu.get("categories", []):
        if cat.get("id") == category_id:
            item = {
                "id": str(uuid.uuid4()),
                "name": name,
                "description": description,
                "price": price,
                "available": available,
                "imageUrl": "",
            }
            cat.setdefault("items", []).append(item)
            break
    save_owner_menu(owner_id, menu)
    flash(f"Item '{name}' added.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


@bp.route("/owner/menu/item/<item_id>/delete", methods=["POST"])
@login_required
def owner_delete_item(item_id: str):
    owner_id = logged_in_owner_id()
    menu = load_owner_menu(owner_id)
    for cat in menu.get("categories", []):
        cat["items"] = [i for i in cat.get("items", []) if i.get("id") != item_id]
    save_owner_menu(owner_id, menu)
    flash("Item deleted.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


@bp.route("/owner/menu/item/<item_id>/toggle", methods=["POST"])
@login_required
def owner_toggle_item(item_id: str):
    owner_id = logged_in_owner_id()
    menu = load_owner_menu(owner_id)
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            if item.get("id") == item_id:
                item["available"] = not item.get("available", True)
                break
    save_owner_menu(owner_id, menu)
    return redirect(url_for("web_owner_menu.owner_menu"))


@bp.route("/owner/menu/import", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_import_menu():
    owner_id = logged_in_owner_id()
    file = request.files.get("menu_file")
    if not file or not file.filename:
        flash("No file selected.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    file_bytes = file.read(2 * 1024 * 1024 + 1)
    if len(file_bytes) > 2 * 1024 * 1024:
        flash("File too large (max 2 MB).", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    err, file_type = validate_uploaded_file(file, file_bytes)
    if err:
        flash(err, "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    if file_type != "json":
        flash("Only JSON files allowed.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    try:
        text = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        flash(f"Invalid menu JSON: file must be UTF-8 encoded ({exc})", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    try:
        menu = json.loads(text, parse_constant=_reject_json_constant)
        _validate_imported_menu(menu)
    except ValueError as exc:
        flash(f"Invalid menu JSON: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    except Exception as exc:
        flash(f"Invalid menu JSON: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    # Dedupe IDs — regenerate uuid4 on collision or missing so that
    # delete/toggle/upsert behave consistently afterwards.
    seen_cat_ids: set[str] = set()
    seen_item_ids: set[str] = set()
    for cat in menu.get("categories", []):
        cid = cat.get("id")
        if not cid or not isinstance(cid, str) or cid in seen_cat_ids:
            cid = str(uuid.uuid4())
            cat["id"] = cid
        seen_cat_ids.add(cid)
        cat["ownerId"] = owner_id
        # Normalise + sanitise category name.
        cat["name"] = _safe_text(cat.get("name", ""), max_len=MAX_NAME_LEN)
        if not isinstance(cat.get("items"), list):
            cat["items"] = []
        for item in cat.get("items", []):
            iid = item.get("id")
            if not iid or not isinstance(iid, str) or iid in seen_item_ids:
                iid = str(uuid.uuid4())
                item["id"] = iid
            seen_item_ids.add(iid)
            item["name"] = _safe_text(item.get("name", ""), max_len=MAX_NAME_LEN)
            item["description"] = _safe_text(
                item.get("description", ""), max_len=MAX_DESC_LEN
            )
            if "available" not in item:
                item["available"] = True
            if "imageUrl" not in item or item.get("imageUrl") is None:
                item["imageUrl"] = ""
    try:
        save_owner_menu(owner_id, menu)
    except Exception as exc:
        log.exception("owner_import_menu save failed for owner %s", owner_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        flash(f"Could not save imported menu: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    flash("Menu imported successfully.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


# ---------------------------------------------------------------------------
# Export menu as CSV
# ---------------------------------------------------------------------------

@bp.route("/owner/export/menu")
@login_required
@limiter.limit("30 per hour")
def export_menu_csv():
    import csv as _csv
    import io as _io
    from datetime import datetime as _dt
    from flask import Response as _Resp
    owner_id = logged_in_owner_id()
    menu = load_owner_menu(owner_id)
    out = _io.StringIO()
    w = _csv.writer(out)
    w.writerow(["category", "id", "name", "price", "description", "available"])
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            w.writerow([
                _sanitize_csv_cell(cat.get("name", "")),
                _sanitize_csv_cell(item.get("id", "")),
                _sanitize_csv_cell(item.get("name", "")),
                _sanitize_csv_cell(item.get("price", "")),
                _sanitize_csv_cell((item.get("description") or "")[:300]),
                _sanitize_csv_cell("yes" if item.get("available", True) else "no"),
            ])
    out.seek(0)
    fname = f"menu_{_dt.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return _Resp(out.getvalue(), mimetype="text/csv; charset=utf-8",
                  headers={"Content-Disposition": f"attachment; filename={fname}",
                           "Cache-Control": "no-store, private, max-age=0",
                           "X-Content-Type-Options": "nosniff"})


# ---------------------------------------------------------------------------
# Full save_menu_item — update or insert (handles dashboard item-edit modal)
# ---------------------------------------------------------------------------

@bp.route("/owner/menu/item", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def save_menu_item():
    """Upsert a menu item: if itemId matches an existing item, update it;
    otherwise delegate to owner_add_item logic inline. Used by the
    owner dashboard #menu inline edit form."""
    owner_id = logged_in_owner_id()
    form = request.form
    category_id = _safe_text(str(form.get("categoryId", "")), max_len=100)
    item_id = _safe_text(str(form.get("itemId", "")), max_len=100)
    name = _safe_text(str(form.get("itemName", "")), max_len=200)
    description = _safe_text(str(form.get("itemDescription", "")), max_len=500)
    price_text = str(form.get("itemPrice", "")).strip()[:20]
    image_url = _safe_text(str(form.get("itemImageUrl", "")), max_len=500)
    try:
        prep_time = max(0, min(300, int(form.get("itemPrepTime") or 0)))
    except (TypeError, ValueError):
        prep_time = 0
    tags_text = _safe_text(str(form.get("itemTags", "")), max_len=300)
    dietary_text = _safe_text(str(form.get("itemDietaryTags", "")), max_len=300)

    if not category_id or not name or not price_text:
        flash("Item name, price, and category are required.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    try:
        price = round(float(price_text), 2)
        if price < 0 or price > 99999.99:
            raise ValueError
    except ValueError:
        flash("Price must be a positive number up to 99,999.99.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))

    available = form.get("itemAvailable", "1") not in ("0", "false", "False", "")
    tags = [t.strip() for t in tags_text.replace(",", " ").split() if t.strip()][:20]
    dietary = [t.strip() for t in dietary_text.replace(",", " ").split() if t.strip()][:10]

    menu = load_owner_menu(owner_id)
    # Try to find and update existing item
    found = False
    for cat in menu.get("categories", []):
        if cat.get("id") != category_id:
            continue
        for item in cat.get("items", []):
            if item.get("id") == item_id:
                item["name"] = name
                item["description"] = description
                item["price"] = price
                item["available"] = available
                if image_url:
                    item["imageUrl"] = image_url
                item["tags"] = tags
                item["dietaryTags"] = dietary
                item["prepTime"] = prep_time
                found = True
                break
        if found:
            break
    if not found:
        # Insert as new item — ensure global id uniqueness so later
        # delete/toggle/upsert stay consistent.
        existing_ids = {
            it.get("id")
            for cat in menu.get("categories", [])
            for it in cat.get("items", [])
            if it.get("id")
        }
        new_id = item_id
        if not new_id or new_id in existing_ids:
            new_id = str(uuid.uuid4())
            while new_id in existing_ids:
                new_id = str(uuid.uuid4())
        for cat in menu.get("categories", []):
            if cat.get("id") == category_id:
                cat.setdefault("items", []).append({
                    "id": new_id,
                    "name": name,
                    "description": description,
                    "price": price,
                    "available": available,
                    "imageUrl": image_url,
                    "tags": tags,
                    "dietaryTags": dietary,
                    "prepTime": prep_time,
                })
                break
    try:
        save_owner_menu(owner_id, menu)
    except Exception as exc:
        log.exception("save_menu_item failed for owner %s", owner_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        flash(f"Could not save menu item: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    flash(f"Menu item '{name}' saved.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


# ---------------------------------------------------------------------------
# Image upload for a menu item
# ---------------------------------------------------------------------------

@bp.route("/owner/menu/download")
@login_required
@limiter.limit("30 per hour")
def download_menu():
    """Download the owner's menu as a JSON file (Bug #16 fix — port from legacy monolith)."""
    import json as _json
    from datetime import date as _date
    from flask import Response as _Resp
    owner_id = logged_in_owner_id()
    menu = load_owner_menu(owner_id)
    fname = f"menu-{_date.today().isoformat()}.json"
    return _Resp(
        _json.dumps(menu, indent=2, ensure_ascii=False),
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={fname}",
                 "Cache-Control": "no-store, private, max-age=0",
                 "X-Content-Type-Options": "nosniff"},
    )


@bp.route("/owner/menu/ai-suggest", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def owner_menu_ai_suggest():
    """Call Gemini AI to suggest menu items for the given cuisine / price range."""
    from flask import current_app, jsonify
    from app.services.ai_menu import suggest_menu_items

    gemini_key = current_app.config.get("GEMINI_API_KEY", "")
    if not gemini_key:
        return jsonify(error="AI suggestions are not enabled on this instance."), 403

    cuisine = _safe_text(request.form.get("cuisine"), max_len=80) or "café"
    price_range = _safe_text(request.form.get("price_range"), max_len=20) or "mid-range"
    try:
        items = suggest_menu_items(gemini_key, cuisine, price_range)
        return jsonify(suggestions=items)
    except Exception as exc:
        return jsonify(error=f"AI suggestion failed: {exc}"), 500


@bp.route("/owner/menu/item/<item_id>/upload-image", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def owner_upload_item_image(item_id: str):
    """Store a base64-inlined image URL on the menu item (small images only).
    For production use, point to an object storage CDN instead."""
    import base64 as _b64
    owner_id = logged_in_owner_id()
    file = request.files.get("image")
    if not file or not file.filename:
        flash("No image selected.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    file_bytes = file.read(512 * 1024 + 1)
    if len(file_bytes) > 512 * 1024:
        flash("Image too large (max 512 KB).", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    err, file_type = validate_uploaded_file(file, file_bytes)
    if err:
        flash(err, "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    if file_type != "image":
        flash("Only image files allowed.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    # validate_uploaded_file returns "image" (not "jpeg"/"png"), so map
    # the real MIME type from the filename extension (fallback to magic).
    _fname_lower = (file.filename or "").lower()
    if _fname_lower.endswith(".png"):
        mime = "image/png"
    elif _fname_lower.endswith((".jpg", ".jpeg")):
        mime = "image/jpeg"
    elif file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif file_bytes.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    else:
        mime = "image/png"
    data_url = f"data:{mime};base64,{_b64.b64encode(file_bytes).decode()}"

    menu = load_owner_menu(owner_id)
    found = False
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            if item.get("id") == item_id:
                item["imageUrl"] = data_url
                found = True
                break
        if found:
            break
    if not found:
        flash("Menu item not found.", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    try:
        save_owner_menu(owner_id, menu)
    except Exception as exc:
        log.exception("owner_upload_item_image save failed for owner %s", owner_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        flash(f"Could not save image: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    flash("Image uploaded.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))
