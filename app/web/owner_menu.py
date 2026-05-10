"""Owner menu management routes."""
from __future__ import annotations

import json
import uuid

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.extensions import db, limiter
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.menu import load_owner_menu, save_owner_menu
from app.services.tables import load_settings
from app.utils.security import login_required, validate_uploaded_file
from app.utils.serializers import _safe_text

bp = Blueprint("web_owner_menu", __name__)


@bp.route("/owner/menu")
@login_required
def owner_menu():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    menu = load_owner_menu(owner_id)
    settings = load_settings(owner_id)
    return render_template("owner_menu.html", owner=owner, menu=menu, settings=settings)


@bp.route("/owner/menu/add-category", methods=["POST"])
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
    try:
        menu = json.loads(file_bytes.decode("utf-8", "strict"))
        if not isinstance(menu, dict) or "categories" not in menu:
            raise ValueError("Expected a JSON object with 'categories' key.")
    except Exception as exc:
        flash(f"Invalid menu JSON: {exc}", "error")
        return redirect(url_for("web_owner_menu.owner_menu"))
    for cat in menu.get("categories", []):
        cat["ownerId"] = owner_id
        if not cat.get("id"):
            cat["id"] = str(uuid.uuid4())
        for item in cat.get("items", []):
            if not item.get("id"):
                item["id"] = str(uuid.uuid4())
    save_owner_menu(owner_id, menu)
    flash("Menu imported successfully.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


# ---------------------------------------------------------------------------
# Export menu as CSV
# ---------------------------------------------------------------------------

@bp.route("/owner/export/menu")
@login_required
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
                cat.get("name", ""),
                item.get("id", ""),
                item.get("name", ""),
                item.get("price", ""),
                (item.get("description") or "")[:300],
                "yes" if item.get("available", True) else "no",
            ])
    out.seek(0)
    fname = f"menu_{_dt.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return _Resp(out.getvalue(), mimetype="text/csv",
                 headers={"Content-Disposition": f"attachment; filename={fname}"})


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
        flash("Item name, price, and category are required.")
        return redirect(url_for("web_owner_menu.owner_menu"))
    try:
        price = round(float(price_text), 2)
        if price < 0 or price > 99999.99:
            raise ValueError
    except ValueError:
        flash("Price must be a positive number up to 99,999.99.")
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
        # Insert as new item
        for cat in menu.get("categories", []):
            if cat.get("id") == category_id:
                cat.setdefault("items", []).append({
                    "id": item_id or str(uuid.uuid4()),
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
    save_owner_menu(owner_id, menu)
    flash(f"Menu item '{name}' saved.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))


# ---------------------------------------------------------------------------
# Image upload for a menu item
# ---------------------------------------------------------------------------

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
    mime = "image/jpeg" if file_type == "jpeg" else f"image/{file_type}"
    data_url = f"data:{mime};base64,{_b64.b64encode(file_bytes).decode()}"

    menu = load_owner_menu(owner_id)
    for cat in menu.get("categories", []):
        for item in cat.get("items", []):
            if item.get("id") == item_id:
                item["imageUrl"] = data_url
    save_owner_menu(owner_id, menu)
    flash("Image uploaded.", "success")
    return redirect(url_for("web_owner_menu.owner_menu"))
