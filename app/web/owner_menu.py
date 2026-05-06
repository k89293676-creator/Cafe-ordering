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
