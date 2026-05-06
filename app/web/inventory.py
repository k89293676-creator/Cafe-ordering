"""Owner inventory management routes."""
from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.extensions import db, limiter
from app.models import Ingredient
from app.services.auth import logged_in_owner_id, logged_in_owner_obj
from app.services.tables import load_settings
from app.utils.security import login_required
from app.utils.serializers import _safe_text

bp = Blueprint("web_inventory", __name__)


def _ingredient_dict(ing: Ingredient) -> dict:
    return {
        "id": ing.id,
        "name": ing.name,
        "unit": ing.unit or "unit",
        "stock": float(ing.stock or 0),
        "lowStockThreshold": float(ing.low_stock_threshold or 5),
        "menuItemId": ing.menu_item_id,
        "qtyPerOrder": float(ing.qty_per_order or 1),
        "costPerUnit": float(ing.cost_per_unit or 0),
    }


@bp.route("/owner/inventory")
@login_required
def owner_inventory():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    ingredients = Ingredient.query.filter_by(owner_id=owner_id).order_by(Ingredient.name).all()
    settings = load_settings(owner_id)
    low_stock = [i for i in ingredients if float(i.stock or 0) <= float(i.low_stock_threshold or 5)]
    return render_template(
        "owner_inventory.html",
        owner=owner,
        ingredients=[_ingredient_dict(i) for i in ingredients],
        low_stock_count=len(low_stock),
        settings=settings,
    )


@bp.route("/owner/inventory/add", methods=["POST"])
@login_required
@limiter.limit("50 per hour")
def owner_add_ingredient():
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    name = _safe_text(request.form.get("name"), max_len=100)
    if not name:
        flash("Ingredient name required.", "error")
        return redirect(url_for("web_inventory.owner_inventory"))
    unit = _safe_text(request.form.get("unit"), max_len=30) or "unit"
    try:
        stock = max(0.0, float(request.form.get("stock", "0")))
    except (TypeError, ValueError):
        stock = 0.0
    try:
        threshold = max(0.0, float(request.form.get("low_stock_threshold", "5")))
    except (TypeError, ValueError):
        threshold = 5.0
    menu_item_id = _safe_text(request.form.get("menu_item_id"), max_len=64) or None
    try:
        qty_per_order = max(0.0, float(request.form.get("qty_per_order", "1")))
    except (TypeError, ValueError):
        qty_per_order = 1.0
    try:
        cost_per_unit = max(0.0, float(request.form.get("cost_per_unit", "0")))
    except (TypeError, ValueError):
        cost_per_unit = 0.0

    ing = Ingredient(
        owner_id=owner_id,
        cafe_id=owner.cafe_id,
        name=name,
        unit=unit,
        stock=stock,
        low_stock_threshold=threshold,
        menu_item_id=menu_item_id,
        qty_per_order=qty_per_order,
        cost_per_unit=cost_per_unit,
    )
    db.session.add(ing)
    db.session.commit()
    flash(f"Ingredient '{name}' added.", "success")
    return redirect(url_for("web_inventory.owner_inventory"))


@bp.route("/owner/inventory/<int:ing_id>/update", methods=["POST"])
@login_required
def owner_update_ingredient(ing_id: int):
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(404)
    name = _safe_text(request.form.get("name"), max_len=100)
    if name:
        ing.name = name
    unit = _safe_text(request.form.get("unit"), max_len=30)
    if unit:
        ing.unit = unit
    try:
        ing.stock = max(0.0, float(request.form.get("stock", ing.stock or "0")))
    except (TypeError, ValueError):
        pass
    try:
        ing.low_stock_threshold = max(0.0, float(request.form.get("low_stock_threshold", ing.low_stock_threshold or "5")))
    except (TypeError, ValueError):
        pass
    menu_item_id = request.form.get("menu_item_id")
    if menu_item_id is not None:
        ing.menu_item_id = _safe_text(menu_item_id, max_len=64) or None
    try:
        ing.qty_per_order = max(0.0, float(request.form.get("qty_per_order", ing.qty_per_order or "1")))
    except (TypeError, ValueError):
        pass
    try:
        ing.cost_per_unit = max(0.0, float(request.form.get("cost_per_unit", ing.cost_per_unit or "0")))
    except (TypeError, ValueError):
        pass
    db.session.commit()
    flash(f"Ingredient '{ing.name}' updated.", "success")
    return redirect(url_for("web_inventory.owner_inventory"))


@bp.route("/owner/inventory/<int:ing_id>/delete", methods=["POST"])
@login_required
def owner_delete_ingredient(ing_id: int):
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(404)
    db.session.delete(ing)
    db.session.commit()
    flash("Ingredient deleted.", "success")
    return redirect(url_for("web_inventory.owner_inventory"))
