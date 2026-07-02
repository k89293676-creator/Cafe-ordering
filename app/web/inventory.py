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
        "inventory.html",
        owner=owner,
        owner_username=owner.username if owner else "",
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


# ---------------------------------------------------------------------------
# Inventory CSV import
# ---------------------------------------------------------------------------

@bp.route("/owner/inventory/import", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def import_inventory_csv():
    """Bulk-import ingredients from a CSV upload (upsert by name)."""
    import csv as _csv
    import io as _io
    owner_id = logged_in_owner_id()
    owner = logged_in_owner_obj()
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a CSV file to import.")
        return redirect(url_for("web_inventory.owner_inventory"))
    try:
        raw = upload.read(2 * 1024 * 1024).decode("utf-8-sig", errors="replace")
    except Exception as exc:
        flash(f"Could not read file: {exc}")
        return redirect(url_for("web_inventory.owner_inventory"))

    reader = _csv.DictReader(_io.StringIO(raw))
    if not reader.fieldnames:
        flash("CSV is empty or missing a header row.")
        return redirect(url_for("web_inventory.owner_inventory"))

    field_map = {(h or "").strip().lower(): h for h in reader.fieldnames}
    if "name" not in field_map:
        flash("CSV must include a 'name' column.")
        return redirect(url_for("web_inventory.owner_inventory"))

    def _get(row, key, default=""):
        h = field_map.get(key)
        return str(row.get(h, default) or default).strip() if h else default

    def _f(val, fallback=0.0):
        try:
            return float(val)
        except (TypeError, ValueError):
            return fallback

    existing = {i.name.lower(): i for i in Ingredient.query.filter_by(owner_id=owner_id).all()}
    inserted = updated = skipped = 0
    for row in reader:
        name = _safe_text(_get(row, "name"), max_len=100)
        if not name:
            skipped += 1
            continue
        ing = existing.get(name.lower())
        is_new = ing is None
        if is_new:
            ing = Ingredient(owner_id=owner_id, cafe_id=owner.cafe_id if owner else None, name=name)
            db.session.add(ing)
        ing.unit = _safe_text(_get(row, "unit", ing.unit or "unit"), max_len=30) or "unit"
        stock_val = _get(row, "stock")
        if stock_val:
            ing.stock = max(0.0, _f(stock_val, float(ing.stock or 0)))
        threshold_val = _get(row, "low_stock_threshold")
        if threshold_val:
            ing.low_stock_threshold = max(0.0, _f(threshold_val, float(ing.low_stock_threshold or 5)))
        qty_val = _get(row, "qty_per_order")
        if qty_val:
            ing.qty_per_order = max(0.0, _f(qty_val, float(ing.qty_per_order or 1)))
        cost_val = _get(row, "cost_per_unit")
        if cost_val:
            ing.cost_per_unit = max(0.0, _f(cost_val, float(ing.cost_per_unit or 0)))
        mid = _get(row, "menu_item_id")
        if mid:
            ing.menu_item_id = _safe_text(mid, max_len=64) or None
        if is_new:
            inserted += 1
        else:
            updated += 1

    db.session.commit()
    flash(f"Import complete: {inserted} added, {updated} updated, {skipped} skipped.")
    return redirect(url_for("web_inventory.owner_inventory"))


# ---------------------------------------------------------------------------
# Inventory CSV export
# ---------------------------------------------------------------------------

@bp.route("/owner/inventory/export")
@login_required
def export_inventory_csv():
    import csv as _csv
    import io as _io
    from datetime import datetime as _dt
    from flask import Response as _Resp
    owner_id = logged_in_owner_id()
    ings = Ingredient.query.filter_by(owner_id=owner_id).order_by(Ingredient.name).all()
    out = _io.StringIO()
    w = _csv.writer(out)
    w.writerow(["id", "name", "unit", "stock", "low_stock_threshold",
                "menu_item_id", "qty_per_order", "cost_per_unit", "stock_value", "status"])
    for i in ings:
        s = float(i.stock or 0)
        t = float(i.low_stock_threshold or 0)
        cost = float(i.cost_per_unit or 0)
        status = "OUT" if s <= 0 else ("LOW" if s <= t else "OK")
        w.writerow([i.id, i.name, i.unit or "unit", s, t,
                    i.menu_item_id or "", float(i.qty_per_order or 1), cost,
                    round(s * cost, 2), status])
    out.seek(0)
    fname = f"inventory_{_dt.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return _Resp(out.getvalue(), mimetype="text/csv",
                 headers={"Content-Disposition": f"attachment; filename={fname}"})


# ---------------------------------------------------------------------------
# Restock ingredient (add/subtract delta)
# ---------------------------------------------------------------------------

@bp.route("/owner/inventory/<int:ing_id>/restock", methods=["POST"])
@login_required
def restock_ingredient(ing_id: int):
    owner_id = logged_in_owner_id()
    ing = db.session.get(Ingredient, ing_id)
    if not ing or ing.owner_id != owner_id:
        abort(403)
    try:
        delta = float(request.form.get("delta", "0"))
    except ValueError:
        flash("Invalid restock amount.")
        return redirect(url_for("web_inventory.owner_inventory"))
    new_stock = max(0.0, float(ing.stock or 0) + delta)
    ing.stock = new_stock
    db.session.commit()
    sign = "+" if delta >= 0 else ""
    flash(f"{ing.name}: stock {sign}{delta} → {new_stock} {ing.unit or 'unit'}")
    return redirect(url_for("web_inventory.owner_inventory"))
