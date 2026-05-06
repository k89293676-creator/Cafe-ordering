"""Order service: placement, status transitions, inventory, feedback."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from flask import abort, current_app

from app.extensions import db
from app.utils.serializers import _order_dict, _feedback_dict, _parse_dt


def _generate_pickup_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def load_orders(owner_id: int | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
    from app.models import Order
    query = Order.query
    if owner_id is not None:
        query = query.filter(Order.owner_id == owner_id)
    query = query.order_by(Order.id)
    if limit and limit > 0:
        query = query.limit(limit)
    if offset:
        query = query.offset(offset)
    return [_order_dict(o) for o in query.all()]


def place_order_in_db(order: dict) -> dict:
    from app.models import Order, Owner
    owner_id = order.get("ownerId")
    if owner_id:
        try:
            from extensions.multi_tenant_bp import (
                enforce_quota as _enforce_quota,
                count_owner_orders_this_month,
                QuotaExceeded,
            )
            owner_obj = db.session.get(Owner, owner_id)
            if owner_obj is not None:
                current = count_owner_orders_this_month(owner_id)
                try:
                    _enforce_quota(owner_obj, "monthly_order_limit", current)
                except QuotaExceeded as exc:
                    from werkzeug.exceptions import HTTPException
                    class _QuotaExceeded(HTTPException):
                        code = 402
                        description = exc.message
                    raise _QuotaExceeded()
        except ImportError:
            pass

    pickup_code = _generate_pickup_code()
    customer_id = None
    try:
        from app.models import Customer
        customer_email = (order.get("customerEmail") or "").strip().lower()
        customer_phone = (order.get("customerPhone") or "").strip()
        customer = None
        if customer_email:
            customer = Customer.query.filter_by(email=customer_email).first()
        if customer is None and customer_phone:
            customer = Customer.query.filter_by(phone=customer_phone).first()
        if customer is not None:
            customer_id = customer.id
            bill_total = float(order.get("total") or 0)
            points_earned = max(0, int(bill_total // 10))
            customer.points = int(customer.points or 0) + points_earned
            db.session.add(customer)
    except Exception:
        customer_id = None

    record = Order(
        owner_id=order.get("ownerId"),
        cafe_id=order.get("cafeId"),
        table_id=order.get("tableId"),
        table_name=order.get("tableName"),
        customer_name=order.get("customerName", "Guest"),
        customer_email=order.get("customerEmail", ""),
        customer_phone=order.get("customerPhone", ""),
        customer_id=customer_id,
        items=order.get("items", []),
        modifiers=order.get("modifiers", {}),
        subtotal=order.get("subtotal", order.get("total", 0)),
        tip=order.get("tip", 0),
        total=order.get("total", 0),
        status=order.get("status", "pending"),
        pickup_code=pickup_code,
        origin=order.get("origin", "table"),
        notes=order.get("notes", ""),
        created_at=_parse_dt(order.get("createdAt")) or datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(record)
    db.session.flush()
    _deduct_inventory(record.owner_id, record.items)
    db.session.commit()
    return _order_dict(record)


def _deduct_inventory(owner_id: int | None, items: list) -> None:
    if not owner_id or not items:
        return
    from app.models import Ingredient
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).with_for_update().all()
            for ing in ingredients:
                deduct = float(ing.qty_per_order or 1) * qty
                ing.stock = max(0, float(ing.stock or 0) - deduct)
                db.session.add(ing)
    except Exception as exc:
        current_app.logger.warning("Inventory deduction failed: %s", exc)


def _restore_inventory(order: dict) -> None:
    from app.models import Ingredient
    owner_id = order.get("ownerId")
    items = order.get("items") or []
    if not owner_id or not items:
        return
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).all()
            for ing in ingredients:
                add_back = float(ing.qty_per_order or 1) * qty
                ing.stock = float(ing.stock or 0) + add_back
                db.session.add(ing)
        db.session.commit()
    except Exception as exc:
        current_app.logger.warning("Inventory restore failed: %s", exc)


def _check_stock_available(owner_id: int | None, items: list) -> tuple[bool, str]:
    from app.models import Ingredient
    if not owner_id or not items:
        return True, ""
    try:
        for item in items:
            item_id = item.get("id")
            qty = int(item.get("quantity", 1))
            if not item_id:
                continue
            ingredients = Ingredient.query.filter_by(owner_id=owner_id, menu_item_id=item_id).with_for_update().all()
            for ing in ingredients:
                needed = float(ing.qty_per_order or 1) * qty
                if float(ing.stock or 0) < needed:
                    name = item.get("name") or f"item {item_id}"
                    ing_name = getattr(ing, "name", None) or "ingredient"
                    return False, f"Not enough stock for '{name}' (insufficient {ing_name})."
    except Exception as exc:
        current_app.logger.warning("Stock check failed: %s", exc)
        return True, ""
    return True, ""


def _db_update_order_status(order_id: int, new_status: str) -> bool:
    from app.models import Order
    valid_statuses = {"pending", "preparing", "ready", "completed", "cancelled", "voided"}
    if new_status not in valid_statuses:
        return False
    order = db.session.get(Order, order_id)
    if not order:
        return False
    invalid_transitions = {
        ("completed", "pending"), ("cancelled", "pending"), ("voided", "pending"),
        ("completed", "preparing"), ("cancelled", "preparing"), ("voided", "preparing"),
    }
    if (order.status, new_status) in invalid_transitions:
        return False
    order.status = new_status
    order.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return True


def _db_get_order(order_id: int) -> dict | None:
    from app.models import Order
    order = db.session.get(Order, order_id)
    return _order_dict(order) if order else None


def _db_delete_order(order_id: int) -> bool:
    from app.models import Order
    order = db.session.get(Order, order_id)
    if not order:
        return False
    db.session.delete(order)
    db.session.commit()
    return True


def compute_order_summary(items: list[dict], owner_menu: dict | None = None) -> dict:
    from app.services.menu import load_menu
    if not isinstance(items, list):
        abort(400, description="items must be a list.")
    menu = owner_menu if owner_menu is not None else load_menu()
    menu_items = {
        item["id"]: item
        for category in menu.get("categories", [])
        for item in category.get("items", [])
    }
    if not items:
        abort(400, description="Order must contain at least one item.")
    total = 0.0
    summary = []
    for entry in items:
        if not isinstance(entry, dict):
            abort(400, description="Each item entry must be an object.")
        item_id = entry.get("id")
        if not item_id or not isinstance(item_id, str):
            abort(400, description="Each item entry must have a valid string 'id'.")
        try:
            quantity = max(int(float(entry.get("quantity", 1))), 1)
        except (TypeError, ValueError):
            abort(400, description=f"Invalid quantity for item {item_id!r}.")
        if quantity > 100:
            abort(400, description="Maximum quantity per item is 100.")
        menu_item = menu_items.get(item_id)
        if not menu_item:
            abort(400, description=f"Unknown item id: {item_id!r}")
        if not menu_item.get("available", True):
            abort(400, description=f"Sorry, '{menu_item['name']}' is currently sold out.")
        modifiers = entry.get("modifiers", [])
        modifier_total = 0.0
        modifier_list = []
        if isinstance(modifiers, list):
            for mod in modifiers:
                if isinstance(mod, dict):
                    try:
                        mod_price = round(float(mod.get("price", 0)), 2)
                    except (TypeError, ValueError):
                        mod_price = 0.0
                    modifier_total += mod_price
                    modifier_list.append({"name": str(mod.get("name", ""))[:50], "price": mod_price})
        item_unit_price = menu_item["price"] + modifier_total
        item_total = item_unit_price * quantity
        total += item_total
        summary.append({
            "id": item_id,
            "name": menu_item["name"],
            "price": menu_item["price"],
            "quantity": quantity,
            "modifiers": modifier_list,
            "size": str(entry.get("size", ""))[:50],
            "extras": str(entry.get("extras", ""))[:200],
            "notes": str(entry.get("notes", ""))[:500],
            "lineTotal": round(item_total, 2),
        })
    return {"items": summary, "total": round(total, 2)}


def save_feedback_entry(entry: dict) -> dict:
    from app.models import Feedback
    feedback = Feedback(
        owner_id=entry.get("ownerId"),
        cafe_id=entry.get("cafeId"),
        order_id=entry.get("orderId"),
        table_id=entry.get("tableId"),
        customer_name=entry.get("customerName", "Guest"),
        rating=entry["rating"],
        comment=entry.get("comment", ""),
        created_at=_parse_dt(entry.get("createdAt")) or datetime.now(timezone.utc),
    )
    db.session.add(feedback)
    db.session.commit()
    return _feedback_dict(feedback)
