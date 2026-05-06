"""Menu service: load/save menus from DB (no JSON file locks)."""
from __future__ import annotations

from typing import Any

from app.extensions import db


def load_menu() -> dict:
    """Load merged menu from DB (all owners' categories)."""
    from app.models import Menu
    rows = Menu.query.all()
    categories = []
    for row in rows:
        data = row.data or {}
        for cat in data.get("categories", []):
            cat_copy = dict(cat)
            cat_copy["ownerId"] = row.owner_id
            cat_copy["cafeId"] = row.cafe_id
            categories.append(cat_copy)
    return {"categories": categories}


def load_owner_menu(owner_id: int) -> dict:
    """Load menu for a single owner."""
    from app.models import Menu
    row = db.session.get(Menu, owner_id)
    if row and isinstance(row.data, dict):
        return row.data
    return {"categories": []}


def save_menu(menu: dict) -> None:
    """Persist menu; groups categories by ownerId."""
    from app.models import Menu
    owner_cats: dict[Any, list] = {}
    for cat in menu.get("categories", []):
        owner_id = cat.get("ownerId")
        owner_cats.setdefault(owner_id, []).append(cat)

    for owner_id, cats in owner_cats.items():
        if owner_id is None:
            continue
        row = db.session.get(Menu, owner_id) or Menu(owner_id=owner_id)
        row.data = {"categories": cats}
        db.session.add(row)
    db.session.commit()


def save_owner_menu(owner_id: int, menu_data: dict) -> None:
    """Save the full menu blob for a single owner."""
    from app.models import Menu
    row = db.session.get(Menu, owner_id)
    if row is None:
        row = Menu(owner_id=owner_id)
        db.session.add(row)
    row.data = menu_data
    db.session.commit()
