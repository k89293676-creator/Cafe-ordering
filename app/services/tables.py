"""Table service: load/save tables from DB (no JSON file locks)."""
from __future__ import annotations

import re

from app.extensions import db
from app.utils.serializers import _iso


def load_tables() -> list[dict]:
    from app.models import CafeTable
    rows = CafeTable.query.order_by(CafeTable.created_at).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "ownerId": t.owner_id,
            "cafeId": t.cafe_id,
            "createdAt": _iso(t.created_at),
        }
        for t in rows
    ]


def load_owner_tables(owner_id: int) -> list[dict]:
    from app.models import CafeTable
    rows = CafeTable.query.filter_by(owner_id=owner_id).order_by(CafeTable.created_at).all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "ownerId": t.owner_id,
            "cafeId": t.cafe_id,
            "createdAt": _iso(t.created_at),
        }
        for t in rows
    ]


def save_tables(tables: list[dict]) -> None:
    """Bulk-upsert tables from a list of dicts (used during JSON→DB migration)."""
    from app.models import CafeTable
    for t in tables:
        table_id = t.get("id")
        if not table_id:
            continue
        row = db.session.get(CafeTable, table_id)
        if row is None:
            row = CafeTable(id=table_id)
            db.session.add(row)
        row.name = t.get("name", "Table")
        row.owner_id = t.get("ownerId")
        row.cafe_id = t.get("cafeId")
    db.session.commit()


def normalize_id(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def unique_id(base: str, existing: set) -> str:
    candidate = base
    counter = 2
    while candidate in existing:
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def next_table_number(tables: list[dict]) -> int:
    nums = []
    for t in tables:
        n = t.get("name", "")
        try:
            nums.append(int(n.replace("Table", "").strip()))
        except (ValueError, AttributeError):
            pass
    return max(nums, default=0) + 1


def load_settings(owner_id: int | None) -> dict:
    from app.models import Settings
    from app.utils.serializers import _settings_dict
    if not owner_id:
        return _settings_dict(None)
    return _settings_dict(db.session.get(Settings, owner_id))


def save_settings(owner_id: int, logo_url: str, brand_color: str) -> dict:
    import re as _re
    from app.models import Settings
    from app.utils.serializers import _settings_dict
    from datetime import datetime, timezone
    settings = db.session.get(Settings, owner_id) or Settings(owner_id=owner_id)
    settings.logo_url = logo_url
    settings.brand_color = brand_color if _re.fullmatch(r"#[0-9a-fA-F]{6}", brand_color) else "#4f46e5"
    settings.updated_at = datetime.now(timezone.utc)
    db.session.add(settings)
    db.session.commit()
    return _settings_dict(settings)
