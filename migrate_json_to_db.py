from __future__ import annotations

import os
from datetime import datetime, timezone

if not os.environ.get("DATABASE_URL"):
    raise SystemExit("DATABASE_URL must be set to import JSON data into PostgreSQL.")

from app import (
    FEEDBACK_PATH,
    MENU_PATH,
    ORDERS_PATH,
    OWNERS_PATH,
    TABLES_PATH,
    USE_DB,
    safe_read_json,
    save_menu,
    save_orders,
    save_owners,
    save_tables,
    save_feedback_entry,
)

if not USE_DB:
    raise SystemExit("Database mode is not active. Check DATABASE_URL and psycopg2 installation.")

owners = safe_read_json(OWNERS_PATH, [])
tables = safe_read_json(TABLES_PATH, [])
menu = safe_read_json(MENU_PATH, {"categories": []})
orders = safe_read_json(ORDERS_PATH, [])
feedback = safe_read_json(FEEDBACK_PATH, [])

save_owners(owners)
save_tables(tables)
save_menu(menu)
save_orders(orders)

for entry in feedback:
    item = dict(entry)
    item.pop("id", None)
    item.setdefault("createdAt", datetime.now(timezone.utc).isoformat())
    save_feedback_entry(item)

print(
    "Imported JSON data into PostgreSQL: "
    f"{len(owners)} owners, {len(tables)} tables, "
    f"{len(menu.get('categories', []))} menu categories, "
    f"{len(orders)} orders, {len(feedback)} feedback entries."
)
