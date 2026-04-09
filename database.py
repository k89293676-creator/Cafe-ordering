"""
Database abstraction layer for Cafe Portal.

Supports both PostgreSQL (via DATABASE_URL) and JSON file fallback for local development.
When DATABASE_URL is set, uses PostgreSQL with connection pooling.
Otherwise, falls back to the original JSON file storage.
"""

from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL)

# ---------------------------------------------------------------------------
# PostgreSQL Support (optional)
# ---------------------------------------------------------------------------

if USE_POSTGRES:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    
    # Fix for Railway PostgreSQL URLs (postgres:// -> postgresql://)
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    
    # Create connection pool
    _connection_pool: Optional[pool.ThreadedConnectionPool] = None
    _pool_lock = threading.Lock()
    
    def get_pool() -> pool.ThreadedConnectionPool:
        """Get or create the connection pool."""
        global _connection_pool
        if _connection_pool is None:
            with _pool_lock:
                if _connection_pool is None:
                    _connection_pool = pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=10,
                        dsn=DATABASE_URL,
                    )
        return _connection_pool
    
    @contextmanager
    def get_db_connection() -> Generator:
        """Context manager for database connections with automatic return to pool."""
        conn = get_pool().getconn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            get_pool().putconn(conn)
    
    @contextmanager
    def get_cursor() -> Generator:
        """Context manager for database cursors with dict-like rows."""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            try:
                yield cursor
            finally:
                cursor.close()

# ---------------------------------------------------------------------------
# JSON File Fallback (for local development)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MENU_PATH = BASE_DIR / "menu.json"
ORDERS_PATH = BASE_DIR / "orders.json"
OWNERS_PATH = BASE_DIR / "owners.json"
TABLES_PATH = BASE_DIR / "tables.json"

_orders_lock = threading.Lock()
_menu_lock = threading.Lock()
_tables_lock = threading.Lock()
_owners_lock = threading.Lock()


def _read_json(path: Path, default: Any) -> Any:
    """Read JSON from path, returning default on error."""
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def _write_json(path: Path, data: Any) -> None:
    """Write data as JSON to path atomically."""
    import tempfile
    try:
        fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".~", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError:
        raise

# ---------------------------------------------------------------------------
# Schema Initialization (PostgreSQL)
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
-- Owners table
CREATE TABLE IF NOT EXISTS owners (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tables table
CREATE TABLE IF NOT EXISTS tables (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Menu categories
CREATE TABLE IF NOT EXISTS menu_categories (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Menu items
CREATE TABLE IF NOT EXISTS menu_items (
    id VARCHAR(100) PRIMARY KEY,
    category_id VARCHAR(100) REFERENCES menu_categories(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description VARCHAR(500),
    price DECIMAL(10, 2) NOT NULL,
    tags TEXT[],
    available BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    customer_name VARCHAR(100) DEFAULT 'Guest',
    table_id VARCHAR(64) REFERENCES tables(id) ON DELETE SET NULL,
    table_name VARCHAR(100),
    status VARCHAR(20) DEFAULT 'pending',
    total DECIMAL(10, 2) NOT NULL,
    origin VARCHAR(20) DEFAULT 'online',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Order items (line items)
CREATE TABLE IF NOT EXISTS order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    item_id VARCHAR(100),
    item_name VARCHAR(200) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    line_total DECIMAL(10, 2) NOT NULL
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_menu_items_category ON menu_items(category_id);

-- Login attempts table for brute-force protection
CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address, attempted_at);
"""


def init_database() -> None:
    """Initialize database schema if using PostgreSQL."""
    if not USE_POSTGRES:
        # Initialize JSON files
        if not ORDERS_PATH.exists():
            _write_json(ORDERS_PATH, [])
        if not OWNERS_PATH.exists():
            _write_json(OWNERS_PATH, [])
        if not TABLES_PATH.exists():
            _write_json(TABLES_PATH, [])
        if not MENU_PATH.exists():
            _write_json(MENU_PATH, {"categories": []})
        return
    
    with get_cursor() as cursor:
        cursor.execute(SCHEMA_SQL)

# ---------------------------------------------------------------------------
# Owners CRUD
# ---------------------------------------------------------------------------

def get_owners() -> list[dict]:
    """Get all owners."""
    if not USE_POSTGRES:
        return _read_json(OWNERS_PATH, [])
    
    with get_cursor() as cursor:
        cursor.execute("SELECT id, username, email, password_hash, created_at FROM owners ORDER BY id")
        rows = cursor.fetchall()
        return [
            {
                "id": r["id"],
                "username": r["username"],
                "email": r.get("email"),
                "passwordHash": r["password_hash"],
                "createdAt": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]


def get_owner_by_identifier(identifier: str) -> Optional[dict]:
    """Get owner by username or email."""
    if not USE_POSTGRES:
        owners = _read_json(OWNERS_PATH, [])
        return next(
            (o for o in owners if o["username"] == identifier or o.get("email", "").lower() == identifier.lower()),
            None
        )
    
    with get_cursor() as cursor:
        cursor.execute(
            "SELECT id, username, email, password_hash, created_at FROM owners WHERE username = %s OR LOWER(email) = LOWER(%s)",
            (identifier, identifier)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "email": row.get("email"),
            "passwordHash": row["password_hash"],
            "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
        }


def create_owner(username: str, password_hash: str, email: Optional[str] = None) -> dict:
    """Create a new owner."""
    if not USE_POSTGRES:
        with _owners_lock:
            owners = _read_json(OWNERS_PATH, [])
            new_id = max((o.get("id", 0) for o in owners), default=0) + 1
            new_owner = {
                "id": new_id,
                "username": username,
                "passwordHash": password_hash,
                "email": email,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
            owners.append(new_owner)
            _write_json(OWNERS_PATH, owners)
            return new_owner
    
    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO owners (username, password_hash, email) VALUES (%s, %s, %s) RETURNING id, created_at",
            (username, password_hash, email)
        )
        row = cursor.fetchone()
        return {
            "id": row["id"],
            "username": username,
            "passwordHash": password_hash,
            "email": email,
            "createdAt": row["created_at"].isoformat(),
        }

# ---------------------------------------------------------------------------
# Tables CRUD
# ---------------------------------------------------------------------------

def get_tables() -> list[dict]:
    """Get all tables."""
    if not USE_POSTGRES:
        return _read_json(TABLES_PATH, [])
    
    with get_cursor() as cursor:
        cursor.execute("SELECT id, name, created_at FROM tables ORDER BY created_at")
        return [
            {"id": r["id"], "name": r["name"], "createdAt": r["created_at"].isoformat() if r["created_at"] else None}
            for r in cursor.fetchall()
        ]


def get_table(table_id: str) -> Optional[dict]:
    """Get a single table by ID."""
    if not USE_POSTGRES:
        tables = _read_json(TABLES_PATH, [])
        return next((t for t in tables if t["id"] == table_id), None)
    
    with get_cursor() as cursor:
        cursor.execute("SELECT id, name, created_at FROM tables WHERE id = %s", (table_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {"id": row["id"], "name": row["name"], "createdAt": row["created_at"].isoformat() if row["created_at"] else None}


def create_table(table_id: str, name: str) -> dict:
    """Create a new table."""
    if not USE_POSTGRES:
        with _tables_lock:
            tables = _read_json(TABLES_PATH, [])
            new_table = {
                "id": table_id,
                "name": name,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
            tables.append(new_table)
            _write_json(TABLES_PATH, tables)
            return new_table
    
    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO tables (id, name) VALUES (%s, %s) RETURNING created_at",
            (table_id, name)
        )
        row = cursor.fetchone()
        return {"id": table_id, "name": name, "createdAt": row["created_at"].isoformat()}


def delete_table(table_id: str) -> bool:
    """Delete a table by ID."""
    if not USE_POSTGRES:
        with _tables_lock:
            tables = _read_json(TABLES_PATH, [])
            filtered = [t for t in tables if t["id"] != table_id]
            if len(filtered) == len(tables):
                return False
            _write_json(TABLES_PATH, filtered)
            return True
    
    with get_cursor() as cursor:
        cursor.execute("DELETE FROM tables WHERE id = %s", (table_id,))
        return cursor.rowcount > 0


def next_table_number() -> int:
    """Get the next table number."""
    tables = get_tables()
    nums = []
    for t in tables:
        tid = t.get("id", "")
        if isinstance(tid, str) and tid.startswith("table-"):
            try:
                nums.append(int(tid[6:]))
            except ValueError:
                pass
    return max(nums, default=0) + 1

# ---------------------------------------------------------------------------
# Menu CRUD
# ---------------------------------------------------------------------------

def get_menu() -> dict:
    """Get the full menu with categories and items."""
    if not USE_POSTGRES:
        menu = _read_json(MENU_PATH, {"categories": []})
        # Ensure all categories have IDs
        import re
        existing_ids = set()
        changed = False
        for cat in menu.get("categories", []):
            if not cat.get("id"):
                slug = re.sub(r"[^\w\s-]", "", cat.get("name", "category").lower().strip())
                slug = re.sub(r"[\s_]+", "-", slug).strip("-") or "category"
                base = slug
                counter = 2
                while slug in existing_ids:
                    slug = f"{base}-{counter}"
                    counter += 1
                cat["id"] = slug
                changed = True
            existing_ids.add(cat["id"])
        if changed:
            _write_json(MENU_PATH, menu)
        return menu
    
    with get_cursor() as cursor:
        # Get categories
        cursor.execute("SELECT id, name, sort_order FROM menu_categories ORDER BY sort_order, name")
        categories = []
        for cat_row in cursor.fetchall():
            # Get items for this category
            cursor.execute(
                """SELECT id, name, description, price, tags, available 
                   FROM menu_items WHERE category_id = %s ORDER BY sort_order, name""",
                (cat_row["id"],)
            )
            items = [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "description": r["description"] or "",
                    "price": float(r["price"]),
                    "tags": r["tags"] or [],
                    "available": r["available"],
                }
                for r in cursor.fetchall()
            ]
            categories.append({
                "id": cat_row["id"],
                "name": cat_row["name"],
                "items": items,
            })
        return {"categories": categories}


def save_menu(menu: dict) -> None:
    """Save the entire menu (replace all)."""
    if not USE_POSTGRES:
        with _menu_lock:
            _write_json(MENU_PATH, menu)
        return
    
    with get_cursor() as cursor:
        # Clear existing menu
        cursor.execute("DELETE FROM menu_items")
        cursor.execute("DELETE FROM menu_categories")
        
        # Insert new categories and items
        for idx, cat in enumerate(menu.get("categories", [])):
            cursor.execute(
                "INSERT INTO menu_categories (id, name, sort_order) VALUES (%s, %s, %s)",
                (cat["id"], cat["name"], idx)
            )
            for item_idx, item in enumerate(cat.get("items", [])):
                cursor.execute(
                    """INSERT INTO menu_items (id, category_id, name, description, price, tags, sort_order)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (item["id"], cat["id"], item["name"], item.get("description", ""),
                     item["price"], item.get("tags", []), item_idx)
                )


def create_menu_category(category_id: str, name: str) -> dict:
    """Create a new menu category."""
    if not USE_POSTGRES:
        with _menu_lock:
            menu = _read_json(MENU_PATH, {"categories": []})
            new_cat = {"id": category_id, "name": name, "items": []}
            menu["categories"].append(new_cat)
            _write_json(MENU_PATH, menu)
            return new_cat
    
    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO menu_categories (id, name) VALUES (%s, %s) RETURNING sort_order",
            (category_id, name)
        )
        return {"id": category_id, "name": name, "items": []}


def delete_menu_category(category_id: str) -> bool:
    """Delete a menu category and all its items."""
    if not USE_POSTGRES:
        with _menu_lock:
            menu = _read_json(MENU_PATH, {"categories": []})
            original_len = len(menu["categories"])
            menu["categories"] = [c for c in menu["categories"] if c["id"] != category_id]
            if len(menu["categories"]) == original_len:
                return False
            _write_json(MENU_PATH, menu)
            return True
    
    with get_cursor() as cursor:
        cursor.execute("DELETE FROM menu_categories WHERE id = %s", (category_id,))
        return cursor.rowcount > 0


def rename_menu_category(category_id: str, new_name: str) -> bool:
    """Rename a menu category."""
    if not USE_POSTGRES:
        with _menu_lock:
            menu = _read_json(MENU_PATH, {"categories": []})
            for cat in menu["categories"]:
                if cat["id"] == category_id:
                    cat["name"] = new_name
                    _write_json(MENU_PATH, menu)
                    return True
            return False
    
    with get_cursor() as cursor:
        cursor.execute("UPDATE menu_categories SET name = %s WHERE id = %s", (new_name, category_id))
        return cursor.rowcount > 0


def save_menu_item(category_id: str, item_id: Optional[str], name: str, description: str, price: float, tags: list[str]) -> Optional[dict]:
    """Create or update a menu item."""
    import re
    
    if not USE_POSTGRES:
        with _menu_lock:
            menu = _read_json(MENU_PATH, {"categories": []})
            category = next((c for c in menu["categories"] if c["id"] == category_id), None)
            if not category:
                return None
            
            if item_id:
                # Update existing
                item = next((i for i in category["items"] if i["id"] == item_id), None)
                if item:
                    item.update({"name": name, "description": description, "price": price, "tags": tags})
                    _write_json(MENU_PATH, menu)
                    return item
                return None
            else:
                # Create new
                existing_ids = {i["id"] for c in menu["categories"] for i in c["items"]}
                slug = re.sub(r"[^\w\s-]", "", name.lower().strip())
                slug = re.sub(r"[\s_]+", "-", slug).strip("-") or "item"
                base = slug
                counter = 2
                while slug in existing_ids:
                    slug = f"{base}-{counter}"
                    counter += 1
                new_item = {"id": slug, "name": name, "description": description, "price": price, "tags": tags}
                category["items"].append(new_item)
                _write_json(MENU_PATH, menu)
                return new_item
    
    with get_cursor() as cursor:
        if item_id:
            cursor.execute(
                """UPDATE menu_items SET name = %s, description = %s, price = %s, tags = %s
                   WHERE id = %s AND category_id = %s RETURNING id""",
                (name, description, price, tags, item_id, category_id)
            )
            if cursor.rowcount == 0:
                return None
            return {"id": item_id, "name": name, "description": description, "price": price, "tags": tags}
        else:
            # Generate new ID
            slug = re.sub(r"[^\w\s-]", "", name.lower().strip())
            slug = re.sub(r"[\s_]+", "-", slug).strip("-") or "item"
            cursor.execute("SELECT id FROM menu_items WHERE id LIKE %s", (f"{slug}%",))
            existing = {r["id"] for r in cursor.fetchall()}
            base = slug
            counter = 2
            while slug in existing:
                slug = f"{base}-{counter}"
                counter += 1
            
            cursor.execute(
                """INSERT INTO menu_items (id, category_id, name, description, price, tags)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (slug, category_id, name, description, price, tags)
            )
            return {"id": slug, "name": name, "description": description, "price": price, "tags": tags}


def delete_menu_item(item_id: str) -> bool:
    """Delete a menu item."""
    if not USE_POSTGRES:
        with _menu_lock:
            menu = _read_json(MENU_PATH, {"categories": []})
            found = False
            for cat in menu["categories"]:
                original_len = len(cat["items"])
                cat["items"] = [i for i in cat["items"] if i["id"] != item_id]
                if len(cat["items"]) < original_len:
                    found = True
            if found:
                _write_json(MENU_PATH, menu)
            return found
    
    with get_cursor() as cursor:
        cursor.execute("DELETE FROM menu_items WHERE id = %s", (item_id,))
        return cursor.rowcount > 0

# ---------------------------------------------------------------------------
# Orders CRUD
# ---------------------------------------------------------------------------

def get_orders() -> list[dict]:
    """Get all orders with their items."""
    if not USE_POSTGRES:
        return _read_json(ORDERS_PATH, [])
    
    with get_cursor() as cursor:
        cursor.execute(
            """SELECT id, customer_name, table_id, table_name, status, total, origin, created_at, updated_at
               FROM orders ORDER BY created_at DESC"""
        )
        orders = []
        for row in cursor.fetchall():
            # Get order items
            cursor.execute(
                """SELECT item_id, item_name, price, quantity, line_total
                   FROM order_items WHERE order_id = %s""",
                (row["id"],)
            )
            items = [
                {
                    "id": r["item_id"],
                    "name": r["item_name"],
                    "price": float(r["price"]),
                    "quantity": r["quantity"],
                    "lineTotal": float(r["line_total"]),
                }
                for r in cursor.fetchall()
            ]
            orders.append({
                "id": row["id"],
                "customerName": row["customer_name"],
                "tableId": row["table_id"],
                "tableName": row["table_name"],
                "status": row["status"],
                "total": float(row["total"]),
                "origin": row["origin"],
                "items": items,
                "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
                "updatedAt": row["updated_at"].isoformat() if row["updated_at"] else None,
            })
        return orders


def get_order(order_id: int) -> Optional[dict]:
    """Get a single order by ID."""
    if not USE_POSTGRES:
        orders = _read_json(ORDERS_PATH, [])
        return next((o for o in orders if o["id"] == order_id), None)
    
    with get_cursor() as cursor:
        cursor.execute(
            """SELECT id, customer_name, table_id, table_name, status, total, origin, created_at
               FROM orders WHERE id = %s""",
            (order_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        
        cursor.execute(
            """SELECT item_id, item_name, price, quantity, line_total
               FROM order_items WHERE order_id = %s""",
            (order_id,)
        )
        items = [
            {
                "id": r["item_id"],
                "name": r["item_name"],
                "price": float(r["price"]),
                "quantity": r["quantity"],
                "lineTotal": float(r["line_total"]),
            }
            for r in cursor.fetchall()
        ]
        
        return {
            "id": row["id"],
            "customerName": row["customer_name"],
            "tableId": row["table_id"],
            "tableName": row["table_name"],
            "status": row["status"],
            "total": float(row["total"]),
            "origin": row["origin"],
            "items": items,
            "createdAt": row["created_at"].isoformat() if row["created_at"] else None,
        }


def create_order(customer_name: str, table_id: Optional[str], table_name: str, items: list[dict], total: float, origin: str) -> dict:
    """Create a new order."""
    if not USE_POSTGRES:
        with _orders_lock:
            orders = _read_json(ORDERS_PATH, [])
            new_id = max((o.get("id", 0) for o in orders), default=0) + 1
            new_order = {
                "id": new_id,
                "customerName": customer_name,
                "tableId": table_id,
                "tableName": table_name,
                "status": "pending",
                "total": total,
                "origin": origin,
                "items": items,
                "createdAt": datetime.now(timezone.utc).isoformat(),
            }
            orders.append(new_order)
            _write_json(ORDERS_PATH, orders)
            return new_order
    
    with get_cursor() as cursor:
        cursor.execute(
            """INSERT INTO orders (customer_name, table_id, table_name, total, origin)
               VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at""",
            (customer_name, table_id, table_name, total, origin)
        )
        row = cursor.fetchone()
        order_id = row["id"]
        created_at = row["created_at"]
        
        # Insert order items
        for item in items:
            cursor.execute(
                """INSERT INTO order_items (order_id, item_id, item_name, price, quantity, line_total)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (order_id, item["id"], item["name"], item["price"], item["quantity"], item["lineTotal"])
            )
        
        return {
            "id": order_id,
            "customerName": customer_name,
            "tableId": table_id,
            "tableName": table_name,
            "status": "pending",
            "total": total,
            "origin": origin,
            "items": items,
            "createdAt": created_at.isoformat(),
        }


def update_order_status(order_id: int, status: str) -> bool:
    """Update an order's status."""
    if not USE_POSTGRES:
        with _orders_lock:
            orders = _read_json(ORDERS_PATH, [])
            for order in orders:
                if order["id"] == order_id:
                    order["status"] = status
                    _write_json(ORDERS_PATH, orders)
                    return True
            return False
    
    with get_cursor() as cursor:
        cursor.execute(
            "UPDATE orders SET status = %s, updated_at = NOW() WHERE id = %s",
            (status, order_id)
        )
        return cursor.rowcount > 0

# ---------------------------------------------------------------------------
# Login Attempts (Brute-force protection)
# ---------------------------------------------------------------------------

def record_login_attempt(ip: str) -> None:
    """Record a failed login attempt."""
    if not USE_POSTGRES:
        return  # In-memory fallback in app.py
    
    with get_cursor() as cursor:
        cursor.execute(
            "INSERT INTO login_attempts (ip_address) VALUES (%s)",
            (ip,)
        )
        # Clean up old attempts (older than 1 hour)
        cursor.execute(
            "DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '1 hour'"
        )


def get_recent_login_attempts(ip: str, window_minutes: int = 15) -> int:
    """Get count of recent login attempts from an IP."""
    if not USE_POSTGRES:
        return 0  # Fallback to in-memory in app.py
    
    with get_cursor() as cursor:
        cursor.execute(
            """SELECT COUNT(*) as count FROM login_attempts 
               WHERE ip_address = %s AND attempted_at > NOW() - INTERVAL '%s minutes'""",
            (ip, window_minutes)
        )
        return cursor.fetchone()["count"]


def clear_login_attempts(ip: str) -> None:
    """Clear login attempts for an IP after successful login."""
    if not USE_POSTGRES:
        return
    
    with get_cursor() as cursor:
        cursor.execute("DELETE FROM login_attempts WHERE ip_address = %s", (ip,))
