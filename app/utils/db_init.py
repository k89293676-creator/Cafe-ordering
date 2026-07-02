"""Database initialisation: schema migrations and superadmin bootstrap.

These routines run inside an app context on first request and after the
app boots.  They are idempotent — safe to call multiple times.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone

log = logging.getLogger("cafe.db_init")

# ── Allowlists — protect against identifier injection ─────────────────────────
# All values passed to _add_column_if_missing come from internal call-sites
# only, never from user input.  These allowlists act as a defence-in-depth
# belt-and-suspenders guard so that future callers cannot accidentally pass
# externally sourced strings into raw SQL.

_ALLOWED_TABLES: frozenset[str] = frozenset({
    "orders", "owners", "settings", "cafes", "cafe_tables",
    "menus", "ingredients", "customers", "employees",
    "feedback", "table_calls", "order_employee_assignments",
    "remember_tokens", "owner_leads", "owner_invitations",
    "billing_logs", "cash_drawer_counts", "payment_credentials",
    "webhook_events", "audit_log", "online_payments",
    "aggregator_credentials", "aggregator_orders", "system_flags",
    "webhook_event_logs",
})

# Column names and type fragments must be plain identifiers + limited SQL keywords.
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
_COLTYPE_RE    = re.compile(
    # Allow letters, digits, spaces, underscores, commas, parens, dots,
    # and single-quoted string literals (e.g. DEFAULT 'unpaid', DEFAULT '').
    # Single quotes are explicitly permitted because all callers use hardcoded
    # internal strings — never user input.
    r"^[A-Z][A-Z0-9_ ,()'\.]{0,120}$",
    re.IGNORECASE,
)


def _safe_identifier(name: str, kind: str) -> str:
    """Raise ValueError if *name* fails the identifier allowlist check."""
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier for {kind}: {name!r}")
    return name


# ── Schema helpers ────────────────────────────────────────────────────────────

def _add_column_if_missing(conn, table: str, column: str, col_type: str) -> None:
    """Idempotently add a column to an existing table (SQLite & Postgres).

    All three parameters are validated against strict allowlists before
    being interpolated into the SQL string.
    """
    from sqlalchemy import text

    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Table not in allowlist: {table!r}")
    _safe_identifier(column, "column")
    if not _COLTYPE_RE.match(col_type):
        raise ValueError(f"Unsafe column type: {col_type!r}")

    try:
        conn.execute(text(f"SELECT {column} FROM {table} LIMIT 0"))
    except Exception:
        try:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
            log.info("Added column %s.%s", table, column)
        except Exception as exc:
            log.warning("Could not add %s.%s: %s", table, column, exc)


def _init_db() -> None:
    from app.extensions import db
    from sqlalchemy import text

    with db.engine.connect() as conn:
        # orders table evolution
        _add_column_if_missing(conn, "orders", "payment_status", "TEXT DEFAULT 'unpaid'")
        _add_column_if_missing(conn, "orders", "payment_method", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "discount", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "tax", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "service_charge", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "invoice_number", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "paid_at", "TIMESTAMP WITH TIME ZONE")
        _add_column_if_missing(conn, "orders", "settled_by", "INTEGER")
        _add_column_if_missing(conn, "orders", "payments_breakdown", "JSON")
        _add_column_if_missing(conn, "orders", "void_reason", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "refund_amount", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "refund_reason", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "customer_id", "INTEGER")
        _add_column_if_missing(conn, "orders", "cafe_id", "INTEGER")
        # owners table evolution
        _add_column_if_missing(conn, "owners", "is_superadmin", "BOOLEAN DEFAULT FALSE")
        _add_column_if_missing(conn, "owners", "totp_secret", "TEXT")
        _add_column_if_missing(conn, "owners", "totp_enabled", "BOOLEAN DEFAULT FALSE")
        _add_column_if_missing(conn, "owners", "phone", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "owners", "approval_status", "TEXT DEFAULT 'active'")
        _add_column_if_missing(conn, "owners", "plan_tier", "TEXT DEFAULT 'free'")
        _add_column_if_missing(conn, "owners", "max_tables", "INTEGER")
        _add_column_if_missing(conn, "owners", "max_menu_items", "INTEGER")
        _add_column_if_missing(conn, "owners", "monthly_order_limit", "INTEGER")
        _add_column_if_missing(conn, "owners", "trial_ends_at", "TIMESTAMP WITH TIME ZONE")
        _add_column_if_missing(conn, "owners", "notes", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "owners", "cafe_id", "INTEGER")
        _add_column_if_missing(conn, "owners", "google_place_id", "TEXT DEFAULT ''")
        # Stripe subscription columns
        _add_column_if_missing(conn, "owners", "stripe_customer_id", "TEXT")
        _add_column_if_missing(conn, "owners", "stripe_subscription_id", "TEXT")
        # Onboarding wizard — DEFAULT TRUE so existing owners are not force-redirected;
        # new owners get False via the ORM Python-level default at insert time.
        _add_column_if_missing(conn, "owners", "onboarding_complete", "BOOLEAN DEFAULT TRUE")
        # Per-owner currency code (ISO 4217 lower-case, e.g. 'gbp', 'usd')
        _add_column_if_missing(conn, "owners", "currency", "TEXT DEFAULT 'gbp'")
        # settings evolution
        _add_column_if_missing(conn, "settings", "tax_rate_percent", "NUMERIC(5,2) DEFAULT 0")
        _add_column_if_missing(conn, "settings", "tax_label", "TEXT DEFAULT 'GST'")
        _add_column_if_missing(conn, "settings", "gstin", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "settings", "service_charge_percent", "NUMERIC(5,2) DEFAULT 0")
        _add_column_if_missing(conn, "settings", "invoice_prefix", "TEXT DEFAULT 'INV'")
        _add_column_if_missing(conn, "settings", "invoice_seq", "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "settings", "billing_address", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "settings", "billing_phone", "TEXT DEFAULT ''")
        # ingredients evolution
        _add_column_if_missing(conn, "ingredients", "cost_per_unit", "NUMERIC(10,4) DEFAULT 0")
        _add_column_if_missing(conn, "ingredients", "cafe_id", "INTEGER")
        conn.commit()


def _make_superadmin_if_missing() -> None:
    """Bootstrap a superadmin owner from env vars if none exist yet."""
    from app.models import Owner
    from app.extensions import db
    from app.services.auth import _make_password_hash

    superadmin_username = os.environ.get("SUPERADMIN_USERNAME", "superadmin")
    superadmin_email = os.environ.get("SUPERADMIN_EMAIL", "")
    superadmin_password = os.environ.get("SUPERADMIN_PASSWORD", "")

    if not superadmin_password:
        return  # Don't bootstrap without an explicit password set

    existing = Owner.query.filter_by(is_superadmin=True).first()
    if existing:
        return

    # Also skip if the username already exists as a non-superadmin (avoid conflict).
    if Owner.query.filter_by(username=superadmin_username).first():
        return

    owner = Owner(
        username=superadmin_username,
        email=superadmin_email or None,
        password_hash=_make_password_hash(superadmin_password),
        cafe_name="Admin",
        is_active=True,
        is_superadmin=True,
    )
    db.session.add(owner)
    db.session.commit()
    log.info("Superadmin bootstrapped: %s", superadmin_username)
