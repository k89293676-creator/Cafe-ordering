"""Database initialisation: schema migrations and superadmin bootstrap.

These routines run inside an app context on first request and after the
app boots.  They are idempotent — safe to call multiple times.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone

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

    IMPORTANT — PostgreSQL transaction safety:
    In PostgreSQL, any failed SQL statement aborts the *entire* transaction.
    Without a SAVEPOINT, the SELECT existence-check that fails (column not
    found) leaves the connection in "transaction aborted" state so that every
    subsequent SQL — including the ALTER TABLE — also fails silently.  We
    wrap the check in a SAVEPOINT/ROLLBACK TO SAVEPOINT so a failed SELECT
    rolls back only to the savepoint, restoring a clean transaction state
    before the ALTER TABLE runs.
    """
    from sqlalchemy import text

    if table not in _ALLOWED_TABLES:
        raise ValueError(f"Table not in allowlist: {table!r}")
    _safe_identifier(column, "column")
    if not _COLTYPE_RE.match(col_type):
        raise ValueError(f"Unsafe column type: {col_type!r}")

    _sp = "_acm_check"  # savepoint name
    try:
        conn.execute(text(f"SAVEPOINT {_sp}"))
        try:
            conn.execute(text(f"SELECT {column} FROM {table} LIMIT 0"))
            conn.execute(text(f"RELEASE SAVEPOINT {_sp}"))
            return  # column already exists — nothing to do
        except Exception:
            # Column missing: roll back to savepoint so the outer transaction
            # is clean and the ALTER TABLE below can run successfully.
            conn.execute(text(f"ROLLBACK TO SAVEPOINT {_sp}"))
    except Exception:
        # SAVEPOINT not supported by this driver/DB; fall through to ALTER TABLE.
        # If the column already exists ALTER TABLE will raise and we warn below.
        pass

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
        # orders additional evolution (columns added after initial schema)
        _add_column_if_missing(conn, "orders", "table_name", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "customer_email", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "customer_phone", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "modifiers", "JSON")
        _add_column_if_missing(conn, "orders", "subtotal", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "tip", "NUMERIC(10,2) DEFAULT 0")
        _add_column_if_missing(conn, "orders", "pickup_code", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "origin", "TEXT DEFAULT 'table'")
        _add_column_if_missing(conn, "orders", "notes", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "orders", "updated_at", "TIMESTAMP WITH TIME ZONE")
        # cafe_tables evolution
        _add_column_if_missing(conn, "cafe_tables", "cafe_id", "INTEGER")
        _add_column_if_missing(conn, "cafe_tables", "created_at", "TIMESTAMP WITH TIME ZONE")
        # menus evolution
        _add_column_if_missing(conn, "menus", "cafe_id", "INTEGER")
        # ingredients evolution
        _add_column_if_missing(conn, "ingredients", "cost_per_unit", "NUMERIC(10,4) DEFAULT 0")
        _add_column_if_missing(conn, "ingredients", "cafe_id", "INTEGER")
        _add_column_if_missing(conn, "ingredients", "menu_item_id", "TEXT")
        _add_column_if_missing(conn, "ingredients", "qty_per_order", "NUMERIC(10,3) DEFAULT 1")
        _add_column_if_missing(conn, "ingredients", "created_at", "TIMESTAMP WITH TIME ZONE")
        # feedback evolution
        _add_column_if_missing(conn, "feedback", "cafe_id", "INTEGER")
        _add_column_if_missing(conn, "feedback", "order_id", "INTEGER")
        # settings evolution (additional)
        _add_column_if_missing(conn, "settings", "updated_at", "TIMESTAMP WITH TIME ZONE")
        # employees evolution
        _add_column_if_missing(conn, "employees", "cafe_id", "INTEGER")
        # table_calls evolution
        _add_column_if_missing(conn, "table_calls", "cafe_id", "INTEGER")
        _add_column_if_missing(conn, "table_calls", "acknowledged_at", "TIMESTAMP WITH TIME ZONE")
        _add_column_if_missing(conn, "table_calls", "resolved_at", "TIMESTAMP WITH TIME ZONE")
        _add_column_if_missing(conn, "table_calls", "resolved_by_employee_id", "INTEGER")
        conn.commit()

        # ── Idempotent correction: restore owners broken by prior DEFAULT FALSE backfill ──
        # A prior deployment added onboarding_complete with DEFAULT FALSE, which PostgreSQL
        # backfills ALL existing rows to FALSE. This UPDATE is naturally idempotent:
        # it updates only rows that are still FALSE or NULL and were created more than
        # 30 minutes ago (to leave genuinely in-progress onboarding signups untouched).
        # Once all affected owners are corrected, subsequent startups update zero rows.
        # Intentionally NOT gated on system_flags — that SELECT fails if the table
        # does not yet exist (e.g. after db.create_all() errors at startup), which
        # would abort the whole correction silently.
        try:
            _corr_cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
            _corr_result = conn.execute(
                text(
                    "UPDATE owners SET onboarding_complete = TRUE "
                    "WHERE (onboarding_complete = FALSE OR onboarding_complete IS NULL) "
                    "AND (created_at IS NULL OR created_at < :cutoff)"
                ),
                {"cutoff": _corr_cutoff.isoformat()},
            )
            conn.commit()
            if getattr(_corr_result, "rowcount", 0):
                log.info(
                    "Corrected onboarding_complete=TRUE for %s pre-existing owner(s).",
                    _corr_result.rowcount,
                )
        except Exception as _corr_exc:
            log.warning("Could not apply onboarding_complete correction: %s", _corr_exc)


def _make_superadmin_if_missing() -> None:
    """Bootstrap a superadmin owner from env vars if none exist yet.

    FIX for Render: previously required SUPERADMIN_PASSWORD to be set, but
    render.yaml didn't expose it, so deploys never got a superadmin and
    /superadmin + /admin both returned 403. Now:
      - If SUPERADMIN_PASSWORD is set, ensure a superadmin exists with that
        password (create or update).
      - If no superadmin exists at all and no password is set, auto-generate
        a random password, create the account, and LOG the credentials once
        so the operator can copy it from Render logs/Dashboard.
    """
    from app.models import Owner
    from app.extensions import db
    from app.services.auth import _make_password_hash
    import secrets as _secrets

    superadmin_username = os.environ.get("SUPERADMIN_USERNAME", "superadmin")
    superadmin_email = os.environ.get("SUPERADMIN_EMAIL", "")
    superadmin_password = os.environ.get("SUPERADMIN_PASSWORD", "")

    existing_sa = Owner.query.filter_by(is_superadmin=True).first()

    # Case 1: password supplied via env → ensure account exists and password matches
    if superadmin_password:
        if existing_sa:
            # If password differs from stored hash, update it (allows rotation)
            from app.services.auth import _password_matches
            try:
                if not _password_matches(existing_sa.password_hash, superadmin_password):
                    existing_sa.password_hash = _make_password_hash(superadmin_password)
                    existing_sa.is_active = True
                    db.session.commit()
                    log.info("Superadmin password rotated from env: %s", superadmin_username)
            except Exception:
                pass
            return
        # No superadmin yet — create with supplied password
        if Owner.query.filter_by(username=superadmin_username).first():
            # Username collision with non-superadmin: promote instead
            owner = Owner.query.filter_by(username=superadmin_username).first()
            if owner:
                owner.is_superadmin = True
                owner.is_active = True
                owner.password_hash = _make_password_hash(superadmin_password)
                db.session.commit()
                log.info("Promoted existing user to superadmin: %s", superadmin_username)
                return
            return
        owner = Owner(
            username=superadmin_username,
            email=superadmin_email or None,
            password_hash=_make_password_hash(superadmin_password),
            cafe_name="Admin",
            is_active=True,
            is_superadmin=True,
            onboarding_complete=True,
        )
        db.session.add(owner)
        db.session.commit()
        log.info("Superadmin bootstrapped from env: %s", superadmin_username)
        # Also print to stdout so Render logs surface it without log-level filtering
        print(f"[bootstrap] superadmin created: {superadmin_username} (password from SUPERADMIN_PASSWORD)", flush=True)
        return

    # Case 2: no password env, but no superadmin exists → auto-generate
    if not existing_sa:
        # Only auto-generate in production (Render) or when explicitly opted in;
        # local dev without env should not create unexpected accounts.
        is_render = os.environ.get("RENDER") is not None
        is_prod = os.environ.get("FLASK_ENV") == "production" or os.environ.get("IS_PRODUCTION","").lower() in {"1","true","yes"}
        if not (is_render or is_prod):
            log.info("No SUPERADMIN_PASSWORD set and not in production — skip auto-bootstrap.")
            return
        auto_pw = _secrets.token_urlsafe(16)
        if Owner.query.filter_by(username=superadmin_username).first():
            return
        owner = Owner(
            username=superadmin_username,
            email=superadmin_email or None,
            password_hash=_make_password_hash(auto_pw),
            cafe_name="Admin",
            is_active=True,
            is_superadmin=True,
            onboarding_complete=True,
        )
        db.session.add(owner)
        db.session.commit()
        # CRITICAL: log credentials exactly once for operator retrieval
        log.warning("AUTO-GENERATED SUPERADMIN — username=%s password=%s — copy this now, it is not stored in plaintext", superadmin_username, auto_pw)
        print(f"[bootstrap] AUTO-GENERATED SUPERADMIN username={superadmin_username} password={auto_pw}", flush=True)
        print(f"[bootstrap] Log in at /owner/login then visit /superadmin", flush=True)
