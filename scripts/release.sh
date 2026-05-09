#!/usr/bin/env bash
# Railway pre-deploy release step.
#
# Runs once per deploy, BEFORE the new container starts serving traffic, so
# schema changes apply atomically and the first request never races a
# half-migrated DB. Idempotent: safe to re-run.
#
# Pipeline:
#   0a. Critical package audit — exits 1 if a load-bearing package is missing.
#   0b. Optional package audit — warns but continues for extras like sentry/rq.
#   0c. Flask extensions smoke-test — imports app.extensions to verify the
#       singleton wiring introduced in the refactor (no I/O, no DB required).
#   1.  Skip cleanly if DATABASE_URL is unset (preview env without DB).
#   2.  Detect legacy DB (tables but no alembic_version) → stamp HEAD.
#   3.  flask db upgrade — apply tracked alembic migrations.
#   4.  flask sync-schema — idempotent CREATE TABLE IF NOT EXISTS safety net.
#   5.  flask db current — log the active revision.
#
# Failure in steps 0-3 aborts the deploy. Steps 4-5 are non-fatal so a
# missing CLI command never blocks a legitimate deploy.
#
# NOTE: SECRET_KEY and other runtime env vars are NOT validated here because
# Railway does not inject Variables into the pre-deploy environment. Runtime
# validation runs in start.py immediately before gunicorn forks workers.

set -euo pipefail

_STEP_START=0
step_start() {
  _STEP_START=$(date +%s 2>/dev/null || echo 0)
  echo "[release] $*"
}
step_done() {
  local now elapsed
  now=$(date +%s 2>/dev/null || echo 0)
  elapsed=$(( now - _STEP_START ))
  echo "[release] done (${elapsed}s)"
}

# ── Step 0a: Critical package audit ───────────────────────────────────────
# These packages must import cleanly or the app cannot start at all.
step_start "Auditing critical packages…"
MISSING_PKGS=""
audit_critical() {
  local import_name="$1" friendly="$2"
  if ! python3 -c "import ${import_name}" 2>/dev/null; then
    echo "[release] MISSING critical package: ${friendly} (import ${import_name} failed)" >&2
    MISSING_PKGS="${MISSING_PKGS} ${friendly}"
  fi
}

audit_critical flask               "Flask"
audit_critical flask_sqlalchemy    "Flask-SQLAlchemy"
audit_critical flask_migrate       "Flask-Migrate"
audit_critical flask_login         "Flask-Login"
audit_critical flask_bcrypt        "Flask-Bcrypt"
audit_critical flask_limiter       "Flask-Limiter"
audit_critical flask_compress      "Flask-Compress"
audit_critical flask_talisman      "Flask-Talisman"
audit_critical flask_wtf           "Flask-WTF"
audit_critical flask_mail          "Flask-Mail"
audit_critical flask_session       "Flask-Session"
audit_critical sqlalchemy          "SQLAlchemy"
audit_critical alembic             "alembic"
audit_critical psycopg2            "psycopg2-binary"
audit_critical cryptography        "cryptography"
audit_critical gunicorn            "gunicorn"

if [[ -n "${MISSING_PKGS}" ]]; then
  echo "[release] FATAL: critical packages missing:${MISSING_PKGS}" >&2
  echo "[release] Re-run the build or add the package to requirements.txt." >&2
  exit 1
fi
step_done

# ── Step 0b: Optional package audit (warn-only) ────────────────────────────
# These are runtime extras whose absence degrades functionality but does not
# prevent the app from starting. A failed C-extension build (gevent, redis)
# after a successful pip install is common on some container runtimes.
step_start "Auditing optional packages…"
audit_optional() {
  local import_name="$1" friendly="$2"
  if ! python3 -c "import ${import_name}" 2>/dev/null; then
    echo "[release] WARN: optional package unavailable: ${friendly} (import ${import_name} failed)" >&2
  fi
}

audit_optional redis              "redis"
audit_optional rq                 "rq"
audit_optional gevent             "gevent"
audit_optional sentry_sdk         "sentry-sdk"
audit_optional prometheus_client  "prometheus-client"
audit_optional psutil             "psutil"
audit_optional pandas             "pandas"
step_done

# ── Step 0c: Flask extensions smoke-test ──────────────────────────────────
# Import app.extensions to verify the singleton wiring (db, session_store,
# etc.) is correct. This is a pure-Python check — no DB, no Redis, no I/O.
# It catches circular-import regressions and missing __init__ re-exports
# before we attempt any DB operation.
step_start "Running Flask extensions smoke-test…"
python3 - <<'PY'
import sys, os

# Provide a dummy SECRET_KEY so FlaskConfig doesn't see an empty string.
# The real key is injected by Railway at runtime, not during pre-deploy.
os.environ.setdefault("SECRET_KEY", "release-smoke-test-placeholder")

try:
    from app.extensions import db, session_store, migrate, bcrypt, compress
    from app.extensions import csrf, limiter, login_manager, mail
    from app.config import FlaskConfig
except ImportError as exc:
    print(f"[release] FATAL: extensions smoke-test failed: {exc}", file=sys.stderr)
    sys.exit(1)

# session_store must be a Flask-Session Session object (or None if
# flask-session somehow isn't installed despite passing the audit above).
if session_store is None:
    print("[release] WARN: session_store is None — flask-session not installed.", file=sys.stderr)

print("[release] extensions smoke-test passed.")
PY
step_done

# ── Step 1: Skip when no DB is configured ─────────────────────────────────
if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[release] DATABASE_URL not set — skipping migrations."
  exit 0
fi

export FLASK_APP="${FLASK_APP:-app}"

# ── Step 2: Detect legacy DB ──────────────────────────────────────────────
step_start "Inspecting alembic state…"
LEGACY_DB="$(python3 - <<'PY'
import os, sys
from sqlalchemy import create_engine, inspect, text

url = os.environ["DATABASE_URL"]
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)

try:
    # connect_timeout prevents hanging when the DB host is briefly unreachable.
    engine = create_engine(
        url,
        connect_args={"connect_timeout": 10},
        pool_pre_ping=True,
    )
    with engine.connect() as conn:
        tables = set(
            row[0] for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        )
except Exception as exc:
    print(f"inspect-failed: {exc}", file=sys.stderr)
    print("no")
    sys.exit(0)

print("yes" if ("owners" in tables and "alembic_version" not in tables) else "no")
PY
)"
step_done

# ── Step 3: Migrations ────────────────────────────────────────────────────
if [[ "${LEGACY_DB}" == "yes" ]]; then
  step_start "Legacy DB detected (no alembic_version) — stamping at head…"
  flask db stamp head
  step_done
else
  step_start "Running flask db upgrade…"
  flask db upgrade
  step_done
fi

# ── Step 4: Idempotent schema sync (non-fatal) ────────────────────────────
step_start "Running flask sync-schema (idempotent ADD COLUMN safety net)…"
if flask sync-schema 2>&1; then
  step_done
else
  echo "[release] WARN: flask sync-schema unavailable or failed — skipping (non-fatal)." >&2
fi

# ── Step 5: Audit trail ───────────────────────────────────────────────────
CURRENT_REV="$(flask db current 2>/dev/null | tail -n 1 || true)"
echo "[release] DB now at revision: ${CURRENT_REV}"
echo "[release] Release complete."
