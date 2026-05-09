#!/usr/bin/env bash
# Railway pre-deploy release step.
#
# Runs once per deploy, BEFORE the new container starts serving traffic, so
# schema changes apply atomically and the first request never races a
# half-migrated DB. Idempotent: safe to re-run.
#
# Pipeline:
#   0. Verify critical Python packages are importable (catches a missing pip
#      install before any DB work begins, keeping the failure message clean).
#   1. Validate required environment variables are set.
#   2. Skip cleanly if DATABASE_URL is unset (e.g. preview env without DB).
#   3. If the DB already has app tables but no alembic_version (legacy DBs
#      bootstrapped via db.create_all() before Flask-Migrate), stamp them at
#      HEAD instead of replaying every CREATE TABLE on top of an already-
#      current schema.
#   4. flask db upgrade — apply tracked alembic migrations.
#   5. flask sync-schema — idempotent CREATE TABLE IF NOT EXISTS + ADD COLUMN
#      IF NOT EXISTS pass that catches anything added to models since the last
#      migration. Without this step a brand-new column would only land on the
#      first request after deploy (worker-local, racey under load).
#   6. flask db current — log the active revision so deploys are auditable.
#
# Failure here aborts the deploy — Railway will keep the previous revision
# serving traffic, which is exactly what we want for schema safety.

set -euo pipefail

_STEP_START=""
step_start() { _STEP_START=$(date +%s%N 2>/dev/null || date +%s); echo "[release] $*"; }
step_done()  {
  local now; now=$(date +%s%N 2>/dev/null || date +%s)
  # Nanoseconds available → show ms; else show s
  if [[ ${#now} -gt 10 ]]; then
    echo "[release] done ($(( (now - _STEP_START) / 1000000 ))ms)"
  else
    echo "[release] done ($((now - _STEP_START))s)"
  fi
}

# ── Step 0: Package audit ──────────────────────────────────────────────────
# Verify every package that the app will import on first request is actually
# installed. This catches a broken/cached pip layer early with a clear error
# instead of a cryptic ImportError at runtime.
step_start "Auditing installed packages…"
MISSING_PKGS=""
audit_pkg() {
  local import_name="$1" friendly="$2"
  if ! python3 -c "import ${import_name}" 2>/dev/null; then
    echo "[release] MISSING package: ${friendly} (import ${import_name} failed)" >&2
    MISSING_PKGS="${MISSING_PKGS} ${friendly}"
  fi
}

audit_pkg flask                  "Flask"
audit_pkg flask_session           "Flask-Session"
audit_pkg flask_sqlalchemy        "Flask-SQLAlchemy"
audit_pkg flask_migrate           "Flask-Migrate"
audit_pkg flask_login             "Flask-Login"
audit_pkg flask_bcrypt            "Flask-Bcrypt"
audit_pkg flask_limiter           "Flask-Limiter"
audit_pkg flask_compress          "Flask-Compress"
audit_pkg flask_talisman          "Flask-Talisman"
audit_pkg flask_wtf               "Flask-WTF"
audit_pkg flask_mail              "Flask-Mail"
audit_pkg sqlalchemy              "SQLAlchemy"
audit_pkg alembic                 "alembic"
audit_pkg psycopg2                "psycopg2-binary"
audit_pkg redis                   "redis"
audit_pkg rq                      "rq"
audit_pkg gevent                  "gevent"
audit_pkg gunicorn                "gunicorn"
audit_pkg cryptography            "cryptography"
audit_pkg sentry_sdk              "sentry-sdk"
audit_pkg prometheus_client       "prometheus-client"

if [[ -n "${MISSING_PKGS}" ]]; then
  echo "[release] FATAL: the following packages are not installed:${MISSING_PKGS}" >&2
  echo "[release] Re-run the build step or add the package to requirements.txt." >&2
  exit 1
fi
step_done

# ── Step 1: Environment validation ────────────────────────────────────────
step_start "Validating environment variables…"

# SECRET_KEY must be set and long enough to be useful.
if [[ -z "${SECRET_KEY:-}" ]]; then
  echo "[release] FATAL: SECRET_KEY is not set. Set it in Railway Variables." >&2
  exit 1
fi
if [[ "${#SECRET_KEY}" -lt 24 ]]; then
  echo "[release] FATAL: SECRET_KEY is too short (${#SECRET_KEY} chars, need ≥ 24)." >&2
  exit 1
fi

step_done

# ── Step 2: Skip when no DB is configured ─────────────────────────────────
if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[release] DATABASE_URL not set — skipping migrations." >&2
  exit 0
fi

export FLASK_APP="${FLASK_APP:-app}"

# ── Step 3: Detect legacy DB ──────────────────────────────────────────────
step_start "Inspecting alembic state…"
LEGACY_DB="$(python3 - <<'PY'
import os, sys
from sqlalchemy import create_engine, inspect
url = os.environ["DATABASE_URL"]
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql://", 1)
try:
    insp = inspect(create_engine(url))
    tables = set(insp.get_table_names())
except Exception as exc:
    print("inspect-failed", exc, file=sys.stderr)
    print("no")
    sys.exit(0)
print("yes" if ("owners" in tables and "alembic_version" not in tables) else "no")
PY
)"
step_done

# ── Step 4: Migrations ────────────────────────────────────────────────────
if [[ "${LEGACY_DB}" == "yes" ]]; then
  step_start "Legacy DB detected (no alembic_version) — stamping at head…"
  flask db stamp head
  step_done
else
  step_start "Running flask db upgrade…"
  flask db upgrade
  step_done
fi

# ── Step 5: Idempotent schema sync ────────────────────────────────────────
# Catches model columns added since the last migration. Non-fatal: if the CLI
# command isn't registered (older deploy) the script continues.
step_start "Running flask sync-schema (idempotent ADD COLUMN safety net)…"
if flask sync-schema; then
  step_done
else
  echo "[release] WARN: flask sync-schema unavailable or failed — skipping (non-fatal)." >&2
fi

# ── Step 6: Audit trail ───────────────────────────────────────────────────
CURRENT_REV="$(flask db current 2>/dev/null | tail -n 1 || true)"
echo "[release] DB now at revision: ${CURRENT_REV}"
echo "[release] Release complete."
