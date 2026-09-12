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
# Failure in step 0 aborts the deploy. Steps 1-5 are non-fatal: a stuck or
# failed migration must never prevent gunicorn from binding a port (a hung
# `flask db upgrade` once burned the whole Render port-scan window). Each
# alembic revision is transactional, so retrying next deploy is safe, and
# the app self-heals schema at startup.
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

# ── Step 0a/0b: Package audits (single interpreter boot, not ~25) ──────────
# One python process imports everything: keeps pre-boot fast so Render's
# port scan sees gunicorn sooner. Critical set exits 1; optional only warns.
step_start "Auditing packages…"
AUDIT_RESULT="$(python3 - <<'PY'
import importlib
def _missing(mod):
    try:
        importlib.import_module(mod)
        return False
    except Exception:
        return True
critical = [
    ("flask", "Flask"), ("flask_sqlalchemy", "Flask-SQLAlchemy"),
    ("flask_migrate", "Flask-Migrate"), ("flask_login", "Flask-Login"),
    ("flask_bcrypt", "Flask-Bcrypt"), ("flask_limiter", "Flask-Limiter"),
    ("flask_compress", "Flask-Compress"), ("flask_talisman", "Flask-Talisman"),
    ("flask_wtf", "Flask-WTF"), ("flask_mail", "Flask-Mail"),
    ("flask_session", "Flask-Session"), ("sqlalchemy", "SQLAlchemy"),
    ("alembic", "alembic"), ("psycopg2", "psycopg2-binary"),
    ("cryptography", "cryptography"), ("gunicorn", "gunicorn"),
]
optional = [
    ("redis", "redis"), ("rq", "rq"), ("gevent", "gevent"),
    ("sentry_sdk", "sentry-sdk"), ("prometheus_client", "prometheus-client"),
    ("psutil", "psutil"), ("pandas", "pandas"),
    # Payment SDKs are load-bearing for checkout (lib_payments imports
    # them lazily). Warn loudly here so a missing SDK is visible in the
    # deploy log instead of surfacing as a customer-facing 500 later.
    ("razorpay", "razorpay-sdk"), ("stripe", "stripe-sdk"),
]
missing = [friendly for mod, friendly in critical if _missing(mod)]
warn = [friendly for mod, friendly in optional if _missing(mod)]
for w in warn:
    print(f"[release] WARN: optional package unavailable: {w}")
if missing:
    print("FATAL:" + ",".join(missing))
PY
)"
if [[ "${AUDIT_RESULT}" == FATAL:* ]]; then
  echo "[release] FATAL: critical packages missing:${AUDIT_RESULT#FATAL}" >&2
  echo "[release] Re-run the build or add the package to requirements.txt." >&2
  exit 1
fi
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

# ── Step 3: Migrations (bounded — must never wedge the deploy) ─────────────
# A hung `flask db upgrade` (DB lock wait, stalled connection, …) used to
# block `python start.py` indefinitely: gunicorn never bound a port and
# Render timed the deploy out. Each alembic revision runs in its own
# transaction, so killing a stuck upgrade is safe — the next deploy retries.
# The app additionally self-heals schema at startup (sync-schema safety net
# below + automatic table creation), so a skipped upgrade degrades to a
# warning, not an outage.
if [[ "${LEGACY_DB}" == "yes" ]]; then
  step_start "Legacy DB detected (no alembic_version) — stamping at head…"
  flask db stamp head
  step_done
else
  step_start "Running flask db upgrade (max ${MIGRATION_TIMEOUT_SECS:-240}s)…"
  echo "[release] DB at revision before upgrade: $(flask db current 2>/dev/null | tail -n 1 || echo unknown)"
  if timeout "${MIGRATION_TIMEOUT_SECS:-240}" flask db upgrade; then
    step_done
  else
    echo "[release] WARN: flask db upgrade failed or timed out — continuing to start." >&2
    echo "[release] WARN: sync-schema below + app startup self-heal still apply; investigate DB locks." >&2
  fi
fi

# ── Step 4: Idempotent schema sync (bounded + non-fatal) ───────────────────
# Same latent hang risk as db upgrade/current (stalled connection), so it
# gets its own timeout. Non-fatal: the app self-heals schema at startup.
step_start "Running flask sync-schema (idempotent ADD COLUMN safety net)…"
if timeout 120 flask sync-schema 2>&1; then
  step_done
else
  echo "[release] WARN: flask sync-schema unavailable, failed, or timed out — skipping (non-fatal)." >&2
fi

# ── Step 5: Audit trail (bounded) ───────────────────────────────────────────
# `flask db current` hung silently on one deploy (no output for 13+ min),
# wedging the whole start command. Bound it like everything else.
CURRENT_REV="$(timeout 60 flask db current 2>/dev/null | tail -n 1 || echo unknown)"
CURRENT_REV="${CURRENT_REV:-unknown}"
echo "[release] DB now at revision: ${CURRENT_REV}"
echo "[release] Release complete."
