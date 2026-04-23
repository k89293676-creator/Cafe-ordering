#!/usr/bin/env bash
# Railway pre-deploy release step.
#
# Runs once per deploy, BEFORE the new container starts serving traffic, so
# schema changes apply atomically and the first request never races a
# half-migrated DB. Idempotent: safe to re-run.
#
# Pipeline:
#   1. Skip cleanly if DATABASE_URL is unset (e.g. preview env without DB).
#   2. If the DB already has app tables but no alembic_version (legacy DBs that
#      were bootstrapped via db.create_all() before Flask-Migrate landed),
#      stamp them at HEAD instead of replaying every CREATE TABLE on top of
#      an already-current schema.
#   3. flask db upgrade — apply tracked alembic migrations.
#   4. flask sync-schema — idempotent CREATE TABLE IF NOT EXISTS + ADD COLUMN
#      IF NOT EXISTS pass that catches anything added to models since the
#      last migration. Without this step a brand-new column would only land
#      on the first request after deploy (worker-local, racey under load).
#   5. flask db current — log the active revision so deploys are auditable.
#
# Failure here aborts the deploy — Railway will keep the previous revision
# serving traffic, which is exactly what we want for schema safety.

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[release] DATABASE_URL not set — skipping migrations." >&2
  exit 0
fi

export FLASK_APP="${FLASK_APP:-app}"

echo "[release] Inspecting alembic state…"

# Detect "legacy DB" = app tables already exist but alembic was never wired up.
# `owners` is one of the original tables and is guaranteed to exist on any
# previously-deployed instance.
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

if [[ "${LEGACY_DB}" == "yes" ]]; then
  echo "[release] Legacy DB detected (no alembic_version table) — stamping at head."
  flask db stamp head
  echo "[release] Stamp complete."
else
  echo "[release] Running flask db upgrade…"
  flask db upgrade
  echo "[release] Migrations applied."
fi

# Catch any model additions that don't yet have a migration. Idempotent.
echo "[release] Running flask sync-schema (idempotent CREATE/ADD COLUMN safety net)…"
flask sync-schema
echo "[release] Schema sync complete."

# Log the active revision for audit trails.
CURRENT_REV="$(flask db current 2>/dev/null | tail -n 1 || true)"
echo "[release] DB now at revision: ${CURRENT_REV}"
echo "[release] Done."
