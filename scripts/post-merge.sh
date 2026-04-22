#!/usr/bin/env bash
# Post-merge setup for the Cafe-ordering Flask app.
#
# Replit manages this project's Python dependencies in a persistent .pythonlibs
# venv via the package-management tooling. Those packages survive merges, so
# this script simply reports the current state and lets the workflow restart
# pick up the merged code. If a future merge introduces new packages the agent
# will install them on demand using the package-management tools.
set -euo pipefail

echo "[post-merge] python: $(python3 --version 2>&1)"

if [ -d .pythonlibs ]; then
  echo "[post-merge] Persistent .pythonlibs venv detected — packages preserved across merges"
fi

if [ -f requirements.txt ]; then
  echo "[post-merge] requirements.txt present ($(wc -l < requirements.txt | tr -d ' ') lines)"
fi

# Quick sanity import to surface a missing-dependency situation early.
python3 - <<'PY' || true
try:
    import flask, sqlalchemy  # noqa: F401
    print("[post-merge] core imports OK (flask, sqlalchemy)")
except Exception as exc:  # noqa: BLE001
    print(f"[post-merge] WARNING: core import failed: {exc}")
PY

echo "[post-merge] done"
