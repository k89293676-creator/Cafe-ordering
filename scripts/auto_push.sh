#!/usr/bin/env bash
# Auto-commit and push current working tree to origin/main using the GB_PAT
# secret. Safe to call repeatedly: a no-op when there are no staged changes.
#
# Usage:
#   GB_PAT=... ./scripts/auto_push.sh ["optional commit message"]

set -euo pipefail

if [[ -z "${GB_PAT:-}" ]]; then
  echo "auto_push: GB_PAT env var is not set." >&2
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

git config user.email "agent@cafe-ordering.local"
git config user.name  "cafe-ordering-agent"

git add -A

if git diff --cached --quiet; then
  echo "auto_push: nothing to commit."
  exit 0
fi

MSG="${1:-chore(agent): automated update $(date -u +%Y-%m-%dT%H:%M:%SZ)}"
git commit -m "$MSG"

REPO_PATH="$(git config --get remote.origin.url \
  | sed -E 's#https?://[^/]+/##' )"

git push "https://k89293676-creator:${GB_PAT}@github.com/${REPO_PATH}" HEAD:main
echo "auto_push: pushed to origin/main."
