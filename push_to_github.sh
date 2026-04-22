#!/usr/bin/env bash
# ============================================================
# Cafe 11:11 — push the current workspace to GitHub `main`.
#
# Usage:
#   bash push_to_github.sh                     # uses default commit message
#   bash push_to_github.sh "your message"      # custom commit message
#
# Reads the GitHub Personal Access Token from the GB_PAT secret
# already configured in this Replit. Pushes to:
#   https://github.com/k89293676-creator/Cafe-ordering  (branch: main)
#
# After a successful push, Railway will auto-deploy the new commit.
# ============================================================
set -euo pipefail

REPO_DIR="/home/runner/workspace"
GH_USER="k89293676-creator"
GH_REPO="Cafe-ordering"
BRANCH="main"

DEFAULT_MSG="feat: table calls tab, kitchen fixes, auto images, printable receipts, health checks (/health, /ready, /health/full, /metrics)"
COMMIT_MSG="${1:-$DEFAULT_MSG}"

cd "$REPO_DIR"

if [ -z "${GB_PAT:-}" ]; then
  echo "ERROR: GB_PAT secret is not set. Add it in Tools → Secrets." >&2
  exit 1
fi

# Clear any stale lock from previous aborted runs.
rm -f .git/index.lock

git config user.email "agent@replit.com"
git config user.name  "Replit Agent"

REMOTE_URL="https://${GB_PAT}@github.com/${GH_USER}/${GH_REPO}.git"
git remote set-url origin "$REMOTE_URL"

# Make sure we're on `main`. If the local branch has another name,
# create/switch to main pointing at the current HEAD.
CURRENT="$(git symbolic-ref --quiet --short HEAD || echo '')"
if [ "$CURRENT" != "$BRANCH" ]; then
  git checkout -B "$BRANCH"
fi

git add -A

# Commit only when there are staged changes; allow the script to
# re-push existing commits (e.g. after a previous failed push).
if ! git diff --cached --quiet; then
  git commit -m "$COMMIT_MSG"
  echo "==> Committed: $COMMIT_MSG"
else
  echo "==> No new changes to commit; pushing existing HEAD."
fi

echo "==> Pushing to ${GH_USER}/${GH_REPO}@${BRANCH} ..."
git push origin "HEAD:${BRANCH}"

echo ""
echo "✓ Push complete. Railway will pick up the new commit and redeploy."
echo "  Health endpoints once live:"
echo "    /health        liveness (cheap)"
echo "    /ready         DB readiness"
echo "    /health/full   deep diagnostics (DB, disk, redis, runtime)"
echo "    /metrics       aggregate runtime metrics"
