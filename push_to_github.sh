#!/usr/bin/env bash
# Run this script from the cafe-ordering directory to push the changes to GitHub.
# Usage: bash push_to_github.sh
set -e

BRANCH="fixes-admin-upgrade"

echo "Creating branch: $BRANCH"
git checkout -b "$BRANCH"

echo "Staging all changes..."
git add -A

echo "Committing..."
git commit -m "Bug fixes + Super Admin dashboard

- Add is_active field to owners (DB + JSON modes)
- Block login for deactivated owner accounts
- Register Super Admin blueprint at /admin
  - /admin/dashboard  — summary stats + owner list
  - /admin/owners     — manage owners, reset passwords, toggle active
  - /admin/analytics  — global revenue + top items + daily chart
  - /admin/status     — disk usage, DB health, file sizes
- Admin login via session (ADMIN_SECRET_KEY env var)
- All bug fixes already in codebase:
  - Atomic JSON writes (portalocker + os.replace)
  - SECRET_KEY enforcement in production
  - File upload MIME type validation
  - Rate limiter with Redis fallback
  - Structured JSON logging + rotating file handler
  - Health endpoint at /health"

echo "Setting remote with PAT..."
git remote set-url origin "https://${PAT_TOKEN}@github.com/k89293676-creator/Cafe-ordering.git"

echo "Pushing to origin/$BRANCH..."
git push origin "$BRANCH"

echo ""
echo "Done! Branch pushed: $BRANCH"
echo ""
echo "Railway deploy URL:"
echo "https://railway.app/new/template?template=https://github.com/k89293676-creator/Cafe-ordering&branch=$BRANCH&env=SECRET_KEY,IS_PRODUCTION,DATABASE_URL,REDIS_URL,ADMIN_SECRET_KEY"
echo ""
echo "Remember to set in Railway dashboard:"
echo "  SECRET_KEY       = <long random string>"
echo "  ADMIN_SECRET_KEY = <separate long random string>"
echo "  IS_PRODUCTION    = true"
echo ""
echo "Access admin panel at: https://your-app.railway.app/admin"
