#!/usr/bin/env bash
# Push the saas-upgrade branch to GitHub.
# Usage: GITHUB_PAT=<token> bash push_to_github.sh
set -e

BRANCH="saas-upgrade"
REMOTE="https://${GITHUB_PAT}@github.com/k89293676-creator/Cafe-ordering.git"

echo "==> Initialising git repo in current directory..."
git init
git config user.email "agent@replit.com"
git config user.name "Replit Agent"

echo "==> Configuring remote..."
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"

echo "==> Creating branch: $BRANCH"
git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"

echo "==> Staging all files..."
git add -A

echo "==> Committing..."
git commit -m "feat: SaaS upgrade - multi-tenant, pay-at-counter, 2FA, kitchen, inventory, reports

- Remove Stripe; add Pay at Counter with 6-digit pickup codes
- Order lifecycle: pending -> confirmed -> preparing -> ready -> completed
- Add Superadmin with /superadmin dashboard (owner/cafe CRUD, analytics)
- Multi-tenant Cafe model scoping all data by cafe_id
- Railway /health endpoint returning DB status
- TOTP 2FA (pyotp + QR code) with /owner/2fa/setup
- Menu modifiers (size, extras, notes per item)
- Kitchen view with 30s auto-refresh and print CSS
- Ingredient inventory with auto-deduct and low-stock alerts
- Phone-based reorder at /owner/reorder
- CSV export with date filter (/owner/export/orders)
- PDF daily report via reportlab (/owner/report/daily)
- 1-5 star feedback with averages
- Flask-Migrate migrations (idempotent initial schema)
- FLASK_APP=app set in Procfile, railway.json, Dockerfile
- Updated requirements.txt (pyotp, reportlab, pandas, waitress)"

echo "==> Pushing to origin/$BRANCH..."
git push -u origin "$BRANCH" --force

echo ""
echo "Done! Pushed to: $BRANCH"
echo "Railway will auto-deploy from the saas-upgrade branch."
echo ""
echo "Required Railway env vars:"
echo "  SECRET_KEY           = <long random string>"
echo "  SUPERADMIN_USERNAME  = <your superadmin username>"
echo "  SUPERADMIN_PASSWORD  = <your superadmin password>"
echo "  IS_PRODUCTION        = true"
