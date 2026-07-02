#!/usr/bin/env bash
# Payment reconciliation runner.
#
# Designed for a Railway "cron" service (separate from the web service).
# Recommended schedule: every 5 minutes — frequent enough to recover a
# missed Stripe / Razorpay / Cashfree webhook before the customer notices,
# rare enough to stay well within every PSP's read-side rate limits.
#
# Idempotent: only touches rows older than 10 minutes still in
# pending/processing, so it never races a webhook still in flight.
#
# Skips cleanly when DATABASE_URL is unset (preview env without a DB).

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "[reconcile] DATABASE_URL not set — skipping." >&2
  exit 0
fi

export FLASK_APP="${FLASK_APP:-app}"
echo "[reconcile] Starting payment reconciliation sweep…"
flask reconcile-payments
echo "[reconcile] Done."
