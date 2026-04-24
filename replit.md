# Cafe Ordering System

A web-based cafe ordering system built with Python and Flask.

## Overview

Customers can browse the cafe menu and place orders from their table via QR codes or online. The app includes an Owner Portal for managing menus, tracking orders, importing menus, and generating table-specific QR codes.

## Tech Stack

- **Backend:** Python 3.12 with Flask
- **Frontend:** HTML, CSS, Vanilla JavaScript with Jinja2 templating
- **Primary storage:** JSON files with portalocker-backed atomic reads/writes
- **Optional storage:** PostgreSQL when `DATABASE_URL` is set
- **Auth:** Session-based with Werkzeug password hashing and CSRF protection
- **Deployment:** Railway-ready Gunicorn + gevent configuration
- **Security:** Flask-WTF CSRF, Flask-Talisman security headers in production, upload validation, rate limiting, compressed responses

## Project Layout

```
app.py                 # Main Flask application with all routes and data access
migrate_json_to_db.py  # Imports JSON data into PostgreSQL when DATABASE_URL is set
requirements.txt       # Python dependencies
railway.json           # Railway build and deployment configuration
Procfile               # Gunicorn process command
.env.example           # Required and optional environment variables
menu.json              # Menu data fallback
orders.json            # Order records fallback
owners.json            # Owner account storage fallback
tables.json            # Table metadata fallback
static/                # CSS and JavaScript
templates/             # Jinja2 templates
```

## Environment Variables

- `SECRET_KEY` — Flask session secret key; required in production
- `IS_PRODUCTION` — set to `true` to enable production-only safeguards
- `PORT` — port provided by the host
- `FLASK_ENV` — set to `production` or `development`
- `DATA_DIR` — optional directory for JSON fallback files
- `DATABASE_URL` — optional PostgreSQL connection string
- `REDIS_URL` — optional Redis backend for rate limiting
- `GEMINI_API_KEY` — optional AI image menu extraction key
- `LOG_FILE` — optional production JSON log file path

## Running the App

```bash
python app.py
```

For production-like local testing:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1
```

## Deployment

Railway uses `railway.json` and `Procfile` to install dependencies, start Gunicorn, and health-check `/health`.

## Key Features

- Menu browsing with categories and item tags
- Cart and checkout for online and table orders
- Table-based ordering via QR codes
- Owner portal with menu, table, order, and profile management
- JSON fallback mode for local/free-tier development
- Optional PostgreSQL mode with JSON-to-database import script
- Production-grade file locking, atomic writes, cache invalidation, security headers, CSRF, logging, and rate limiting

## Production Upgrade (April 2026)

Added a unified **Integrations Hub** at `/owner/integrations` so the cafe owner manages every external service from one screen — payment gateways (Stripe, Razorpay, Cashfree), food-delivery aggregators (Swiggy, Zomato, Uber Eats), and notifications (email, SMS, web push).

**New files**
- `lib_integrations.py` — provider catalog, status overview, signup-link prefill, email/SMS setup-brief sender (Twilio via stdlib HTTP — no SDK), production-readiness checks. Zero I/O at import.
- `templates/owner_integrations/index.html` — hub UI with status cards, copyable webhook URLs, color-coded readiness checklist.

**New routes (in `app.py`)**
- `GET /owner/integrations` — the hub.
- `POST /owner/integrations/send-setup/<email|sms>/<provider>` — emails or texts the owner (at their *registered* address only) a setup brief with the webhook URL and a signup link pre-filled with their name + email.
- `GET /owner/integrations/checklist.json` — non-secret JSON for monitoring.

**New optional env vars** (see `ENV_CONFIG.md`): `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`, `IS_PRODUCTION`, `BILLING_ENCRYPTION_KEY`. None are required — the hub degrades gracefully when channels aren't configured.

**Test coverage** added to `tests/test_smoke.py`: auth gate on hub + checklist + send-setup, side-effect-free import, signup-link prefill.

## Billing dashboard v2 (April 2026)

Hardened the entire owner-billing surface area for production: step-up auth on high-value voids and refunds, daily refund cap, per-hour velocity ceiling, same-origin re-check on destructive routes, per-route rate limits, cash-drawer reconciliation, A/R aging report, refund history, and a public health probe.

**New files**
- `lib_billing_security.py` — env-tunable thresholds, step-up/freshness helpers, refund cap + velocity, origin check, webhook dedupe key.
- `templates/owner_billing/refunds.html`, `aging.html`, `drawer.html`, `health.html` — new dashboard tabs.
- `tests/test_billing_v2.py` — 40 tests covering thresholds, parsing, aging buckets, sparkline, drawer variance, health snapshot.

**Extended files**
- `lib_billing.py` — added `parse_date_range`, `aging_bucket_for`, `summarise_aging`, `revenue_sparkline`, `drawer_variance`, `billing_health_snapshot`.
- `app.py` — new model `CashDrawerCount`; new helpers `_billing_health_compute`, `_billing_sparkline_7d`, `_refund_total_today`, `_refund_count_last_hour`, `_severity_pill`; new routes `owner_billing_refunds`, `owner_billing_aging`, `owner_billing_drawer` (GET+POST), `owner_billing_health`, `owner_billing_health_json`, public `public_billing_health` at `/health/billing`. EOD route + CSV now accept `?from=&to=` ranges. Existing void/refund routes carry step-up + cap + velocity + origin checks; adjust/settle/void/refund/charge are rate-limited.
- Templates `_base.html`, `overview.html`, `eod.html`, `invoice.html`, `order_detail.html` updated for the new nav, sparkline, range filter, thermal-print rules, and step-up password fields.

**New optional env vars** (see `ENV_CONFIG.md`): `BILLING_STEPUP_REFUND_THRESHOLD`, `BILLING_STEPUP_VOID_THRESHOLD`, `BILLING_STEPUP_TTL_SECONDS`, `BILLING_REFUND_DAILY_CAP_PCT`, `BILLING_REFUND_VELOCITY_PER_HOUR`, `BILLING_DRAWER_VARIANCE_ALERT_PCT`. All have safe defaults.

**Public health probe**: `GET /health/billing` returns 200/503 with no per-owner data — safe for load-balancer wiring.
