# Deploying Cafe Ordering SaaS on Railway

## Prerequisites

- GitHub repository pushed to the `saas-upgrade` branch.
- Railway account.

## 1. Create the Railway project

1. In Railway, choose **New Project**.
2. Select **Deploy from GitHub repo**.
3. Pick `k89293676-creator/Cafe-ordering` and the `saas-upgrade` branch.
4. Railway will detect Nixpacks automatically and use `railway.json` for config.

## 2. Configure environment variables

Set these in the Railway project's **Variables** tab:

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | ✅ | Long random string for session/CSRF |
| `SUPERADMIN_USERNAME` | Optional | Superadmin login username, defaults to `superadmin` |
| `SUPERADMIN_PASSWORD` | Optional | When set, creates or promotes the superadmin account |
| `DATABASE_URL` | ✅ | Railway Postgres connection string; required in production for durable data |
| `REDIS_URL` | Recommended | Shared rate-limit storage; in-memory storage is only for single-process deployments |
| `IS_PRODUCTION` | Optional | Railway is detected automatically, but `true` is acceptable |

## 3. Start command (auto-configured via railway.json)

```bash
python start.py
```

- The app initializes tables and additive upgrade columns on startup.
- Production startup fails fast without `DATABASE_URL` so orders are not accidentally stored on Railway's ephemeral filesystem.
- `start.py` reads Railway's `PORT` environment variable directly, avoiding shell-specific parsing issues.
- Railway liveness health check is at `/health` (cheap, always-on JSON with version + uptime).
- Database readiness is available at `/ready` (DB SELECT 1 ping; returns 503 on failure).
- Deep diagnostics at `/health/full` — DB latency, disk writability, Redis (if configured), worker info. 503 on any critical failure.
- Aggregate runtime metrics at `/metrics` — orders today, active orders, uptime. No PII.

## 4. First-time setup

1. Add a Railway PostgreSQL service and confirm `DATABASE_URL` is present in the app service variables.
2. Set `ADMIN_SECRET_KEY` for `/admin/login`.
3. Optionally set `SUPERADMIN_USERNAME` and `SUPERADMIN_PASSWORD` before first boot to create a superadmin owner.
4. Log in as an Owner at `/owner/login`, or create an owner at `/owner/signup`.
5. Add menu items, tables, and ingredients.
6. Share the table QR codes with customers.

## 5. Feature overview

- **Pay at Counter** — 6-digit pickup codes on every order (no Stripe required).
- **Order lifecycle** — Pending → Confirmed → Preparing → Ready → Completed.
- **Kitchen view** — `/kitchen` with 30-second auto-refresh and print CSS.
- **Inventory** — Auto-deduct ingredients per order, low-stock alerts on dashboard.
- **2FA** — TOTP via Google Authenticator for owner accounts (`/owner/2fa/setup`).
- **Reports** — CSV export (`/owner/export/orders`) and PDF daily report (`/owner/report/daily`).
- **Feedback** — 1-5 star ratings linked to orders, averages shown on dashboard.
- **Reorder** — Phone-based repeat ordering at `/owner/reorder`.

## Integrations Hub (post-deploy)

After your Railway redeploy, log in as the cafe owner and open
`/owner/integrations`. This is the single screen that:

1. Shows every supported payment gateway and food-delivery aggregator
   with their connection state (Live / Test / Saved / Not connected).
2. Lets you copy the per-provider webhook URL (HTTPS-enforced in
   production) straight into the gateway dashboard.
3. Emails (or, if Twilio is configured, SMS-es) **you** at your
   registered email/phone a step-by-step setup brief — including the
   webhook URL and a signup link with your name and email pre-filled.
4. Surfaces a production-readiness checklist: missing env vars, weak
   secrets, `OWNER_SIGNUP_MODE=open`, etc. Items are color-coded by
   severity (blocker / warn / info / ok).

You can also hit `GET /owner/integrations/checklist.json` (auth required)
for a non-secret JSON snapshot — useful as a post-deploy smoke check.
