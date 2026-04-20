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
| `SUPERADMIN_USERNAME` | ✅ | Superadmin login username |
| `SUPERADMIN_PASSWORD` | ✅ | Superadmin login password |
| `DATABASE_URL` | Optional | SQLite used by default; set for Postgres |
| `IS_PRODUCTION` | Optional | Set to `true` to enable production mode |

## 3. Start command (auto-configured via railway.json)

```bash
FLASK_APP=app flask db upgrade && gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1 --threads 4
```

- Migrations run automatically before the server starts.
- Health check is at `/health`.

## 4. First-time setup

1. Log in at `/superadmin` with the `SUPERADMIN_USERNAME` / `SUPERADMIN_PASSWORD` you set.
2. Create one or more Cafe / Owner accounts from the superadmin dashboard.
3. Log in as an Owner at `/owner/login`.
4. Add menu items, tables, and ingredients.
5. Share the table QR codes with customers.

## 5. Feature overview

- **Pay at Counter** — 6-digit pickup codes on every order (no Stripe required).
- **Order lifecycle** — Pending → Confirmed → Preparing → Ready → Completed.
- **Kitchen view** — `/kitchen` with 30-second auto-refresh and print CSS.
- **Inventory** — Auto-deduct ingredients per order, low-stock alerts on dashboard.
- **2FA** — TOTP via Google Authenticator for owner accounts (`/owner/2fa/setup`).
- **Reports** — CSV export (`/owner/export/orders`) and PDF daily report (`/owner/report/daily`).
- **Feedback** — 1-5 star ratings linked to orders, averages shown on dashboard.
- **Reorder** — Phone-based repeat ordering at `/owner/reorder`.
