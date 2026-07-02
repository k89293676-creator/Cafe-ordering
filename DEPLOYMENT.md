# Deploying Cafe Ordering SaaS on Railway

## Prerequisites

- GitHub repository pushed to the `main` branch.
- Railway account with a PostgreSQL service attached.

## 1. Create the Railway project

1. In Railway, choose **New Project**.
2. Select **Deploy from GitHub repo**.
3. Pick `k89293676-creator/Cafe-ordering` and the `main` branch.
4. Railway will detect Nixpacks automatically and use `railway.json` for config.

## 2. Configure environment variables

Set these in the Railway project's **Variables** tab:

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | ✅ | Long random string for session/CSRF. Must be ≥ 32 bytes. Rotating logs everyone out. |
| `DATABASE_URL` | ✅ | Railway Postgres connection string; required in production. |
| `REDIS_URL` | Recommended | Enables distributed rate-limiting, server-side sessions, SSE pub/sub, and the background task queue. Strongly recommended when running more than one gunicorn worker. |
| `SUPERADMIN_USERNAME` | Optional | Superadmin login username, defaults to `superadmin`. |
| `SUPERADMIN_PASSWORD` | Optional | When set, creates or promotes the superadmin account on first boot. |
| `IS_PRODUCTION` | Optional | Railway is auto-detected, but `true` is accepted as an override. |
| `OWNER_SIGNUP_MODE` | Optional | `approval` (default) or `invite_only`. **Never `open` in production.** |
| `SENTRY_DSN` | Optional | Enables Sentry error + performance monitoring. |
| `OPS_HEALTH_TOKEN` | Optional | Bearer token for `GET /api/ops/health`. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `TRUSTED_PROXIES` | Optional | Comma-separated IPs/CIDRs trusted behind Railway's edge (e.g. `0.0.0.0/0`). |

See `ENV_CONFIG.md` for the full variable reference including gunicorn tuning, alerting, backups, and billing knobs.

## 3. Build & release pipeline (auto-configured via railway.json)

```
NIXPACKS build  →  pip install -r requirements.txt
                            ↓
Pre-deploy      →  bash scripts/release.sh
  [0] Package audit   — verifies Flask-Session, SQLAlchemy, redis, etc. importable
  [1] Env validation  — checks SECRET_KEY is set and ≥ 24 chars
  [2] DB inspect      — detects legacy (pre-Alembic) databases
  [3] flask db upgrade — applies Alembic migrations (001 → 006)
  [4] flask sync-schema — idempotent ADD COLUMN safety net
  [5] Revision audit  — logs active migration revision
                            ↓
Start           →  python start.py
  validates SECRET_KEY length + DATABASE_URL before forking workers
  → gunicorn (gevent, config from gunicorn_conf.py)
```

**Failure at any pre-deploy step aborts the deploy.** Railway keeps the previous revision serving while you fix the issue.

## 4. Start command internals

`start.py` validates the environment before exec-ing gunicorn:

- Fails fast if `SECRET_KEY` is missing or too short.
- Fails fast if `DATABASE_URL` is unset in production.
- Prints a startup banner with commit SHA, env, port, and worker count.
- Gunicorn config lives in `gunicorn_conf.py` — all values are overridable via env vars without touching code. See `ENV_CONFIG.md → Gunicorn tuning`.

## 5. Health check endpoints

| Path | Purpose | Auth |
|---|---|---|
| `/health` | Liveness — cheap, no DB. Railway's primary healthcheck. | None |
| `/ready` | Readiness — DB SELECT 1 ping. Returns 503 while DB is unreachable. | None |
| `/health/full` | Deep diagnostics: DB latency, disk writability, Redis, pool stats, SSE subscribers. Returns 503 on any critical failure. | None |
| `/health/billing` | Billing subsystem liveness: DB reachable + webhook log writable. | None |
| `/metrics` | JSON runtime metrics (orders today, active orders, uptime, version). | None |
| `/metrics/prom` | Prometheus text-format exposition for `cafe_*` gauges. | None |
| `/version` | Build identifier (commit, branch, deployedAt). | None |
| `/api/ops/health` | Per-section health probe (inventory, billing, payment methods, food delivery, employees, …). Returns `{ok, sections}`. | Bearer `$OPS_HEALTH_TOKEN` |
| `/api/ops/errors` | Cross-worker recent-error log (JSONL). | Bearer `$OPS_HEALTH_TOKEN` |
| `/api/ops/webhooks` | Outbound webhook dead-letter queue. | Bearer `$OPS_HEALTH_TOKEN` |

## 6. First-time setup

1. Attach a Railway PostgreSQL service and confirm `DATABASE_URL` is present.
2. Set `SECRET_KEY` (32+ random bytes) and `ADMIN_SECRET_KEY`.
3. Optionally set `SUPERADMIN_USERNAME` + `SUPERADMIN_PASSWORD` to create a superadmin on first boot.
4. Deploy — the release script runs migrations automatically.
5. Log in as an Owner at `/owner/login`, or create an account at `/owner/signup`.
6. Add menu items, tables, and ingredients.
7. Share the table QR codes with customers.

## 7. Feature overview

- **Pay at Counter** — 6-digit pickup codes on every order (no payment gateway required).
- **Order lifecycle** — Pending → Confirmed → Preparing → Ready → Completed.
- **Kitchen view** — `/kitchen` with 30-second auto-refresh and print CSS.
- **Inventory** — Auto-deduct ingredients per order, low-stock alerts on dashboard.
- **2FA** — TOTP via Google Authenticator for owner accounts (`/owner/2fa/setup`).
- **Reports** — CSV export (`/owner/export/orders`) and PDF daily report (`/owner/report/daily`).
- **Feedback** — 1–5 star ratings linked to orders, averages shown on dashboard.
- **Reorder** — Phone-based repeat ordering at `/owner/reorder`.
- **Server-side sessions** — Flask-Session stores sessions in Redis (when `REDIS_URL` is set) for consistent sessions across multiple gunicorn workers. Falls back to signed cookies if Redis is unavailable.
- **Rate limiting** — Flask-Limiter with Redis storage (multi-worker safe). Protects checkout, login, and export routes.
- **Response compression** — Brotli/gzip via Flask-Compress. Enabled automatically.
- **Circuit breakers** — External API calls (payment gateways, aggregators) have failure thresholds to stop cascading failures.
- **Distributed tracing** — Request IDs propagated via `X-Request-ID` header through every log line and Sentry event. Slow requests (> `SLOW_REQUEST_MS`) logged at WARNING.
- **Idempotent checkout** — `POST /api/checkout` deduplicates requests via `Idempotency-Key` header (24h TTL).
- **Query caching** — Frequently-read catalogue data cached in Redis to reduce DB load.
- **Background jobs** — RQ worker (`python rqworker.py`) for email delivery, PDF generation, and webhook retries. Runs as a separate Railway service.
- **Outbound webhook retries** — Exponential back-off, dead-letter queue, operator requeue UI at `/api/ops/webhooks`.
- **Backup workflow** — Daily GPG-encrypted DB dump via `.github/workflows/backup.yml`.

## 8. Integrations Hub (post-deploy)

After your Railway redeploy, log in as the cafe owner and open `/owner/integrations`. This screen:

1. Shows every supported payment gateway and food-delivery aggregator with their connection state (Live / Test / Saved / Not connected).
2. Lets you copy the per-provider webhook URL (HTTPS-enforced in production) straight into the gateway dashboard.
3. Emails (or, if Twilio is configured, SMS-es) you a step-by-step setup brief including the webhook URL and a signup link.
4. Surfaces a production-readiness checklist: missing env vars, weak secrets, `OWNER_SIGNUP_MODE=open`. Items are colour-coded by severity (blocker / warn / info / ok).

`GET /owner/integrations/checklist.json` (auth required) returns a non-secret JSON snapshot — useful as a post-deploy smoke check.

## 9. Production checklist

- [ ] `SECRET_KEY` is set and is at least 32 random bytes
- [ ] `DATABASE_URL` points at the production Postgres instance
- [ ] `REDIS_URL` is set (required for multi-worker sessions and rate-limiting)
- [ ] `SUPERADMIN_KEY` is set (and `ADMIN_SECRET_KEY` only if you need the legacy admin portal)
- [ ] `OWNER_SIGNUP_MODE` is `approval` or `invite_only` (never `open`)
- [ ] `TRUSTED_PROXIES` is set so HSTS / secure cookies work behind Railway's edge
- [ ] `OPS_HEALTH_TOKEN` is set and stored in GitHub Actions secrets for post-deploy probes
- [ ] `SENTRY_DSN` is set for production error monitoring
- [ ] `SECURITY_CONTACT` is updated from the default `mailto:security@example.com`
