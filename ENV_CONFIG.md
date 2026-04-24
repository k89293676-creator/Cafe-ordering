# Environment Configuration

This document describes the environment variables that control the Cafe 11:11
ordering system. Set these in Railway (Project → Variables) or, for local dev,
in a `.env` file loaded by your shell.

## Required (security-critical)

| Variable | Purpose | Notes |
| --- | --- | --- |
| `SECRET_KEY` | Flask session signing + CSRF token secret. | Must be a long, random string (32+ bytes). Rotating it logs everyone out. **Never share or commit.** |
| `DATABASE_URL` | PostgreSQL connection URL (`postgresql://...`). | Provided automatically by Railway when a Postgres plugin is attached. |

## Admin / Superadmin access

| Variable | Purpose | Notes |
| --- | --- | --- |
| `ADMIN_SECRET_KEY` | Legacy `/admin` portal key. Lets an operator without a superadmin Owner reach the admin dashboard. | **Optional** if at least one Owner row already has `is_superadmin=True`. Treat as sensitive. |
| `SUPERADMIN_KEY` | Master key required for non-superadmin admins to reach `/superadmin`. | Required for the legacy `/admin → /superadmin` elevation flow. Rotate periodically. |

## Owner signup gating

| Variable | Purpose | Notes |
| --- | --- | --- |
| `OWNER_SIGNUP_MODE` | Controls who may create new owner accounts. | **Must be `approval` or `invite_only` in production.** `open` is for development only — it allows the public to self-register cafés. Default: `approval`. |

## Optional infrastructure

| Variable | Purpose | Notes |
| --- | --- | --- |
| `REDIS_URL` | Redis connection string. | Enables multi-worker SSE pub/sub, distributed rate-limit storage, and the background task queue. If unset, the app falls back to in-memory implementations (single-worker only). |
| `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER` | Flask-Mail SMTP settings. | Required for order-confirmation and password-reset emails. |
| `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_CLAIM_EMAIL` | Web push notification keys. | Generate with `python extensions/generate_vapid.py`. |
| `TRUSTED_PROXIES` | Comma-separated list of trusted proxy IPs/CIDRs in front of the app. | Required so Flask-Talisman correctly applies HSTS behind Railway's reverse proxy. Example: `0.0.0.0/0` for Railway's edge. |

## Gunicorn tuning (defaults live in `gunicorn_conf.py`)

The defaults in `gunicorn_conf.py` are tuned for Railway's free tier
(512 MB RAM, 1 vCPU): 1 worker, 2 threads, 60 s timeout, 500 max-requests,
50 jitter, gevent worker class. Each value can be overridden via env vars
without editing code:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEB_CONCURRENCY` | `1` | Number of gunicorn workers. Bump only after raising container memory. |
| `GUNICORN_THREADS` | `2` | Threads per worker (I/O concurrency on top of gevent). |
| `GUNICORN_TIMEOUT` | `60` | Seconds before a stuck worker is killed. |
| `GUNICORN_GRACEFUL_TIMEOUT` | `30` | Drain window on SIGTERM (Railway redeploys). |
| `GUNICORN_KEEPALIVE` | `5` | HTTP keep-alive seconds. |
| `GUNICORN_MAX_REQUESTS` | `500` | Recycle workers after N requests to bound memory creep. |
| `GUNICORN_MAX_REQUESTS_JITTER` | `50` | Random offset to avoid thundering-herd recycles. |
| `GUNICORN_WORKER_CONNECTIONS` | `1000` | gevent concurrent connections per worker. |
| `GUNICORN_LOG_LEVEL` | `info` | gunicorn log level. |
| `FORWARDED_ALLOW_IPS` | `*` | Trust X-Forwarded-* from any IP (Railway terminates TLS at the edge). |

## Observability & error tracking

| Variable | Purpose | Notes |
| --- | --- | --- |
| `SENTRY_DSN` | Enables Sentry error + performance monitoring. | Leave unset to disable. The Sentry SDK is loaded lazily so it costs nothing when off. |
| `SENTRY_TRACES_SAMPLE_RATE` | Fraction of requests to sample for performance tracing (0.0–1.0). | Defaults to `0.0`. Start small (e.g. `0.05`) on production. |
| `SENTRY_PROFILES_SAMPLE_RATE` | Fraction of sampled traces to profile. | Defaults to `0.0`. |
| `APP_VERSION` | Build identifier surfaced at `/version`, `/health`, and as the Sentry release tag. | Falls back to the first 12 chars of `RAILWAY_GIT_COMMIT_SHA`. |
| `SLOW_REQUEST_MS` | Requests slower than this (in milliseconds) are logged at WARNING with their `X-Request-ID`. | Default: `1500`. |
| `SECURITY_CONTACT` | Email/URL surfaced at `/.well-known/security.txt` for vuln disclosure. | Default: `mailto:security@example.com` — change before going live. |
| `IDEMPOTENCY_TTL_SECONDS` | TTL of the in-process idempotency cache used by `POST /api/checkout`. | Default: `86400` (24h). Clients pass `Idempotency-Key: <uuid>` in the request header to opt in. |
| `FEATURE_<NAME>` | Generic feature-flag pattern. Set to `on` / `1` / `true` to enable a flag at runtime; anything else (or unset) disables. | Read in code via `feature_enabled("name")`. Lets you dark-launch risky changes without a redeploy. |

## Health-check endpoints

| Path | Purpose |
| --- | --- |
| `/health` | Liveness — always cheap, no DB. Use as Railway's healthcheck. |
| `/ready` | Readiness — DB ping. Returns 503 while the DB is unreachable. |
| `/health/full` | Deep diagnostics: DB latency, disk, redis, pool stats, SSE subs. |
| `/metrics` | JSON runtime metrics (orders today, active orders, version). |
| `/metrics/prom` | Prometheus text-format exposition for `cafe_*` gauges. |
| `/version` | Build identifier (commit, branch, deployedAt). Useful for post-deploy smoke tests. |

## Quick checklist for production

- [ ] `SECRET_KEY` is set and is at least 32 random bytes
- [ ] `DATABASE_URL` points at the production Postgres instance
- [ ] `SUPERADMIN_KEY` is set (and `ADMIN_SECRET_KEY` only if you still need
      the legacy admin portal)
- [ ] `OWNER_SIGNUP_MODE` is `approval` or `invite_only` (never `open`)
- [ ] `REDIS_URL` is set if you run more than one gunicorn worker
- [ ] `TRUSTED_PROXIES` is set so HSTS / secure cookies work behind Railway

## Integrations Hub (`/owner/integrations`)

The unified Integrations Hub gives the owner a single screen for every
external service (payment gateways, food-delivery aggregators, notifications)
and is read by `lib_integrations.py`. The variables below are **only** used
by that screen — they don't affect order taking, billing, or payment
verification.

| Variable | Purpose | Notes |
| --- | --- | --- |
| `TWILIO_ACCOUNT_SID` | Twilio account SID for the optional "SMS me the setup link" button. | Lazy-loaded — when unset, the SMS button is hidden in the UI. No SDK is shipped; the helper uses a stdlib HTTP POST. |
| `TWILIO_AUTH_TOKEN` | Twilio auth token. Paired with the SID. | Treat as sensitive. |
| `TWILIO_FROM_NUMBER` | E.164 sender number registered on your Twilio account. | Example: `+15551234567`. |
| `IS_PRODUCTION` | Forces the production-readiness checker into "production mode" even when not on Railway. | Set to `1` / `true` to make blocker checks active in any environment. Otherwise auto-detected from `FLASK_ENV=production` or `RAILWAY_ENVIRONMENT`. |
| `BILLING_ENCRYPTION_KEY` | Independent Fernet key for the encrypted-at-rest payment + aggregator credentials. | Optional. Defaults to a key derived from `SECRET_KEY`. Set this if you want to rotate session secrets without re-encrypting every credential. |

The "Email me the setup link" button reuses the existing `MAIL_*` /
`SENDGRID_API_KEY` envs above — no extra config is needed for the email
channel.

### Production-readiness JSON

`GET /owner/integrations/checklist.json` (auth required) returns a JSON
snapshot of the readiness checks above plus per-integration status, with
**no secret material**. Useful for external uptime monitors.

## Billing dashboard v2

These knobs tune the hardened billing dashboard (refunds, voids, drawer,
health). All have safe defaults — only set them if you need to deviate
from the shipping policy. Numbers are in INR for amounts, plain integers
for counts, and seconds for durations.

| Variable | Purpose | Default |
| --- | --- | --- |
| `BILLING_STEPUP_REFUND_THRESHOLD` | Refund amount that forces the owner to re-enter their password before the refund is committed. | `500` |
| `BILLING_STEPUP_VOID_THRESHOLD` | Bill total that forces the owner to re-enter their password before voiding. | `2000` |
| `BILLING_STEPUP_TTL_SECONDS` | How long a successful step-up is cached on the session before we re-prompt. | `300` |
| `BILLING_REFUND_DAILY_CAP_PCT` | Max percentage of today's gross any single owner can refund before the route returns "daily cap reached". | `30` |
| `BILLING_REFUND_VELOCITY_PER_HOUR` | Hard ceiling on refund events per owner per rolling hour. | `20` |
| `BILLING_DRAWER_VARIANCE_ALERT_PCT` | Cash-drawer variance percentage above which the row is flagged `alert` (red pill). Below half of this is `warn`. | `2` |

These are read by `lib_billing_security.py` at request time, so changing
them only requires restarting the worker — no schema migration.

### Public billing health probe

`GET /health/billing` is unauthenticated and returns
`{"ok": true, "checks": [...]}` with HTTP 200 when the database is
reachable and the webhook log is writable, or HTTP 503 otherwise. Wire
this into your load-balancer / uptime monitor — it never leaks
per-owner data. The signed-in `/owner/billing/health.json` returns the
richer per-cafe view (stale tabs, refund ratio, aggregator credentials,
webhook volume).
