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

## Gunicorn tuning (defaults are baked into `start.py`)

The defaults in `start.py` are tuned for Railway's free tier (512 MB RAM,
1 vCPU): 1 worker, 2 threads, 60 s timeout, 500 max-requests, 50 jitter,
gevent worker class. Override these only after load testing on a paid plan
with more headroom.

## Quick checklist for production

- [ ] `SECRET_KEY` is set and is at least 32 random bytes
- [ ] `DATABASE_URL` points at the production Postgres instance
- [ ] `SUPERADMIN_KEY` is set (and `ADMIN_SECRET_KEY` only if you still need
      the legacy admin portal)
- [ ] `OWNER_SIGNUP_MODE` is `approval` or `invite_only` (never `open`)
- [ ] `REDIS_URL` is set if you run more than one gunicorn worker
- [ ] `TRUSTED_PROXIES` is set so HSTS / secure cookies work behind Railway
