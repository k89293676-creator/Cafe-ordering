# Security Policy

## Reporting a vulnerability

We take security reports seriously. Please **do not** open a public GitHub
issue for security problems.

- Email the maintainers at the address listed in
  [`/.well-known/security.txt`](./.well-known/security.txt) (served live by
  the deployed app — defaults to `security@example.com`; override via the
  `SECURITY_CONTACT` environment variable).
- Provide enough detail to reproduce: steps, affected URLs, expected vs
  actual behaviour, and any proof-of-concept payloads.
- We aim to acknowledge new reports within **3 business days** and to
  publish a fix or mitigation within **30 days** for high-severity issues.

## Supported versions

Only the `main` branch is actively maintained. We do not back-port fixes
to older tags.

## Hardening already in place

- CSRF protection on every form (`Flask-WTF`).
- Strict Content-Security-Policy + clickjacking + MIME-sniffing headers
  (`Flask-Talisman` + custom `after_request` hardening).
- Per-IP login lockout (15 min after 5 failed attempts).
- Per-route rate limits (`Flask-Limiter`).
- Bcrypt password hashing with `Flask-Bcrypt`.
- Optional TOTP (RFC 6238) two-factor authentication on owner accounts.
- Session cookies marked `HttpOnly`, `SameSite=Lax`, and `Secure` in
  production.
- Sessions are bound to the requesting browser's user-agent fingerprint
  on login and revoked on mismatch.
- Reverse-proxy aware (`ProxyFix`) so client IPs are honoured behind
  Railway's edge.
- Long-cache `immutable` headers on `/static/` only — never on HTML.
- Optional Sentry error tracking (gated on `SENTRY_DSN`).
- Dependency audits run on every CI build (`pip-audit`).

## Out of scope

- Self-XSS, social engineering, physical access attacks.
- Reports that require a privileged owner account compromising their own
  cafe's data.
- Missing security headers on third-party CDN responses.

## Integrations Hub controls

* `/owner/integrations` requires `@login_required` + a valid CSRF token on
  every form post. The "send setup link" endpoint accepts only `email`
  and `sms` channels and **always** sends to the owner's registered
  email/phone — there is no free-form recipient field, so the route
  cannot be abused as an open relay even if CSRF were bypassed.
* The send-setup endpoint is rate-limited (`12 per hour; 3 per minute`)
  and emits a `INTEGRATION_SETUP_SENT` (or `..._FAIL`) entry to the
  security log so spam attempts are observable.
* Webhook URLs surfaced by the hub respect the existing HTTPS
  enforcement guard (`_enforce_https_for_webhooks`) — plaintext
  callbacks are rejected with HTTP 400 in production.
* `lib_integrations.py` performs **no I/O at import time** and ships no
  new dependencies; the optional Twilio path uses a stdlib `urllib`
  POST gated on `TWILIO_ACCOUNT_SID`, so the attack surface only grows
  when the operator opts in.

## Billing v2 hardening

The billing dashboard sits on top of payment data, so it gets a heavier
posture than the rest of the app:

* **Step-up authentication.** Voiding a high-value bill or issuing a
  large refund re-prompts the owner for their password before the
  action is committed. The threshold for each is tuned via
  `BILLING_STEPUP_VOID_THRESHOLD` and `BILLING_STEPUP_REFUND_THRESHOLD`
  (see `ENV_CONFIG.md`); a successful step-up is cached on the session
  for `BILLING_STEPUP_TTL_SECONDS` so back-to-back actions don't keep
  prompting. The password is verified with a constant-time comparison
  against the existing bcrypt/Werkzeug hash via `_password_matches`.
* **Daily refund cap.** Refunds are clamped to a percentage of the
  cafe's gross for the same UTC day, controlled by
  `BILLING_REFUND_DAILY_CAP_PCT`. Attempts that would exceed the cap
  are rejected and logged to `billing_logs` with action
  `refund_blocked` so a tampered button can't quietly drain the float.
* **Per-hour velocity ceiling.** No more than
  `BILLING_REFUND_VELOCITY_PER_HOUR` refund events per owner per
  rolling hour. This is independent of the per-IP rate limiter so it
  catches scripted abuse from a logged-in session.
* **Same-origin re-check on destructive actions.** Beyond the CSRF
  token, void and refund routes verify that the `Origin`/`Referer`
  matches `request.host`. Mismatches return HTTP 403 and log to the
  application logger.
* **Per-route rate limits.** `Flask-Limiter` decorators sit on
  `adjust`, `settle`, `void`, `refund`, `charge`, and the cash-drawer
  POST so even authenticated abuse is bounded.
* **Cash-drawer reconciliation.** Every count is stored with the
  recomputed expected cash, the variance, and a denormalised severity
  word so historical reads don't depend on the runtime threshold; the
  alert percentage is owner-tunable via
  `BILLING_DRAWER_VARIANCE_ALERT_PCT`.
* **Webhook idempotency.** Razorpay/Stripe-style providers and the
  third-party-aggregator webhook all funnel through `WebhookEventLog`,
  which has a unique `(provider, event_id)` index — re-deliveries are
  no-ops.
* **Health probe.** `GET /health/billing` is unauthenticated but only
  reports database reachability and webhook-log writability — never
  per-owner data — so it is safe to wire into a load-balancer probe.
  The signed-in `/owner/billing/health` and `/owner/billing/health.json`
  variants additionally surface owner-scoped checks (stale tabs, 7-day
  refund ratio, unverified aggregator credentials, webhook volume).
* **Audit log.** Every billing state change — adjust, settle, void,
  refund, blocked refund, drawer count — appends an immutable row to
  `billing_logs` with the actor, amount, reason, and a structured
  payload. The table is indexed on `(owner_id, created_at DESC)` so
  the audit page stays fast even after years of rows.
