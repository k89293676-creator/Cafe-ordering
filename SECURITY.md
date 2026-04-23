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
