"""Unified integrations hub — onboarding, status, and production-readiness.

Sits *above* ``lib_payments`` and ``lib_aggregators`` and gives the owner
a single screen (``/owner/integrations``) where every external service
attached to the cafe is visible, testable, and onboardable.

Design goals
------------

* **Zero new heavy dependencies.** SMS uses a tiny ``urllib`` POST to
  Twilio's REST API only when ``TWILIO_ACCOUNT_SID`` is set — no SDK,
  no extra wheel in ``requirements.txt``. Email reuses ``Flask-Mail``
  which is already configured for order receipts.
* **Owner-friendly setup.** The "Email me the setup link" button takes
  the owner's *already-verified* registered email/phone, builds a
  signup URL for the chosen gateway with name + email prefilled, and
  ships them a step-by-step brief (including their unique webhook URL).
  This is the part that turns a 30-minute gateway onboarding into a
  3-minute one.
* **Production-readiness in the UI.** ``production_readiness_check()``
  surfaces missing env vars, weak secrets, mis-set ``OWNER_SIGNUP_MODE``
  etc. so the owner sees "things to fix before going live" without
  having to read DEPLOYMENT.md.
* **No I/O at import time.** The Twilio POST and Flask-Mail import
  happen lazily inside the helpers so unit tests and the audit harness
  can import this module without side effects.
"""
from __future__ import annotations

import json
import logging
import os
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider catalog — drives the hub UI even when nothing is configured yet
# ---------------------------------------------------------------------------

PAYMENT_CATALOG: list[dict] = [
    {
        "key": "stripe",
        "label": "Stripe",
        "category": "payment",
        "summary": "Cards, Apple Pay, Google Pay. Best for international.",
        "signup_url": "https://dashboard.stripe.com/register",
        "dashboard_url": "https://dashboard.stripe.com/apikeys",
        "docs_url": "https://stripe.com/docs/keys",
    },
    {
        "key": "razorpay",
        "label": "Razorpay",
        "category": "payment",
        "summary": "UPI, cards, netbanking, wallets. Default for India.",
        "signup_url": "https://dashboard.razorpay.com/signup",
        "dashboard_url": "https://dashboard.razorpay.com/app/website-app-settings/api-keys",
        "docs_url": "https://razorpay.com/docs/payments/dashboard/account-settings/api-keys/",
    },
    {
        "key": "cashfree",
        "label": "Cashfree",
        "category": "payment",
        "summary": "UPI, cards, netbanking. Lower fees in India for high volume.",
        "signup_url": "https://merchant.cashfree.com/merchants/signup",
        "dashboard_url": "https://merchant.cashfree.com/merchants/pg/developers/keys",
        "docs_url": "https://www.cashfree.com/docs/payments/online/intro",
    },
]

AGGREGATOR_CATALOG: list[dict] = [
    {
        "key": "swiggy",
        "label": "Swiggy",
        "category": "delivery",
        "summary": "India's largest food-delivery aggregator. Push-based POS integration.",
        "signup_url": "https://partner.swiggy.com/login",
        "dashboard_url": "https://partner.swiggy.com",
        "docs_url": "https://partner.swiggy.com/help",
    },
    {
        "key": "zomato",
        "label": "Zomato",
        "category": "delivery",
        "summary": "Zomato POS Integration — receives orders, accepts/rejects via API.",
        "signup_url": "https://www.zomato.com/business/sign-up",
        "dashboard_url": "https://www.zomato.com/business",
        "docs_url": "mailto:pos-integration@zomato.com",
    },
    {
        "key": "ubereats",
        "label": "Uber Eats",
        "category": "delivery",
        "summary": "Uber Eats Marketplace API. OAuth client-credentials with webhook events.",
        "signup_url": "https://www.ubereats.com/restaurant/en-US/signup",
        "dashboard_url": "https://developer.uber.com/dashboard",
        "docs_url": "https://developer.uber.com/docs/eats",
    },
]

NOTIFICATION_CATALOG: list[dict] = [
    {
        "key": "email",
        "label": "Email (SMTP / SendGrid)",
        "category": "notification",
        "summary": "Order confirmations, receipts, owner alerts. Required for setup links.",
        "env_keys": ["MAIL_USERNAME", "MAIL_PASSWORD", "MAIL_DEFAULT_SENDER"],
        "alt_env_keys": ["SENDGRID_API_KEY"],
    },
    {
        "key": "sms",
        "label": "SMS (Twilio)",
        "category": "notification",
        "summary": "Optional. Used only to text owners their setup link / OTP. Lazy-loaded.",
        "env_keys": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"],
    },
    {
        "key": "webpush",
        "label": "Web Push (VAPID)",
        "category": "notification",
        "summary": "Browser push notifications for new orders.",
        "env_keys": ["VAPID_PUBLIC_KEY", "VAPID_PRIVATE_KEY", "VAPID_CLAIM_EMAIL"],
    },
]


# ---------------------------------------------------------------------------
# Status snapshot — the data the hub template renders
# ---------------------------------------------------------------------------

@dataclass
class IntegrationCard:
    key: str
    label: str
    category: str  # "payment" | "delivery" | "notification"
    summary: str
    state: str  # "live" | "test" | "configured" | "available" | "missing"
    badge_text: str
    is_verified: bool = False
    last_test_status: str = ""
    last_test_message: str = ""
    last_tested_at: datetime | None = None
    setup_url: str = ""          # internal route to the existing setup screen
    signup_url: str = ""         # external dashboard signup URL
    dashboard_url: str = ""      # external dashboard URL
    webhook_url: str = ""        # if applicable
    can_send_email: bool = False
    can_send_sms: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


def _payment_state(cred_view: dict) -> tuple[str, str]:
    if not cred_view.get("is_active"):
        return "configured", "Disabled"
    if cred_view.get("mode") == "live" and cred_view.get("is_verified"):
        return "live", "Live"
    if cred_view.get("is_verified"):
        return "test", "Test (verified)"
    if cred_view.get("has_secret"):
        return "test", "Test (unverified)"
    return "configured", "Saved"


def _aggregator_state(cred_view: dict) -> tuple[str, str]:
    if not cred_view.get("is_active"):
        return "configured", "Disabled"
    if cred_view.get("mode") == "live" and cred_view.get("is_verified"):
        return "live", "Live"
    if cred_view.get("is_verified"):
        return "test", "Test (verified)"
    return "configured", "Saved"


def build_overview(
    *,
    payment_credentials: list[dict],
    aggregator_credentials: list[dict],
    payments_setup_url: str,
    aggregators_setup_url: str,
) -> list[IntegrationCard]:
    """Merge configured credentials with the catalog so the hub shows
    every supported provider — even ones the owner hasn't connected yet."""
    cards: list[IntegrationCard] = []

    # Payments
    by_key = {c["provider"]: c for c in payment_credentials}
    for entry in PAYMENT_CATALOG:
        cred = by_key.get(entry["key"])
        if cred:
            state, badge = _payment_state(cred)
            cards.append(IntegrationCard(
                key=entry["key"], label=entry["label"], category="payment",
                summary=entry["summary"],
                state=state, badge_text=badge,
                is_verified=bool(cred.get("is_verified")),
                last_test_status=cred.get("last_test_status") or "",
                last_test_message=cred.get("last_test_message") or "",
                last_tested_at=cred.get("last_tested_at"),
                setup_url=payments_setup_url,
                signup_url=entry["signup_url"],
                dashboard_url=entry["dashboard_url"],
                webhook_url=cred.get("webhook_url", ""),
                can_send_email=True,
                can_send_sms=True,
                extra={"display_name": cred.get("display_name", "")},
            ))
        else:
            cards.append(IntegrationCard(
                key=entry["key"], label=entry["label"], category="payment",
                summary=entry["summary"],
                state="available", badge_text="Not connected",
                setup_url=payments_setup_url,
                signup_url=entry["signup_url"],
                dashboard_url=entry["dashboard_url"],
                can_send_email=True,
                can_send_sms=True,
            ))

    # Aggregators
    by_key = {c["platform"]: c for c in aggregator_credentials}
    for entry in AGGREGATOR_CATALOG:
        cred = by_key.get(entry["key"])
        if cred:
            state, badge = _aggregator_state(cred)
            cards.append(IntegrationCard(
                key=entry["key"], label=entry["label"], category="delivery",
                summary=entry["summary"],
                state=state, badge_text=badge,
                is_verified=bool(cred.get("is_verified")),
                last_test_status=cred.get("last_test_status") or "",
                last_test_message=cred.get("last_test_message") or "",
                last_tested_at=cred.get("last_tested_at"),
                setup_url=aggregators_setup_url,
                signup_url=entry["signup_url"],
                dashboard_url=entry["dashboard_url"],
                webhook_url=cred.get("webhook_url", ""),
                can_send_email=True,
                can_send_sms=True,
            ))
        else:
            cards.append(IntegrationCard(
                key=entry["key"], label=entry["label"], category="delivery",
                summary=entry["summary"],
                state="available", badge_text="Not connected",
                setup_url=aggregators_setup_url,
                signup_url=entry["signup_url"],
                dashboard_url=entry["dashboard_url"],
                can_send_email=True,
                can_send_sms=True,
            ))

    # Notifications — driven entirely by env-var presence
    for entry in NOTIFICATION_CATALOG:
        present = all(os.environ.get(k) for k in entry.get("env_keys", []))
        if not present and entry.get("alt_env_keys"):
            present = any(os.environ.get(k) for k in entry["alt_env_keys"])
        cards.append(IntegrationCard(
            key=entry["key"], label=entry["label"], category="notification",
            summary=entry["summary"],
            state="live" if present else "missing",
            badge_text="Configured" if present else "Missing",
        ))
    return cards


# ---------------------------------------------------------------------------
# Owner setup-link delivery
# ---------------------------------------------------------------------------

def build_provider_signup_link(provider_key: str, *,
                               owner_name: str = "",
                               owner_email: str = "") -> str:
    """Return a signup URL for ``provider_key`` with the owner's details
    pre-filled where the gateway supports it. Falls back to the bare
    signup URL if the provider doesn't accept query-string prefill."""
    catalog = {e["key"]: e for e in PAYMENT_CATALOG + AGGREGATOR_CATALOG}
    entry = catalog.get(provider_key)
    if not entry:
        return ""
    base = entry["signup_url"]
    # Stripe supports ?email=
    # Razorpay registration form picks up ?email=, ?name=
    # Cashfree onboarding accepts ?name=, ?email=
    # Aggregators don't generally support prefill — we still pass utm_*
    params: dict[str, str] = {}
    if owner_email:
        params["email"] = owner_email
    if owner_name:
        params["name"] = owner_name
    params["utm_source"] = "cafe-portal"
    params["utm_medium"] = "owner-onboarding"
    params["utm_campaign"] = provider_key
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode(params)}"


def render_setup_brief(provider_key: str, provider_label: str, *,
                       webhook_url: str = "",
                       signup_url: str = "",
                       dashboard_url: str = "",
                       events: list[str] | None = None,
                       steps: list[str] | None = None,
                       owner_name: str = "",
                       cafe_name: str = "") -> tuple[str, str, str]:
    """Returns ``(subject, plaintext_body, html_body)`` for the setup
    email. Used for both email and (subject + plaintext only) SMS."""
    subject = f"Set up {provider_label} for {cafe_name or 'your cafe'}"
    greeting = f"Hi {owner_name}," if owner_name else "Hi,"
    steps = steps or [
        "Create your account on the provider dashboard (link below).",
        "Generate API credentials.",
        "Paste them into the cafe portal and click Verify & Save.",
        "Add the webhook URL shown after saving back into the provider dashboard.",
    ]
    events = events or []

    plain_lines = [
        f"{greeting}",
        "",
        f"Here's everything you need to connect {provider_label} to your cafe portal.",
        "",
    ]
    if signup_url:
        plain_lines.append(f"1) Sign up / log in: {signup_url}")
    if dashboard_url:
        plain_lines.append(f"2) Open the credentials page: {dashboard_url}")
    if webhook_url:
        plain_lines.append("")
        plain_lines.append(f"Your webhook URL (paste this into the {provider_label} dashboard):")
        plain_lines.append(f"  {webhook_url}")
    if events:
        plain_lines.append("")
        plain_lines.append("Subscribe these events:")
        for ev in events:
            plain_lines.append(f"  - {ev}")
    plain_lines.append("")
    plain_lines.append("Step-by-step:")
    for i, s in enumerate(steps, 1):
        plain_lines.append(f"  {i}. {s}")
    plain_lines.append("")
    plain_lines.append("Once you save your keys we'll auto-verify them against the provider.")
    plain_lines.append("")
    plain_lines.append("— Cafe Portal")
    plain = "\n".join(plain_lines)

    # Minimal HTML, no remote assets — survives strict email clients.
    html_steps = "".join(f"<li>{s}</li>" for s in steps)
    html_events = "".join(f"<code>{e}</code> " for e in events) if events else ""
    html = f"""\
<!doctype html>
<html><body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
                  background:#f6f8fb;color:#0f172a;padding:24px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;
              padding:24px;border:1px solid #e2e8f0;">
    <h2 style="margin:0 0 8px;">Set up {provider_label}</h2>
    <p style="color:#475569;margin:0 0 16px;">
      {greeting} here's everything you need to connect <strong>{provider_label}</strong>
      to {cafe_name or 'your cafe'}.
    </p>
    <ol style="padding-left:18px;line-height:1.6;">{html_steps}</ol>
    <p style="margin-top:16px;">
      {('<a href="' + signup_url + '" style="display:inline-block;padding:10px 16px;background:#0f172a;color:#fff;border-radius:8px;text-decoration:none;margin-right:8px;">Sign up / log in</a>') if signup_url else ''}
      {('<a href="' + dashboard_url + '" style="display:inline-block;padding:10px 16px;background:#fff;color:#0f172a;border:1px solid #cbd5e1;border-radius:8px;text-decoration:none;">Open dashboard</a>') if dashboard_url else ''}
    </p>
    {('<p style="margin-top:20px;font-size:13px;color:#475569;">Webhook URL (paste this in the ' + provider_label + ' dashboard):<br><code style="background:#0f172a;color:#e2e8f0;padding:8px 10px;border-radius:6px;display:inline-block;margin-top:4px;word-break:break-all;">' + webhook_url + '</code></p>') if webhook_url else ''}
    {('<p style="margin-top:12px;font-size:13px;color:#475569;">Events to subscribe: ' + html_events + '</p>') if html_events else ''}
    <p style="margin-top:24px;font-size:12px;color:#94a3b8;">
      Sent by Cafe Portal because you clicked "Email me the setup link". If this wasn't you,
      delete this email — no account changes have been made.
    </p>
  </div>
</body></html>
"""
    return subject, plain, html


def send_setup_email(*, mail_obj, recipient: str, subject: str,
                     plain: str, html: str,
                     sender: str | None = None) -> None:
    """Send an email via Flask-Mail. Raises on failure so the route can
    surface the error to the owner instead of silently dropping it."""
    if not recipient:
        raise ValueError("No recipient email on file. Add one in your owner profile.")
    from flask_mail import Message  # local import — keeps tests light
    msg = Message(
        subject=subject,
        recipients=[recipient],
        body=plain,
        html=html,
        sender=sender,
    )
    mail_obj.send(msg)


def send_setup_sms_via_twilio(*, recipient: str, body: str) -> None:
    """Tiny Twilio REST POST. No SDK; just stdlib so requirements stay
    light. Activated only when Twilio credentials are in the env."""
    if not recipient:
        raise ValueError("No recipient phone on file. Add one in your owner profile.")
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    from_num = os.environ.get("TWILIO_FROM_NUMBER", "").strip()
    if not (sid and token and from_num):
        raise RuntimeError(
            "SMS is not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, "
            "and TWILIO_FROM_NUMBER in Railway, or use 'Email me the link' instead."
        )
    import base64
    import urllib.error
    import urllib.request
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    auth = base64.b64encode(f"{sid}:{token}".encode("ascii")).decode("ascii")
    # Twilio caps a single SMS at ~1600 chars but charges per 160. Trim
    # the body to a sane single-page limit so the owner doesn't get a
    # surprise bill from a 12-segment SMS.
    if len(body) > 480:
        body = body[:477] + "..."
    data = urlencode({"To": recipient, "From": from_num, "Body": body}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status >= 400:
                raise RuntimeError(
                    f"Twilio rejected the SMS (HTTP {resp.status}). "
                    "Check the destination number is valid and SMS-enabled."
                )
    except urllib.error.HTTPError as exc:
        body_excerpt = ""
        try:
            body_excerpt = exc.read().decode("utf-8", errors="replace")[:300]
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(
            f"Twilio rejected the SMS (HTTP {exc.code}). {body_excerpt}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Twilio: {exc.reason}") from exc


# ---------------------------------------------------------------------------
# Production-readiness checks — surfaced in the hub UI
# ---------------------------------------------------------------------------

@dataclass
class ReadinessItem:
    key: str
    severity: str   # "blocker" | "warn" | "info" | "ok"
    label: str
    detail: str = ""
    fix_hint: str = ""


def _env(key: str) -> str:
    return (os.environ.get(key) or "").strip()


def _is_production() -> bool:
    return (
        _env("IS_PRODUCTION").lower() in {"1", "true", "yes", "on"}
        or _env("FLASK_ENV") == "production"
        or bool(_env("RAILWAY_ENVIRONMENT"))
    )


def production_readiness_check() -> list[ReadinessItem]:
    """Snapshot of "things you should fix before going live". Returned as
    a flat list so it renders trivially in Jinja and serialises to JSON
    for `/owner/integrations/checklist.json`."""
    items: list[ReadinessItem] = []
    prod = _is_production()

    # Mandatory secrets
    secret_key = _env("SECRET_KEY") or _env("SESSION_SECRET")
    if not secret_key:
        items.append(ReadinessItem(
            key="SECRET_KEY", severity="blocker",
            label="SECRET_KEY missing",
            detail="Sessions and CSRF tokens cannot be signed without it.",
            fix_hint="Set SECRET_KEY to at least 32 random bytes in Railway → Variables.",
        ))
    elif len(secret_key) < 32:
        items.append(ReadinessItem(
            key="SECRET_KEY", severity="warn",
            label="SECRET_KEY is too short",
            detail=f"Current length is {len(secret_key)} chars; recommended ≥ 32.",
            fix_hint="Regenerate with `python -c 'import secrets; print(secrets.token_urlsafe(48))'`.",
        ))
    else:
        items.append(ReadinessItem(
            key="SECRET_KEY", severity="ok",
            label="SECRET_KEY configured",
        ))

    if not _env("DATABASE_URL"):
        items.append(ReadinessItem(
            key="DATABASE_URL", severity="blocker" if prod else "warn",
            label="DATABASE_URL missing",
            detail=("Production refuses to boot without a real Postgres URL — "
                    "Railway's filesystem is wiped on every redeploy."),
            fix_hint="Add a PostgreSQL plugin in Railway; the URL is injected automatically.",
        ))
    else:
        items.append(ReadinessItem(
            key="DATABASE_URL", severity="ok", label="DATABASE_URL configured"))

    # Encryption key for stored gateway credentials
    if not (_env("BILLING_ENCRYPTION_KEY") or secret_key):
        items.append(ReadinessItem(
            key="BILLING_ENCRYPTION_KEY", severity="blocker",
            label="BILLING_ENCRYPTION_KEY missing",
            detail="Owner-side payment credentials cannot be encrypted at rest.",
            fix_hint="Either set SECRET_KEY (used as fallback) or a dedicated BILLING_ENCRYPTION_KEY.",
        ))
    elif not _env("BILLING_ENCRYPTION_KEY"):
        items.append(ReadinessItem(
            key="BILLING_ENCRYPTION_KEY", severity="info",
            label="Using SECRET_KEY for billing encryption",
            detail="Rotating SECRET_KEY will simultaneously rotate the encryption key.",
            fix_hint=("Optional: set BILLING_ENCRYPTION_KEY independently so you can "
                      "rotate session secrets without re-encrypting every credential."),
        ))
    else:
        items.append(ReadinessItem(
            key="BILLING_ENCRYPTION_KEY", severity="ok",
            label="BILLING_ENCRYPTION_KEY configured (independent from SECRET_KEY)"))

    # Owner signup mode — never `open` in production
    mode = (_env("OWNER_SIGNUP_MODE") or "approval").lower()
    if prod and mode == "open":
        items.append(ReadinessItem(
            key="OWNER_SIGNUP_MODE", severity="blocker",
            label="OWNER_SIGNUP_MODE=open in production",
            detail="Anyone on the internet can self-register a cafe right now.",
            fix_hint="Set OWNER_SIGNUP_MODE=approval (or invite_only) in Railway → Variables.",
        ))
    else:
        items.append(ReadinessItem(
            key="OWNER_SIGNUP_MODE", severity="ok",
            label=f"OWNER_SIGNUP_MODE={mode}"))

    # Email — required so the "send setup link" button works
    if not (_env("MAIL_USERNAME") or _env("SENDGRID_API_KEY")):
        items.append(ReadinessItem(
            key="MAIL", severity="warn",
            label="Outbound email not configured",
            detail="The Integrations Hub can't email you setup links until SMTP/SendGrid is set.",
            fix_hint="Set SENDGRID_API_KEY (recommended) or MAIL_USERNAME + MAIL_PASSWORD.",
        ))
    else:
        items.append(ReadinessItem(key="MAIL", severity="ok", label="Outbound email configured"))

    # Webhook HTTPS enforcement
    if prod:
        if _env("RAILWAY_ENVIRONMENT") or _env("FLASK_ENV") == "production":
            items.append(ReadinessItem(
                key="WEBHOOK_HTTPS", severity="ok",
                label="Webhook HTTPS enforcement is on",
                detail="Plaintext webhook callbacks will be rejected with HTTP 400.",
            ))

    # Sentry — recommended, not required
    if not _env("SENTRY_DSN"):
        items.append(ReadinessItem(
            key="SENTRY_DSN", severity="info",
            label="Sentry not configured",
            detail="Production exceptions go only to Railway's stdout logs.",
            fix_hint="Set SENTRY_DSN to capture errors with stack traces.",
        ))
    else:
        items.append(ReadinessItem(
            key="SENTRY_DSN", severity="ok", label="Sentry error tracking enabled"))

    # Trusted proxies (matters for HSTS / secure cookies behind Railway)
    if prod and not _env("TRUSTED_PROXIES"):
        items.append(ReadinessItem(
            key="TRUSTED_PROXIES", severity="info",
            label="TRUSTED_PROXIES not set",
            detail="Defaults to 1 hop — fine for plain Railway. Increase if you front it with Cloudflare.",
        ))

    # Superadmin gate
    if prod and not _env("SUPERADMIN_KEY"):
        items.append(ReadinessItem(
            key="SUPERADMIN_KEY", severity="warn",
            label="SUPERADMIN_KEY not set",
            detail="Non-superadmin admins cannot elevate to /superadmin without it.",
            fix_hint="Set SUPERADMIN_KEY to a long random string and rotate periodically.",
        ))

    return items


def readiness_summary(items: list[ReadinessItem]) -> dict:
    counts = {"blocker": 0, "warn": 0, "info": 0, "ok": 0}
    for it in items:
        counts[it.severity] = counts.get(it.severity, 0) + 1
    if counts["blocker"]:
        verdict = "blocked"
    elif counts["warn"]:
        verdict = "needs_attention"
    else:
        verdict = "production_ready"
    return {
        "verdict": verdict,
        "counts": counts,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Helpers reused by the route
# ---------------------------------------------------------------------------

def to_jsonable(card: IntegrationCard) -> dict:
    """Plain dict for ``jsonify`` — datetimes become ISO strings."""
    return {
        "key": card.key,
        "label": card.label,
        "category": card.category,
        "summary": card.summary,
        "state": card.state,
        "badge_text": card.badge_text,
        "is_verified": card.is_verified,
        "last_test_status": card.last_test_status,
        "last_test_message": card.last_test_message,
        "last_tested_at": card.last_tested_at.isoformat() if card.last_tested_at else None,
        "setup_url": card.setup_url,
        "signup_url": card.signup_url,
        "dashboard_url": card.dashboard_url,
        "webhook_url": card.webhook_url,
    }


def channel_available(channel: str) -> tuple[bool, str]:
    """Return (available, human_message). Used by the route to fail
    early with a friendly error before invoking the actual sender."""
    if channel == "email":
        if _env("MAIL_USERNAME") or _env("SENDGRID_API_KEY") or _env("MAIL_PASSWORD"):
            return True, ""
        return False, "Outbound email isn't configured yet — set up SendGrid/SMTP first."
    if channel == "sms":
        if _env("TWILIO_ACCOUNT_SID") and _env("TWILIO_AUTH_TOKEN") and _env("TWILIO_FROM_NUMBER"):
            return True, ""
        return False, "SMS isn't configured — set Twilio env vars or use email instead."
    return False, f"Unknown channel: {channel!r}"
