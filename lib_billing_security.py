"""Hardening helpers for billing-side actions.

Purpose
-------

Refund/void/settle endpoints touch real money and write to an
append-only audit log; this module centralises the security checks that
sit *in front* of those endpoints so the route bodies stay focused on
the business logic.

Three categories of check live here:

1. **Step-up authentication.** For any destructive action above a
   configurable rupee threshold (defaults: refund > ₹500, void > ₹2000),
   require the operator to re-confirm by re-entering their password (or,
   if 2FA is on, a fresh TOTP code). This thwarts a coffee-shop attack
   where the cashier walks away from an authenticated session.

2. **Velocity caps.** "No single owner can refund more than N% of
   today's gross revenue" and "no single owner can issue more than M
   refunds per hour". This is the single most effective control against
   insider fraud — caps an attacker's blast radius even if they have
   the password.

3. **Same-origin assertion.** On state-changing POSTs, verify
   ``Origin`` (or ``Referer``) host matches the configured
   ``SERVER_NAME`` / request host. Defence-in-depth on top of CSRF
   tokens — closes the small window between a stolen CSRF token and
   the request being made from another origin.

All helpers here are pure-Python with **no Flask import at module
top-level** so they're trivially unit-testable. They take their input
as plain dicts/strings; the caller (app.py) wires them to the request.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Thresholds — env-overridable so an owner can dial them up/down without
# a code change. Defaults err on the strict side: any cashier-driven
# refund > ₹500 or void > ₹2000 triggers a re-auth prompt.
# ---------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(0.0, float(raw))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def stepup_refund_threshold() -> float:
    """Refund amount above which the owner must re-enter their password
    even though they're already logged in. Default: ₹500."""
    return _env_float("BILLING_STEPUP_REFUND_THRESHOLD", 500.0)


def stepup_void_threshold() -> float:
    """Same idea for voids. Default ₹2000 — voids cancel an entire
    bill, so the threshold is intentionally higher than refunds."""
    return _env_float("BILLING_STEPUP_VOID_THRESHOLD", 2000.0)


def refund_daily_cap_pct() -> float:
    """Maximum cumulative refunds in a single UTC day, expressed as a
    percentage of *today's gross revenue*. Default 30%. ``0`` disables."""
    return _env_float("BILLING_REFUND_DAILY_CAP_PCT", 30.0)


def refund_velocity_per_hour() -> int:
    """Max refund operations per owner per rolling hour. Default 20."""
    return _env_int("BILLING_REFUND_VELOCITY_PER_HOUR", 20)


def stepup_session_ttl_seconds() -> int:
    """How long a successful step-up keeps subsequent destructive
    actions un-prompted within the same session. Default 5 minutes."""
    return _env_int("BILLING_STEPUP_TTL_SECONDS", 300)


def drawer_variance_alert_pct() -> float:
    """Cash-drawer variance (|expected−counted|/expected) above this
    triggers an *info* flash, not a hard block. Default 2%."""
    return _env_float("BILLING_DRAWER_VARIANCE_ALERT_PCT", 2.0)


# ---------------------------------------------------------------------------
# Step-up auth gating
# ---------------------------------------------------------------------------

@dataclass
class StepUpDecision:
    """Outcome of ``stepup_required`` / ``check_stepup_token``.

    ``required=False`` means: proceed, no re-auth needed.
    ``required=True`` and ``ok=False`` means: stop, render the prompt /
    flash an error.
    ``required=True`` and ``ok=True`` means: proceed, re-auth was just
    accepted.
    """
    required: bool
    ok: bool = False
    reason: str = ""


def stepup_required_for_refund(amount: float) -> bool:
    return float(amount or 0) > stepup_refund_threshold()


def stepup_required_for_void(bill_total: float) -> bool:
    return float(bill_total or 0) > stepup_void_threshold()


def is_stepup_session_fresh(stepup_at_iso: str | None) -> bool:
    """Returns True if the cached ``billing_stepup_at`` timestamp on the
    session is within the configured TTL. Empty/invalid → False."""
    if not stepup_at_iso:
        return False
    try:
        when = datetime.fromisoformat(stepup_at_iso)
    except (TypeError, ValueError):
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - when).total_seconds()
    return age >= 0 and age <= stepup_session_ttl_seconds()


def verify_password_constant_time(submitted: str, password_check_fn,
                                  *, owner) -> bool:
    """Wrapper around the app's existing password-check function so we
    can call it without importing Flask. ``password_check_fn`` is
    expected to be ``check_password_hash`` from werkzeug or the app's
    own ``_check_password`` — anything that takes ``(hash, plaintext)``.

    Empty submission always returns False without calling the check
    (so we don't leak timing on the constant-time comparator)."""
    if not submitted:
        return False
    pw = str(submitted).strip()
    if not pw:
        return False
    pw_hash = getattr(owner, "password_hash", "") or ""
    if not pw_hash:
        return False
    try:
        return bool(password_check_fn(pw_hash, pw))
    except Exception:  # noqa: BLE001 — never let pw verification crash the route
        return False


# ---------------------------------------------------------------------------
# Velocity / cap checks
# ---------------------------------------------------------------------------

@dataclass
class VelocityVerdict:
    allowed: bool
    reason: str = ""
    cap: float = 0.0
    used: float = 0.0


def check_refund_amount_cap(*, requested: float, refunded_today: float,
                            gross_revenue_today: float) -> VelocityVerdict:
    """Block refunds that would push today's refund total above the
    configured percentage of today's *gross revenue*. The cap is on
    cumulative refunds, not single-event size — a determined attacker
    can't escape it by splitting one ₹10k refund into 100 × ₹100."""
    cap_pct = refund_daily_cap_pct()
    if cap_pct <= 0:
        return VelocityVerdict(allowed=True)
    gross = max(0.0, float(gross_revenue_today or 0))
    if gross <= 0:
        # No revenue today → can't refund anything. Caller should
        # surface a clear message.
        return VelocityVerdict(
            allowed=False,
            reason=("No paid bills yet today. Refunds are blocked until "
                    "at least one bill has been settled."),
            cap=0.0, used=float(refunded_today or 0),
        )
    cap_amount = round(gross * (cap_pct / 100.0), 2)
    new_total = round(float(refunded_today or 0) + float(requested or 0), 2)
    if new_total > cap_amount + 0.01:
        return VelocityVerdict(
            allowed=False,
            reason=(
                f"Refund cap reached: today's refunds may not exceed "
                f"{cap_pct:.0f}% of gross revenue (₹{cap_amount:.2f}). "
                f"Already refunded ₹{float(refunded_today or 0):.2f}; "
                f"this would bring it to ₹{new_total:.2f}."
            ),
            cap=cap_amount, used=float(refunded_today or 0),
        )
    return VelocityVerdict(allowed=True, cap=cap_amount,
                           used=float(refunded_today or 0))


def check_refund_velocity_per_hour(*, refund_count_last_hour: int) -> VelocityVerdict:
    cap = refund_velocity_per_hour()
    if cap <= 0:
        return VelocityVerdict(allowed=True)
    if int(refund_count_last_hour or 0) >= cap:
        return VelocityVerdict(
            allowed=False,
            reason=(
                f"Refund rate limit hit ({cap}/hour). "
                "Wait a few minutes before issuing more refunds, or "
                "raise BILLING_REFUND_VELOCITY_PER_HOUR if this is "
                "expected for your venue."
            ),
            cap=float(cap), used=float(refund_count_last_hour),
        )
    return VelocityVerdict(allowed=True, cap=float(cap),
                           used=float(refund_count_last_hour))


# ---------------------------------------------------------------------------
# Same-origin / referrer assertion
# ---------------------------------------------------------------------------

def _host_of(url: str) -> str:
    if not url:
        return ""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def origin_matches(*, request_host: str,
                   origin_header: str = "",
                   referer_header: str = "",
                   extra_allowed_hosts: Iterable[str] = ()) -> bool:
    """Return True iff Origin (or, if absent, Referer) host matches
    ``request_host`` or any of ``extra_allowed_hosts``.

    Browsers omit Origin on top-level GETs but always send it on
    cross-origin POSTs and on most modern same-origin POSTs. Some
    older browsers / curl don't send it at all — when *both* headers
    are missing we accept the request (the CSRF token covers us)."""
    rh = (request_host or "").lower().split(":", 1)[0]
    allowed = {rh, *(h.lower() for h in extra_allowed_hosts if h)}
    o = _host_of(origin_header)
    if o:
        return o in allowed
    r = _host_of(referer_header)
    if r:
        return r in allowed
    # Both headers missing → don't fail; CSRF token already covers us.
    return True


# ---------------------------------------------------------------------------
# Webhook idempotency
# ---------------------------------------------------------------------------

def webhook_dedupe_key(provider: str, event_id: str) -> str:
    """Canonical (provider, event_id) tuple as a single string. Used as
    the unique key on the WebhookEvent table — preventing the same
    Stripe `evt_*` from settling the same bill twice if the provider
    retries (which they will, aggressively, on any non-2xx response)."""
    p = (provider or "").strip().lower()[:32]
    e = (event_id or "").strip()[:128]
    return f"{p}::{e}" if p and e else ""


def constant_time_eq(a: str, b: str) -> bool:
    """Re-export of hmac.compare_digest with str-coercion."""
    return hmac.compare_digest((a or "").encode("utf-8"),
                               (b or "").encode("utf-8"))
