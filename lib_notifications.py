"""Unified notification dispatcher (email + SMS) with retry & audit.

Why a wrapper exists
--------------------
Routes used to reach for ``Flask-Mail`` directly and copy the same
try/except wrapper everywhere. SMS support lived in a single helper
buried in ``lib_integrations.py``. This module gives the rest of the
codebase one entry point — ``send_notification(...)`` — that handles:

- Channel selection (email / sms / both)
- "Not configured" detection without raising
- Outbound retry through ``lib_webhook_retry`` for SMS (Twilio's REST
  API is just an HTTP POST), so transient 5xx failures don't drop a
  one-time-password text on the floor
- Structured audit logging so the operator can prove "did the OTP go
  out at 14:32?"

The functions never raise on a configuration miss; they return a
``NotificationResult`` so the caller can display "We couldn't send
the SMS — check your number" instead of a stack trace.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

_logger = logging.getLogger("cafe.notifications")


@dataclass
class NotificationResult:
    """What happened to the send attempt.

    ``ok`` is True when the message was either delivered synchronously
    (email via SMTP) or accepted for asynchronous delivery (SMS queued
    on the webhook retry queue). ``ok=False`` always carries a
    user-displayable ``reason``.
    """
    ok: bool
    channel: str
    detail: dict = field(default_factory=dict)
    reason: str = ""


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def email_configured() -> bool:
    """Return True if Flask-Mail has enough config to actually send.

    We check ``MAIL_SERVER`` plus a sender so the "send setup link"
    button can disable itself instead of silently failing.
    """
    return bool(
        os.environ.get("MAIL_SERVER")
        and (os.environ.get("MAIL_DEFAULT_SENDER")
             or os.environ.get("MAIL_USERNAME"))
    )


def send_email(*, to: str, subject: str, body: str,
                html: str | None = None,
                sender: str | None = None) -> NotificationResult:
    """Send a single email via Flask-Mail. Best-effort, never raises."""
    if not to or "@" not in to:
        return NotificationResult(ok=False, channel="email",
                                   reason="invalid recipient")
    if not email_configured():
        return NotificationResult(ok=False, channel="email",
                                   reason="email not configured")
    try:
        from flask_mail import Message  # type: ignore
        from flask import current_app
        mail = current_app.extensions.get("mail")
        if mail is None:
            return NotificationResult(ok=False, channel="email",
                                       reason="Flask-Mail not initialised")
        msg = Message(
            subject=subject,
            recipients=[to],
            body=body,
            html=html,
            sender=sender or os.environ.get("MAIL_DEFAULT_SENDER"),
        )
        mail.send(msg)
        _logger.info("notify.email.sent", extra={"to": _redact(to),
                                                   "subject": subject[:100]})
        return NotificationResult(ok=True, channel="email",
                                   detail={"to": _redact(to)})
    except Exception as exc:  # noqa: BLE001
        _logger.warning("notify.email.failed: %s", exc, extra={
            "to": _redact(to), "subject": subject[:100]})
        return NotificationResult(ok=False, channel="email",
                                   reason=f"send failed: {exc}")


# ---------------------------------------------------------------------------
# SMS via Twilio (HTTP, no SDK dep)
# ---------------------------------------------------------------------------

def sms_configured() -> bool:
    return all(os.environ.get(k) for k in (
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"))


def send_sms(*, to: str, body: str,
              owner_id: int | None = None,
              dedup_key: str | None = None,
              async_retry: bool = True) -> NotificationResult:
    """Send a single SMS.

    When ``async_retry`` is true (the default) the message goes through
    the outbound webhook retry queue, so Twilio 5xx blips don't drop
    OTPs on the floor. Pass ``async_retry=False`` for tests or for
    "send right now" flows where blocking the user briefly is acceptable.
    """
    if not to or len(to) < 6:
        return NotificationResult(ok=False, channel="sms",
                                   reason="invalid recipient")
    if not sms_configured():
        return NotificationResult(ok=False, channel="sms",
                                   reason="sms not configured")

    sid = os.environ["TWILIO_ACCOUNT_SID"].strip()
    token = os.environ["TWILIO_AUTH_TOKEN"].strip()
    from_num = os.environ["TWILIO_FROM_NUMBER"].strip()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    payload = {"From": from_num, "To": to, "Body": body}

    if async_retry:
        # Route via the webhook retry queue. Twilio's API takes
        # form-encoded bodies, so we pre-encode and store as a string;
        # the worker will POST as-is.
        try:
            from flask import current_app
            helpers = current_app.extensions.get("outbound_webhooks")
            if helpers is not None:
                helpers.enqueue(
                    target_url=url,
                    payload=payload,
                    owner_id=owner_id,
                    method="POST",
                    headers=_basic_auth_header(sid, token) | {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    dedup_key=dedup_key,
                )
                _logger.info("notify.sms.queued", extra={
                    "to": _redact(to), "owner_id": owner_id})
                return NotificationResult(ok=True, channel="sms",
                                           detail={"to": _redact(to),
                                                    "queued": True})
        except Exception as exc:  # noqa: BLE001 - fall through to sync path
            _logger.warning("notify.sms.queue-failed: %s", exc)

    # Synchronous path (tests, fallback).
    try:
        import urllib.parse
        import urllib.request
        body_enc = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=body_enc, method="POST",
            headers=_basic_auth_header(sid, token) | {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = getattr(resp, "status", 200) or 200
            ok = 200 <= code < 300
            return NotificationResult(
                ok=ok, channel="sms",
                detail={"to": _redact(to), "status": code},
                reason="" if ok else f"HTTP {code}")
    except Exception as exc:  # noqa: BLE001
        return NotificationResult(ok=False, channel="sms",
                                   reason=f"send failed: {exc}")


def send_notification(*, to_email: str | None = None,
                       to_phone: str | None = None,
                       subject: str = "", body: str = "",
                       html: str | None = None,
                       owner_id: int | None = None) -> dict:
    """High-level: try email + SMS independently, return both results.

    The caller decides what to do with the per-channel ``ok`` flags.
    Channels with no recipient are silently skipped (not failures).
    """
    out: dict[str, Any] = {}
    if to_email:
        out["email"] = send_email(to=to_email, subject=subject,
                                    body=body, html=html).__dict__
    if to_phone:
        out["sms"] = send_sms(to=to_phone, body=body,
                               owner_id=owner_id).__dict__
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact(value: str) -> str:
    """Return a recipient string safe to log: keep first 3 and last 3 chars."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}…{value[-3:]}"


def _basic_auth_header(user: str, password: str) -> dict:
    import base64
    creds = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {creds}"}
