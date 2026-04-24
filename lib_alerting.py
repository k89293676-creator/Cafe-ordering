"""Lightweight alert dispatcher with cooldown.

Posts a short alert to whichever channel the operator configured in
env vars:

- ``ALERT_SLACK_WEBHOOK``  — incoming-webhook URL
- ``ALERT_DISCORD_WEBHOOK`` — incoming-webhook URL
- ``ALERT_EMAIL``           — comma-separated list of recipients

Multiple channels can be configured at once — every configured channel
fires for every alert so the on-call doesn't miss it because Slack ate
the notification.

Cooldown
--------
``alert(..., dedup_key="db-down")`` will only fire once per
``ALERT_COOLDOWN_SECONDS`` (default 5 minutes) for the same key. This
matters when the same root cause (e.g. DB unreachable) would otherwise
fan out to dozens of identical pages.

Backed by Redis when ``REDIS_URL`` is set so the cooldown is honoured
across all gunicorn workers; falls back to a per-process dict
otherwise.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request

_logger = logging.getLogger("cafe.alerts")

COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))

_recent_local: dict[str, float] = {}
_recent_local_lock = threading.Lock()

_redis_client = None
try:  # pragma: no cover - optional dependency
    if os.environ.get("REDIS_URL"):
        import redis as _redis_lib
        _redis_client = _redis_lib.Redis.from_url(
            os.environ["REDIS_URL"], decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
        _redis_client.ping()
except Exception:  # noqa: BLE001
    _redis_client = None


def _was_recently_sent(key: str) -> bool:
    """Return True if an alert with this key was sent inside the cooldown."""
    if not key:
        return False
    if _redis_client is not None:
        try:
            return bool(_redis_client.exists(f"cafe:alert:cooldown:{key}"))
        except Exception:  # noqa: BLE001
            pass
    now = time.monotonic()
    with _recent_local_lock:
        ts = _recent_local.get(key, 0)
        return (now - ts) < COOLDOWN_SECONDS


def _mark_sent(key: str) -> None:
    if not key:
        return
    if _redis_client is not None:
        try:
            _redis_client.set(f"cafe:alert:cooldown:{key}", "1",
                               ex=COOLDOWN_SECONDS)
            return
        except Exception:  # noqa: BLE001
            pass
    with _recent_local_lock:
        _recent_local[key] = time.monotonic()


def _post_json(url: str, body: dict) -> bool:
    """Best-effort POST a small JSON body. Never raises."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        _logger.warning("alert post failed (%s): %s", url[:60], exc)
        return False


def _send_slack(title: str, body: str, severity: str) -> bool:
    url = os.environ.get("ALERT_SLACK_WEBHOOK", "").strip()
    if not url:
        return False
    icon = {"critical": ":rotating_light:", "warning": ":warning:",
             "info": ":information_source:"}.get(severity, ":bell:")
    return _post_json(url, {
        "text": f"{icon} *[{severity.upper()}]* {title}\n{body}",
    })


def _send_discord(title: str, body: str, severity: str) -> bool:
    url = os.environ.get("ALERT_DISCORD_WEBHOOK", "").strip()
    if not url:
        return False
    color = {"critical": 0xE53935, "warning": 0xFFA000,
              "info": 0x1976D2}.get(severity, 0x6E7681)
    return _post_json(url, {
        "embeds": [{
            "title": f"[{severity.upper()}] {title}",
            "description": body[:2000],
            "color": color,
        }],
    })


def _send_email(title: str, body: str, severity: str) -> bool:
    recipients = [r.strip() for r in
                   os.environ.get("ALERT_EMAIL", "").split(",") if r.strip()]
    if not recipients:
        return False
    try:
        # Reuse the unified notification dispatcher so configuration
        # checks live in one place.
        import lib_notifications as notify
        ok_any = False
        for rcpt in recipients:
            res = notify.send_email(
                to=rcpt,
                subject=f"[{severity.upper()}] {title}",
                body=body,
            )
            ok_any = ok_any or res.ok
        return ok_any
    except Exception as exc:  # noqa: BLE001
        _logger.warning("alert email failed: %s", exc)
        return False


def alert(*, severity: str, title: str, body: str = "",
           dedup_key: str = "") -> dict:
    """Fire an alert across every configured channel.

    Returns a per-channel dict so the caller (and tests) can see what
    was attempted.
    """
    severity = (severity or "info").lower()
    if dedup_key and _was_recently_sent(dedup_key):
        return {"deduped": True, "key": dedup_key}
    out = {
        "deduped": False,
        "slack": _send_slack(title, body, severity),
        "discord": _send_discord(title, body, severity),
        "email": _send_email(title, body, severity),
    }
    if any(out.get(k) for k in ("slack", "discord", "email")):
        _mark_sent(dedup_key)
    return out


def configured_channels() -> list[str]:
    """Quick health-check helper — what's actually wired up?"""
    out = []
    if os.environ.get("ALERT_SLACK_WEBHOOK"):
        out.append("slack")
    if os.environ.get("ALERT_DISCORD_WEBHOOK"):
        out.append("discord")
    if os.environ.get("ALERT_EMAIL"):
        out.append("email")
    return out
