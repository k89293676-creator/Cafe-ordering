"""Tests for the unified notification dispatcher and alerting hub."""
from __future__ import annotations

import importlib
import json

import pytest


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def test_email_not_configured_returns_clear_reason(monkeypatch):
    monkeypatch.delenv("MAIL_SERVER", raising=False)
    monkeypatch.delenv("MAIL_USERNAME", raising=False)
    monkeypatch.delenv("MAIL_DEFAULT_SENDER", raising=False)

    import lib_notifications as notify
    importlib.reload(notify)
    res = notify.send_email(to="ops@example.com", subject="x", body="y")
    assert res.ok is False
    assert "not configured" in res.reason


def test_email_invalid_recipient_short_circuits(monkeypatch):
    monkeypatch.setenv("MAIL_SERVER", "smtp.example.com")
    monkeypatch.setenv("MAIL_DEFAULT_SENDER", "ops@example.com")
    import lib_notifications as notify
    importlib.reload(notify)
    res = notify.send_email(to="not-an-email", subject="x", body="y")
    assert res.ok is False
    assert "invalid" in res.reason


def test_sms_not_configured_returns_clear_reason(monkeypatch):
    for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"):
        monkeypatch.delenv(k, raising=False)
    import lib_notifications as notify
    importlib.reload(notify)
    res = notify.send_sms(to="+15555550100", body="hi")
    assert res.ok is False
    assert "not configured" in res.reason


def test_sms_async_path_enqueues_via_webhook_queue(monkeypatch, app):
    """When async_retry=True the SMS becomes a queued webhook."""
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
    monkeypatch.setenv("TWILIO_FROM_NUMBER", "+15550001000")
    import lib_notifications as notify
    importlib.reload(notify)

    # Capture what gets enqueued without actually firing HTTP.
    captured = {}
    helpers = app.extensions["outbound_webhooks"]
    real_enqueue = helpers.enqueue

    def fake_enqueue(**kwargs):
        captured.update(kwargs)
        return {"id": 1, "status": "pending"}

    helpers.enqueue = staticmethod(fake_enqueue)
    try:
        with app.test_request_context("/"):
            res = notify.send_sms(to="+15555550100", body="otp 123",
                                    async_retry=True)
    finally:
        helpers.enqueue = real_enqueue

    assert res.ok is True
    assert captured["target_url"].startswith("https://api.twilio.com")
    assert captured["payload"]["To"] == "+15555550100"
    assert "Authorization" in captured["headers"]


def test_recipient_redaction_keeps_logs_safe():
    from lib_notifications import _redact
    assert _redact("+15555550100") == "+15…100"
    assert _redact("ab") == "***"
    assert _redact("") == ""


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------

def test_alert_no_channels_configured_is_noop(monkeypatch):
    for k in ("ALERT_SLACK_WEBHOOK", "ALERT_DISCORD_WEBHOOK", "ALERT_EMAIL"):
        monkeypatch.delenv(k, raising=False)
    import lib_alerting as alerting
    importlib.reload(alerting)
    res = alerting.alert(severity="critical", title="x", body="y")
    # Every channel returns False, but the call itself does not crash.
    assert res["slack"] is False
    assert res["discord"] is False
    assert res["email"] is False


def test_alert_cooldown_dedups(monkeypatch):
    """Same dedup_key fired twice in a row → second is deduped."""
    import lib_alerting as alerting
    importlib.reload(alerting)
    # Force the in-memory cooldown path
    alerting._redis_client = None

    monkeypatch.setattr(alerting, "_send_slack",
                          lambda *a, **kw: True)
    res1 = alerting.alert(severity="warning", title="db slow",
                            body="p99=2s", dedup_key="db-slow")
    res2 = alerting.alert(severity="warning", title="db slow",
                            body="p99=2s", dedup_key="db-slow")
    assert res1["slack"] is True
    assert res2["deduped"] is True


def test_alert_cooldown_does_not_block_no_dedup(monkeypatch):
    """Without a dedup_key every call goes through."""
    import lib_alerting as alerting
    importlib.reload(alerting)
    alerting._redis_client = None
    monkeypatch.setattr(alerting, "_send_slack", lambda *a, **kw: True)
    a = alerting.alert(severity="info", title="t", body="b")
    b = alerting.alert(severity="info", title="t", body="b")
    assert a["deduped"] is False
    assert b["deduped"] is False


def test_configured_channels_lists_only_set(monkeypatch):
    monkeypatch.setenv("ALERT_SLACK_WEBHOOK", "https://hooks.slack.com/x")
    monkeypatch.delenv("ALERT_DISCORD_WEBHOOK", raising=False)
    monkeypatch.setenv("ALERT_EMAIL", "ops@example.com")
    import lib_alerting as alerting
    importlib.reload(alerting)
    chans = alerting.configured_channels()
    assert "slack" in chans
    assert "email" in chans
    assert "discord" not in chans
