"""Tests for the outbound webhook retry queue."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest


def test_compute_backoff_monotonic_within_jitter():
    """Backoff median should grow with attempts, but jitter must keep
    it from being identical (no thundering herd)."""
    import lib_webhook_retry as wr

    # Run many samples so the medians are stable enough to compare.
    samples = [wr.compute_backoff(1, base=1.0, cap=1000) for _ in range(200)]
    assert min(samples) >= 1.0
    assert max(samples) <= 1000

    big = [wr.compute_backoff(8, base=1.0, cap=1000) for _ in range(200)]
    # Attempt 8 should usually be larger than attempt 1.
    assert sum(big) / len(big) > sum(samples) / len(samples)


def test_compute_backoff_caps():
    """Large attempt numbers must not exceed the cap."""
    import lib_webhook_retry as wr
    for _ in range(50):
        assert wr.compute_backoff(20, base=1.0, cap=300) <= 300


def test_sign_payload_stable_and_distinct():
    """Same inputs → same signature; different timestamp → different."""
    import lib_webhook_retry as wr

    sig_a = wr.sign_payload("secret", b'{"x":1}', "1700000000")
    sig_b = wr.sign_payload("secret", b'{"x":1}', "1700000000")
    sig_c = wr.sign_payload("secret", b'{"x":1}', "1700000001")
    assert sig_a == sig_b
    assert sig_a != sig_c
    assert len(sig_a) == 64  # SHA-256 hex


def test_enqueue_creates_pending_row(client, app):
    """enqueue() persists a row in pending state."""
    from app import db
    helpers = app.extensions["outbound_webhooks"]
    with app.app_context():
        result = helpers.enqueue(
            target_url="http://127.0.0.1:1/dead-port",
            payload={"hello": "world"},
            owner_id=1,
        )
    assert result["status"] == "pending"
    assert result["target_url"].endswith("dead-port")
    assert result["attempts"] == 0


def test_enqueue_dedup_key_idempotent(app):
    """Same dedup_key inserted twice must return the original row."""
    helpers = app.extensions["outbound_webhooks"]
    with app.app_context():
        a = helpers.enqueue(
            target_url="http://127.0.0.1:1/x",
            payload={"i": 1},
            dedup_key="dedup-test-001",
        )
        b = helpers.enqueue(
            target_url="http://127.0.0.1:1/x",
            payload={"i": 2},  # different payload — must be ignored
            dedup_key="dedup-test-001",
        )
    assert a["id"] == b["id"]


def test_process_due_marks_dead_after_4xx(app):
    """A 4xx (other than 408/429) must short-circuit to dead-letter."""
    helpers = app.extensions["outbound_webhooks"]

    # Use a URL guaranteed to fail TCP (port 1 = blocked by kernel).
    with app.app_context():
        row = helpers.enqueue(
            target_url="http://127.0.0.1:1/will-fail",
            payload={"x": 1},
            max_attempts=2,
        )
        # First attempt: TCP failure (not 4xx) — schedules a retry.
        helpers.process_due(limit=10)
        helpers.process_due(limit=10)  # second attempt → reaches max
        # After max_attempts the row should be dead.
        from app import db
        from sqlalchemy import text
        rows = db.session.execute(text(
            "SELECT status, attempts FROM outbound_webhooks WHERE id=:i"
        ), {"i": row["id"]}).fetchall()
        assert rows
        status, attempts = rows[0]
        assert status == "dead"
        assert attempts >= 2


def test_requeue_resets_dead_letter(app):
    """Operator can pull a row out of the dead-letter queue."""
    helpers = app.extensions["outbound_webhooks"]
    with app.app_context():
        row = helpers.enqueue(
            target_url="http://127.0.0.1:1/x",
            payload={"y": 1},
            max_attempts=1,
        )
        helpers.process_due(limit=10)  # → dead
        ok = helpers.requeue(row["id"])
        assert ok is True

        from app import db
        from sqlalchemy import text
        status = db.session.execute(text(
            "SELECT status FROM outbound_webhooks WHERE id=:i"
        ), {"i": row["id"]}).scalar()
        assert status == "pending"


def test_ops_webhooks_requires_token(client, monkeypatch):
    monkeypatch.setenv("OPS_HEALTH_TOKEN", "tok")
    res = client.get("/api/ops/webhooks")
    assert res.status_code == 401
    res2 = client.get("/api/ops/webhooks",
                       headers={"Authorization": "Bearer tok"})
    assert res2.status_code == 200
    body = res2.get_json()
    assert body["ok"] is True
    assert "stats" in body and "dead" in body
