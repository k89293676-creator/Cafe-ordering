"""Unit tests for the new stuck-order escalation in tables_overview_bp.

These are pure-function tests — they don't require the Flask test
client, the DB, or the blueprint to actually be wired up. They cover
the threshold logic that flips a table card to ``needs_attention``
when an order has been sitting in the same status for too long.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace


def _import_helpers():
    """Imported lazily so the module-level env reads happen *after* we
    set ``DATABASE_URL`` etc. via conftest."""
    from extensions import tables_overview_bp as bp
    return bp


def test_order_is_stuck_thresholds_per_status():
    bp = _import_helpers()
    # Below threshold for every status → not stuck.
    for status in ("pending", "confirmed", "preparing", "ready"):
        order = SimpleNamespace(status=status)
        assert bp._order_is_stuck(order, 30) is False, status

    # Right at the configured boundary → stuck.
    assert bp._order_is_stuck(SimpleNamespace(status="preparing"),
                              bp.STUCK_PREPARING_SECONDS) is True
    assert bp._order_is_stuck(SimpleNamespace(status="ready"),
                              bp.STUCK_READY_SECONDS) is True
    assert bp._order_is_stuck(SimpleNamespace(status="pending"),
                              bp.STUCK_PENDING_SECONDS) is True


def test_order_is_stuck_unknown_status_never_alerts():
    bp = _import_helpers()
    # We don't want to accidentally fire on completed/cancelled orders
    # if somebody passes one in by mistake.
    for status in ("completed", "cancelled", "", None):
        assert bp._order_is_stuck(SimpleNamespace(status=status), 99_999) is False


def test_order_is_stuck_handles_none_order():
    bp = _import_helpers()
    assert bp._order_is_stuck(None, 99_999) is False


def test_classify_escalates_stuck_preparing_order_to_needs_attention():
    bp = _import_helpers()
    now = datetime.now(timezone.utc)
    # Preparing order that's been sitting forever → needs_attention.
    old_created = now - timedelta(seconds=bp.STUCK_PREPARING_SECONDS + 60)
    order = SimpleNamespace(status="preparing", created_at=old_created)
    assert bp._classify(order, [], now) == "needs_attention"

    # A fresh preparing order is just "occupied".
    fresh = SimpleNamespace(status="preparing", created_at=now)
    assert bp._classify(fresh, [], now) == "occupied"


def test_classify_stuck_takes_priority_over_ready():
    """A 'ready' ticket sitting too long should escalate, not stay in
    the calmer ready_to_serve bucket."""
    bp = _import_helpers()
    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=bp.STUCK_READY_SECONDS + 60)
    order = SimpleNamespace(status="ready", created_at=old)
    assert bp._classify(order, [], now) == "needs_attention"


def test_classify_free_when_no_order_no_calls():
    bp = _import_helpers()
    now = datetime.now(timezone.utc)
    assert bp._classify(None, [], now) == "free"
    assert bp._classify(None, [], now, cleaning=True) == "cleaning"
