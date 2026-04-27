"""Unit tests for the v2 billing helpers (lib_billing extensions and
lib_billing_security). Pure-function tests — no Flask test client is
required, so the suite stays fast (< 50ms) and runs as part of the
default ``pytest`` invocation in CI."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from lib_billing import (
    aging_bucket_for,
    billing_health_snapshot,
    drawer_variance,
    parse_date_range,
    revenue_sparkline,
    summarise_aging,
)
from lib_billing_security import (
    StepUpDecision,
    check_refund_amount_cap,
    check_refund_velocity_per_hour,
    constant_time_eq,
    is_stepup_session_fresh,
    origin_matches,
    refund_daily_cap_pct,
    stepup_refund_threshold,
    stepup_required_for_refund,
    stepup_required_for_void,
    verify_password_constant_time,
    webhook_dedupe_key,
)


# ---------------------------------------------------------------------------
# parse_date_range
# ---------------------------------------------------------------------------

def test_parse_date_range_both_dates():
    s, e, label = parse_date_range("2026-04-01", "2026-04-03")
    assert s == datetime(2026, 4, 1, tzinfo=timezone.utc)
    # End is exclusive — the day *after* the inclusive "to"
    assert e == datetime(2026, 4, 4, tzinfo=timezone.utc)
    assert "2026-04-01" in label and "2026-04-03" in label


def test_parse_date_range_invalid_falls_back_to_today():
    s, e, label = parse_date_range("garbage", "also-garbage", fallback_days=1)
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    assert s == today
    assert e == today + timedelta(days=1)
    assert label == today.strftime("%Y-%m-%d")


def test_parse_date_range_only_from():
    s, e, _label = parse_date_range("2026-04-01", None)
    assert s == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert e == datetime(2026, 4, 2, tzinfo=timezone.utc)


def test_parse_date_range_fallback_window_days():
    s, e, _label = parse_date_range(None, None, fallback_days=7)
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    assert s == today - timedelta(days=6)
    assert e == today + timedelta(days=1)


def test_parse_date_range_today_kwarg_anchors_fallback():
    """Callers (the EOD route) pass an explicit ``today`` so the
    fallback window is anchored to the cafe's local midnight rather
    than UTC midnight."""
    anchor = datetime(2026, 1, 15, tzinfo=timezone.utc)
    s, e, _label = parse_date_range(None, None, fallback_days=1, today=anchor)
    assert s == anchor
    assert e == anchor + timedelta(days=1)


# ---------------------------------------------------------------------------
# aging buckets
# ---------------------------------------------------------------------------

def test_aging_bucket_boundaries():
    assert aging_bucket_for(0) == "under_1h"
    assert aging_bucket_for(60 * 60 - 1) == "under_1h"
    assert aging_bucket_for(60 * 60) == "1h_to_4h"
    assert aging_bucket_for(4 * 60 * 60 - 1) == "1h_to_4h"
    assert aging_bucket_for(4 * 60 * 60) == "4h_to_24h"
    assert aging_bucket_for(24 * 60 * 60 - 1) == "4h_to_24h"
    assert aging_bucket_for(24 * 60 * 60) == "over_24h"
    assert aging_bucket_for(99 * 24 * 60 * 60) == "over_24h"


def test_summarise_aging_groups_by_age_and_sums_value():
    now = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    orders = [
        {"createdAt": (now - timedelta(minutes=5)).isoformat(),  "total": 100.0},
        {"createdAt": (now - timedelta(hours=2)).isoformat(),    "total": 250.0},
        {"createdAt": (now - timedelta(hours=10)).isoformat(),   "total": 50.0},
        {"createdAt": (now - timedelta(days=3)).isoformat(),     "total": 999.99},
        {"createdAt": "garbage-date",                             "total": 1.0},  # tolerated
    ]
    out = summarise_aging(orders, now=now)
    assert out["under_1h"]["count"] == 2  # 5min + garbage→0s
    assert out["1h_to_4h"]["count"] == 1
    assert out["4h_to_24h"]["count"] == 1
    assert out["over_24h"]["count"] == 1
    assert out["_total"]["count"] == 5
    assert out["_total"]["value"] == pytest.approx(1400.99, rel=1e-6)


def test_summarise_aging_empty():
    out = summarise_aging([])
    assert out["_total"] == {"count": 0, "value": 0.0}
    for bucket in ("under_1h", "1h_to_4h", "4h_to_24h", "over_24h"):
        assert out[bucket] == {"count": 0, "value": 0.0}


# ---------------------------------------------------------------------------
# revenue_sparkline
# ---------------------------------------------------------------------------

def test_revenue_sparkline_basic_rollup():
    rows = [
        {"date": "2026-04-01", "gross": 1000, "refunds": 100},
        {"date": "2026-04-02", "gross": 500,  "refunds": 0},
        {"date": "2026-04-03", "gross": 0,    "refunds": 0},
    ]
    out = revenue_sparkline(rows)
    assert out["labels"] == ["2026-04-01", "2026-04-02", "2026-04-03"]
    assert out["gross"] == [1000.0, 500.0, 0.0]
    assert out["net"] == [900.0, 500.0, 0.0]
    assert out["refund_pct"] == [10.0, 0.0, 0.0]
    assert out["peak"] == 900.0
    assert out["total_net"] == 1400.0


def test_revenue_sparkline_handles_zero_division():
    out = revenue_sparkline([{"date": "x", "gross": 0, "refunds": 50}])
    assert out["refund_pct"] == [0.0]  # never divides by 0
    assert out["net"] == [0.0]         # net clamps at 0


def test_revenue_sparkline_empty():
    out = revenue_sparkline([])
    assert out == {
        "labels": [], "gross": [], "net": [], "refund_pct": [],
        "peak": 0.0, "total_net": 0.0,
    }


# ---------------------------------------------------------------------------
# drawer variance
# ---------------------------------------------------------------------------

def test_drawer_variance_perfect():
    out = drawer_variance(expected_cash=1000.0, counted_cash=1000.0)
    assert out["variance"] == 0.0
    assert out["severity"] == "ok"


def test_drawer_variance_small_overage():
    out = drawer_variance(expected_cash=1000.0, counted_cash=1005.0)
    assert out["variance"] == 5.0
    assert out["variance_pct"] == 0.5
    assert out["severity"] == "ok"


def test_drawer_variance_warn_band():
    out = drawer_variance(expected_cash=1000.0, counted_cash=970.0)
    assert out["variance"] == -30.0
    assert out["variance_pct"] == 3.0
    assert out["severity"] == "warn"


def test_drawer_variance_critical():
    out = drawer_variance(expected_cash=1000.0, counted_cash=900.0)
    assert out["severity"] == "critical"


def test_drawer_variance_no_expected_no_counted():
    out = drawer_variance(expected_cash=0, counted_cash=0)
    assert out == {"variance": 0.0, "variance_pct": 0.0, "severity": "ok"}


def test_drawer_variance_no_expected_but_counted_is_critical():
    out = drawer_variance(expected_cash=0, counted_cash=500)
    assert out["severity"] == "critical"


# ---------------------------------------------------------------------------
# health snapshot
# ---------------------------------------------------------------------------

def test_health_snapshot_ok():
    snap = billing_health_snapshot(db_ok=True)
    assert snap["verdict"] == "ok"
    assert snap["issues"] == []


def test_health_snapshot_critical_when_db_down():
    snap = billing_health_snapshot(db_ok=False, stuck_settling_count=0)
    assert snap["verdict"] == "critical"
    assert "database_unreachable" in snap["issues"]


def test_health_snapshot_degraded_on_stuck_rows():
    snap = billing_health_snapshot(db_ok=True, stuck_settling_count=3)
    assert snap["verdict"] == "degraded"
    assert any("stuck_settling" in i for i in snap["issues"])


def test_health_snapshot_degraded_on_slow_settle():
    snap = billing_health_snapshot(db_ok=True, recent_settle_seconds=10.0)
    assert snap["verdict"] == "degraded"


def test_health_snapshot_degraded_on_webhook_failures():
    snap = billing_health_snapshot(db_ok=True, webhook_failures_last_hour=42)
    assert snap["verdict"] == "degraded"


# ---------------------------------------------------------------------------
# step-up auth thresholds
# ---------------------------------------------------------------------------

def test_stepup_thresholds_default():
    assert stepup_refund_threshold() == 500.0
    assert stepup_required_for_refund(501.0) is True
    assert stepup_required_for_refund(500.0) is False
    assert stepup_required_for_refund(499.99) is False
    assert stepup_required_for_void(2001.0) is True
    assert stepup_required_for_void(2000.0) is False


def test_stepup_threshold_env_override(monkeypatch):
    monkeypatch.setenv("BILLING_STEPUP_REFUND_THRESHOLD", "1000")
    assert stepup_refund_threshold() == 1000.0
    monkeypatch.setenv("BILLING_STEPUP_REFUND_THRESHOLD", "garbage")
    assert stepup_refund_threshold() == 500.0  # falls back to default


def test_stepup_session_freshness():
    fresh = datetime.now(timezone.utc).isoformat()
    assert is_stepup_session_fresh(fresh) is True
    stale = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert is_stepup_session_fresh(stale) is False
    assert is_stepup_session_fresh(None) is False
    assert is_stepup_session_fresh("not-a-date") is False


# ---------------------------------------------------------------------------
# refund cap / velocity
# ---------------------------------------------------------------------------

def test_refund_cap_blocks_when_over_pct(monkeypatch):
    monkeypatch.setenv("BILLING_REFUND_DAILY_CAP_PCT", "30")
    v = check_refund_amount_cap(requested=400, refunded_today=0,
                                gross_revenue_today=1000)
    assert v.allowed is False
    assert "30%" in v.reason


def test_refund_cap_allows_when_under(monkeypatch):
    monkeypatch.setenv("BILLING_REFUND_DAILY_CAP_PCT", "30")
    v = check_refund_amount_cap(requested=200, refunded_today=50,
                                gross_revenue_today=1000)
    assert v.allowed is True
    assert v.cap == 300.0


def test_refund_cap_zero_disables(monkeypatch):
    monkeypatch.setenv("BILLING_REFUND_DAILY_CAP_PCT", "0")
    v = check_refund_amount_cap(requested=1_000_000, refunded_today=0,
                                gross_revenue_today=1)
    assert v.allowed is True


def test_refund_cap_zero_revenue_blocks(monkeypatch):
    monkeypatch.setenv("BILLING_REFUND_DAILY_CAP_PCT", "30")
    v = check_refund_amount_cap(requested=10, refunded_today=0,
                                gross_revenue_today=0)
    assert v.allowed is False
    assert "no paid bills" in v.reason.lower()


def test_velocity_blocks_at_cap(monkeypatch):
    monkeypatch.setenv("BILLING_REFUND_VELOCITY_PER_HOUR", "20")
    v = check_refund_velocity_per_hour(refund_count_last_hour=20)
    assert v.allowed is False
    v2 = check_refund_velocity_per_hour(refund_count_last_hour=19)
    assert v2.allowed is True


# ---------------------------------------------------------------------------
# password verification
# ---------------------------------------------------------------------------

class _FakeOwner:
    password_hash = "fake$hash"


def test_verify_password_calls_check_fn():
    calls = []
    def check(h, pw):
        calls.append((h, pw))
        return pw == "secret"
    assert verify_password_constant_time("secret", check, owner=_FakeOwner()) is True
    assert verify_password_constant_time("wrong",  check, owner=_FakeOwner()) is False


def test_verify_password_empty_short_circuits():
    called = []
    def check(h, pw):
        called.append(1)
        return True
    assert verify_password_constant_time("",   check, owner=_FakeOwner()) is False
    assert verify_password_constant_time(None, check, owner=_FakeOwner()) is False
    assert called == []  # never called check_fn for empty


def test_verify_password_no_hash_returns_false():
    class O: password_hash = ""
    assert verify_password_constant_time("anything", lambda h, pw: True, owner=O()) is False


def test_verify_password_check_fn_exception_returns_false():
    def boom(h, pw): raise RuntimeError("db down")
    assert verify_password_constant_time("x", boom, owner=_FakeOwner()) is False


# ---------------------------------------------------------------------------
# origin / referer assertion
# ---------------------------------------------------------------------------

def test_origin_matches_origin_header():
    assert origin_matches(request_host="cafe.example.com",
                          origin_header="https://cafe.example.com/billing") is True
    assert origin_matches(request_host="cafe.example.com",
                          origin_header="https://evil.com/foo") is False


def test_origin_matches_falls_back_to_referer():
    assert origin_matches(request_host="cafe.example.com",
                          origin_header="",
                          referer_header="https://cafe.example.com/dash") is True


def test_origin_matches_both_empty_accepts():
    # CSRF token already covers us when both headers are missing
    assert origin_matches(request_host="cafe.example.com") is True


def test_origin_matches_extra_allowed_hosts():
    assert origin_matches(request_host="cafe.example.com",
                          origin_header="https://staging.cafe.example.com/x",
                          extra_allowed_hosts=["staging.cafe.example.com"]) is True


# ---------------------------------------------------------------------------
# webhook idempotency helpers
# ---------------------------------------------------------------------------

def test_webhook_dedupe_key_format():
    assert webhook_dedupe_key("stripe", "evt_abc") == "stripe::evt_abc"
    assert webhook_dedupe_key("STRIPE", " evt_abc ") == "stripe::evt_abc"


def test_webhook_dedupe_key_empty_components():
    assert webhook_dedupe_key("", "evt_abc") == ""
    assert webhook_dedupe_key("stripe", "") == ""
    assert webhook_dedupe_key("", "") == ""


def test_constant_time_eq():
    assert constant_time_eq("abc", "abc") is True
    assert constant_time_eq("abc", "abd") is False
    assert constant_time_eq("", "") is True
    assert constant_time_eq(None, None) is True  # defensive
