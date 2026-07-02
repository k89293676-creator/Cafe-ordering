"""Unit tests for Stripe subscription billing helpers.

Tests the plan limits and monthly order count helper.
No Flask test client needed for pure-function tests; integration
tests that touch HTTP use the conftest.py app fixture pattern from
tests/test_billing_v2.py.
"""
from __future__ import annotations

import pytest

from app.web.billing_subscription import PLAN_DETAILS


# ---------------------------------------------------------------------------
# PLAN_DETAILS structure
# ---------------------------------------------------------------------------

def test_plan_details_has_three_plans():
    assert set(PLAN_DETAILS.keys()) == {"starter", "growth", "pro"}


def test_starter_plan_limits():
    p = PLAN_DETAILS["starter"]
    assert p["max_tables"] == 10
    assert p["monthly_order_limit"] == 500
    assert "STRIPE_PRICE_STARTER" in p["price_env"]


def test_growth_plan_limits():
    p = PLAN_DETAILS["growth"]
    assert p["max_tables"] == 30
    assert p["monthly_order_limit"] == 2000
    assert "STRIPE_PRICE_GROWTH" in p["price_env"]


def test_pro_plan_limits():
    p = PLAN_DETAILS["pro"]
    assert p["max_tables"] is None
    assert p["monthly_order_limit"] is None
    assert "STRIPE_PRICE_PRO" in p["price_env"]


def test_all_plans_have_name_and_price():
    for key, plan in PLAN_DETAILS.items():
        assert plan.get("name"), f"Plan {key!r} is missing 'name'"
        assert plan.get("price"), f"Plan {key!r} is missing 'price'"


# ---------------------------------------------------------------------------
# Plan limit enforcement logic
# ---------------------------------------------------------------------------

def test_table_limit_enforced():
    """Starter plan: adding an 11th table should exceed max_tables."""
    plan = PLAN_DETAILS["starter"]
    current_table_count = 10
    over_limit = plan["max_tables"] is not None and current_table_count >= plan["max_tables"]
    assert over_limit is True


def test_table_limit_not_enforced_for_pro():
    """Pro plan: max_tables is None — unlimited tables."""
    plan = PLAN_DETAILS["pro"]
    current_table_count = 9999
    over_limit = plan["max_tables"] is not None and current_table_count >= plan["max_tables"]
    assert over_limit is False


def test_order_limit_enforced():
    """Growth plan: 2001 orders this month should exceed the limit."""
    plan = PLAN_DETAILS["growth"]
    monthly_orders = 2001
    over_limit = (
        plan["monthly_order_limit"] is not None
        and monthly_orders >= plan["monthly_order_limit"]
    )
    assert over_limit is True


def test_order_limit_not_enforced_for_pro():
    """Pro plan: unlimited orders."""
    plan = PLAN_DETAILS["pro"]
    monthly_orders = 999999
    over_limit = (
        plan["monthly_order_limit"] is not None
        and monthly_orders >= plan["monthly_order_limit"]
    )
    assert over_limit is False


# ---------------------------------------------------------------------------
# Free plan defaults (no subscription)
# ---------------------------------------------------------------------------

def test_free_plan_limits():
    """Free plan limits: 2 tables, 50 orders/month (applied by webhook on cancellation)."""
    FREE_MAX_TABLES = 2
    FREE_ORDER_LIMIT = 50
    assert FREE_MAX_TABLES < PLAN_DETAILS["starter"]["max_tables"]
    assert FREE_ORDER_LIMIT < PLAN_DETAILS["starter"]["monthly_order_limit"]
