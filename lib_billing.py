"""Pure billing logic — no Flask, no DB, no I/O.

Keeps the math + invariants in one place so the routes stay thin and the
behaviour is unit-testable. Anything that mutates the database lives in
``app.py``; this module only computes.

Design notes:
  - All money values are rounded to 2dp using bankers'-rounding-free
    ``round(x, 2)`` because the existing app stores Numeric(10, 2) — same
    semantics throughout avoids drift.
  - Tax is computed on (subtotal - discount + service_charge + tip), the
    standard restaurant convention in India / most jurisdictions. If a
    user wants a different base, expose a config flag — do not hard-code
    a second formula.
  - Settlement payments must sum to (within ₹0.01 of) the grand total.
    The 1-paisa tolerance absorbs UPI rounding without permitting silent
    under-collection.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

VALID_PAYMENT_METHODS = (
    "cash", "upi", "card", "wallet", "netbanking", "due", "complimentary", "other",
)
VALID_PAYMENT_STATUSES = ("unpaid", "paid", "refunded", "voided")
SETTLEMENT_TOLERANCE = 0.01  # ₹ — covers UPI rounding


@dataclass
class BillTotals:
    """Snapshot of how a bill currently stands. Used by the order-detail
    view to render the breakdown and by ``compute_settlement`` to validate
    a settle attempt."""
    subtotal: float
    discount: float
    service_charge: float
    tax: float
    tip: float
    total: float


def _money(x) -> float:
    try:
        return round(float(x or 0), 2)
    except (TypeError, ValueError):
        return 0.0


def compute_bill_totals(*, subtotal, discount=0, service_charge_pct=0,
                        tax_pct=0, tip=0,
                        service_charge_flat=0, tax_flat=0) -> BillTotals:
    """Recompute the entire bill from primitives.

    Either ``service_charge_pct`` or ``service_charge_flat`` may be set;
    if both are non-zero the percent is applied first and the flat amount
    is added on top. Same for tax. Discount is always subtracted *before*
    service charge / tax — owners hate paying tax on a discount they
    just gave away.
    """
    sub = _money(subtotal)
    disc = max(0.0, min(_money(discount), sub))
    base_after_discount = max(0.0, sub - disc)

    sc_pct_amt = _money(base_after_discount * (_money(service_charge_pct) / 100.0))
    service_charge = _money(sc_pct_amt + _money(service_charge_flat))

    tax_base = base_after_discount + service_charge + _money(tip)
    tax_pct_amt = _money(tax_base * (_money(tax_pct) / 100.0))
    tax = _money(tax_pct_amt + _money(tax_flat))

    total = _money(base_after_discount + service_charge + tax + _money(tip))
    return BillTotals(
        subtotal=sub,
        discount=disc,
        service_charge=service_charge,
        tax=tax,
        tip=_money(tip),
        total=total,
    )


def validate_payment_method(method: str) -> str:
    method = (method or "").strip().lower()
    if method not in VALID_PAYMENT_METHODS:
        raise ValueError(f"Unknown payment method: {method!r}")
    return method


def normalise_payments(raw: Iterable[dict]) -> list[dict]:
    """Turn a list of submitted ``{method, amount}`` dicts into a clean
    canonical form. Drops zero/negative amounts. Validates methods."""
    out: list[dict] = []
    for entry in raw or []:
        try:
            method = validate_payment_method(str(entry.get("method", "")))
        except ValueError:
            continue
        amount = _money(entry.get("amount", 0))
        if amount <= 0:
            continue
        ref = str(entry.get("reference", "") or "").strip()[:64]
        out.append({"method": method, "amount": amount, "reference": ref})
    return out


def compute_settlement(totals: BillTotals, payments: list[dict]) -> tuple[float, float, str | None]:
    """Returns (paid_amount, change_due, error_message_or_None).

    Cash overpayment yields positive ``change_due``. Any non-cash
    overpayment is rejected — UPI/card overpayment is almost always a
    typo and would force a refund.
    """
    if not payments:
        return 0.0, 0.0, "Add at least one payment to settle this bill."
    paid = _money(sum(p["amount"] for p in payments))
    cash_paid = _money(sum(p["amount"] for p in payments if p["method"] == "cash"))
    target = totals.total
    diff = _money(paid - target)

    if diff < -SETTLEMENT_TOLERANCE:
        return paid, 0.0, f"Short by ₹{abs(diff):.2f}. Collected ₹{paid:.2f}, total ₹{target:.2f}."
    if diff > SETTLEMENT_TOLERANCE:
        # Overpayment is only OK if there's enough cash to cover it (we
        # give the change back from cash). Otherwise it's a data-entry
        # error and we refuse rather than create phantom revenue.
        if cash_paid >= diff:
            return paid, diff, None
        return paid, 0.0, (
            f"Overpaid by ₹{diff:.2f} but no cash was tendered to give change. "
            "Reduce the non-cash amount, or add cash to cover the change."
        )
    return paid, 0.0, None


def next_invoice_number(prefix: str, last_seq: int, today: datetime | None = None) -> tuple[str, int]:
    """Generates ``PREFIX/YYYYMM/000001``-style invoice numbers.

    Year+month in the middle keeps invoice numbers human-scannable and
    naturally restarts the sequence across financial periods if the
    caller resets ``last_seq`` at month boundaries (optional)."""
    today = today or datetime.now(timezone.utc)
    seq = (last_seq or 0) + 1
    cleaned_prefix = (prefix or "INV").strip()[:16] or "INV"
    return f"{cleaned_prefix}/{today:%Y%m}/{seq:06d}", seq


def summarise_payment_breakdown(payments: list[dict]) -> dict[str, float]:
    """Aggregate a payments list for reporting (EOD Z-report etc)."""
    totals: dict[str, float] = {m: 0.0 for m in VALID_PAYMENT_METHODS}
    for p in payments or []:
        m = p.get("method")
        if m in totals:
            totals[m] = _money(totals[m] + _money(p.get("amount", 0)))
    totals = {k: v for k, v in totals.items() if v > 0}
    totals["_total"] = _money(sum(totals.values()))
    return totals


# ---------------------------------------------------------------------------
# v2: reporting helpers — pure-functions consumed by the new dashboard
# pages (refunds, aging, drawer, health).
# ---------------------------------------------------------------------------

from datetime import timedelta as _timedelta  # local re-import for clarity


def parse_date_range(from_str: str | None, to_str: str | None,
                     fallback_days: int = 1) -> tuple[datetime, datetime]:
    """Parse ``?from=YYYY-MM-DD&to=YYYY-MM-DD``. Inclusive day-bounds.

    Returns ``(start_utc, end_utc)`` where ``end_utc`` is the *exclusive*
    upper bound (i.e. start of the day *after* ``to_str``). Falls back
    to "today minus ``fallback_days``" when no range is supplied so the
    EOD page keeps working without any query string."""
    now = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    def _parse(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.strptime(s.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    start = _parse(from_str)
    end_inclusive = _parse(to_str)
    if start and end_inclusive:
        return start, end_inclusive + _timedelta(days=1)
    if start and not end_inclusive:
        return start, start + _timedelta(days=1)
    if end_inclusive and not start:
        return end_inclusive, end_inclusive + _timedelta(days=1)
    # Neither: today (or last N days back).
    return now - _timedelta(days=max(0, fallback_days - 1)), now + _timedelta(days=1)


# Aging-bucket boundaries in seconds. The boundaries are intentionally
# coarse so the dashboard groups orders into "fresh / warm / stale /
# critical" without needing to over-think — finer-grain reports go in
# the EOD CSV.
AGING_BUCKETS: list[tuple[str, int]] = [
    ("under_1h",     60 * 60),
    ("1h_to_4h",     4 * 60 * 60),
    ("4h_to_24h",    24 * 60 * 60),
    ("over_24h",     None),  # type: ignore[arg-type]
]


def aging_bucket_for(seconds_old: float) -> str:
    """Map an "age in seconds" to a bucket key from ``AGING_BUCKETS``."""
    s = max(0.0, float(seconds_old or 0))
    for key, upper in AGING_BUCKETS:
        if upper is None or s < upper:
            return key
    return AGING_BUCKETS[-1][0]


def summarise_aging(open_orders: Iterable[dict],
                    *, now: datetime | None = None) -> dict:
    """Return ``{bucket_key: {count, value}}`` for the aging report.

    Each ``open_orders`` entry is expected to expose ``createdAt`` (ISO
    string) and ``total`` (float). The function tolerates missing /
    malformed values rather than raising, because dashboards must not
    500 just because one row has a NULL ``created_at``."""
    now = now or datetime.now(timezone.utc)
    out = {key: {"count": 0, "value": 0.0} for key, _ in AGING_BUCKETS}
    for o in open_orders or []:
        created_iso = o.get("createdAt") if isinstance(o, dict) else None
        try:
            created = datetime.fromisoformat(str(created_iso).replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).total_seconds()
        except (TypeError, ValueError):
            age = 0.0
        bucket = aging_bucket_for(age)
        out[bucket]["count"] += 1
        try:
            out[bucket]["value"] = round(out[bucket]["value"] + float(o.get("total") or 0), 2)
        except (TypeError, ValueError):
            pass
    out["_total"] = {
        "count": sum(b["count"] for b in out.values()),
        "value": round(sum(b["value"] for b in out.values()), 2),
    }
    return out


def revenue_sparkline(daily_rows: Iterable[dict]) -> dict:
    """Reduce a list of ``{date, gross, refunds, orders}`` rows to a
    sparkline payload suitable for the dashboard.

    Returns ``{labels, gross, net, refund_pct, peak, total_net}``.
    Caller is responsible for the SQL aggregation; this helper exists so
    the formatting/edge-cases (zero-revenue days etc.) live in one
    tested place instead of being repeated in each route."""
    rows = list(daily_rows or [])
    labels: list[str] = []
    gross: list[float] = []
    net: list[float] = []
    refund_pct: list[float] = []
    for r in rows:
        d = r.get("date") if isinstance(r, dict) else None
        labels.append(str(d) if d else "")
        g = _money(r.get("gross", 0))
        rf = _money(r.get("refunds", 0))
        n = max(0.0, round(g - rf, 2))
        gross.append(g)
        net.append(n)
        refund_pct.append(round((rf / g * 100.0) if g > 0 else 0.0, 2))
    peak = max(net) if net else 0.0
    return {
        "labels": labels,
        "gross": gross,
        "net": net,
        "refund_pct": refund_pct,
        "peak": peak,
        "total_net": round(sum(net), 2),
    }


def drawer_variance(*, expected_cash: float, counted_cash: float) -> dict:
    """Return ``{variance, variance_pct, severity}`` for a cash-drawer
    count. Severity follows ``BILLING_DRAWER_VARIANCE_ALERT_PCT``
    semantics and is computed against the *expected* total."""
    exp = _money(expected_cash)
    counted = _money(counted_cash)
    var = round(counted - exp, 2)
    if exp > 0:
        pct = round(abs(var) / exp * 100.0, 2)
    else:
        pct = 100.0 if var != 0 else 0.0
    if abs(var) < 0.01:
        severity = "ok"
    elif pct < 1.0:
        severity = "ok"
    elif pct < 2.0:
        severity = "info"
    elif pct < 5.0:
        severity = "warn"
    else:
        severity = "critical"
    return {"variance": var, "variance_pct": pct, "severity": severity}


def billing_health_snapshot(*, db_ok: bool,
                            stuck_settling_count: int = 0,
                            unsettled_value: float = 0.0,
                            recent_settle_seconds: float | None = None,
                            webhook_failures_last_hour: int = 0,
                            payment_creds_active: int = 0) -> dict:
    """Compose the response body for ``/health/billing`` and
    ``/owner/billing/health.json``.

    Verdict policy:
      * ``critical`` if DB is unreachable.
      * ``degraded`` if there are stuck "settling" rows, or the most
        recent settle took > 5s, or webhook failures > 5/hour.
      * ``ok`` otherwise.
    """
    issues: list[str] = []
    if not db_ok:
        issues.append("database_unreachable")
    if stuck_settling_count > 0:
        issues.append(f"stuck_settling:{stuck_settling_count}")
    if recent_settle_seconds is not None and recent_settle_seconds > 5.0:
        issues.append(f"slow_recent_settle:{recent_settle_seconds:.2f}s")
    if webhook_failures_last_hour > 5:
        issues.append(f"webhook_failures:{webhook_failures_last_hour}")
    if not db_ok:
        verdict = "critical"
    elif issues:
        verdict = "degraded"
    else:
        verdict = "ok"
    return {
        "verdict": verdict,
        "issues": issues,
        "metrics": {
            "stuck_settling_count": stuck_settling_count,
            "unsettled_value": _money(unsettled_value),
            "recent_settle_seconds": (
                round(recent_settle_seconds, 3)
                if recent_settle_seconds is not None else None
            ),
            "webhook_failures_last_hour": int(webhook_failures_last_hour),
            "payment_credentials_active": int(payment_creds_active),
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
