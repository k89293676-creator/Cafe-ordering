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
