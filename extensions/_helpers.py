"""Shared helpers for the extensions blueprints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable


def parse_date_range(start: str | None, end: str | None, default_days: int = 30):
    """Return (start_dt, end_dt) tuple as timezone-aware UTC datetimes."""
    now = datetime.now(timezone.utc)
    end_dt = _parse_iso_date(end) if end else now
    if end_dt is None:
        end_dt = now
    # Make end-of-day inclusive
    end_dt = end_dt.replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
    start_dt = _parse_iso_date(start) if start else (end_dt - timedelta(days=default_days))
    if start_dt is None:
        start_dt = end_dt - timedelta(days=default_days)
    start_dt = start_dt.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)
    return start_dt, end_dt


def _parse_iso_date(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def sum_field(rows: Iterable, field: str) -> float:
    total = 0.0
    for r in rows:
        total += safe_float(getattr(r, field, 0))
    return total
