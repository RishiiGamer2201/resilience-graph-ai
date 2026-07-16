"""
Timestamps for the SOC Command Center — India Standard Time.

The operator we're building for is Indian critical infrastructure (PS7) and the
topbar clock already reads IST, so every wall-clock timestamp in the product is
IST. A FIXED +5:30 offset is used deliberately: India observes no DST, so this is
exact, and it needs no `tzdata` package in the slim deploy image.

    from src.shared.timeutil import now_ist, fmt_ist
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30), "IST")


def now_ist() -> datetime:
    return datetime.now(IST)


def fmt_ist(dt: datetime | None = None) -> str:
    """'2026-07-16 18:20 IST' — date + time, sortable, timezone stated."""
    dt = dt or now_ist()
    return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M IST")


def fmt_ist_date(dt: datetime | None = None) -> str:
    """'2026-07-16' — for feeds that publish a date with no time."""
    dt = dt or now_ist()
    return dt.astimezone(IST).strftime("%Y-%m-%d")
