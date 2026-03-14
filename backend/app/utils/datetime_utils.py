"""
Datetime utility functions.

Helpers for timezone conversion, formatting, and calculations.
"""

from datetime import date, datetime, time, timedelta
from typing import Optional


def get_current_utc() -> datetime:
    """Get current UTC datetime."""
    return datetime.utcnow()


def date_range(start_date: date, end_date: date):
    """Iterate over a range of dates (inclusive)."""
    for n in range((end_date - start_date).days + 1):
        yield start_date + timedelta(n)


def calculate_hours_between(start: time, end: time) -> float:
    """Calculate hours between two time objects."""
    start_dt = datetime.combine(date.today(), start)
    end_dt = datetime.combine(date.today(), end)
    if end_dt < start_dt:
        end_dt += timedelta(days=1)
    diff = end_dt - start_dt
    return diff.total_seconds() / 3600


def format_date(d: date, fmt: str = "%Y-%m-%d") -> str:
    """Format a date object to string."""
    return d.strftime(fmt)


def format_datetime(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime object to string."""
    return dt.strftime(fmt)
