"""
Input validators.

Common validation helpers for use across the application.
"""

import re
from typing import Optional, Tuple


def validate_email_format(email: str) -> bool:
    """Basic email format validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_phone_number(phone: str) -> bool:
    """Validate phone number (10+ digits, optional + prefix)."""
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    pattern = r'^\+?\d{10,15}$'
    return bool(re.match(pattern, cleaned))


def validate_date_range(start_date, end_date) -> Tuple[bool, Optional[str]]:
    """Validate that start_date is before or equal to end_date."""
    if start_date > end_date:
        return False, "Start date must be before or equal to end date"
    return True, None
