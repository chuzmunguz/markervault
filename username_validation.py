"""Shared username policy for the web application and bootstrap CLI."""

import re


USERNAME_MAX = 32


def validate_username(raw):
    """Return ``(ok, cleaned, error_message)`` for a prospective username."""
    if not isinstance(raw, str):
        return False, None, "Username is required"

    name = raw.strip()
    if not name:
        return False, None, "Username is required"
    if len(name) > USERNAME_MAX:
        return False, None, f"Username must be at most {USERNAME_MAX} characters"
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return False, None, "Username may contain only letters, digits, and . _ -"
    return True, name, None
