"""Shared request-field validation contracts (S-13/D-09).

One side-effect-free home for the typed field validators, explicit maximums,
password policy, and profile validation used by both the Flask backend and the
CLI. The browser keeps a mirror of the password policy for immediate feedback
only; the values here are authoritative and are contract-tested against that
mirror through tests/password_contract_vectors.json.

Maximums are chosen from current real UI payloads plus documented headroom —
ordinary names, notes, and Unicode passwords within bcrypt's byte boundary
must never be rejected.
"""
import re

from datetime import datetime


# Free-text profile fields (first/last name, email, company, department).
PROFILE_FIELD_MAX = 100
# Map and group names.
NAME_MAX = 100
# Marker names allow more room than map names (imported KML names run long).
SPOT_NAME_MAX = 200
DESCRIPTION_MAX = 2000
NOTES_MAX = 10000
CAPTION_MAX = 500
# Marker listing/subset grouping labels.
LISTING_MAX = 100
# Client-supplied created timestamps (ISO-8601 strings).
CREATED_MAX = 40
# bcrypt silently ignores nothing: 5.x raises above 72 UTF-8 bytes.
PASSWORD_MAX_BYTES = 72
# Bulk-operation collections (map_ids) stay far below SQLite's parameter limit.
ID_LIST_MAX = 500

# Allowed values for the optional 'sex' profile field. Empty string means
# "not stated" (the 'Prefer not to say' choice stores empty).
SEX_VALUES = ('male', 'female', 'other', '')


def text_value(value, label, max_length, required=False):
    """Typed text validation returning (ok, error, cleaned).

    None passes through unchanged for optional fields so PUT handlers keep
    their "absent means unchanged" semantics; any other non-string is a stable
    400-shaped error instead of a crash.
    """
    if value is None:
        if required:
            return False, f"{label} is required", None
        return True, "", None
    if not isinstance(value, str):
        return False, f"{label} must be text", None
    value = value.strip()
    if required and not value:
        return False, f"{label} is required", None
    if len(value) > max_length:
        return False, f"{label} is too long (max {max_length} characters)", None
    return True, "", value


def id_list(value, label, max_items=ID_LIST_MAX):
    """Bounded list of integer IDs; booleans are not IDs."""
    if not isinstance(value, list) or not value:
        return False, f"{label} must be a non-empty list of ids", None
    if len(value) > max_items:
        return False, f"{label} has too many entries (max {max_items})", None
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            return False, f"{label} must contain integer ids", None
    return True, "", value


def validate_password_policy(password):
    if not isinstance(password, str):
        return False, "Password must be text"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password.encode('utf-8')) > PASSWORD_MAX_BYTES:
        return False, f"Password must be at most {PASSWORD_MAX_BYTES} bytes of UTF-8"
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must include at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must include at least one special character"
    return True, ""


def valid_email_format(email):
    # Pragmatic format check (not full RFC): non-space local@domain.tld.
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


# Validate + normalize the profile fields shared by /register, PUT /profile, and the
# admin user routes. Returns (ok, error_message, cleaned_dict). first/last name and
# email are required; the rest optional.
def validate_profile_fields(data):
    cleaned = {}
    for key, label, required in (
        ('first_name', "First name", True),
        ('last_name', "Last name", True),
        ('email', "Email", True),
        ('company', "Company", False),
        ('department', "Department", False),
        ('birth_date', "Birth date", False),
        ('sex', "Sex", False),
    ):
        ok, error, value = text_value(data.get(key), label, PROFILE_FIELD_MAX, required=required)
        if not ok:
            return False, error, None
        cleaned[key] = value or ''

    if not valid_email_format(cleaned['email']):
        return False, "Invalid email address", None

    cleaned['sex'] = cleaned['sex'].lower()
    if cleaned['sex'] not in SEX_VALUES:
        return False, "Invalid value for sex", None

    if cleaned['birth_date']:
        try:
            datetime.strptime(cleaned['birth_date'], "%Y-%m-%d")
        except ValueError:
            return False, "Birth date must be YYYY-MM-DD", None

    return True, "", cleaned
