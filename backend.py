import sqlite3, requests, re, os, unicodedata, threading, uuid, json, shutil, ipaddress, socket, time, secrets, hashlib, hmac, base64, logging, itertools
import defusedxml.ElementTree as ET
import jwt, bcrypt

from urllib.parse import urlparse, urljoin
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify, make_response, g, abort
from datetime import datetime, timedelta, timezone
from PIL import Image, ImageOps
from io import BytesIO
from email_delivery import (
    EmailDeliveryError, SMTPDelivery, password_reset_email_content,
    verification_email_content,
)
from markervault_config import load_backend_configuration
from markervault_schema import initialize_schema
from request_validation import (
    CAPTION_MAX, CREATED_MAX, DESCRIPTION_MAX, LISTING_MAX, NAME_MAX, NOTES_MAX,
    PASSWORD_MAX_BYTES, PROFILE_FIELD_MAX, SPOT_NAME_MAX,
    id_list, text_value, valid_email_format, validate_password_policy,
    validate_profile_fields,
)
from username_validation import validate_username


# =====================
# Backend configuration
# =====================
# All MARKERVAULT_* values are parsed and validated once in markervault_config.py.
# SMTP is constructed without connecting; no product flow calls it before Stage 12.
BACKEND_CONFIG = load_backend_configuration()

ENVIRONMENT = BACKEND_CONFIG.environment
DB_FILE = BACKEND_CONFIG.database_path
PHOTOS_FOLDER = BACKEND_CONFIG.photos_path
THUMBS_FOLDER = BACKEND_CONFIG.thumbs_path
AVATARS_FOLDER = BACKEND_CONFIG.avatars_path
TEMP_FOLDER = BACKEND_CONFIG.temp_path
ACCESS_TOKEN_SECRET = BACKEND_CONFIG.access_token_secret
ACCESS_TOKEN_DURATION = BACKEND_CONFIG.access_token_duration
REFRESH_TOKEN_DURATION = BACKEND_CONFIG.refresh_token_duration
BIND_TOKEN_TO_IP = BACKEND_CONFIG.bind_token_to_ip
COOKIE_SECURE = BACKEND_CONFIG.cookie_secure
TRUSTED_PROXIES = BACKEND_CONFIG.trusted_proxies
ALLOWED_IP_RANGES = BACKEND_CONFIG.allowed_ip_ranges
CANONICAL_HOSTS = BACKEND_CONFIG.canonical_hosts
TEMPORARY_LAN_HOSTS = BACKEND_CONFIG.temporary_lan_hosts
ALLOWED_HOSTS = BACKEND_CONFIG.allowed_hosts
MAX_KML_PHOTO_BYTES = BACKEND_CONFIG.max_kml_photo_bytes
MAX_IMAGE_DIMENSION = BACKEND_CONFIG.max_image_dimension
MAX_IMAGE_PIXELS = BACKEND_CONFIG.max_image_pixels
KML_MAX_WORKERS = BACKEND_CONFIG.kml_max_workers
KML_JOBS_PER_USER = BACKEND_CONFIG.kml_jobs_per_user
KML_JOBS_GLOBAL = BACKEND_CONFIG.kml_jobs_global
KML_MAX_BYTES = BACKEND_CONFIG.kml_max_bytes
KML_MAX_ELEMENTS = BACKEND_CONFIG.kml_max_elements
KML_MAX_DEPTH = BACKEND_CONFIG.kml_max_depth
KML_MAX_PLACEMARKS = BACKEND_CONFIG.kml_max_placemarks
KML_MAX_PHOTOS_PER_SPOT = BACKEND_CONFIG.kml_max_photos_per_spot
KML_MAX_DOWNLOAD_BYTES = BACKEND_CONFIG.kml_max_download_bytes
KML_MAX_FETCH_ATTEMPTS = BACKEND_CONFIG.kml_max_fetch_attempts
KML_MAX_JOB_SECONDS = BACKEND_CONFIG.kml_max_job_seconds
NOTIF_HISTORY_CAP = BACKEND_CONFIG.notif_history_cap
PRIVATE_REFILL_INTERVAL = BACKEND_CONFIG.private_refill_interval
AUTH_REFILL_INTERVAL = BACKEND_CONFIG.auth_refill_interval
PUBLIC_REFILL_INTERVAL = BACKEND_CONFIG.public_refill_interval
BURST = BACKEND_CONFIG.rate_burst
PRIVATE_BURST = BACKEND_CONFIG.private_rate_burst
EMAIL_DELIVERY_ENABLED = BACKEND_CONFIG.email_delivery_enabled
REQUIRE_EMAIL_VERIFICATION = BACKEND_CONFIG.require_email_verification
PUBLIC_ORIGIN = BACKEND_CONFIG.public_origin
EMAIL_VERIFICATION_TOKEN_DURATION = BACKEND_CONFIG.email_verification_token_duration
PASSWORD_RESET_TOKEN_DURATION = BACKEND_CONFIG.password_reset_token_duration
EMAIL_RESEND_COOLDOWN = BACKEND_CONFIG.email_resend_cooldown
EMAIL_SENDER = SMTPDelivery.from_backend_configuration(BACKEND_CONFIG)

if BACKEND_CONFIG.access_token_secret_is_ephemeral:
    print("WARNING: MARKERVAULT_ACCESS_TOKEN_SECRET not set - using an ephemeral dev secret")

# A missing username still performs exactly one cost-12 bcrypt check. This static hash
# is not a credential and avoids generating a new hash on every failed login.
DUMMY_PASSWORD_HASH = b'$2b$12$hY8fcy8PN6xr0xtnvR/2BOEvf3azQa/1LEOYoj2JoQywg7BTdMiPy'

NOTIF_MESSAGE_MAX = 500
NOTIF_TARGET_TYPE_MAX = 40
NOTIF_TARGET_ID_MAX = 200
NOTIF_TARGET_LABEL_MAX = 200
NOTIF_DETAIL_MAX = 2000
NOTIF_CORRELATION_ID_MAX = 64
NOTIF_EVENTS = frozenset((
    'map.deleted',
    'marker.deleted',
    'photo.deleted',
    'kml.import_done',
    'kml.import_degraded',
    'kml.import_error',
    'server.error',
))


app = Flask(__name__)
# Frontend static files and the API are served from the same origin (nginx + gunicorn
# on one host), so no CORS is needed — the previous wildcard CORS(app) was removed.

# Reject request bodies above this size outright (protects direct photo uploads
# and any other multipart POST from unbounded memory use).
app.config['MAX_CONTENT_LENGTH'] = BACKEND_CONFIG.max_content_length


# S-12: nginx rejects unrecognized Host values at the edge; this mirror of the same
# allowlist covers direct backend exposure, so a request that bypasses nginx cannot
# use an attacker-chosen Host either.
@app.before_request
def require_trusted_host():
    host = (request.host or '').lower().rstrip('.')
    if host.startswith('['):
        host = host[1:host.find(']')]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    if host not in ALLOWED_HOSTS:
        return jsonify({'error': 'Unrecognized request host'}), 421

# Access tokens: short-lived JWTs sent in the Authorization header.
# Refresh tokens: opaque, hashed at rest, rotated, delivered in an HttpOnly cookie
#                 scoped to /auth so it is sent to /auth/refresh and /auth/logout only.

# Token-bucket rate limiting (in-memory: {ip: {"requests": int, "last_refill": ts}})
PRIVATE_BUCKET = {}                      # authenticated data routes
AUTH_BUCKET = {}                         # /auth/refresh
PUBLIC_BUCKET = {}                       # /login
EMAIL_BUCKET = {}                        # verification/recovery requests
PHOTO_BUCKET = {}                        # signed photo/thumb serving (bursty gallery loads)
USERNAME_BUCKET = {}                     # failed logins per submitted username (not per IP)
# Entries are allocated before a request is known to be legitimate (the allowlist and
# rate limit run ahead of any credential or signature check), so without eviction a
# stream of distinct source addresses grows these dicts without bound — one IPv6 /64
# supplies more than enough from a single machine. How many stale entries each call
# examines; see _evict_refilled.
RATE_LIMIT_EVICTION_SCAN = 8


# Uploaded-image folders and the external database directory (Stage 7 layout)
os.makedirs(PHOTOS_FOLDER, exist_ok=True)
os.makedirs(THUMBS_FOLDER, exist_ok=True)
os.makedirs(AVATARS_FOLDER, exist_ok=True)
if os.path.dirname(DB_FILE):
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)


# Sanitize filenames
# Remove characters that are unsafe for file system / URLs. Keep alphanumerics, dot, dash, underscore, space and parentheses)
def sanitize_filename(filename: str) -> str:
    safe_name = unicodedata.normalize("NFC", filename)              # Normalize Unicode
    safe_name = re.sub(r'[^A-Za-z0-9\s._\-\(\)]', '_', safe_name)   # Replace unsafe characters with underscore
    safe_name = re.sub(r'[\s_]+', '_', safe_name)                   # Collapse multiple consecutive underscores or spaces into a single underscore
    safe_name = safe_name.strip()                                   # Strip leading/trailing whitespace
    safe_name = os.path.basename(safe_name)                         # Ensure no directory traversal
    return safe_name[:255]                                          # Limit length


# =====================
# S-14: structured logging and generic client errors
# =====================
# Clients get a stable generic message plus a correlation id; the exception detail
# stays server-side under the same id. The truncation/redaction helpers exist for any
# log line that carries untrusted text (Stage 11 applies them to the KML worker).
LOGGER = logging.getLogger("markervault.backend")


def clean_log_value(value, limit=200):
    text = str(value)
    text = ''.join(character for character in text if character.isprintable())
    return text[:limit]


def url_authority(parsed):
    host = parsed.hostname or ''
    host = f"[{host}]" if ':' in host else host
    port = parsed.port
    return host if port is None else f"{host}:{port}"


def redact_url(url):
    # Query strings and fragments can carry credentials; log scheme/host/path only.
    try:
        parsed = urlparse(str(url))
        authority = url_authority(parsed)
    except (TypeError, ValueError):
        return ''
    return f"{parsed.scheme}://{authority}{parsed.path}" if parsed.scheme else clean_log_value(url)


def internal_error(area, message):
    correlation_id = uuid.uuid4().hex[:12]
    LOGGER.exception("area=%s correlation_id=%s", area, correlation_id)
    user_id = getattr(g, 'user_id', None)
    if user_id:
        route_rule = request.url_rule.rule if request.url_rule else 'unmatched'
        notify(
            user_id,
            'server.error',
            f'Something went wrong. Reference {correlation_id}.',
            target_type='request',
            target_id=route_rule,
            target_label=area,
            detail={
                'area': area,
                'method': request.method,
                'route': route_rule,
            },
            correlation_id=correlation_id,
        )
    return jsonify({'error': message, 'correlation_id': correlation_id}), 500


# =====================
# S-10: shared decode-safety gate for every uploaded/imported image
# =====================
# The dimension check reads only the parsed header, so an oversized source is
# rejected before its pixel data is decoded; Pillow's bomb error is the backstop.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS


def open_validated_image(source):
    """Returns (rgb_image, None) on success or (None, client_error_message)."""
    try:
        image = Image.open(source)
        image_format = (image.format or '').lower()
        width, height = image.size
    except Image.DecompressionBombError:
        return None, 'Image dimensions are too large'
    except Exception:
        return None, 'Invalid image file'
    if image_format not in ('jpeg', 'png', 'gif'):
        return None, 'Accepted image file types: jpg, jpeg, png, gif'
    if (width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION
            or width * height > MAX_IMAGE_PIXELS):
        return None, 'Image dimensions are too large'
    try:
        image.load()
        image = ImageOps.exif_transpose(image)
    except Image.DecompressionBombError:
        return None, 'Image dimensions are too large'
    except Exception:
        return None, 'Invalid image file'
    if image.mode != 'RGB':
        image = image.convert('RGB')
    return image, None


# =====================
# SSRF protection for outbound requests
# =====================
# A user controls the URLs we fetch (Google Maps links and photo links inside
# imported KML files). Without a guard, those URLs could point at internal hosts
# or cloud metadata endpoints (e.g. 169.254.169.254). We therefore follow
# redirects manually and validate every hop before connecting.

# Google Maps short/long link hosts (suffix-matched)
GOOGLE_MAPS_HOSTS = ("google.com", "goo.gl")

def _is_public_ip(ip):
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

def _resolve_public_ip(host):
    # Resolve once and return a single vetted IP to connect to. Returning the address
    # (rather than a bool) lets the caller dial exactly the IP we validated, which
    # narrows the DNS-rebinding window between this check and the actual connection.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    chosen = None
    for info in infos:
        ip_str = info[4][0].split('%')[0]  # strip IPv6 scope id if present
        ip = ipaddress.ip_address(ip_str)
        if not _is_public_ip(ip):
            return None  # any non-public answer poisons the whole host
        if chosen is None:
            chosen = ip_str
    return chosen

class _PinnedHTTPSAdapter(requests.adapters.HTTPAdapter):
    # S-15: the request URL carries the pre-vetted IP, while TLS keeps the original
    # hostname for SNI and certificate verification. Nothing between validation and
    # connection re-resolves DNS, so a rebinding resolver cannot redirect the socket.
    def __init__(self, hostname):
        self._server_hostname = hostname
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['server_hostname'] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


# with_final_url returns (response, url) instead of just the response. The S-15
# rebinding defence rewrites the netloc to the vetted IP before dialling, so
# response.url carries that IP rather than the hostname the caller asked about — fine
# for fetching bytes, wrong for anything reported back to a client. This loop already
# tracks the logical hostname-form URL at every hop (it is what each Location is
# rejoined against), so returning it costs nothing.
def fetch_url_safely(url, allowed_hosts=None, max_redirects=5, timeout=10, stream=False,
                     with_final_url=False):
    # Follow redirects by hand so each hop is validated, not just the first URL.
    for _ in range(max_redirects + 1):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only http/https URLs are allowed")

        host = parsed.hostname
        if not host:
            raise ValueError("URL has no host")

        if allowed_hosts is not None:
            host_l = host.lower()
            if not any(host_l == h or host_l.endswith("." + h) for h in allowed_hosts):
                raise ValueError(f"Host not allowed: {host}")

        pinned_ip = _resolve_public_ip(host)
        if pinned_ip is None:
            raise ValueError(f"Host resolves to a non-public address: {host}")

        # Both schemes connect straight to the vetted IP and carry the hostname in the
        # Host header, so requests never re-resolves DNS between validation and
        # connection. HTTPS additionally pins SNI/certificate verification to the
        # original hostname through the adapter (S-15).
        host_ip = f"[{pinned_ip}]" if ':' in pinned_ip else pinned_ip
        netloc = host_ip if not parsed.port else f"{host_ip}:{parsed.port}"
        request_url = parsed._replace(netloc=netloc).geturl()
        headers = {"Host": url_authority(parsed)}
        if parsed.scheme == "https":
            session = requests.Session()
            session.mount("https://", _PinnedHTTPSAdapter(host))
            resp = session.get(request_url, headers=headers, allow_redirects=False,
                               timeout=timeout, stream=stream)
        else:
            resp = requests.get(request_url, headers=headers, allow_redirects=False,
                                timeout=timeout, stream=stream)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return (resp, url) if with_final_url else resp
            url = urljoin(url, location)
            resp.close()
            continue
        return (resp, url) if with_final_url else resp

    raise ValueError("Too many redirects")


# =====================
# Initialize database
# =====================
def init_db():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    # Canonical schema shared with create_users.py (D-10); table definitions and
    # their design commentary live in markervault_schema.py.
    initialize_schema(conn)
    # Import jobs live in the in-process executor, so anything still queued/running
    # belongs to a previous process and can never finish. Freeze their owners and
    # counters before changing the exact selected rows to their terminal state.
    interrupted_jobs = conn.execute(
        "SELECT ip.job_id, ip.owner_id, ip.map_id, m.name, ip.imported, ip.total, "
        "ip.skipped, ip.photos_failed, ip.photos_budget_skipped "
        "FROM import_progress ip LEFT JOIN maps m ON m.id=ip.map_id "
        "WHERE ip.status IN ('queued', 'running')"
    ).fetchall()
    for job in interrupted_jobs:
        conn.execute(
            "UPDATE import_progress SET status='error', error='interrupted', "
            "completed=CURRENT_TIMESTAMP, last_updated=CURRENT_TIMESTAMP "
            "WHERE job_id=? AND status IN ('queued', 'running')",
            (job[0],),
        )
    conn.commit()
    conn.close()
    for job in interrupted_jobs:
        _notify_kml_job(
            job[1],
            job[0],
            job[2],
            job[3],
            imported=job[4] or 0,
            total=job[5] or 0,
            skipped=job[6] or 0,
            photos_failed=job[7] or 0,
            photos_budget_skipped=job[8] or 0,
            error_token='interrupted',
        )

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def audit(action, target_type=None, target_id=None, target_label=None,
          actor_id=None, actor_username=None, actor_role=None, client_ip=None,
          **detail):
    # Audit is a fail-open side effect. It owns its connection so callers invoke it
    # only after their real mutation has committed.
    conn = None
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (ts, actor_id, actor_username, actor_role, "
            "action, target_type, target_id, target_label, detail, client_ip) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                actor_id if actor_id is not None else getattr(g, "user_id", None),
                actor_username if actor_username is not None else getattr(g, "username", None),
                actor_role if actor_role is not None else getattr(g, "role", None),
                action,
                target_type,
                str(target_id) if target_id is not None else None,
                target_label,
                json.dumps(detail) if detail else None,
                client_ip if client_ip is not None else getattr(g, "client_ip", None),
            ),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _notification_text(value, limit):
    if value is None:
        return None
    text = ''.join(character for character in str(value) if character.isprintable())
    if len(text) <= limit:
        return text
    return text[:limit - 1] + '…'


def _trim_notification_history(cursor, user_id):
    cursor.execute(
        "DELETE FROM notif_history WHERE user_id=? AND id NOT IN "
        "(SELECT id FROM notif_history WHERE user_id=? ORDER BY id DESC LIMIT ?)",
        (user_id, user_id, NOTIF_HISTORY_CAP),
    )


def notify(user_id, event, message, target_type=None, target_id=None,
           target_label=None, detail=None, correlation_id=None):
    # Notification history is a fail-open side effect. It owns its connection and
    # callers invoke it only after their real mutation has committed.
    conn = None
    safe_user_id = _notification_text(user_id, NOTIF_TARGET_ID_MAX)
    safe_event = _notification_text(event, NOTIF_TARGET_TYPE_MAX)
    safe_target_type = _notification_text(target_type, NOTIF_TARGET_TYPE_MAX)
    safe_target_id = _notification_text(target_id, NOTIF_TARGET_ID_MAX)
    safe_correlation_id = _notification_text(correlation_id, NOTIF_CORRELATION_ID_MAX)
    try:
        if safe_event not in NOTIF_EVENTS:
            raise ValueError('unknown notification event')
        if not safe_user_id:
            raise ValueError('notification user is required')
        safe_message = _notification_text(message, NOTIF_MESSAGE_MAX)
        if not safe_message:
            raise ValueError('notification message is required')
        safe_target_label = _notification_text(target_label, NOTIF_TARGET_LABEL_MAX)
        detail_text = None
        if detail is not None:
            detail_text = json.dumps(
                detail,
                ensure_ascii=False,
                separators=(',', ':'),
                sort_keys=True,
            )
            if len(detail_text) > NOTIF_DETAIL_MAX:
                raise ValueError('notification detail is too long')

        conn = get_db()
        conn.execute(
            "INSERT INTO notif_history (user_id, created, event, target_type, "
            "target_id, target_label, message, detail, correlation_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                safe_user_id,
                datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                safe_event,
                safe_target_type,
                safe_target_id,
                safe_target_label,
                safe_message,
                detail_text,
                safe_correlation_id,
            ),
        )
        _trim_notification_history(conn, safe_user_id)
        conn.commit()
        return True
    except Exception:
        LOGGER.exception(
            "area=notif_history.write_failed user_id=%s event=%s "
            "target_type=%s target_id=%s correlation_id=%s",
            clean_log_value(safe_user_id),
            clean_log_value(safe_event),
            clean_log_value(safe_target_type),
            clean_log_value(safe_target_id),
            clean_log_value(safe_correlation_id),
        )
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _notify_kml_job(user_id, job_id, map_id, map_label=None, *, imported=0,
                    total=0, skipped=0, photos_failed=0,
                    photos_budget_skipped=0, affected_spots=(),
                    exhausted_budgets=(), error_token=None,
                    correlation_id=None):
    if not map_label:
        conn = None
        try:
            conn = get_db()
            row = conn.execute("SELECT name FROM maps WHERE id=?", (map_id,)).fetchone()
            map_label = row[0] if row else f'Map {map_id}'
        except Exception:
            map_label = f'Map {map_id}'
        finally:
            if conn is not None:
                conn.close()

    unique_spots = []
    seen_spots = set()
    for name in affected_spots:
        safe_name = _notification_text(name, NOTIF_TARGET_LABEL_MAX)
        if safe_name and safe_name not in seen_spots:
            seen_spots.add(safe_name)
            unique_spots.append(safe_name)
    included_spots = unique_spots[:10]
    omitted_spots = len(unique_spots) - len(included_spots)
    detail = {
        'affected_spots': included_spots,
        'affected_spots_omitted': omitted_spots,
        'exhausted_budgets': list(exhausted_budgets),
        'imported': imported,
        'job_id': job_id,
        'map_id': map_id,
        'photos_budget_skipped': photos_budget_skipped,
        'photos_failed': photos_failed,
        'skipped': skipped,
        'total': total,
    }
    if error_token:
        detail['error'] = error_token
    while len(json.dumps(
            detail,
            ensure_ascii=False,
            separators=(',', ':'),
            sort_keys=True,
    )) > NOTIF_DETAIL_MAX and included_spots:
        included_spots.pop()
        omitted_spots += 1
        detail['affected_spots_omitted'] = omitted_spots

    if error_token:
        event = 'kml.import_error'
        if error_token == 'interrupted':
            message = f'KML import into “{map_label}” was interrupted by a server restart.'
        else:
            message = f'KML import into “{map_label}” failed.'
            if correlation_id:
                message += f' Reference {correlation_id}.'
    elif photos_failed or photos_budget_skipped:
        event = 'kml.import_degraded'
        message = (
            f'KML import into “{map_label}” completed with issues: '
            f'{imported} of {total} markers imported, {skipped} skipped, '
            f'{photos_failed} photos failed, {photos_budget_skipped} skipped by limits.'
        )
        if unique_spots:
            message_names = [_notification_text(name, 24) for name in unique_spots[:10]]
            message += f' Affected markers: {", ".join(message_names)}'
            if len(unique_spots) > 10:
                message += f', and {len(unique_spots) - 10} more…'
            else:
                message += '.'
    else:
        event = 'kml.import_done'
        message = (
            f'KML import into “{map_label}” completed: '
            f'{imported} of {total} markers imported, {skipped} skipped.'
        )

    return notify(
        user_id,
        event,
        message,
        target_type='kml_job',
        target_id=job_id,
        target_label=map_label,
        detail=detail,
        correlation_id=correlation_id,
    )


init_db()


# =====================
# Authentication & rate-limiting helpers
# =====================

# Validate a latitude/longitude value: must be a real number in range.
def _coord_ok(value, limit):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return -limit <= value <= limit


# Create a user's personal Base Map (their undeletable starter map) if they don't have one.
# Idempotent: safe to call more than once. Uses its own connection so it can be called from
# both request handlers and standalone scripts.
def create_base_map(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM maps WHERE owner_id = ? AND is_base = 1", (user_id,))
    if not c.fetchone():
        c.execute(
            "INSERT INTO maps (owner_id, name, is_base, created, description) VALUES (?, 'Base Map', 1, ?, ?)",
            (user_id, datetime.now().isoformat(), 'Your default map. This map cannot be deleted.')
        )
    conn.commit()
    conn.close()


# Role hierarchy: super_admin > admin > user. Super-admins are unscoped (global reach
# over everyone); regular admins manage ONLY the users delegated to them — the
# controls() relation, user_controllers (many-to-many: a user can be co-managed by
# several admins, each acting independently). There is no admin tier above admins.
ADMIN_ROLES = ('admin', 'super_admin')


# effective_controls(admin, user) — the controls() relation with its TWO sources
# (Addendum 3): a direct user_controllers grant OR membership in a management group
# the admin is a delegated manager of. One shared SQL fragment so every authorization
# and visibility site checks the identical union — never inline one half only.
# user_col is a column reference (never request data); the returned predicate consumes
# TWO ? parameters, both the acting admin's user_id.
def controls_predicate(user_col):
    return (f"(EXISTS (SELECT 1 FROM user_controllers uc WHERE uc.user_id = {user_col} AND uc.admin_id = ?) "
            f"OR EXISTS (SELECT 1 FROM mgmt_group_members mm "
            f"JOIN mgmt_group_managers mg ON mg.group_id = mm.group_id "
            f"WHERE mm.user_id = {user_col} AND mg.admin_id = ?))")


# Guard for admin actions on a user. Super-admins act on anyone; a regular admin only
# on users they control — directly or via a management group. Admin-level targets,
# nobody-land users and other admins' users all get the same 403 — none of them are in
# the caller's scope, and account existence is no secret (usernames are public in the
# share picker). Returns None when the caller may act, a ready (response, code) tuple
# otherwise. A missing target also returns None so the handler can 404 on its own terms.
def _guard_admin_target(target_user_id):
    if g.role == 'super_admin':
        return None
    conn = get_db()
    c = conn.cursor()
    c.execute(f'''
        SELECT u.role, {controls_predicate('u.user_id')} FROM users u
        WHERE u.user_id = ?
    ''', (g.user_id, g.user_id, target_user_id))
    row = c.fetchone()
    conn.close()
    if not row:
        return None  # target doesn't exist; let the handler return its own 404
    if row[0] != 'user' or not row[1]:
        return (jsonify({'error': 'You do not manage this user'}), 403)
    return None


# Central authorization for a map. Returns (allowed, is_owner, is_base). Access comes
# ONLY from ownership or an explicit share — admin/super-admin get NO blanket map access
# (a truly private map stays private; an admin needing in can reset the owner's password
# and log in as them). Sharing: an 'editor' may read+edit map contents AND edit the map
# entity; a 'viewer' may only read (need_edit=False). Deletion / re-sharing are NOT
# granted here — use is_map_owner() for those.
def user_can_access_map(map_id, user_id, need_edit=False):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT owner_id, is_base FROM maps WHERE id = ?", (map_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return (False, False, False)
    owner_id, is_base = row
    if user_id == owner_id:
        conn.close()
        return (True, True, bool(is_base))
    # Base Maps are per-user scaffolding — owner-only, never shared. A share row on one
    # (which the share routes refuse to create) grants nothing.
    if is_base:
        conn.close()
        return (False, False, True)
    # Shared access, direct or via share-group membership: the effective role is the
    # best of all grants (editor beats viewer). Editor can read+edit contents; viewer
    # read-only.
    c.execute('''
        SELECT role FROM map_shares WHERE map_id = ? AND user_id = ?
        UNION ALL
        SELECT mgs.role FROM map_group_shares mgs
        JOIN share_group_members gm ON gm.group_id = mgs.group_id
        WHERE mgs.map_id = ? AND gm.user_id = ?
    ''', (map_id, user_id, map_id, user_id))
    roles = {r[0] for r in c.fetchall()}
    conn.close()
    if 'editor' in roles:
        return (True, False, bool(is_base))
    if 'viewer' in roles and not need_edit:
        return (True, False, bool(is_base))
    return (False, False, bool(is_base))


# True only for the map's owner. Gates map deletion and sharing (an editor may edit the
# map entity but must NOT be able to delete/re-share it; admins get no bypass).
def is_map_owner(map_id, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT owner_id FROM maps WHERE id = ?", (map_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return user_id == row[0]


# Resolve the map that owns a spot, for spot/photo authorization.
def _map_id_for_spot(spot_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT map_id FROM spots WHERE id = ?", (spot_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


# Guard for spot-scoped routes (incl. photos). Returns None if the caller may act on the
# spot, else a ready (response, code) tuple to return. Uses g.user_id (set by require_auth).
def _authorize_spot(spot_id, need_edit=False):
    map_id = _map_id_for_spot(spot_id)
    if map_id is None:
        return (jsonify({'error': 'Spot not found'}), 404)
    allowed, _, _ = user_can_access_map(map_id, g.user_id, need_edit=need_edit)
    if not allowed:
        return (jsonify({'error': 'Spot not found'}), 404)
    return None


# =====================
# Signed photo/thumb/avatar URLs
# =====================
# Photos are served through Flask (X-Accel-Redirect to nginx) and gated on map access.
# A browser <img src> can't send a Bearer header, so the URL itself carries a short-lived
# HMAC signature. Each URL is a short-lived BEARER capability issued for a user id, not
# a session-bound link: anyone holding it can use it until expiry, subject to the serving
# route's live DB re-check of the signed uid's access (C-01).
PHOTO_URL_TTL = 3600  # 1 hour

# The signed URL is SELF-AUTHENTICATING: a browser <img src> can't send a Bearer header,
# so everything needed to authorize the request lives in the URL. The uid it was issued
# to travels in the query and is covered by the HMAC, so the serving route needs no token
# — it recovers the uid from the URL, verifies the signature, then re-checks map access.
def sign_photo_url(kind, filename, user_id):
    # kind is 'photos', 'thumbs', or 'avatars'
    # exp is rounded UP to a half-TTL bucket boundary (validity TTL/2..TTL) so repeated
    # issuances within a bucket produce byte-identical URLs — the browser then serves
    # re-renders from its cache instead of refetching every image on every payload.
    # Authorization is unaffected: every non-cached request still verifies + re-checks.
    bucket = PHOTO_URL_TTL // 2
    exp = (int(time.time()) // bucket + 2) * bucket
    msg = f"{kind}:{filename}:{exp}:{user_id}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(ACCESS_TOKEN_SECRET.encode(), msg, hashlib.sha256).digest()).decode().rstrip("=")
    return f"/{kind}/{filename}?exp={exp}&uid={user_id}&sig={sig}"

def verify_photo_sig(kind, filename, exp, uid, sig):
    if not uid:
        return False
    try:
        exp_int = int(exp)
    except (TypeError, ValueError):
        return False
    if exp_int < int(time.time()):
        return False
    msg = f"{kind}:{filename}:{exp_int}:{uid}".encode()
    expected = base64.urlsafe_b64encode(hmac.new(ACCESS_TOKEN_SECRET.encode(), msg, hashlib.sha256).digest()).decode().rstrip("=")
    return hmac.compare_digest(expected, sig or "")

def _avatar_url(filename, user_id):
    if not filename:
        return None
    # v is a CONTENT version outside the HMAC-covered authorization fields: the file's
    # mtime_ns, which only moves when the avatar is re-uploaded (the filename itself is
    # stable per user). Within an exp bucket the whole URL is therefore stable — one
    # fetch per page load — and any re-upload changes v, forcing an image reload.
    try:
        version = os.stat(os.path.join(AVATARS_FOLDER, os.path.basename(filename))).st_mtime_ns
    except OSError:
        version = 0
    return f"{sign_photo_url('avatars', filename, user_id)}&v={version}"

# Resolve the map a photo belongs to, for photo-serving authorization.
def _map_id_for_photo(filename):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT s.map_id FROM photos p JOIN spots s ON s.id = p.spot_id WHERE p.filename = ?", (filename,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None


# Profile/password validation lives in request_validation.py, shared with the CLI
# (D-09); the browser keeps only a mirrored password hint for immediate feedback.


# True if the email is already taken by another account (case-insensitive).
# exclude_user_id lets a user keep their own email when editing their profile.
def email_taken(cursor, email, exclude_user_id=None):
    if exclude_user_id:
        cursor.execute("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND user_id <> ?",
                       (email, exclude_user_id))
    else:
        cursor.execute("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,))
    if cursor.fetchone() is not None:
        return True
    if exclude_user_id:
        cursor.execute(
            "SELECT 1 FROM account_tokens WHERE purpose='email_verification' "
            "AND target_email = ? COLLATE NOCASE AND user_id <> ?",
            (email, exclude_user_id),
        )
    else:
        cursor.execute(
            "SELECT 1 FROM account_tokens WHERE purpose='email_verification' "
            "AND target_email = ? COLLATE NOCASE",
            (email,),
        )
    return cursor.fetchone() is not None


def _account_email_mode_required():
    if not REQUIRE_EMAIL_VERIFICATION:
        abort(404)


def _purge_expired_account_tokens(cursor, now_ts):
    cursor.execute("DELETE FROM account_tokens WHERE expires < ?", (now_ts,))


def _account_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _account_token_fragment(purpose):
    if purpose == 'email_verification':
        return 'verify-email'
    return 'reset-password'


def _account_token_url(purpose, token):
    return f"{PUBLIC_ORIGIN}/#{_account_token_fragment(purpose)}={token}"


def _replace_account_token(cursor, user_id, purpose, target_email, now_ts):
    token = secrets.token_urlsafe(32)
    duration = (EMAIL_VERIFICATION_TOKEN_DURATION
                if purpose == 'email_verification'
                else PASSWORD_RESET_TOKEN_DURATION)
    cursor.execute(
        "DELETE FROM account_tokens WHERE user_id=? AND purpose=?",
        (user_id, purpose),
    )
    cursor.execute(
        "INSERT INTO account_tokens "
        "(user_id, purpose, token_hash, target_email, created, expires) "
        "VALUES (?,?,?,?,?,?)",
        (
            user_id,
            purpose,
            _account_token_hash(token),
            target_email,
            now_ts,
            now_ts + duration,
        ),
    )
    return token


def _remove_account_token(token):
    conn = get_db()
    conn.execute(
        "DELETE FROM account_tokens WHERE token_hash=?",
        (_account_token_hash(token),),
    )
    conn.commit()
    conn.close()


def _make_verification_retryable(token):
    conn = get_db()
    conn.execute(
        "UPDATE account_tokens SET created=0 WHERE token_hash=? "
        "AND purpose='email_verification'",
        (_account_token_hash(token),),
    )
    conn.commit()
    conn.close()


def _send_verification_email(user_id, display_name, email, now_ts):
    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, now_ts)
    if email_taken(c, email, exclude_user_id=user_id):
        conn.commit()
        conn.close()
        return 'conflict'
    existing = c.execute(
        "SELECT target_email, created FROM account_tokens "
        "WHERE user_id=? AND purpose='email_verification'",
        (user_id,),
    ).fetchone()
    if (existing
            and existing[0].casefold() == email.casefold()
            and now_ts - existing[1] < EMAIL_RESEND_COOLDOWN):
        conn.commit()
        conn.close()
        return 'cooldown'
    try:
        token = _replace_account_token(
            c,
            user_id,
            'email_verification',
            email,
            now_ts,
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return 'conflict'
    conn.close()
    try:
        EMAIL_SENDER.send(
            email,
            verification_email_content(
                display_name,
                _account_token_url('email_verification', token),
            ),
        )
    except EmailDeliveryError:
        _make_verification_retryable(token)
        return 'failed'
    return 'sent'


def _send_password_reset_email(user_id, display_name, email, now_ts):
    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, now_ts)
    existing = c.execute(
        "SELECT created FROM account_tokens "
        "WHERE user_id=? AND purpose='password_reset'",
        (user_id,),
    ).fetchone()
    if existing and now_ts - existing[0] < EMAIL_RESEND_COOLDOWN:
        conn.commit()
        conn.close()
        return 'cooldown'
    token = _replace_account_token(
        c,
        user_id,
        'password_reset',
        None,
        now_ts,
    )
    conn.commit()
    conn.close()
    try:
        EMAIL_SENDER.send(
            email,
            password_reset_email_content(
                display_name,
                _account_token_url('password_reset', token),
            ),
        )
    except EmailDeliveryError:
        _remove_account_token(token)
        return 'failed'
    return 'sent'


def _password_reset_token_row(cursor, token, now_ts):
    return cursor.execute(
        "SELECT t.user_id, u.username FROM account_tokens t "
        "JOIN users u ON u.user_id=t.user_id "
        "WHERE t.purpose='password_reset' AND t.token_hash=? "
        "AND t.expires>=? AND u.status='approved' "
        "AND u.email_verified_at IS NOT NULL",
        (_account_token_hash(token), now_ts),
    ).fetchone()


# Real client IP: trust X-Forwarded-For only when the direct peer is a known proxy.
def get_client_ip():
    raw_ip = request.remote_addr
    if raw_ip in TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the LAST entry: nginx appends the real peer via $proxy_add_x_forwarded_for,
            # so earlier entries are client-supplied and spoofable. Using the first entry would
            # let a client forge its IP and bypass the allowlist / rate limits / token IP-binding.
            return forwarded.split(",")[-1].strip()
    return raw_ip


def is_ip_allowed(client_ip):
    if "0.0.0.0" in ALLOWED_IP_RANGES:
        return
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        abort(403)
    for net in ALLOWED_IP_RANGES:
        if ip in ipaddress.ip_network(net, strict=False):
            return
    abort(403)


# Drop entries that would refill to full right now. rate_limit already treats an
# unknown IP as having a full bucket, so a full entry and an absent one are
# behaviourally identical: removing the full ones changes nothing observable and
# bounds each dict to genuinely active clients. The test is "would refill to full
# NOW", not "is currently stored as full" — a stale entry is stored below full and
# only becomes full once the refill is applied, so the stored-value test would evict
# almost nothing.
#
# Scanning the whole dict per call would be O(n) per request, turning the memory
# problem into a CPU one under exactly the flood this defends against. rate_limit
# reinserts the calling IP so that touching an entry moves it to the end: the front
# of the dict is therefore the stalest end, and a short fixed-width scan there finds
# eviction candidates without a timer, a thread, or a full sweep.
#
# INVARIANT: each bucket dict is used with exactly one (refill_interval, burst) pair
# across all call sites, so effective_max here is the one that built every entry.
# Sharing a bucket between two different limits would evict entries as "full" that
# are not, handing back tokens — configuration_test asserts this holds.
def _evict_refilled(endpoint_bucket, now, refill_interval, effective_max):
    for stale_ip in list(itertools.islice(endpoint_bucket, RATE_LIMIT_EVICTION_SCAN)):
        entry = endpoint_bucket[stale_ip]
        regenerated = int((now - entry["last_refill"]) // refill_interval)
        if entry["requests"] + regenerated >= effective_max:
            del endpoint_bucket[stale_ip]


# In-memory token bucket. (Note: per-process; behind multiple workers each has its
# own buckets. Swap for a shared store like Redis if you scale out.)
def rate_limit(ip, now, endpoint_bucket, refill_interval, burst=BURST):
    effective_max = 1 + burst
    bucket = endpoint_bucket.get(ip, {"requests": effective_max, "last_refill": now})
    tokens = bucket["requests"]
    last_refill = bucket["last_refill"]

    elapsed = now - last_refill
    regenerated = int(elapsed // refill_interval)
    tokens = min(effective_max, tokens + regenerated)
    last_refill += regenerated * refill_interval
    if tokens == effective_max:
        last_refill = now

    if tokens <= 0:
        endpoint_bucket.pop(ip, None)
        endpoint_bucket[ip] = {"requests": tokens, "last_refill": last_refill}
        _evict_refilled(endpoint_bucket, now, refill_interval, effective_max)
        abort(429)

    tokens -= 1
    endpoint_bucket.pop(ip, None)
    endpoint_bucket[ip] = {"requests": tokens, "last_refill": last_refill}
    _evict_refilled(endpoint_bucket, now, refill_interval, effective_max)


# Per-username login throttle. Every bucket above keys on client IP, so a distributed
# attempt against one known account was limited only by bcrypt's cost and nginx's
# per-IP zone. Failures are therefore also counted per submitted username.
#
# Only failures are counted, and a correct password clears the entry: a successful
# login is not brute-force signal, and charging it would let the one person who knows
# the password throttle themselves out.
#
# A token bucket rather than a strike counter with a lockout. Exhaustion self-heals
# within minutes of the attacker stopping, and *holding* an account down needs
# sustained per-account traffic — implausible and visible behind nginx's per-IP limit
# on a LAN deployment. Brute force degrades to about one guess per minute per account
# against bcrypt cost 12. Lockout-as-denial-of-service is accepted; the bucket shape
# is the mitigation.
USERNAME_MAX_FAILURES = 10
USERNAME_REFILL_INTERVAL = 60


# Case-folded so a bucket cannot be dodged by changing capitalization, and truncated
# like attempted_username so one request cannot store an arbitrarily large key.
# str.casefold() is a strict superset of SQLite's ASCII-only NOCASE: any two strings
# NOCASE treats as one account differ only in ASCII case and casefold identically, so
# there is no bypass — the extra merging only over-throttles junk variants.
def username_bucket_key(username):
    return username.casefold()[:128]


# Entries share rate_limit's shape, so _evict_refilled bounds this dict too. That
# matters more here than for the IP buckets: keys are minted by the attacker, since a
# username that does not exist must throttle identically to one that does — otherwise
# the 429-vs-401 difference becomes an account-existence oracle.
def username_throttled(key, now):
    entry = USERNAME_BUCKET.get(key)
    if entry is None:
        return False
    regenerated = int((now - entry["last_refill"]) // USERNAME_REFILL_INTERVAL)
    return entry["requests"] + regenerated <= 0


def charge_username_failure(key, now):
    entry = USERNAME_BUCKET.get(key, {"requests": USERNAME_MAX_FAILURES, "last_refill": now})
    tokens = entry["requests"]
    last_refill = entry["last_refill"]

    regenerated = int((now - last_refill) // USERNAME_REFILL_INTERVAL)
    tokens = min(USERNAME_MAX_FAILURES, tokens + regenerated)
    last_refill += regenerated * USERNAME_REFILL_INTERVAL
    if tokens == USERNAME_MAX_FAILURES:
        last_refill = now

    USERNAME_BUCKET.pop(key, None)
    USERNAME_BUCKET[key] = {"requests": max(0, tokens - 1), "last_refill": last_refill}
    _evict_refilled(USERNAME_BUCKET, now, USERNAME_REFILL_INTERVAL, USERNAME_MAX_FAILURES)


# Validate the Bearer access token; returns the JWT payload or aborts 401.
def check_access_token(client_ip):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        abort(401)
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:  # covers expired, bad signature, malformed
        abort(401)
    if BIND_TOKEN_TO_IP and payload.get("ip") and payload.get("ip") != client_ip:
        abort(401)
    return payload


# Decorator for authenticated data routes: IP allowlist + rate limit + token check +
# the S-03 identity gate — the user must still exist and be approved, the token's
# session generation must match the user's current auth_version, and the token's
# refresh family must still hold a live head. Disable, password reset/change, and
# logout therefore kill outstanding access JWTs immediately instead of at expiry.
# On success, g.user_id / g.username / g.role / g.client_ip carry the CURRENT DB
# identity (not the token snapshot), so renames and role changes apply at once.
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        client_ip = get_client_ip()
        now_ts = int(time.time())
        is_ip_allowed(client_ip)
        # Authenticated UI flows are legitimately bursty — a multi-photo upload or a
        # multi-marker copy fires one request per item back to back (same profile as
        # the gallery loads that gave signed serving its own large burst). The bigger
        # burst only fronts the unchanged ~20 req/s sustained refill; the public
        # login/register/refresh buckets keep the tight default burst.
        rate_limit(client_ip, now_ts, PRIVATE_BUCKET, PRIVATE_REFILL_INTERVAL, burst=PRIVATE_BURST)
        payload = check_access_token(client_ip)
        if not payload.get("fam") or "ver" not in payload:
            abort(401)
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "SELECT status, role, username, auth_version, email_verified_at, "
            "EXISTS(SELECT 1 FROM refresh_tokens rt WHERE rt.family_id = ? "
            "AND rt.status = 'active' AND rt.expires > ?) "
            "FROM users WHERE user_id = ?",
            (payload["fam"], now_ts, payload["user_id"]),
        )
        row = c.fetchone()
        conn.close()
        if (not row or row[0] != 'approved' or row[3] != payload["ver"]
                or (REQUIRE_EMAIL_VERIFICATION and row[4] is None)
                or not row[5]):
            abort(401)
        g.user_id = payload["user_id"]
        g.username = row[2]
        g.role = row[1]
        g.client_ip = client_ip
        return f(*args, **kwargs)
    return wrapper


# Admin-only gate. Stacks on top of @require_auth (so g.user_id is set) and re-reads the
# role and canonical username from the DB rather than trusting the token, so a demotion
# or rename takes effect immediately instead of lingering until the current access token
# expires. Stashes both fresh values in g for downstream scope checks and audit snapshots.
def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT role, status, username FROM users WHERE user_id = ?", (g.user_id,))
        row = c.fetchone()
        conn.close()
        if not row or row[0] not in ADMIN_ROLES or row[1] != 'approved':
            abort(403)
        g.role = row[0]
        g.username = row[2]
        return f(*args, **kwargs)
    return wrapper


# Return JSON (not HTML) for the auth/limit error codes.
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(429)
def _json_error(e):
    return jsonify({"error": e.name}), e.code


@app.errorhandler(500)
def _unhandled_error(e):
    return internal_error('request.unhandled', 'Unexpected server error')


# =====================
# Per-user notification history
# =====================
def _notification_unseen_count(cursor, user_id):
    cursor.execute(
        "SELECT COUNT(*) FROM notif_history WHERE user_id=? AND seen=0",
        (user_id,),
    )
    return cursor.fetchone()[0]


@app.route('/notif_history', methods=['GET'])
@require_auth
def notification_history():
    summary = request.args.get('summary')
    if summary not in (None, '1'):
        return jsonify({'error': 'Invalid summary value'}), 400

    conn = get_db()
    c = conn.cursor()
    # Reapply retention on reads so lowering the configured cap at restart cannot
    # leave unseen rows outside the rendered high-water snapshot.
    _trim_notification_history(c, g.user_id)
    unseen = _notification_unseen_count(c, g.user_id)
    if summary == '1':
        conn.commit()
        conn.close()
        return jsonify({'unseen': unseen})

    c.execute(
        "SELECT id, created, event, target_type, target_id, target_label, "
        "message, detail, correlation_id, seen FROM notif_history "
        "WHERE user_id=? ORDER BY id DESC LIMIT ?",
        (g.user_id, NOTIF_HISTORY_CAP),
    )
    rows = c.fetchall()
    conn.commit()
    conn.close()
    notifications = []
    for row in rows:
        notifications.append({
            'id': row[0],
            'created': row[1],
            'event': row[2],
            'target_type': row[3],
            'target_id': row[4],
            'target_label': row[5],
            'message': row[6],
            'detail': json.loads(row[7]) if row[7] else None,
            'correlation_id': row[8],
            'seen': bool(row[9]),
        })
    return jsonify({
        'notifications': notifications,
        'unseen': unseen,
        'through_id': notifications[0]['id'] if notifications else None,
    })


@app.route('/notif_history/seen', methods=['POST'])
@require_auth
def mark_notification_history_seen():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'through_id' not in data:
        return jsonify({'error': 'through_id is required'}), 400
    through_id = data['through_id']
    if through_id is None:
        through_id = 0
    if isinstance(through_id, bool) or not isinstance(through_id, int) or through_id < 0:
        return jsonify({'error': 'through_id must be a non-negative integer'}), 400

    conn = get_db()
    c = conn.cursor()
    _trim_notification_history(c, g.user_id)
    c.execute(
        "UPDATE notif_history SET seen=1 WHERE user_id=? AND seen=0 AND id<=?",
        (g.user_id, through_id),
    )
    marked = c.rowcount
    unseen = _notification_unseen_count(c, g.user_id)
    conn.commit()
    conn.close()
    return jsonify({'marked': marked, 'unseen': unseen})


@app.route('/notif_history/<int:notification_id>/seen', methods=['POST'])
@require_auth
def set_notification_history_seen(notification_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('seen'), bool):
        return jsonify({'error': 'seen must be a boolean'}), 400

    seen = data['seen']
    conn = get_db()
    c = conn.cursor()
    _trim_notification_history(c, g.user_id)
    c.execute(
        "UPDATE notif_history SET seen=? WHERE id=? AND user_id=?",
        (int(seen), notification_id, g.user_id),
    )
    if c.rowcount == 0:
        conn.commit()
        conn.close()
        return jsonify({'error': 'Notification not found'}), 404
    unseen = _notification_unseen_count(c, g.user_id)
    conn.commit()
    conn.close()
    return jsonify({
        'id': notification_id,
        'seen': seen,
        'unseen': unseen,
    })


# =====================
# Auth routes
# =====================

@app.route('/account-capabilities', methods=['GET'])
def account_capabilities():
    return jsonify({
        'email_account_flows': REQUIRE_EMAIL_VERIFICATION,
    })


@app.route('/email-verification/resend', methods=['POST'])
def resend_email_verification():
    _account_email_mode_required()
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, EMAIL_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    email = data.get('email') if isinstance(data, dict) else None
    if isinstance(email, str):
        email = email.strip()
    generic = {
        'success': True,
        'message': 'If verification is available for that address, a new link will be sent.',
    }
    if not isinstance(email, str) or not valid_email_format(email):
        return jsonify(generic)

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, now_ts)
    row = c.execute(
        "SELECT u.user_id, u.first_name, u.last_name, "
        "COALESCE(t.target_email, u.email) "
        "FROM users u "
        "LEFT JOIN account_tokens t ON t.user_id=u.user_id "
        "AND t.purpose='email_verification' "
        "WHERE (u.email_verified_at IS NULL AND u.email = ? COLLATE NOCASE) "
        "OR t.target_email = ? COLLATE NOCASE",
        (email, email),
    ).fetchone()
    conn.commit()
    conn.close()
    if row:
        display_name = ' '.join(value for value in row[1:3] if value)
        _send_verification_email(row[0], display_name, row[3], now_ts)
    return jsonify(generic)


@app.route('/email-verification/confirm', methods=['POST'])
def confirm_email_verification():
    _account_email_mode_required()
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, EMAIL_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    token = data.get('token') if isinstance(data, dict) else None
    if not isinstance(token, str) or not token or len(token) > 256:
        return jsonify({'error': 'Verification link is invalid or expired'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("BEGIN IMMEDIATE")
    _purge_expired_account_tokens(c, now_ts)
    row = c.execute(
        "SELECT t.user_id, t.target_email, u.username, u.email, u.status "
        "FROM account_tokens t "
        "JOIN users u ON u.user_id=t.user_id "
        "WHERE t.purpose='email_verification' AND t.token_hash=? "
        "AND t.expires>=?",
        (_account_token_hash(token), now_ts),
    ).fetchone()
    if not row:
        conn.commit()
        conn.close()
        return jsonify({'error': 'Verification link is invalid or expired'}), 400
    user_id, target_email, username, old_email, status = row
    if email_taken(c, target_email, exclude_user_id=user_id):
        c.execute(
            "DELETE FROM account_tokens WHERE user_id=? "
            "AND purpose='email_verification'",
            (user_id,),
        )
        conn.commit()
        conn.close()
        return jsonify({'error': 'That email address is no longer available'}), 409
    verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    c.execute(
        "UPDATE users SET email=?, email_verified_at=? WHERE user_id=?",
        (target_email, verified_at, user_id),
    )
    c.execute(
        "DELETE FROM account_tokens WHERE user_id=? "
        "AND purpose='email_verification'",
        (user_id,),
    )
    conn.commit()
    conn.close()
    detail = {}
    if (old_email or '').casefold() != target_email.casefold():
        detail = {'old': old_email, 'new': target_email}
    audit(
        'account.email_verified',
        actor_id=user_id,
        actor_username=username,
        target_type='user',
        target_id=user_id,
        target_label=username,
        **detail,
    )
    message = 'Email address updated.'
    if status == 'pending':
        message = (
            'Email verified. An administrator must approve your account before '
            'you can log in.'
        )
    return jsonify({'success': True, 'message': message})


@app.route('/password-recovery/request', methods=['POST'])
def request_password_recovery():
    _account_email_mode_required()
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, EMAIL_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    email = data.get('email') if isinstance(data, dict) else None
    if isinstance(email, str):
        email = email.strip()
    generic = {
        'success': True,
        'message': 'If that address belongs to an eligible account, a reset link will be sent.',
    }
    if not isinstance(email, str) or not valid_email_format(email):
        return jsonify(generic)

    conn = get_db()
    row = conn.execute(
        "SELECT user_id, username, first_name, last_name, email "
        "FROM users WHERE email = ? COLLATE NOCASE "
        "AND status='approved' AND email_verified_at IS NOT NULL",
        (email,),
    ).fetchone()
    conn.close()
    if row:
        display_name = ' '.join(value for value in row[2:4] if value)
        outcome = _send_password_reset_email(
            row[0],
            display_name,
            row[4],
            now_ts,
        )
        if outcome == 'sent':
            audit(
                'account.password_reset_requested',
                actor_id=row[0],
                actor_username=row[1],
                target_type='user',
                target_id=row[0],
                target_label=row[1],
                client_ip=client_ip,
            )
    return jsonify(generic)


@app.route('/password-recovery/validate', methods=['POST'])
def validate_password_recovery():
    _account_email_mode_required()
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, EMAIL_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    token = data.get('token') if isinstance(data, dict) else None
    if not isinstance(token, str) or not token or len(token) > 256:
        return jsonify({'error': 'Reset link is invalid or expired'}), 400

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, now_ts)
    row = _password_reset_token_row(c, token, now_ts)
    conn.commit()
    conn.close()
    if not row:
        return jsonify({'error': 'Reset link is invalid or expired'}), 400
    return jsonify({'valid': True})


@app.route('/password-recovery/reset', methods=['POST'])
def reset_recovered_password():
    _account_email_mode_required()
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, EMAIL_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    token = data.get('token')
    password = data.get('new_password')
    if not isinstance(token, str) or not token or len(token) > 256:
        return jsonify({'error': 'Reset link is invalid or expired'}), 400
    ok, reason = validate_password_policy(password)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("BEGIN IMMEDIATE")
    _purge_expired_account_tokens(c, now_ts)
    row = _password_reset_token_row(c, token, now_ts)
    if not row:
        conn.commit()
        conn.close()
        return jsonify({'error': 'Reset link is invalid or expired'}), 400
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute(
        "UPDATE users SET password_hash=?, auth_version=auth_version+1 "
        "WHERE user_id=?",
        (password_hash, row[0]),
    )
    c.execute("DELETE FROM refresh_tokens WHERE user_id=?", (row[0],))
    c.execute(
        "DELETE FROM account_tokens WHERE user_id=? AND purpose='password_reset'",
        (row[0],),
    )
    conn.commit()
    conn.close()
    audit(
        'account.password_reset',
        actor_id=row[0],
        actor_username=row[1],
        target_type='user',
        target_id=row[0],
        target_label=row[1],
        client_ip=client_ip,
    )
    return jsonify({
        'success': True,
        'message': 'Password reset. You can now log in with the new password.',
    })


@app.route('/login', methods=['POST'])
def login():
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, PUBLIC_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    if (not isinstance(data, dict)
            or 'username' not in data
            or 'password' not in data
            or not isinstance(data['username'], str)
            or not isinstance(data['password'], str)):
        return jsonify({'error': 'Invalid request'}), 400

    username = data['username']
    password = data['password']
    attempted_username = username[:128] if isinstance(username, str) else str(username)[:128]

    # Refuse an exhausted username before the bcrypt call. Skipping bcrypt here leaks
    # nothing: unknown and known usernames are throttled identically, so the 429
    # reveals only bucket state the caller created.
    username_key = username_bucket_key(username)
    if username_throttled(username_key, now_ts):
        abort(429)

    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT user_id, username, password_hash, status, role, email_verified_at "
        "FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    )
    row = c.fetchone()
    conn.close()

    password_hash = row[2] if row else DUMMY_PASSWORD_HASH
    # bcrypt raises above 72 UTF-8 bytes. Substitute a policy-impossible one-byte
    # password (real passwords are at least 8 characters) so over-limit input still
    # fails through the same single bcrypt check.
    password_bytes = password.encode()
    if len(password_bytes) > PASSWORD_MAX_BYTES:
        password_bytes = b'!'
    password_matches = bcrypt.checkpw(password_bytes, password_hash)

    # Charge a wrong password or an unknown username identically; a proven-correct
    # password clears the counter whatever the account's state turns out to be.
    if not row or not password_matches:
        charge_username_failure(username_key, now_ts)
    else:
        USERNAME_BUCKET.pop(username_key, None)

    if not row:
        # Unknown and known usernames both perform exactly one bcrypt check.
        audit(
            'auth.login_failed',
            actor_username=attempted_username,
            client_ip=client_ip,
            reason='unknown_user',
        )
        return jsonify({'error': 'Invalid username or password'}), 401

    user_id, canonical_username, _, status, role, email_verified_at = row
    if not password_matches:
        audit(
            'auth.login_failed',
            actor_id=user_id,
            actor_username=attempted_username,
            actor_role=role,
            client_ip=client_ip,
            reason='bad_password',
        )
        return jsonify({'error': 'Invalid username or password'}), 401

    # Verify the password BEFORE revealing account state, so status isn't a username oracle.
    if status != 'approved':
        if (status == 'pending'
                and REQUIRE_EMAIL_VERIFICATION
                and email_verified_at is None):
            reason = 'email_unverified'
        elif status == 'pending':
            reason = 'approval_pending'
        elif status == 'disabled':
            reason = 'account_disabled'
        else:
            reason = 'not_approved'
        audit(
            'auth.login_failed',
            actor_id=user_id,
            actor_username=attempted_username,
            actor_role=role,
            client_ip=client_ip,
            reason=reason,
        )
        if status == 'pending':
            if REQUIRE_EMAIL_VERIFICATION and email_verified_at is None:
                return jsonify({
                    'error': 'Email verification required before administrator approval'
                }), 403
            return jsonify({'error': 'Account pending admin approval'}), 403
        return jsonify({'error': 'Account is disabled'}), 403
    if REQUIRE_EMAIL_VERIFICATION and email_verified_at is None:
        audit(
            'auth.login_failed',
            actor_id=user_id,
            actor_username=attempted_username,
            actor_role=role,
            client_ip=client_ip,
            reason='email_unverified',
        )
        return jsonify({'error': 'Email verification required'}), 403

    # Each login starts a fresh session family (S-05); rotation stays inside it and
    # logout/replay revocation end exactly this family without touching other devices.
    refresh_token = secrets.token_urlsafe(32)
    refresh_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    family_id = str(uuid.uuid4())
    expires = now_ts + REFRESH_TOKEN_DURATION

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO refresh_tokens (user_id, family_id, token, status, expires, created) "
              "VALUES (?, ?, ?, 'active', ?, ?)",
              (user_id, family_id, refresh_hash, expires, now_ts))
    conn.commit()
    conn.close()
    audit(
        'auth.login',
        actor_id=user_id,
        actor_username=canonical_username,
        actor_role=role,
        client_ip=client_ip,
    )

    response = make_response(jsonify({'success': True}))
    response.set_cookie('refresh_token', refresh_token, max_age=REFRESH_TOKEN_DURATION,
                        path='/auth', httponly=True, secure=COOKIE_SECURE, samesite='Strict')
    return response


@app.route('/register', methods=['POST'])
def register():
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, PUBLIC_BUCKET, PUBLIC_REFILL_INTERVAL)

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    ok, username, reason = validate_username(data['username'])
    if not ok:
        return jsonify({'error': reason}), 400
    password = data['password']

    ok, reason = validate_password_policy(password)
    if not ok:
        return jsonify({'error': reason}), 400

    # First/last name are required at signup; company/department/birth_date/sex optional.
    ok, reason, profile = validate_profile_fields(data)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, now_ts)
    c.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Username already taken'}), 400
    if email_taken(c, profile['email']):
        conn.close()
        return jsonify({'error': 'Email already registered'}), 400

    user_uuid = str(uuid.uuid4())
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    verified_at = None
    if not REQUIRE_EMAIL_VERIFICATION:
        verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    # Self-registered users start pending; an admin must approve before they can log in.
    c.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email, company, department, birth_date, sex, "
        "email_verified_at) "
        "VALUES (?, ?, ?, 'user', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_uuid, username, pw_hash, datetime.now().isoformat(),
         profile['first_name'], profile['last_name'], profile['email'], profile['company'],
         profile['department'], profile['birth_date'], profile['sex'], verified_at)
    )
    conn.commit()
    conn.close()

    if REQUIRE_EMAIL_VERIFICATION:
        display_name = ' '.join((
            profile['first_name'],
            profile['last_name'],
        )).strip()
        outcome = _send_verification_email(
            user_uuid,
            display_name,
            profile['email'],
            now_ts,
        )
        if outcome == 'failed':
            return jsonify({
                'success': True,
                'email_sent': False,
                'message': (
                    'Registration received, but the verification email could not '
                    'be sent. Use Resend verification to try again.'
                ),
            })
        return jsonify({
            'success': True,
            'email_sent': outcome == 'sent',
            'message': 'Registration received. Verify your email.',
        })
    return jsonify({'success': True, 'message': 'Registration received.'})


# =====================
# Admin: user management
# =====================

@app.route('/admin/audit', methods=['GET'])
@require_admin
def admin_get_audit():
    if g.role != 'super_admin':
        return jsonify({'error': 'Forbidden'}), 403

    def _nonnegative_int(name, default, minimum=None, maximum=None):
        raw = request.args.get(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        if value < 0:
            return None
        if minimum is not None:
            value = max(value, minimum)
        if maximum is not None:
            value = min(value, maximum)
        return value

    limit = _nonnegative_int('limit', 100, minimum=1, maximum=500)
    before_supplied = request.args.get('before') is not None
    before = _nonnegative_int('before', None)
    if limit is None or (before_supplied and before is None):
        return jsonify({'error': 'Invalid pagination parameter'}), 400

    event = (request.args.get('event') or '').strip()
    search = (request.args.get('search') or '').strip()
    if len(event) > 100 or len(search) > 200:
        return jsonify({'error': 'Invalid audit filter'}), 400
    # Adblocker naming rule: request URLs never carry "share", so the client sends
    # collab-aliased action names; stored actions keep their share_* spelling.
    event = event.replace('collab', 'share')

    def _utc_bound(name):
        raw = (request.args.get(name) or '').strip()
        if not raw:
            return True, None
        try:
            parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except (TypeError, ValueError):
            return False, None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return False, None
        return True, parsed.astimezone(timezone.utc)

    begin_valid, begin = _utc_bound('begin')
    end_valid, end = _utc_bound('end')
    if not begin_valid or not end_valid or (begin is not None and end is not None and begin >= end):
        return jsonify({'error': 'Invalid audit filter'}), 400

    conn = get_db()
    c = conn.cursor()
    fields = (
        "id, ts, actor_id, actor_username, actor_role, action, target_type, "
        "target_id, target_label, detail, client_ip"
    )
    clauses = []
    parameters = []
    if event:
        clauses.append("action = ?")
        parameters.append(event)
    if begin is not None:
        clauses.append("julianday(ts) >= julianday(?)")
        parameters.append(begin.isoformat())
    if end is not None:
        clauses.append("julianday(ts) < julianday(?)")
        parameters.append(end.isoformat())
    if search:
        escaped = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        pattern = f"%{escaped}%"
        search_fields = (
            "CAST(id AS TEXT)", "ts", "actor_id", "actor_username", "actor_role",
            "action", "target_type", "target_id", "target_label", "detail", "client_ip",
        )
        clauses.append(
            "(" + " OR ".join(
                f"COALESCE({field}, '') LIKE ? ESCAPE '\\'" for field in search_fields
            ) + ")"
        )
        parameters.extend([pattern] * len(search_fields))
    if before is not None:
        clauses.append("id < ?")
        parameters.append(before)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    c.execute(
        f"SELECT {fields} FROM audit_log{where} ORDER BY id DESC LIMIT ?",
        (*parameters, limit + 1),
    )
    rows = c.fetchall()
    conn.close()

    has_more = len(rows) > limit
    rows = rows[:limit]
    entries = []
    for row in rows:
        entries.append({
            'id': row[0],
            'ts': row[1],
            'actor_id': row[2],
            'actor_username': row[3],
            'actor_role': row[4],
            'action': row[5],
            'target_type': row[6],
            'target_id': row[7],
            'target_label': row[8],
            # Deliberate API contract: JSON text at rest, object/null on the wire.
            'detail': json.loads(row[9]) if row[9] is not None else None,
            'client_ip': row[10],
        })
    next_before = entries[-1]['id'] if has_more and entries else None
    return jsonify({'entries': entries, 'next_before': next_before})


def _serialize_user(row):
    payload = {
        'user_id': row[0],
        'username': row[1],
        'role': row[2],
        'status': row[3],
        'created': row[4],
        'first_name': row[5] or '',
        'last_name': row[6] or '',
        'email': row[7] or '',
        'company': row[8] or '',
        'department': row[9] or '',
        'birth_date': row[10] or '',
        'sex': row[11] or '',
        # Pending self-registrations never have an avatar in the administration
        # queue. Approved and disabled accounts use the same signed URL as the
        # profile and sharing surfaces; a null URL lets the UI use its default.
        'avatar_url': _avatar_url(row[12], row[0]) if row[3] != 'pending' else None,
    }
    if REQUIRE_EMAIL_VERIFICATION:
        payload['email_verified'] = row[13] is not None
    return payload


# The management list is the scope: a super-admin sees every account; a regular admin
# sees ONLY the users they control. Nobody-land users, other admins' users and
# admin-level accounts (including the caller's own) are absent entirely — there is no
# action an admin could take on any of them, so listing them would only leak. With
# multi-control the scopes of different admins can overlap: a co-managed user appears
# in EVERY controlling admin's list.
@app.route('/admin/users', methods=['GET'])
@require_admin
def admin_list_users():
    conn = get_db()
    c = conn.cursor()
    scope_filter = "" if g.role == 'super_admin' else f" WHERE {controls_predicate('u.user_id')}"
    params = () if g.role == 'super_admin' else (g.user_id, g.user_id)
    c.execute(f'''
        SELECT u.user_id, u.username, u.role, u.status, u.created, u.first_name, u.last_name, u.email,
               u.company, u.department, u.birth_date, u.sex, u.avatar,
               u.email_verified_at
        FROM users u
        {scope_filter}
        ORDER BY u.username COLLATE NOCASE
    ''', params)
    rows = c.fetchall()
    # DIRECT controllers per user, for the detail pane's Managed-by chips (assignable/
    # revocable, so group-derived control must NOT appear here).
    c.execute('''
        SELECT uc.user_id, uc.admin_id, a.username, a.first_name, a.last_name
        FROM user_controllers uc
        JOIN users a ON a.user_id = uc.admin_id
        ORDER BY a.username COLLATE NOCASE
    ''')
    controllers = {}
    for uid, admin_id, admin_name, first, last in c.fetchall():
        controllers.setdefault(uid, []).append({
            'admin_id': admin_id,
            'username': admin_name,
            'first_name': first or '',
            'last_name': last or '',
        })
    # GROUP-DERIVED managers per user (member of a management group × its delegated
    # managers) — the second controls() source. Kept separate from the chips: revoking
    # it means removing the member or the manager grant, never a per-user revoke.
    # Admin usernames only, no group names — the co-managers line needs the WHO, and a
    # regular admin must not learn management-group composition.
    c.execute('''
        SELECT DISTINCT mm.user_id, mg.admin_id, a.username, a.first_name, a.last_name
        FROM mgmt_group_members mm
        JOIN mgmt_group_managers mg ON mg.group_id = mm.group_id
        JOIN users a ON a.user_id = mg.admin_id
        ORDER BY a.username COLLATE NOCASE
    ''')
    group_managers = {}
    for uid, admin_id, admin_name, first, last in c.fetchall():
        group_managers.setdefault(uid, []).append({
            'admin_id': admin_id,
            'username': admin_name,
            'first_name': first or '',
            'last_name': last or '',
        })
    # Share-group memberships per user, for the detail pane's Share Groups line.
    c.execute('''
        SELECT gm.user_id, gr.name
        FROM share_group_members gm
        JOIN share_groups gr ON gr.id = gm.group_id
        ORDER BY gr.name COLLATE NOCASE
    ''')
    memberships = {}
    for uid, gname in c.fetchall():
        memberships.setdefault(uid, []).append(gname)
    # Management-group membership is super-admin detail only (addendum-3 Visibility:
    # source information belongs in superadmin tooling and nowhere else). Regular
    # admins get no management-group key at all, matching the omitted-keys contract.
    management_memberships = {}
    if g.role == 'super_admin':
        c.execute('''
            SELECT mm.user_id, gr.name
            FROM mgmt_group_members mm
            JOIN management_groups gr ON gr.id = mm.group_id
            ORDER BY gr.name COLLATE NOCASE
        ''')
        for uid, gname in c.fetchall():
            management_memberships.setdefault(uid, []).append(gname)
    conn.close()

    payload = []
    for row in rows:
        user_id = row[0]
        item = {
            **_serialize_user(row),
            'share_groups': memberships.get(user_id, []),
        }
        if g.role == 'super_admin':
            # Source detail is super-admin tooling: direct grants are editable while
            # group-derived grants are read-only and managed through their group.
            item['management_groups'] = management_memberships.get(user_id, [])
            item['controllers'] = controllers.get(user_id, [])
            item['group_managers'] = group_managers.get(user_id, [])
        else:
            # Regular admins need only the source-agnostic WHO for coordination.
            # Merge both controls() origins on the server, remove duplicates where an
            # admin holds both kinds of grant, and omit source keys/IDs entirely.
            merged = {}
            for manager in controllers.get(user_id, []) + group_managers.get(user_id, []):
                merged.setdefault(manager['admin_id'], {
                    'username': manager['username'],
                    'first_name': manager['first_name'],
                    'last_name': manager['last_name'],
                })
            item['managers'] = sorted(
                merged.values(),
                key=lambda manager: manager['username'].casefold(),
            )
        payload.append(item)
    return jsonify(payload)


# Pending self-registrations are super-admin territory: invisible to regular admins and
# only approvable (or rejectable) by a super-admin. Approval moves the account to
# nobody-land — active and loginable but under no admin; assigning it to an admin is a
# separate, explicit super-admin step (the /controller route).
@app.route('/admin/users/<user_id>/approve', methods=['POST'])
@require_admin
def admin_approve_user(user_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can approve registrations'}), 403
    conn = get_db()
    c = conn.cursor()
    data = request.get_json(silent=True)
    bypass = isinstance(data, dict) and data.get('bypass_verification') is True
    c.execute(
        "SELECT username, email_verified_at FROM users "
        "WHERE user_id = ? AND status='pending'",
        (user_id,),
    )
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'No pending user with that id'}), 404
    if REQUIRE_EMAIL_VERIFICATION and target[1] is None and not bypass:
        conn.close()
        return jsonify({'error': 'Email verification is required before approval'}), 409
    verified_at = target[1]
    if verified_at is None:
        verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    c.execute(
        "UPDATE users SET status='approved', email_verified_at=? "
        "WHERE user_id = ? AND status='pending'",
        (verified_at, user_id),
    )
    changed = c.rowcount
    if changed:
        c.execute(
            "DELETE FROM account_tokens WHERE user_id=? "
            "AND purpose='email_verification'",
            (user_id,),
        )
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'No pending user with that id'}), 404
    # Give the newly approved user their personal Base Map so they don't open an empty canvas.
    create_base_map(user_id)
    audit(
        'user.approve',
        target_type='user',
        target_id=user_id,
        target_label=target[0],
        **({'verification_bypassed': True} if target[1] is None else {}),
    )
    return jsonify({'success': True})


@app.route('/admin/users/<user_id>/reject', methods=['POST'])
@require_admin
def admin_reject_user(user_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can reject registrations'}), 403
    conn = get_db()
    c = conn.cursor()
    # Only pending users can be rejected (deleted). Approved users are disabled, not rejected.
    c.execute("SELECT username FROM users WHERE user_id = ? AND status='pending'", (user_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'No pending user with that id'}), 404
    c.execute("DELETE FROM users WHERE user_id = ? AND status='pending'", (user_id,))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'No pending user with that id'}), 404
    audit('user.reject', target_type='user', target_id=user_id, target_label=target[0])
    return jsonify({'success': True})


@app.route('/admin/users/<user_id>/role', methods=['POST'])
@require_admin
def admin_set_role(user_id):
    # Promote/demote is admin-management: super-admins only. Regular admins manage users.
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can change admin roles'}), 403

    data = request.get_json(silent=True)
    # The UI can only set 'admin' or 'user'. 'super_admin' is CLI-only and cannot be granted here.
    if not isinstance(data, dict) or data.get('role') not in ('admin', 'user'):
        return jsonify({'error': "role must be 'admin' or 'user'"}), 400
    new_role = data['role']

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role, username FROM users WHERE user_id = ?", (user_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # A super-admin's role can only be changed via the CLI, never demoted through the UI.
    if target[0] == 'super_admin':
        conn.close()
        return jsonify({'error': 'A super-admin cannot be demoted from the UI'}), 403
    if target[0] == new_role:
        conn.close()
        return jsonify({'success': True})

    # Prevent removing the last admin-level account (would lock everyone out of management).
    if new_role == 'user' and target[0] in ADMIN_ROLES:
        c.execute("SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND status='approved'", ())
        if c.fetchone()[0] <= 1:
            conn.close()
            return jsonify({'error': 'Cannot demote the last remaining admin'}), 400

    c.execute("UPDATE users SET role = ? WHERE user_id = ?", (new_role, user_id))
    # Delegation cleanup. Promotion: admins can never be controlled, so a promoted user
    # sheds all controllers — the management-group memberships too, since a membership
    # left behind would keep producing controls() over the new admin through any
    # manager grant (the union in controls_predicate). Demotion: only the ex-admin's
    # OWN grants dissolve — a co-managed user or co-owned group keeps its other
    # controllers/owners/managers, and one with none left is thereby in nobody-land /
    # superadmin-owned.
    c.execute("DELETE FROM user_controllers WHERE user_id = ?", (user_id,))
    c.execute("DELETE FROM mgmt_group_members WHERE user_id = ?", (user_id,))
    if new_role == 'user':
        c.execute("DELETE FROM user_controllers WHERE admin_id = ?", (user_id,))
        c.execute("DELETE FROM share_group_owners WHERE admin_id = ?", (user_id,))
        c.execute("DELETE FROM mgmt_group_managers WHERE admin_id = ?", (user_id,))
    conn.commit()
    conn.close()
    audit(
        'user.role',
        target_type='user',
        target_id=user_id,
        target_label=target[1],
        old=target[0],
        new=new_role,
    )
    return jsonify({'success': True})


@app.route('/admin/users/<user_id>/disable', methods=['POST'])
@require_admin
def admin_disable_user(user_id):
    denied = _guard_admin_target(user_id)
    if denied:
        return denied
    # Guard against disabling the last admin-level account (self-lockout).
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role, username FROM users WHERE user_id = ?", (user_id,))
    target = c.fetchone()
    if target and target[0] in ADMIN_ROLES:
        c.execute("SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND status='approved'", ())
        if c.fetchone()[0] <= 1:
            conn.close()
            return jsonify({'error': 'Cannot disable the last remaining admin'}), 400
    c.execute("UPDATE users SET status='disabled', auth_version = auth_version + 1 "
              "WHERE user_id = ? AND status='approved'", (user_id,))
    changed = c.rowcount
    if changed == 0:
        conn.close()
        return jsonify({'error': 'No approved user with that id'}), 404
    # The disable takes effect immediately: every session family is revoked and the
    # auth_version bump makes outstanding access JWTs fail the identity gate now.
    c.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
    c.execute(
        "DELETE FROM account_tokens WHERE user_id = ? AND purpose='password_reset'",
        (user_id,),
    )
    conn.commit()
    conn.close()
    audit(
        'user.disable',
        target_type='user',
        target_id=user_id,
        target_label=target[1] if target else None,
    )
    return jsonify({'success': True})


@app.route('/admin/users/<user_id>/enable', methods=['POST'])
@require_admin
def admin_enable_user(user_id):
    denied = _guard_admin_target(user_id)
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, int(time.time()))
    c.execute(
        "SELECT username, email_verified_at FROM users WHERE user_id = ?",
        (user_id,),
    )
    target = c.fetchone()
    verified_at = target[1] if target else None
    if verified_at is None:
        verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    c.execute(
        "UPDATE users SET status='approved', email_verified_at=? "
        "WHERE user_id = ? AND status='disabled'",
        (verified_at, user_id),
    )
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'No disabled user with that id'}), 404
    audit(
        'user.enable',
        target_type='user',
        target_id=user_id,
        target_label=target[0] if target else None,
        **({'verification_bypassed': True}
           if target and target[1] is None else {}),
    )
    return jsonify({'success': True})


@app.route('/admin/users/<user_id>/resetpwd', methods=['POST'])
@require_admin
def admin_reset_password(user_id):
    # Admin sets a new password for a user (no old password needed). The target's
    # sessions are revoked so the new password takes effect immediately.
    denied = _guard_admin_target(user_id)
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'new_password' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    new_password = data['new_password']
    ok, reason = validate_password_policy(new_password)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, int(time.time()))
    c.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    c.execute("UPDATE users SET password_hash = ?, auth_version = auth_version + 1 "
              "WHERE user_id = ?", (new_hash, user_id))
    # Force the target to re-login everywhere with the new password: families are
    # revoked and the auth_version bump invalidates outstanding access JWTs at once.
    c.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
    c.execute(
        "DELETE FROM account_tokens WHERE user_id = ? AND purpose='password_reset'",
        (user_id,),
    )
    conn.commit()
    conn.close()
    audit('user.resetpwd', target_type='user', target_id=user_id, target_label=target[0])
    return jsonify({'success': True})


# Admin edit of a user's profile INCLUDING username — same governance as resetpwd:
# controls(admin, target) for regular admins, supers unscoped (admin-level targets and
# the caller's own row included — explicitly decided). Username follows the /register
# rules: shared allowlist/length policy, unique NOCASE (excluding the target). No session
# revocation: identity is user_id, a rename changes neither credentials nor grants.
@app.route('/admin/users/<user_id>/profile', methods=['PUT'])
@require_admin
def admin_edit_user_profile(user_id):
    denied = _guard_admin_target(user_id)
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'username' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    ok, username, reason = validate_username(data['username'])
    if not ok:
        return jsonify({'error': reason}), 400

    ok, reason, profile = validate_profile_fields(data)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, int(time.time()))
    profile_fields = (
        'username', 'first_name', 'last_name', 'email',
        'company', 'department', 'birth_date', 'sex',
    )
    c.execute(
        "SELECT username, first_name, last_name, email, company, department, birth_date, sex, "
        "email_verified_at "
        "FROM users WHERE user_id = ?",
        (user_id,),
    )
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    c.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE AND user_id <> ?", (username, user_id))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Username already taken'}), 400
    if email_taken(c, profile['email'], exclude_user_id=user_id):
        conn.close()
        return jsonify({'error': 'Email already registered'}), 400

    new_values = {
        'username': username,
        'first_name': profile['first_name'],
        'last_name': profile['last_name'],
        'email': profile['email'],
        'company': profile['company'],
        'department': profile['department'],
        'birth_date': profile['birth_date'],
        'sex': profile['sex'],
    }
    # Optional columns are nullable, and users created outside the app (create_users.py
    # inserts only first/last/email) store NULL for company/department/birth_date/sex.
    # The validated new values are always strings (blank = ''), so compare NULL as '':
    # NULL and '' both mean "unset" and must not register as a change (else the first
    # edit of any CLI-created user emits a spurious NULL->'' diff and a forced UPDATE).
    old_values = {field: (value if value is not None else '')
                  for field, value in zip(profile_fields, target)}
    changed_fields = {
        field: {'old': old_values[field], 'new': new_values[field]}
        for field in profile_fields
        if old_values[field] != new_values[field]
    }
    email_changed = old_values['email'].casefold() != new_values['email'].casefold()
    verification_bypassed = (
        REQUIRE_EMAIL_VERIFICATION
        and (target[8] is None or email_changed)
    )
    if (verification_bypassed
            and data.get('bypass_verification') is not True):
        conn.close()
        return jsonify({
            'error': 'Explicit verification bypass is required for this profile edit'
        }), 409
    if not changed_fields and not verification_bypassed:
        conn.close()
        return jsonify({'success': True, 'user_id': user_id, 'username': username})

    verified_at = target[8]
    if verified_at is None or verification_bypassed:
        verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    c.execute("UPDATE users SET username=?, first_name=?, last_name=?, email=?, company=?, department=?, birth_date=?, sex=?, "
              "email_verified_at=? "
              "WHERE user_id = ?",
              (username, profile['first_name'], profile['last_name'], profile['email'], profile['company'],
               profile['department'], profile['birth_date'], profile['sex'], verified_at, user_id))
    if verification_bypassed:
        c.execute(
            "DELETE FROM account_tokens WHERE user_id=? "
            "AND purpose='email_verification'",
            (user_id,),
        )
    conn.commit()
    conn.close()
    if user_id == g.user_id:
        g.username = username
    audit(
        'user.profile_edit',
        target_type='user',
        target_id=user_id,
        target_label=username,
        **({'verification_bypassed': True} if verification_bypassed else {}),
        **changed_fields,
    )
    return jsonify({'success': True, 'user_id': user_id, 'username': username})


@app.route('/admin/users/<user_id>', methods=['DELETE'])
@require_admin
def admin_delete_user(user_id):
    # Permanent: the user's maps/spots/photos cascade-delete via the FK ON DELETE CASCADE.
    # Hard delete is always cross-scope blast radius, so it is super-admin only — no
    # matter how the deleting admin's controls() over the target was acquired. A
    # super-admin still cannot delete their own account (mid-session foot-gun) nor the
    # last admin-level one.
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can delete accounts'}), 403
    if user_id == g.user_id:
        return jsonify({'error': 'You cannot delete your own account'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role, username, avatar FROM users WHERE user_id = ?", (user_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if target[0] in ADMIN_ROLES:
        c.execute("SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND status='approved'", ())
        if c.fetchone()[0] <= 1:
            conn.close()
            return jsonify({'error': 'Cannot delete the last remaining admin'}), 400

    # Remove the user's owned maps' photo files from disk before the cascade drops the rows.
    c.execute('''
        SELECT p.filename FROM photos p
        JOIN spots s ON s.id = p.spot_id
        JOIN maps m ON m.id = s.map_id
        WHERE m.owner_id = ?
    ''', (user_id,))
    filenames = [r[0] for r in c.fetchall()]

    c.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    audit('user.delete', target_type='user', target_id=user_id, target_label=target[1])

    # Best-effort cleanup after the committed deletion (R-02)
    for filename in filenames:
        for folder in (PHOTOS_FOLDER, THUMBS_FOLDER):
            fpath = os.path.join(folder, filename)
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
            except OSError:
                LOGGER.warning("user.delete: could not remove %s", clean_log_value(fpath))

    avatar_filename = target[2] or f"{user_id}.jpg"
    avatar_path = os.path.join(AVATARS_FOLDER, os.path.basename(avatar_filename))
    try:
        if os.path.exists(avatar_path):
            os.remove(avatar_path)
    except OSError:
        LOGGER.warning("user.delete: could not remove %s", clean_log_value(avatar_path))

    return jsonify({'success': True})


@app.route('/admin/users/create', methods=['POST'])
@require_admin
def admin_create_user():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    ok, username, reason = validate_username(data['username'])
    if not ok:
        return jsonify({'error': reason}), 400
    password = data['password']
    role = data.get('role', 'user')
    # UI can create 'user' or 'admin'. 'super_admin' is CLI-only.
    if role not in ('user', 'admin'):
        return jsonify({'error': "role must be 'user' or 'admin'"}), 400
    # Only a super-admin may create an admin; regular admins create regular users only.
    if role == 'admin' and g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can create admin accounts'}), 403

    ok, reason = validate_password_policy(password)
    if not ok:
        return jsonify({'error': reason}), 400

    ok, reason, profile = validate_profile_fields(data)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    _purge_expired_account_tokens(c, int(time.time()))
    c.execute("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Username already taken'}), 400
    if email_taken(c, profile['email']):
        conn.close()
        return jsonify({'error': 'Email already registered'}), 400

    user_uuid = str(uuid.uuid4())
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    # Admin-created users are pre-approved (like the CLI) and can log in immediately.
    c.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email, company, department, birth_date, sex, "
        "email_verified_at) "
        "VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_uuid, username, pw_hash, role, datetime.now().isoformat(),
         profile['first_name'], profile['last_name'], profile['email'], profile['company'],
         profile['department'], profile['birth_date'], profile['sex'], verified_at)
    )
    # Create is self-serve and auto-grants controls() ONLY when the creating actor is a
    # regular admin creating a regular user — no nobody-land stopover for those. A
    # super-admin's creations start unassigned (superadmins need no grant), and admin
    # accounts can never be controlled.
    if g.role == 'admin' and role == 'user':
        c.execute("INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?, ?, ?)",
                  (user_uuid, g.user_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    # Give them their personal Base Map so they don't open an empty canvas.
    create_base_map(user_uuid)
    audit(
        'user.create',
        target_type='user',
        target_id=user_uuid,
        target_label=username,
        role=role,
    )

    return jsonify({'success': True, 'user_id': user_uuid, 'username': username, 'role': role})


# Delegation of controls() — the ONLY path out of nobody-land, and it is super-admin
# only (there is no admin self-claim). Assignment is ADDITIVE: it grants one more
# co-managing admin without disturbing existing ones (adding an existing controller is
# an idempotent no-op). Pending accounts must be approved first, and only regular users
# can be assigned (admins are never controlled).
@app.route('/admin/users/<user_id>/controllers', methods=['PUT'])
@require_admin
def admin_add_user_controller(user_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can assign users to an admin'}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get('admin_id'):
        return jsonify({'error': 'admin_id is required'}), 400
    admin_id = data['admin_id']

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT role, status, username FROM users WHERE user_id = ?", (user_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if target[0] != 'user':
        conn.close()
        return jsonify({'error': 'Only regular users can be assigned to an admin'}), 400
    if target[1] == 'pending':
        conn.close()
        return jsonify({'error': 'Approve the registration before assigning the user'}), 400

    c.execute("SELECT role, status, username FROM users WHERE user_id = ?", (admin_id,))
    arow = c.fetchone()
    if not arow or arow[0] != 'admin' or arow[1] != 'approved':
        conn.close()
        return jsonify({'error': 'The controller must be an approved admin'}), 400

    c.execute('''
        INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?, ?, ?)
        ON CONFLICT(user_id, admin_id) DO NOTHING
    ''', (user_id, admin_id, datetime.now().isoformat()))
    inserted = c.rowcount
    conn.commit()
    conn.close()
    if inserted:
        audit(
            'user.controller.add',
            target_type='user',
            target_id=user_id,
            target_label=target[2],
            admin_id=admin_id,
            admin_label=arow[2],
        )
    return jsonify({'success': True, 'user_id': user_id, 'admin_id': admin_id})


# Revocation of controls() — super-admin only and always TARGETED: it removes one named
# admin's grant and never touches co-controllers. A user whose last grant is revoked is
# back in nobody-land (superadmin-assignable only, never admin-claimable).
@app.route('/admin/users/<user_id>/controllers/<admin_id>', methods=['DELETE'])
@require_admin
def admin_remove_user_controller(user_id, admin_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can revoke an assignment'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT u.username, a.username
        FROM user_controllers uc
        JOIN users u ON u.user_id = uc.user_id
        JOIN users a ON a.user_id = uc.admin_id
        WHERE uc.user_id = ? AND uc.admin_id = ?
    ''', (user_id, admin_id))
    labels = c.fetchone()
    if not labels:
        conn.close()
        return jsonify({'error': 'Assignment not found'}), 404
    c.execute("DELETE FROM user_controllers WHERE user_id = ? AND admin_id = ?", (user_id, admin_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Assignment not found'}), 404
    audit(
        'user.controller.remove',
        target_type='user',
        target_id=user_id,
        target_label=labels[0],
        admin_id=admin_id,
        admin_label=labels[1],
    )
    return jsonify({'success': True, 'user_id': user_id, 'admin_id': admin_id})


# Admin-visible map METADATA for one user. Regular admins get bare owned-map metadata
# only; the relationship graph (owned-map collaborator rosters and maps shared with the
# user) is sealed from them. Super-admins keep the full metadata view. Contents stay
# sealed for both roles — spots, photos and user-written description/notes are never in
# this payload, and admin requests for a map's data routes keep 404ing.
@app.route('/admin/users/<user_id>/maps', methods=['GET'])
@require_admin
def admin_user_maps(user_id):
    # Same governance as the other admin actions: viewing a user's map metadata requires
    # controls() over that user (super-admins are unscoped). An admin's own maps live in
    # the app itself, not behind this window.
    denied = _guard_admin_target(user_id)
    if denied:
        return denied

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # markers must be COUNT(DISTINCT ...) — the photos join repeats a spot row once per
    # photo. photos counts the join rows themselves, which is exactly the photo total.
    c.execute('''
        SELECT m.id, m.name, m.created, m.is_base,
               COUNT(DISTINCT s.id) AS markers, COUNT(p.id) AS photos
        FROM maps m
        LEFT JOIN spots s ON s.map_id = m.id
        LEFT JOIN photos p ON p.spot_id = s.id
        WHERE m.owner_id = ?
        GROUP BY m.id
        ORDER BY m.name COLLATE NOCASE
    ''', (user_id,))
    map_rows = c.fetchall()

    is_super = g.role == 'super_admin'
    collabs = {}
    shared = {}
    if is_super:
        c.execute('''
            SELECT ms.map_id, u.username, ms.role
            FROM map_shares ms
            JOIN users u ON u.user_id = ms.user_id
            JOIN maps m ON m.id = ms.map_id
            WHERE m.owner_id = ?
            ORDER BY u.username COLLATE NOCASE
        ''', (user_id,))
        for map_id, username, role in c.fetchall():
            collabs.setdefault(map_id, []).append({'type': 'user', 'name': username, 'role': role})
        c.execute('''
            SELECT mgs.map_id, gr.name, mgs.role
            FROM map_group_shares mgs
            JOIN share_groups gr ON gr.id = mgs.group_id
            JOIN maps m ON m.id = mgs.map_id
            WHERE m.owner_id = ?
            ORDER BY gr.name COLLATE NOCASE
        ''', (user_id,))
        for map_id, name, role in c.fetchall():
            collabs.setdefault(map_id, []).append({'type': 'group', 'name': name, 'role': role})

        # Maps shared WITH this user — direct grants plus grants via group membership,
        # aggregated per map so one map reached both ways shows both paths. This
        # relationship metadata is super-admin-only; regular admins receive neither
        # this key nor empty stand-ins for hidden data.
        c.execute('''
            SELECT m.id, m.name, ou.username, ou.first_name, ou.last_name, ms.role
            FROM map_shares ms
            JOIN maps m ON m.id = ms.map_id
            JOIN users ou ON ou.user_id = m.owner_id
            WHERE ms.user_id = ? AND m.owner_id <> ? AND m.is_base = 0
        ''', (user_id, user_id))
        for map_id, name, owner, owner_first, owner_last, role in c.fetchall():
            entry = shared.setdefault(map_id, {
                'id': map_id,
                'name': name,
                'owner': owner,
                'owner_first': owner_first or '',
                'owner_last': owner_last or '',
                'paths': [],
            })
            entry['paths'].append({'type': 'direct', 'role': role})
        c.execute('''
            SELECT m.id, m.name, ou.username, ou.first_name, ou.last_name,
                   gr.name, mgs.role
            FROM share_group_members gm
            JOIN map_group_shares mgs ON mgs.group_id = gm.group_id
            JOIN share_groups gr ON gr.id = gm.group_id
            JOIN maps m ON m.id = mgs.map_id
            JOIN users ou ON ou.user_id = m.owner_id
            WHERE gm.user_id = ? AND m.owner_id <> ? AND m.is_base = 0
            ORDER BY gr.name COLLATE NOCASE
        ''', (user_id, user_id))
        for map_id, name, owner, owner_first, owner_last, group_name, role in c.fetchall():
            entry = shared.setdefault(map_id, {
                'id': map_id,
                'name': name,
                'owner': owner,
                'owner_first': owner_first or '',
                'owner_last': owner_last or '',
                'paths': [],
            })
            entry['paths'].append({'type': 'group', 'group': group_name, 'role': role})
    conn.close()

    owned = []
    for r in map_rows:
        row = {
            'id': r[0],
            'name': r[1],
            'created': r[2],
            'is_base': bool(r[3]),
            'markers': r[4],
            'photos': r[5]
        }
        if is_super:
            row['collaborators'] = collabs.get(r[0], [])
        owned.append(row)

    payload = {'owned': owned, 'sharing_visible': is_super}
    if is_super:
        payload['shared'] = sorted(shared.values(), key=lambda x: x['name'].casefold())
    return jsonify(payload)


# Preserve the admin collaborator API's Map-not-found contract independently of its
# authorization gate. Callers check super-admin status first so regular admins always
# receive 403, including for nonexistent map ids.
def _map_exists_or_404(map_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT 1 FROM maps WHERE id = ?", (map_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return (jsonify({'error': 'Map not found'}), 404)
    return None


# Super-admins manage WHO a map is shared with from the Administration screen. Regular
# admins have no read or write path to these relationships. The no-self-grant guard is
# retained for the super-admin PUT; owner-facing collaborator routes are separate and
# unchanged.

@app.route('/admin/maps/<int:map_id>/collaborators', methods=['GET'])
@require_admin
def admin_get_map_shares(map_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Forbidden'}), 403
    missing = _map_exists_or_404(map_id)
    if missing:
        return missing
    return _map_shares_json(map_id)


@app.route('/admin/maps/<int:map_id>/collaborators', methods=['PUT'])
@require_admin
def admin_set_map_share(map_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Forbidden'}), 403
    missing = _map_exists_or_404(map_id)
    if missing:
        return missing
    response, change = _apply_map_share(
        map_id,
        request.get_json(silent=True),
        forbid_user_id=g.user_id,
    )
    if change:
        access_path = 'group' if 'group' in change else 'direct'
        access_event = 'grant' if change.get('operation') == 'created' else 'change'
        audit(
            f'map_share.{access_path}.{access_event}',
            target_type='map',
            target_id=map_id,
            target_label=change.pop('map_label'),
            **change,
        )
    return response


@app.route('/admin/maps/<int:map_id>/collaborators/<user_id>', methods=['DELETE'])
@require_admin
def admin_delete_map_share(map_id, user_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Forbidden'}), 403
    missing = _map_exists_or_404(map_id)
    if missing:
        return missing
    conn = get_db()
    labels = conn.execute(
        "SELECT m.name, u.username FROM maps m, users u "
        "WHERE m.id = ? AND u.user_id = ?",
        (map_id, user_id),
    ).fetchone()
    conn.close()
    response = _remove_user_share(map_id, user_id)
    status = response[1] if isinstance(response, tuple) else response.status_code
    if status == 200 and labels:
        audit(
            'map_share.direct.remove',
            target_type='map',
            target_id=map_id,
            target_label=labels[0],
            recipient=user_id,
            recipient_label=labels[1],
        )
    return response


@app.route('/admin/maps/<int:map_id>/collaborators/group/<int:group_id>', methods=['DELETE'])
@require_admin
def admin_delete_map_group_share(map_id, group_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Forbidden'}), 403
    missing = _map_exists_or_404(map_id)
    if missing:
        return missing
    conn = get_db()
    labels = conn.execute(
        "SELECT m.name, gr.name FROM maps m, share_groups gr "
        "WHERE m.id = ? AND gr.id = ?",
        (map_id, group_id),
    ).fetchone()
    conn.close()
    response = _remove_group_share(map_id, group_id)
    status = response[1] if isinstance(response, tuple) else response.status_code
    if status == 200 and labels:
        audit(
            'map_share.group.remove',
            target_type='map',
            target_id=map_id,
            target_label=labels[0],
            group=group_id,
            group_label=labels[1],
        )
    return response


# =====================
# Share groups (admin-managed). Membership defines what "shared with a group" reaches,
# so create/delete/membership are admin-only; owners only pick group names when sharing.
# Authority over a share group is owns_share_group() — share_group_owners, many-to-many
# like user_controllers — exactly as controls() is for users: a regular admin manages
# only the groups they (co-)own; a super-admin all of them. Co-owners act independently.
# Membership itself stays administratively inert (map-sharing reach only).
# NOTE: the URL paths (and the frontend's DOM ids/classes) deliberately keep the bare
# "group(s)" naming — adblock filter lists match "share" substrings in URLs and element
# ids and quietly block/hide them (same reason the share routes are /collaborators).
# =====================

# Share-group governance gate. Returns (denied, created_by): denied is None when the
# caller may manage the group (else a ready (response, code)), created_by for the
# delete rule.
def _guard_admin_share_group(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT gr.created_by,
               EXISTS (SELECT 1 FROM share_group_owners go WHERE go.group_id = gr.id AND go.admin_id = ?)
        FROM share_groups gr WHERE gr.id = ?
    ''', (g.user_id, group_id))
    row = c.fetchone()
    conn.close()
    if not row:
        return (jsonify({'error': 'Group not found'}), 404), None
    if g.role != 'super_admin' and not row[1]:
        return (jsonify({'error': 'You do not manage this group'}), 403), None
    return None, row[0]


@app.route('/admin/groups', methods=['GET'])
@require_admin
def admin_list_share_groups():
    conn = get_db()
    c = conn.cursor()
    scope_filter = "" if g.role == 'super_admin' else \
        " WHERE EXISTS (SELECT 1 FROM share_group_owners go WHERE go.group_id = gr.id AND go.admin_id = ?)"
    params = () if g.role == 'super_admin' else (g.user_id,)
    c.execute(f'''
        SELECT gr.id, gr.name, gr.created, gr.created_by, cu.username,
               cu.first_name, cu.last_name
        FROM share_groups gr
        LEFT JOIN users cu ON cu.user_id = gr.created_by
        {scope_filter}
        ORDER BY gr.name COLLATE NOCASE
    ''', params)
    group_rows = c.fetchall()
    # Owners per group (owns_share_group is many-to-many; empty list = superadmin-owned).
    c.execute('''
        SELECT go.group_id, go.admin_id, a.username, a.first_name, a.last_name
        FROM share_group_owners go
        JOIN users a ON a.user_id = go.admin_id
        ORDER BY a.username COLLATE NOCASE
    ''')
    owners = {}
    for group_id, admin_id, admin_name, first, last in c.fetchall():
        owners.setdefault(group_id, []).append({
            'admin_id': admin_id,
            'username': admin_name,
            'first_name': first or '',
            'last_name': last or '',
        })
    # Per member, 'managed' says whether the CALLER controls that member (directly or
    # via a management group) — the UI uses it to offer Remove only where the backend
    # would allow it.
    c.execute(f'''
        SELECT gm.group_id, u.user_id, u.username, u.first_name, u.last_name, u.avatar,
               {controls_predicate('u.user_id')}
        FROM share_group_members gm
        JOIN users u ON u.user_id = gm.user_id
        ORDER BY u.username COLLATE NOCASE
    ''', (g.user_id, g.user_id))
    members = {}
    for group_id, uid, username, first, last, avatar, caller_controls in c.fetchall():
        members.setdefault(group_id, []).append({
            'user_id': uid, 'username': username,
            'first_name': first or '', 'last_name': last or '',
            'avatar_url': _avatar_url(avatar, uid),
            'managed': g.role == 'super_admin' or bool(caller_controls)
        })
    # Members outside the CALLER's own control list, per group — the delete rule's
    # clean-membership check is individual, never collective (admin/superadmin members
    # are never controlled, so any group containing one always counts as having
    # outsiders).
    c.execute(f'''
        SELECT gm.group_id, COUNT(*)
        FROM share_group_members gm
        WHERE NOT {controls_predicate('gm.user_id')}
        GROUP BY gm.group_id
    ''', (g.user_id, g.user_id))
    outside = dict(c.fetchall())
    conn.close()
    # Delete rule: super always. An admin only for groups they created themselves AND
    # still own, with every member inside their OWN control list. Co-owners never gain
    # delete authority however many there are, and revoking the creator's grant removes
    # it — delegation governs edit/membership only, never delete.
    def _deletable(gid, created_by, olist):
        if g.role == 'super_admin':
            return True
        if created_by != g.user_id:
            return False
        if not any(o['admin_id'] == g.user_id for o in olist):
            return False
        return outside.get(gid, 0) == 0
    return jsonify([
        {'id': r[0], 'name': r[1], 'created': r[2],
         'created_by_username': r[4],
         'created_by_first': r[5] or '',
         'created_by_last': r[6] or '',
         'owners': owners.get(r[0], []),
         'deletable': _deletable(r[0], r[3], owners.get(r[0], [])),
         'members': members.get(r[0], [])}
        for r in group_rows
    ])


@app.route('/admin/groups', methods=['POST'])
@require_admin
def admin_create_share_group():
    data = request.get_json(silent=True)
    ok, reason, name = text_value(data.get('name') if isinstance(data, dict) else None,
                                  'Group name', NAME_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    created = datetime.now().isoformat()
    # Create is self-serve. An admin's creation is superadmin ownership delegated at
    # birth (a share_group_owners row for the creator); a super-admin's creation stays
    # superadmin-owned (no rows). created_by records the creator permanently for the
    # creator-only delete rule.
    try:
        c.execute("INSERT INTO share_groups (name, created, created_by) VALUES (?, ?, ?)",
                  (name, created, g.user_id))
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'A group with this name already exists'}), 400
    group_id = c.lastrowid
    owners = []
    if g.role == 'admin':
        c.execute("INSERT INTO share_group_owners (group_id, admin_id, created) VALUES (?, ?, ?)",
                  (group_id, g.user_id, created))
        owners = [{'admin_id': g.user_id, 'username': g.username}]
    conn.commit()
    conn.close()
    audit(
        'share_group.create',
        target_type='share_group',
        target_id=group_id,
        target_label=name,
        name=name,
    )
    return jsonify({'id': group_id, 'name': name, 'created': created,
                    'owners': owners, 'deletable': True, 'members': []})


@app.route('/admin/groups/<int:group_id>', methods=['PUT'])
@require_admin
def admin_rename_share_group(group_id):
    denied, _ = _guard_admin_share_group(group_id)
    if denied:
        return denied
    data = request.get_json(silent=True)
    ok, reason, name = text_value(data.get('name') if isinstance(data, dict) else None,
                                  'Group name', NAME_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM share_groups WHERE id = ?", (group_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    if target[0] == name:
        conn.close()
        return jsonify({'success': True, 'id': group_id, 'name': name})
    try:
        c.execute("UPDATE share_groups SET name = ? WHERE id = ?", (name, group_id))
        changed = c.rowcount
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'A group with this name already exists'}), 400
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Group not found'}), 404
    audit(
        'share_group.rename',
        target_type='share_group',
        target_id=group_id,
        target_label=name,
        old_name=target[0],
        new_name=name,
    )
    return jsonify({'success': True, 'id': group_id, 'name': name})


@app.route('/admin/groups/<int:group_id>', methods=['DELETE'])
@require_admin
def admin_delete_share_group(group_id):
    # Memberships and map shares cascade — every member loses the group's map access
    # on their next request. Delete authority for a regular admin belongs to the
    # creator alone: self-created AND still owned (the guard checks ownership), with
    # every member inside the creator's OWN control list — co-owners never gain delete
    # authority however many there are. Any outside member (other admins' users,
    # nobody-land users, admin-level accounts) escalates to a super-admin.
    denied, created_by = _guard_admin_share_group(group_id)
    if denied:
        return denied
    if g.role != 'super_admin':
        if created_by != g.user_id:
            return jsonify({'error': 'Only the group\'s creator can delete it'}), 403
        conn = get_db()
        c = conn.cursor()
        c.execute(f'''
            SELECT COUNT(*) FROM share_group_members gm
            WHERE gm.group_id = ? AND NOT {controls_predicate('gm.user_id')}
        ''', (group_id, g.user_id, g.user_id))
        outside = c.fetchone()[0]
        conn.close()
        if outside:
            return jsonify({'error': 'The group has members outside your control; only a super-admin can delete it'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM share_groups WHERE id = ?", (group_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    c.execute("DELETE FROM share_groups WHERE id = ?", (group_id,))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Group not found'}), 404
    audit(
        'share_group.delete',
        target_type='share_group',
        target_id=group_id,
        target_label=target[0],
        name=target[0],
    )
    return jsonify({'success': True})


@app.route('/admin/groups/<int:group_id>/members', methods=['PUT'])
@require_admin
def admin_add_share_group_member(group_id):
    denied, _ = _guard_admin_share_group(group_id)
    if denied:
        return denied
    data = request.get_json(silent=True)
    ok, reason, username = text_value(data.get('username') if isinstance(data, dict) else None,
                                      'username', PROFILE_FIELD_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM share_groups WHERE id = ?", (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    # Members must be approved accounts, same rule as the direct-share targets.
    c.execute(f'''
        SELECT u.user_id, {controls_predicate('u.user_id')}, u.username
        FROM users u WHERE u.username = ? COLLATE NOCASE AND u.status = 'approved'
    ''', (g.user_id, g.user_id, username))
    urow = c.fetchone()
    if not urow:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Adding grants the member access to every map shared with the group, so it needs
    # authority over the PERSON too: controls(admin, user) AND owns_share_group(admin,
    # group). This also closes admin self-add (nobody controls themselves). Super-admins
    # are unscoped and may add anyone, themselves included.
    if g.role != 'super_admin' and not urow[1]:
        conn.close()
        return jsonify({'error': 'You do not manage this user'}), 403
    # Idempotent: adding an existing member is a no-op, not an error.
    c.execute('''
        INSERT INTO share_group_members (group_id, user_id, created) VALUES (?, ?, ?)
        ON CONFLICT(group_id, user_id) DO NOTHING
    ''', (group_id, urow[0], datetime.now().isoformat()))
    inserted = c.rowcount
    conn.commit()
    conn.close()
    if inserted:
        audit(
            'share_group.member.add',
            target_type='share_group',
            target_id=group_id,
            target_label=group[0],
            user_id=urow[0],
            user_label=urow[2],
        )
    return jsonify({'success': True, 'group_id': group_id, 'user_id': urow[0], 'username': urow[2]})


@app.route('/admin/groups/<int:group_id>/members/<user_id>', methods=['DELETE'])
@require_admin
def admin_remove_share_group_member(group_id, user_id):
    denied, _ = _guard_admin_share_group(group_id)
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    # Removal is scoped like adding: an owner may only remove members they control.
    # Members placed by a super-admin from outside the owner's scope stay until a
    # super-admin removes them.
    if g.role != 'super_admin':
        c.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
        if c.fetchone():
            c.execute(f"SELECT {controls_predicate('u.user_id')} FROM users u WHERE u.user_id = ?",
                      (g.user_id, g.user_id, user_id))
            if not c.fetchone()[0]:
                conn.close()
                return jsonify({'error': 'You do not manage this user'}), 403
    c.execute('''
        SELECT gr.name, u.username
        FROM share_group_members gm
        JOIN share_groups gr ON gr.id = gm.group_id
        JOIN users u ON u.user_id = gm.user_id
        WHERE gm.group_id = ? AND gm.user_id = ?
    ''', (group_id, user_id))
    labels = c.fetchone()
    if not labels:
        conn.close()
        return jsonify({'error': 'Membership not found'}), 404
    c.execute("DELETE FROM share_group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Membership not found'}), 404
    audit(
        'share_group.member.remove',
        target_type='share_group',
        target_id=group_id,
        target_label=labels[0],
        user_id=user_id,
        user_label=labels[1],
    )
    return jsonify({'success': True})


# Delegation of owns_share_group() — super-admin only, mirroring the users'
# /controllers route: ADDITIVE, granting one more co-owner without disturbing existing
# ones (idempotent on an existing owner).
@app.route('/admin/groups/<int:group_id>/owners', methods=['PUT'])
@require_admin
def admin_add_share_group_owner(group_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can delegate groups'}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get('admin_id'):
        return jsonify({'error': 'admin_id is required'}), 400
    admin_id = data['admin_id']

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM share_groups WHERE id = ?", (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    c.execute("SELECT role, status, username FROM users WHERE user_id = ?", (admin_id,))
    arow = c.fetchone()
    if not arow or arow[0] != 'admin' or arow[1] != 'approved':
        conn.close()
        return jsonify({'error': 'The owner must be an approved admin'}), 400
    c.execute('''
        INSERT INTO share_group_owners (group_id, admin_id, created) VALUES (?, ?, ?)
        ON CONFLICT(group_id, admin_id) DO NOTHING
    ''', (group_id, admin_id, datetime.now().isoformat()))
    inserted = c.rowcount
    conn.commit()
    conn.close()
    if inserted:
        audit(
            'share_group.owner.add',
            target_type='share_group',
            target_id=group_id,
            target_label=group[0],
            admin_id=admin_id,
            admin_label=arow[2],
        )
    return jsonify({'success': True, 'group_id': group_id, 'admin_id': admin_id})


# Revocation of owns_share_group() — super-admin only and always TARGETED: it removes
# one named admin's grant, never touching co-owners. A group whose last grant is
# revoked is superadmin-owned again (who retains it — never a claimable pool).
@app.route('/admin/groups/<int:group_id>/owners/<admin_id>', methods=['DELETE'])
@require_admin
def admin_remove_share_group_owner(group_id, admin_id):
    if g.role != 'super_admin':
        return jsonify({'error': 'Only a super-admin can revoke a delegation'}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT gr.name, a.username
        FROM share_group_owners go
        JOIN share_groups gr ON gr.id = go.group_id
        JOIN users a ON a.user_id = go.admin_id
        WHERE go.group_id = ? AND go.admin_id = ?
    ''', (group_id, admin_id))
    labels = c.fetchone()
    if not labels:
        conn.close()
        return jsonify({'error': 'Delegation not found'}), 404
    c.execute("DELETE FROM share_group_owners WHERE group_id = ? AND admin_id = ?", (group_id, admin_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Delegation not found'}), 404
    audit(
        'share_group.owner.remove',
        target_type='share_group',
        target_id=group_id,
        target_label=labels[0],
        admin_id=admin_id,
        admin_label=labels[1],
    )
    return jsonify({'success': True, 'group_id': group_id, 'admin_id': admin_id})


# =====================
# Management groups (Addendum 3) — bulk delegation of controls(), superadmin-only END
# TO END: every route below hard-gates on super_admin. There is no admin-facing
# equivalent of any action here, no self-serve create, no claim path — an admin listed
# as a manager was put there by a superadmin. Structurally a clone of the share-group
# routes above, pointed at the management_groups / mgmt_group_members /
# mgmt_group_managers tables; behaviorally different where the spec says so: members
# are regular users only, the manager relation delegates management (not ownership),
# and delete is a superadmin bookkeeping action (no creator-scoped rule).
# =====================

def _mgmt_super_only():
    if g.role != 'super_admin':
        return (jsonify({'error': 'Only a super-admin can manage management groups'}), 403)
    return None


@app.route('/admin/mgmt-groups', methods=['GET'])
@require_admin
def admin_list_mgmt_groups():
    denied = _mgmt_super_only()
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT gr.id, gr.name, gr.created, cu.username, cu.first_name, cu.last_name
        FROM management_groups gr
        LEFT JOIN users cu ON cu.user_id = gr.created_by
        ORDER BY gr.name COLLATE NOCASE
    ''')
    group_rows = c.fetchall()
    # Delegated managers per group (manage_mgmt_group; empty list = nobody manages the
    # members through this group yet — the group is still superadmin-owned either way).
    c.execute('''
        SELECT mg.group_id, mg.admin_id, a.username, a.first_name, a.last_name
        FROM mgmt_group_managers mg
        JOIN users a ON a.user_id = mg.admin_id
        ORDER BY a.username COLLATE NOCASE
    ''')
    managers = {}
    for group_id, admin_id, admin_name, first, last in c.fetchall():
        managers.setdefault(group_id, []).append({
            'admin_id': admin_id,
            'username': admin_name,
            'first_name': first or '',
            'last_name': last or '',
        })
    c.execute('''
        SELECT mm.group_id, u.user_id, u.username, u.first_name, u.last_name, u.avatar
        FROM mgmt_group_members mm
        JOIN users u ON u.user_id = mm.user_id
        ORDER BY u.username COLLATE NOCASE
    ''')
    members = {}
    for group_id, uid, username, first, last, avatar in c.fetchall():
        members.setdefault(group_id, []).append({
            'user_id': uid, 'username': username,
            'first_name': first or '', 'last_name': last or '',
            'avatar_url': _avatar_url(avatar, uid)
        })
    conn.close()
    return jsonify([
        {'id': r[0], 'name': r[1], 'created': r[2],
         'created_by_username': r[3],
         'created_by_first': r[4] or '',
         'created_by_last': r[5] or '',
         'managers': managers.get(r[0], []),
         'members': members.get(r[0], [])}
        for r in group_rows
    ])


@app.route('/admin/mgmt-groups', methods=['POST'])
@require_admin
def admin_create_mgmt_group():
    denied = _mgmt_super_only()
    if denied:
        return denied
    data = request.get_json(silent=True)
    ok, reason, name = text_value(data.get('name') if isinstance(data, dict) else None,
                                  'Group name', NAME_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    created = datetime.now().isoformat()
    try:
        c.execute("INSERT INTO management_groups (name, created, created_by) VALUES (?, ?, ?)",
                  (name, created, g.user_id))
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'A group with this name already exists'}), 400
    group_id = c.lastrowid
    conn.commit()
    conn.close()
    audit(
        'mgmt_group.create',
        target_type='mgmt_group',
        target_id=group_id,
        target_label=name,
        name=name,
    )
    return jsonify({'id': group_id, 'name': name, 'created': created,
                    'managers': [], 'members': []})


@app.route('/admin/mgmt-groups/<int:group_id>', methods=['PUT'])
@require_admin
def admin_rename_mgmt_group(group_id):
    denied = _mgmt_super_only()
    if denied:
        return denied
    data = request.get_json(silent=True)
    ok, reason, name = text_value(data.get('name') if isinstance(data, dict) else None,
                                  'Group name', NAME_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM management_groups WHERE id = ?", (group_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    if target[0] == name:
        conn.close()
        return jsonify({'success': True, 'id': group_id, 'name': name})
    try:
        c.execute("UPDATE management_groups SET name = ? WHERE id = ?", (name, group_id))
        changed = c.rowcount
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'A group with this name already exists'}), 400
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Group not found'}), 404
    audit(
        'mgmt_group.rename',
        target_type='mgmt_group',
        target_id=group_id,
        target_label=name,
        old_name=target[0],
        new_name=name,
    )
    return jsonify({'success': True, 'id': group_id, 'name': name})


@app.route('/admin/mgmt-groups/<int:group_id>', methods=['DELETE'])
@require_admin
def admin_delete_mgmt_group(group_id):
    # Superadmin bookkeeping, not an earned right: Invariant 3's creator-scoped delete
    # rule doesn't apply here because management groups are never admin-created.
    # Memberships and manager grants cascade; every member's group-derived controls()
    # is gone on the next request.
    denied = _mgmt_super_only()
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM management_groups WHERE id = ?", (group_id,))
    target = c.fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    c.execute("DELETE FROM management_groups WHERE id = ?", (group_id,))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Group not found'}), 404
    audit(
        'mgmt_group.delete',
        target_type='mgmt_group',
        target_id=group_id,
        target_label=target[0],
        name=target[0],
    )
    return jsonify({'success': True})


@app.route('/admin/mgmt-groups/<int:group_id>/members', methods=['PUT'])
@require_admin
def admin_add_mgmt_group_member(group_id):
    denied = _mgmt_super_only()
    if denied:
        return denied
    data = request.get_json(silent=True)
    ok, reason, username = text_value(data.get('username') if isinstance(data, dict) else None,
                                      'username', PROFILE_FIELD_MAX, required=True)
    if not ok:
        return jsonify({'error': reason}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT u.user_id, u.role, u.status, u.username FROM users u WHERE u.username = ? COLLATE NOCASE",
              (username,))
    urow = c.fetchone()
    if not urow:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Members are END-USERS BEING MANAGED, never admin-level accounts: membership plus
    # a manager grant produces controls(), and admins are never controlled (admin-over-
    # admin authority is superadmin territory, not a controls() fact). Pending accounts
    # must be approved first, same as direct assignment; disabled ones may be members
    # (control over a disabled user is what enables re-enabling them).
    if urow[1] != 'user':
        conn.close()
        return jsonify({'error': 'Only regular users can be members of a management group'}), 400
    if urow[2] == 'pending':
        conn.close()
        return jsonify({'error': 'Approve the registration before adding the user'}), 400
    c.execute("SELECT name FROM management_groups WHERE id = ?", (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    # Idempotent: adding an existing member is a no-op, not an error.
    c.execute('''
        INSERT INTO mgmt_group_members (group_id, user_id, created) VALUES (?, ?, ?)
        ON CONFLICT(group_id, user_id) DO NOTHING
    ''', (group_id, urow[0], datetime.now().isoformat()))
    inserted = c.rowcount
    conn.commit()
    conn.close()
    if inserted:
        audit(
            'mgmt_group.member.add',
            target_type='mgmt_group',
            target_id=group_id,
            target_label=group[0],
            user_id=urow[0],
            user_label=urow[3],
        )
    return jsonify({'success': True, 'group_id': group_id, 'user_id': urow[0], 'username': urow[3]})


# Removing a member revokes that source of control only — co-controllers via direct
# grants or other management groups are untouched, and the user falls back to
# nobody-land only when no source of control remains (no extra bookkeeping needed:
# nobody-land is derived, not stored).
@app.route('/admin/mgmt-groups/<int:group_id>/members/<user_id>', methods=['DELETE'])
@require_admin
def admin_remove_mgmt_group_member(group_id, user_id):
    denied = _mgmt_super_only()
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT gr.name, u.username
        FROM mgmt_group_members mm
        JOIN management_groups gr ON gr.id = mm.group_id
        JOIN users u ON u.user_id = mm.user_id
        WHERE mm.group_id = ? AND mm.user_id = ?
    ''', (group_id, user_id))
    labels = c.fetchone()
    if not labels:
        conn.close()
        return jsonify({'error': 'Membership not found'}), 404
    c.execute("DELETE FROM mgmt_group_members WHERE group_id = ? AND user_id = ?", (group_id, user_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Membership not found'}), 404
    audit(
        'mgmt_group.member.remove',
        target_type='mgmt_group',
        target_id=group_id,
        target_label=labels[0],
        user_id=user_id,
        user_label=labels[1],
    )
    return jsonify({'success': True})


# Delegation of manage_mgmt_group() — superadmin-only like all delegation, ADDITIVE
# and idempotent like the /controllers and /owners routes. The recipient must be an
# approved regular admin: superadmins need no grant (recording one would be noise) and
# a manager grant is exactly what makes membership produce controls().
@app.route('/admin/mgmt-groups/<int:group_id>/managers', methods=['PUT'])
@require_admin
def admin_add_mgmt_group_manager(group_id):
    denied = _mgmt_super_only()
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get('admin_id'):
        return jsonify({'error': 'admin_id is required'}), 400
    admin_id = data['admin_id']

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM management_groups WHERE id = ?", (group_id,))
    group = c.fetchone()
    if not group:
        conn.close()
        return jsonify({'error': 'Group not found'}), 404
    c.execute("SELECT role, status, username FROM users WHERE user_id = ?", (admin_id,))
    arow = c.fetchone()
    if not arow or arow[0] != 'admin' or arow[1] != 'approved':
        conn.close()
        return jsonify({'error': 'The manager must be an approved admin'}), 400
    c.execute('''
        INSERT INTO mgmt_group_managers (group_id, admin_id, created) VALUES (?, ?, ?)
        ON CONFLICT(group_id, admin_id) DO NOTHING
    ''', (group_id, admin_id, datetime.now().isoformat()))
    inserted = c.rowcount
    conn.commit()
    conn.close()
    if inserted:
        audit(
            'mgmt_group.manager.add',
            target_type='mgmt_group',
            target_id=group_id,
            target_label=group[0],
            admin_id=admin_id,
            admin_label=arow[2],
        )
    return jsonify({'success': True, 'group_id': group_id, 'admin_id': admin_id})


# Revocation of manage_mgmt_group() — targeted at one named admin's grant; the whole
# group's members drop out of that admin's effective controls() in one action while
# other managers and all direct grants stay untouched.
@app.route('/admin/mgmt-groups/<int:group_id>/managers/<admin_id>', methods=['DELETE'])
@require_admin
def admin_remove_mgmt_group_manager(group_id, admin_id):
    denied = _mgmt_super_only()
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT gr.name, a.username
        FROM mgmt_group_managers mg
        JOIN management_groups gr ON gr.id = mg.group_id
        JOIN users a ON a.user_id = mg.admin_id
        WHERE mg.group_id = ? AND mg.admin_id = ?
    ''', (group_id, admin_id))
    labels = c.fetchone()
    if not labels:
        conn.close()
        return jsonify({'error': 'Delegation not found'}), 404
    c.execute("DELETE FROM mgmt_group_managers WHERE group_id = ? AND admin_id = ?", (group_id, admin_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Delegation not found'}), 404
    audit(
        'mgmt_group.manager.remove',
        target_type='mgmt_group',
        target_id=group_id,
        target_label=labels[0],
        admin_id=admin_id,
        admin_label=labels[1],
    )
    return jsonify({'success': True, 'group_id': group_id, 'admin_id': admin_id})


@app.route('/auth/refresh', methods=['POST'])
def auth_refresh():
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, AUTH_BUCKET, AUTH_REFILL_INTERVAL)

    cookie = request.cookies.get('refresh_token')
    if not cookie:
        return jsonify({'error': 'Unauthorized'}), 401
    token_hash = hashlib.sha256(cookie.encode()).hexdigest()

    # S-03/S-05: the whole rotation — sweep, lookup, consume, successor insert — runs
    # in ONE immediate transaction, so two presenters of the same token serialize and
    # at most one can ever mint a successor.
    conn = get_db()
    c = conn.cursor()
    c.execute("BEGIN IMMEDIATE")
    c.execute("DELETE FROM refresh_tokens WHERE expires < ?", (now_ts,))
    c.execute("SELECT id, user_id, family_id, status FROM refresh_tokens WHERE token = ?",
              (token_hash,))
    row = c.fetchone()
    if not row:
        conn.commit()
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 401
    token_row_id, user_id, family_id, status = row

    if status == 'active':
        c.execute("UPDATE refresh_tokens SET status = 'consumed', consumed_at = ? "
                  "WHERE id = ? AND status = 'active'", (now_ts, token_row_id))
        if c.rowcount != 1:
            status = 'consumed'  # lost a concurrent race: strict semantics, same as replay

    if status == 'consumed':
        # Replay: a consumed token was presented again. No reuse grace — revoke the
        # entire family (including its live head, which kills the family's outstanding
        # access JWTs at the identity gate) and clear the presented cookie. The
        # accepted false positive is one forced re-login after a lost refresh response.
        c.execute("SELECT username, role FROM users WHERE user_id = ?", (user_id,))
        urow = c.fetchone()
        c.execute("DELETE FROM refresh_tokens WHERE family_id = ?", (family_id,))
        conn.commit()
        conn.close()
        audit(
            'auth.refresh_replay',
            actor_id=user_id,
            actor_username=urow[0] if urow else None,
            actor_role=urow[1] if urow else None,
            client_ip=client_ip,
            family_id=family_id,
        )
        response = make_response(jsonify({'error': 'Unauthorized'}), 401)
        response.set_cookie('refresh_token', '', max_age=0, path='/auth',
                            httponly=True, secure=COOKIE_SECURE, samesite='Strict')
        return response

    c.execute("SELECT username, role, status, first_name, last_name, avatar, auth_version, "
              "email_verified_at "
              "FROM users WHERE user_id = ?", (user_id,))
    urow = c.fetchone()

    # A disabled/removed account must not be able to refresh into a fresh access token.
    if (not urow or urow[2] != 'approved'
            or (REQUIRE_EMAIL_VERIFICATION and urow[7] is None)):
        c.execute("DELETE FROM refresh_tokens WHERE family_id = ?", (family_id,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 401

    # Rotate: the consumed predecessor row stays for replay detection; exactly one
    # active successor continues the family.
    new_refresh = secrets.token_urlsafe(32)
    new_hash = hashlib.sha256(new_refresh.encode()).hexdigest()
    new_expires = now_ts + REFRESH_TOKEN_DURATION
    c.execute("INSERT INTO refresh_tokens "
              "(user_id, family_id, token, status, expires, created, predecessor_id) "
              "VALUES (?, ?, ?, 'active', ?, ?, ?)",
              (user_id, family_id, new_hash, new_expires, now_ts, token_row_id))
    conn.commit()
    conn.close()
    username, role = urow[0], urow[1]
    first_name, last_name = urow[3] or '', urow[4] or ''
    avatar_url = _avatar_url(urow[5], user_id)

    now = datetime.utcnow()
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'fam': family_id,
        'ver': urow[6],
        'iat': int(now.timestamp()),
        'jti': str(uuid.uuid4()),
        'exp': now + timedelta(seconds=ACCESS_TOKEN_DURATION)
    }
    if BIND_TOKEN_TO_IP:
        payload['ip'] = client_ip
    access_token = jwt.encode(payload, ACCESS_TOKEN_SECRET, algorithm='HS256')

    response = make_response(jsonify({
        'access_token': access_token,
        'access_expires_in': ACCESS_TOKEN_DURATION,
        'role': role,
        'username': username,
        'first_name': first_name,
        'last_name': last_name,
        'avatar_url': avatar_url
    }))
    response.set_cookie('refresh_token', new_refresh, max_age=REFRESH_TOKEN_DURATION,
                        path='/auth', httponly=True, secure=COOKIE_SECURE, samesite='Strict')
    return response


@app.route('/auth/logout', methods=['POST'])
def auth_logout():
    # Logout is authorized by possession of the refresh cookie, not a live access JWT.
    # This lets an expired access token end its current refresh session.
    cookie = request.cookies.get('refresh_token')
    actor = None
    if cookie:
        token_hash = hashlib.sha256(cookie.encode()).hexdigest()
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "SELECT rt.user_id, rt.family_id, u.username, u.role "
            "FROM refresh_tokens rt "
            "LEFT JOIN users u ON u.user_id = rt.user_id "
            "WHERE rt.token = ?",
            (token_hash,),
        )
        actor = c.fetchone()
        # Logout ends this browser's whole session family — its lineage rows and its
        # outstanding access JWTs (via the require_auth family check) die together,
        # while other devices' families stay logged in. Any family member token,
        # active or consumed, identifies the family.
        if actor:
            c.execute("DELETE FROM refresh_tokens WHERE family_id = ?", (actor[1],))
        conn.commit()
        conn.close()
    if actor:
        audit(
            'auth.logout',
            actor_id=actor[0],
            actor_username=actor[2],
            actor_role=actor[3],
            client_ip=get_client_ip(),
        )

    response = make_response(jsonify({'success': True, 'message': 'Logged out'}))
    response.set_cookie('refresh_token', '', max_age=0, path='/auth',
                        httponly=True, secure=COOKIE_SECURE, samesite='Strict')
    return response


@app.route('/changepwd', methods=['POST'])
@require_auth
def change_password():
    data = request.get_json(silent=True)
    if (not isinstance(data, dict)
            or not all(isinstance(data.get(k), str)
                       for k in ('old_password', 'new_password', 'repeat_password'))):
        return jsonify({'error': 'Invalid request'}), 400

    old_password = data['old_password']
    new_password = data['new_password']
    repeat_password = data['repeat_password']

    # Validate BEFORE writing anything to the database.
    if new_password != repeat_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    ok, reason = validate_password_policy(new_password)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE user_id = ?", (g.user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Over-byte-limit input can never be a stored policy-valid password, and bcrypt
    # would raise on it — reject it as an ordinary mismatch.
    if (len(old_password.encode()) > PASSWORD_MAX_BYTES
            or not bcrypt.checkpw(old_password.encode(), row[0])):
        conn.close()
        return jsonify({'error': 'Old password is incorrect'}), 400

    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    c.execute("UPDATE users SET password_hash = ?, auth_version = auth_version + 1 "
              "WHERE user_id = ?", (new_hash, g.user_id))
    # Force re-login everywhere after a password change: families are revoked and the
    # auth_version bump invalidates outstanding access JWTs immediately.
    c.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (g.user_id,))
    c.execute(
        "DELETE FROM account_tokens WHERE user_id = ? AND purpose='password_reset'",
        (g.user_id,),
    )
    conn.commit()
    conn.close()
    audit('account.changepwd')

    return jsonify({'success': True, 'message': 'Password changed successfully'})


# =====================
# User profile (self-service: view/edit own profile fields)
# =====================
# username, role and password are NOT editable here (username/role are identity/authz,
# password has its own /changepwd flow). Only the descriptive profile fields change.

def _profile_json(row, user_id, pending_email=None):
    # row: username, role, first_name, last_name, email, company, department,
    #      birth_date, sex, avatar, email_verified_at
    payload = {
        'username': row[0], 'role': row[1],
        'first_name': row[2] or '', 'last_name': row[3] or '', 'email': row[4] or '',
        'company': row[5] or '', 'department': row[6] or '',
        'birth_date': row[7] or '', 'sex': row[8] or '',
        'avatar_url': _avatar_url(row[9], user_id),
    }
    if REQUIRE_EMAIL_VERIFICATION:
        payload['email_verified'] = row[10] is not None
        payload['pending_email'] = pending_email
    return payload


@app.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username, role, first_name, last_name, email, company, department, birth_date, sex, avatar, "
              "email_verified_at "
              "FROM users WHERE user_id = ?", (g.user_id,))
    row = c.fetchone()
    pending = None
    if REQUIRE_EMAIL_VERIFICATION:
        pending_row = c.execute(
            "SELECT target_email FROM account_tokens "
            "WHERE user_id=? AND purpose='email_verification' "
            "AND expires>=?",
            (g.user_id, int(time.time())),
        ).fetchone()
        pending = pending_row[0] if pending_row else None
    conn.close()
    if not row:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(_profile_json(row, g.user_id, pending))


@app.route('/profile', methods=['PUT'])
@require_auth
def update_profile():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400

    ok, reason, profile = validate_profile_fields(data)
    if not ok:
        return jsonify({'error': reason}), 400

    conn = get_db()
    c = conn.cursor()
    now_ts = int(time.time())
    _purge_expired_account_tokens(c, now_ts)
    current = c.execute(
        "SELECT email FROM users WHERE user_id=?",
        (g.user_id,),
    ).fetchone()
    if not current:
        conn.commit()
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    if email_taken(c, profile['email'], exclude_user_id=g.user_id):
        conn.commit()
        conn.close()
        return jsonify({'error': 'Email already registered'}), 400
    current_email = current[0] or ''
    email_changed = current_email.casefold() != profile['email'].casefold()
    stored_email = profile['email']
    verified_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    if REQUIRE_EMAIL_VERIFICATION and email_changed:
        stored_email = current_email
        verified_at = None
    c.execute(
        "UPDATE users SET first_name=?, last_name=?, email=?, company=?, "
        "department=?, birth_date=?, sex=?, "
        "email_verified_at=COALESCE(?, email_verified_at) WHERE user_id = ?",
        (
            profile['first_name'],
            profile['last_name'],
            stored_email,
            profile['company'],
            profile['department'],
            profile['birth_date'],
            profile['sex'],
            verified_at,
            g.user_id,
        ),
    )
    changed = c.rowcount
    if not REQUIRE_EMAIL_VERIFICATION:
        c.execute(
            "DELETE FROM account_tokens WHERE user_id=? "
            "AND purpose='email_verification'",
            (g.user_id,),
        )
    conn.commit()
    if changed == 0:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    conn.close()

    email_outcome = None
    pending_email = None
    if REQUIRE_EMAIL_VERIFICATION and email_changed:
        display_name = ' '.join((
            profile['first_name'],
            profile['last_name'],
        )).strip()
        email_outcome = _send_verification_email(
            g.user_id,
            display_name,
            profile['email'],
            now_ts,
        )
        if email_outcome == 'conflict':
            return jsonify({'error': 'Email already registered'}), 400
        pending_email = profile['email']

    conn = get_db()
    row = conn.execute(
        "SELECT username, role, first_name, last_name, email, company, department, "
        "birth_date, sex, avatar, email_verified_at FROM users WHERE user_id = ?",
        (g.user_id,),
    ).fetchone()
    if REQUIRE_EMAIL_VERIFICATION and pending_email is None:
        pending_row = conn.execute(
            "SELECT target_email FROM account_tokens "
            "WHERE user_id=? AND purpose='email_verification' AND expires>=?",
            (g.user_id, now_ts),
        ).fetchone()
        pending_email = pending_row[0] if pending_row else None
    conn.close()
    payload = _profile_json(row, g.user_id, pending_email)
    if pending_email:
        payload['email_sent'] = email_outcome == 'sent'
        payload['message'] = (
            'Profile saved. Verify the new email address before it replaces your '
            'current address.'
        )
        if email_outcome == 'failed':
            payload['message'] = (
                'Profile saved, but the verification email could not be sent. '
                'Use Resend verification to try again.'
            )
    return jsonify(payload)


AVATAR_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif'}


@app.route('/profile/avatar', methods=['POST'])
@require_auth
def upload_profile_avatar():
    if 'avatar' not in request.files:
        return jsonify({'error': 'No avatar file provided'}), 400

    upload = request.files['avatar']
    if not upload.filename:
        return jsonify({'error': 'No selected file'}), 400
    if os.path.splitext(upload.filename)[1].lower() not in AVATAR_EXTENSIONS:
        return jsonify({'error': 'Accepted image file types: jpg, jpeg, png, gif'}), 400

    # Shared decode-safety gate (S-10), then the square avatar crop
    image, image_error = open_validated_image(BytesIO(upload.read()))
    if image_error:
        return jsonify({'error': image_error}), 400
    image = ImageOps.fit(image, (256, 256), method=Image.Resampling.LANCZOS)

    filename = f"{g.user_id}.jpg"
    os.makedirs(AVATARS_FOLDER, exist_ok=True)
    destination = os.path.join(AVATARS_FOLDER, filename)
    temporary = os.path.join(AVATARS_FOLDER, f".{g.user_id}.{uuid.uuid4().hex}.tmp")
    try:
        image.save(temporary, format='JPEG', quality=85, optimize=True)
        os.replace(temporary, destination)
    except OSError:
        if os.path.exists(temporary):
            os.remove(temporary)
        return internal_error('avatar.save', 'Could not save avatar')

    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET avatar = ? WHERE user_id = ?", (filename, g.user_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        if os.path.exists(destination):
            os.remove(destination)
        return jsonify({'error': 'User not found'}), 404

    # Self-service profile content is deliberately outside the audit event boundary.
    return jsonify({'success': True, 'avatar_url': _avatar_url(filename, g.user_id)})


@app.route('/profile/avatar', methods=['DELETE'])
@require_auth
def delete_profile_avatar():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT avatar FROM users WHERE user_id = ?", (g.user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    c.execute("UPDATE users SET avatar = NULL WHERE user_id = ?", (g.user_id,))
    conn.commit()
    conn.close()

    filename = row[0] or f"{g.user_id}.jpg"
    avatar_path = os.path.join(AVATARS_FOLDER, os.path.basename(filename))
    try:
        if os.path.exists(avatar_path):
            os.remove(avatar_path)
    except OSError:
        LOGGER.warning("avatar.delete: could not remove %s", clean_log_value(avatar_path))

    # Self-service profile content is deliberately outside the audit event boundary.
    return jsonify({'success': True})


# Self-service account deletion: wipes the caller and everything they own (maps/spots/photos
# cascade via FK). Requires the user to re-type their username as confirmation. The last
# remaining admin cannot self-delete (would leave the system with no user manager).
@app.route('/account', methods=['DELETE'])
@require_auth
def delete_own_account():
    data = request.get_json(silent=True)
    ok, _, confirm = text_value(data.get('confirm_username') if isinstance(data, dict) else None,
                                'confirm_username', PROFILE_FIELD_MAX)
    if not ok:
        return jsonify({'error': 'Invalid request'}), 400
    confirm = confirm or ''

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username, role, avatar FROM users WHERE user_id = ?", (g.user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    username, role, avatar_filename = row

    # Confirmation must match the caller's own username (case-insensitive).
    if confirm.lower() != (username or '').lower():
        conn.close()
        return jsonify({'error': 'Username confirmation does not match'}), 400

    if role in ADMIN_ROLES:
        c.execute("SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND status='approved'", ())
        if c.fetchone()[0] <= 1:
            conn.close()
            return jsonify({'error': 'The last remaining admin cannot delete their own account'}), 400

    # Collect the caller's owned photo files to remove from disk before the cascade.
    c.execute('''
        SELECT p.filename FROM photos p
        JOIN spots s ON s.id = p.spot_id
        JOIN maps m ON m.id = s.map_id
        WHERE m.owner_id = ?
    ''', (g.user_id,))
    filenames = [r[0] for r in c.fetchall()]

    c.execute("DELETE FROM users WHERE user_id = ?", (g.user_id,))
    conn.commit()
    conn.close()
    audit('account.delete')

    # Best-effort cleanup after the committed account deletion (R-02): a filesystem
    # failure must not turn the irreversible DB success into an error response.
    for filename in filenames:
        for folder in (PHOTOS_FOLDER, THUMBS_FOLDER):
            fpath = os.path.join(folder, filename)
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
            except OSError:
                LOGGER.warning("account.delete: could not remove %s", clean_log_value(fpath))

    avatar_filename = avatar_filename or f"{g.user_id}.jpg"
    avatar_path = os.path.join(AVATARS_FOLDER, os.path.basename(avatar_filename))
    try:
        if os.path.exists(avatar_path):
            os.remove(avatar_path)
    except OSError:
        LOGGER.warning("account.delete: could not remove %s", clean_log_value(avatar_path))

    response = make_response(jsonify({'success': True, 'message': 'Account deleted'}))
    # Clear the refresh cookie so the (now-deleted) session can't refresh.
    response.set_cookie('refresh_token', '', max_age=0, path='/auth',
                        httponly=True, secure=COOKIE_SECURE, samesite='Strict')
    return response


# =====================
# Routes
# =====================

# Get all maps
@app.route('/maps', methods=['GET'])
@require_auth
def get_maps():
    conn = get_db()
    c = conn.cursor()

    # Own maps ∪ maps shared with the caller (directly or via a group) — nobody (admins
    # included) sees anything else, and Base Maps are owner-only (excluded from the shared
    # half like everywhere else). Each row carries the caller's direct share role plus the
    # best group-share role (both NULL if absent; the group role is a correlated scalar
    # subquery so a user in several sharing groups doesn't multiply the spot COUNT), and
    # the owner's identity (username + name) so non-owned maps can show who created them.
    c.execute('''
        SELECT m.id, m.name, m.created, m.description, m.notes, COUNT(s.id) as markers,
               m.is_base, m.owner_id, ms.role,
               (SELECT MAX(CASE mgs.role WHEN 'editor' THEN 2 ELSE 1 END)
                  FROM map_group_shares mgs
                  JOIN share_group_members gm ON gm.group_id = mgs.group_id
                 WHERE mgs.map_id = m.id AND gm.user_id = ?) AS group_role,
               u.username, u.first_name, u.last_name,
               (EXISTS (SELECT 1 FROM map_shares s2 WHERE s2.map_id = m.id)
                OR EXISTS (SELECT 1 FROM map_group_shares g3 WHERE g3.map_id = m.id)) AS shared
        FROM maps m
        LEFT JOIN spots s ON m.id = s.map_id
        LEFT JOIN map_shares ms ON ms.map_id = m.id AND ms.user_id = ?
        LEFT JOIN users u ON u.user_id = m.owner_id
        WHERE m.owner_id = ?
           OR ((ms.user_id = ? OR EXISTS (
                    SELECT 1 FROM map_group_shares mgs2
                    JOIN share_group_members gm2 ON gm2.group_id = mgs2.group_id
                    WHERE mgs2.map_id = m.id AND gm2.user_id = ?
               )) AND m.is_base = 0)
        GROUP BY m.id
    ''', (g.user_id, g.user_id, g.user_id, g.user_id, g.user_id))

    rows = c.fetchall()
    conn.close()

    def role_for(owner_id, share_role, group_role):
        if owner_id == g.user_id:
            return 'owner'
        if share_role == 'editor' or group_role == 2:
            return 'editor'
        if share_role or group_role:
            return 'viewer'
        return None

    # Owner display label: "First Last" if set, else the username.
    def owner_label(username, first, last):
        full = ' '.join(p for p in (first, last) if p).strip()
        return full or username or ''

    return jsonify([
        {
            'id': r[0],
            'name': r[1],
            'created': r[2],
            'description': r[3],
            'notes': r[4],
            'markers': r[5],
            'is_base': bool(r[6]),
            'owned': r[7] == g.user_id,
            'role': role_for(r[7], r[8], r[9]),
            'owner_username': r[10] or '',
            'owner_name': owner_label(r[10], r[11], r[12]),
            'shared': bool(r[13])
        } for r in rows
    ])


# Add map
@app.route('/maps', methods=['POST'])
@require_auth
def add_map():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    cleaned = {}
    for label, key, limit, required in (
            ('Map name', 'name', NAME_MAX, True),
            ('Created', 'created', CREATED_MAX, False),
            ('Description', 'description', DESCRIPTION_MAX, False),
            ('Notes', 'notes', NOTES_MAX, False)):
        ok, reason, value = text_value(data.get(key), label, limit, required=required)
        if not ok:
            return jsonify({'error': reason}), 400
        cleaned[key] = value
    name = cleaned['name']
    created = cleaned['created'] or datetime.now().isoformat()
    description = cleaned['description']
    notes = cleaned['notes']

    conn = get_db()
    c = conn.cursor()

    # Name uniqueness is per-owner: check only against this user's own maps.
    c.execute('SELECT id FROM maps WHERE owner_id=? AND name=?', (g.user_id, name))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'A map with this name already exists'}), 400

    c.execute(
        'INSERT INTO maps (owner_id, name, is_base, created, description, notes) VALUES (?, ?, 0, ?, ?, ?)',
        (g.user_id, name, created, description, notes)
    )
    conn.commit()
    map_id = c.lastrowid
    conn.close()

    return jsonify({
        'id': map_id,
        'name': name,
        'created': created,
        'description': description,
        'notes': notes,
        'markers': 0,
        'is_base': False,
        'owned': True,
        'role': 'owner'
    })


# Edit map
@app.route('/maps/<int:map_id>', methods=['PUT'])
@require_auth
def edit_map(map_id):
    # Editing the map entity (name/description/notes) is owner-or-editor — a viewer
    # may not, and deletion/re-sharing stay owner-only.
    allowed, _, is_base = user_can_access_map(map_id, g.user_id, need_edit=True)
    if not allowed:
        return jsonify({'error': 'Map not found'}), 404
    # A Base Map is never editable.
    if is_base:
        return jsonify({'error': 'Base Map cannot be edited'}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    # Absent name means unchanged; a present one must clear the same bar as POST.
    cleaned = {}
    for label, key, limit, required in (
            ('Map name', 'name', NAME_MAX, 'name' in data),
            ('Created', 'created', CREATED_MAX, False),
            ('Description', 'description', DESCRIPTION_MAX, False),
            ('Notes', 'notes', NOTES_MAX, False)):
        ok, reason, value = text_value(data.get(key), label, limit, required=required)
        if not ok:
            return jsonify({'error': reason}), 400
        cleaned[key] = value
    name = cleaned['name']
    created = cleaned['created']
    description = cleaned['description']
    notes = cleaned['notes'] if 'notes' in data else None

    conn = get_db()
    c = conn.cursor()

    # Prevent duplicate name within the map's owner (not globally).
    if name is not None:
        c.execute('SELECT owner_id FROM maps WHERE id=?', (map_id,))
        orow = c.fetchone()
        map_owner = orow[0] if orow else g.user_id
        c.execute('SELECT id FROM maps WHERE owner_id=? AND name=? AND id<>?', (map_owner, name, map_id))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'A map with this name already exists'}), 400

    fields = []
    values = []

    if name is not None:
        fields.append("name=?")
        values.append(name)
    if created is not None:
        fields.append("created=?")
        values.append(created)
    if description is not None:
        fields.append("description=?")
        values.append(description)
    if notes is not None:
        fields.append("notes=?")
        values.append(notes)

    if not fields:
        return jsonify({'error': 'No fields to update'}), 400

    values.append(map_id)
    c.execute(f"UPDATE maps SET {', '.join(fields)} WHERE id=?", values)
    updated = c.rowcount
    conn.commit()

    if updated == 0:
        conn.close()
        return jsonify({'error': 'Map not found'}), 404

    # Fetch updated map along with marker count
    c.execute('''
        SELECT m.id, m.name, m.created, m.description, m.notes, COUNT(s.id) as markers
        FROM maps m
        LEFT JOIN spots s ON m.id = s.map_id
        WHERE m.id=?
        GROUP BY m.id
    ''', (map_id,))
    row = c.fetchone()
    conn.close()

    updated_map = {
        'id': row[0],
        'name': row[1],
        'created': row[2],
        'description': row[3],
        'notes': row[4],
        'markers': row[5]
    }

    return jsonify(updated_map)



# Delete a map by ID
@app.route('/maps/<int:map_id>', methods=['DELETE'])
@require_auth
def delete_map(map_id):
    # Deleting a map is owner-only (an editor/viewer may not delete a shared map).
    if not is_map_owner(map_id, g.user_id):
        return jsonify({'error': 'Map not found'}), 404
    _, _, is_base = user_can_access_map(map_id, g.user_id, need_edit=True)
    # A Base Map is never deletable (by anyone) — the invariant is that every user keeps one.
    if is_base:
        return jsonify({'error': 'Base Map cannot be deleted'}), 400

    conn = get_db()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT m.name, COUNT(DISTINCT s.id), COUNT(p.id)
            FROM maps m
            LEFT JOIN spots s ON s.map_id = m.id
            LEFT JOIN photos p ON p.spot_id = s.id
            WHERE m.id = ?
            GROUP BY m.id, m.name
        ''', (map_id,))
        map_row = c.fetchone()
        if not map_row:
            conn.close()
            return jsonify({'error': 'Map not found'}), 404
        map_name, marker_count, photo_count = map_row

        # R-02: the DB cascade removes photo rows, so their files must be collected
        # first and cleaned up after the commit (previously they leaked forever).
        c.execute('''
            SELECT p.filename FROM photos p
            JOIN spots s ON s.id = p.spot_id
            WHERE s.map_id = ?
        ''', (map_id,))
        filenames = [r[0] for r in c.fetchall()]
        c.execute("DELETE FROM maps WHERE id = ?", (map_id,))
        deleted = c.rowcount
        conn.commit()
    except sqlite3.Error:
        conn.close()
        return internal_error('map.delete', 'Could not delete the map')
    conn.close()
    if deleted == 0:
        return jsonify({'error': 'Map not found'}), 404

    notify(
        g.user_id,
        'map.deleted',
        f'Map “{map_name}” deleted.',
        target_type='map',
        target_id=map_id,
        target_label=map_name,
        detail={'markers': marker_count, 'photos': photo_count},
    )

    for filename in filenames:
        for folder in (PHOTOS_FOLDER, THUMBS_FOLDER):
            path = os.path.join(folder, filename)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                LOGGER.warning("map.delete: could not remove %s", clean_log_value(path))

    return jsonify({'success': True, 'deleted_map_id': map_id})


# =====================
# Map sharing (the owner manages who a map is shared with, as viewer/editor; the
# /admin/maps/... routes reuse the same helpers under admin governance)
# =====================

# Typed collaborator rows (users + groups) for a map. Callers authorize first.
def _map_shares_json(map_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT u.user_id, u.username, ms.role, u.first_name, u.last_name, u.avatar
        FROM map_shares ms
        JOIN users u ON u.user_id = ms.user_id
        WHERE ms.map_id = ?
        ORDER BY u.username COLLATE NOCASE
    ''', (map_id,))
    user_rows = c.fetchall()
    c.execute('''
        SELECT gr.id, gr.name, mgs.role
        FROM map_group_shares mgs
        JOIN share_groups gr ON gr.id = mgs.group_id
        WHERE mgs.map_id = ?
        ORDER BY gr.name COLLATE NOCASE
    ''', (map_id,))
    group_rows = c.fetchall()
    conn.close()
    return jsonify(
        [{'type': 'user', 'user_id': r[0], 'username': r[1], 'role': r[2],
          'first_name': r[3] or '', 'last_name': r[4] or '',
          'avatar_url': _avatar_url(r[5], r[0])} for r in user_rows]
        + [{'type': 'group', 'group_id': r[0], 'name': r[1], 'role': r[2]} for r in group_rows]
    )


# Shared by the owner and admin share routes once the caller is authorized: validates
# {username XOR group, role}, resolves the target and upserts the share. forbid_user_id
# blocks a specific target account — the admin routes pass the caller, so an
# administrator cannot quietly grant themselves access to someone's map (directly or
# via a group they belong to); content access for admins stays loud (password reset).
def _apply_map_share(map_id, data, forbid_user_id=None):
    if not isinstance(data, dict):
        return (jsonify({'error': 'Invalid request'}), 400), None
    ok_user, _, username = text_value(data.get('username'), 'username', PROFILE_FIELD_MAX)
    ok_group, _, group_name = text_value(data.get('group'), 'group', NAME_MAX)
    if not ok_user or not ok_group:
        return (jsonify({'error': 'Invalid request'}), 400), None
    username = username or ''
    group_name = group_name or ''
    role = data.get('role')
    # The target is either a user (username) or a group (group), never both.
    if (not username and not group_name) or (username and group_name) or role not in ('viewer', 'editor'):
        return (
            jsonify({'error': "username or group, and role ('viewer'/'editor'), are required"}),
            400,
        ), None

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT owner_id, is_base, name FROM maps WHERE id = ?", (map_id,))
    owner_id, is_base, map_name = c.fetchone()

    # Base Maps are per-user scaffolding, never shareable.
    if is_base:
        conn.close()
        return (jsonify({'error': 'Base Map cannot be shared'}), 400), None

    if group_name:
        c.execute("SELECT id, name FROM share_groups WHERE name = ? COLLATE NOCASE", (group_name,))
        grow = c.fetchone()
        if not grow:
            conn.close()
            return (jsonify({'error': 'Group not found'}), 404), None
        if forbid_user_id:
            c.execute("SELECT 1 FROM share_group_members WHERE group_id = ? AND user_id = ?", (grow[0], forbid_user_id))
            if c.fetchone():
                conn.close()
                return (jsonify({'error': 'Administrators cannot grant themselves access'}), 403), None
        c.execute(
            "SELECT role FROM map_group_shares WHERE map_id = ? AND group_id = ?",
            (map_id, grow[0]),
        )
        previous = c.fetchone()
        old_role = previous[0] if previous else None
        operation = 'created' if previous is None else ('role_changed' if old_role != role else None)
        if operation is None:
            conn.close()
            return jsonify({'success': True, 'group_id': grow[0], 'group': grow[1], 'role': role}), None
        # Upsert the group share (UNIQUE(map_id,group_id)); role change is an update.
        c.execute('''
            INSERT INTO map_group_shares (map_id, group_id, role, created) VALUES (?, ?, ?, ?)
            ON CONFLICT(map_id, group_id) DO UPDATE SET role = excluded.role
        ''', (map_id, grow[0], role, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'group_id': grow[0], 'group': grow[1], 'role': role}), {
            'map_label': map_name,
            'group': grow[0],
            'group_label': grow[1],
            'operation': operation,
            'old_role': old_role,
            'new_role': role,
        }

    # Resolve target user (must be an approved account).
    c.execute(
        "SELECT user_id, username FROM users "
        "WHERE username = ? COLLATE NOCASE AND status = 'approved'",
        (username,),
    )
    urow = c.fetchone()
    if not urow:
        conn.close()
        return (jsonify({'error': 'User not found'}), 404), None
    target_id = urow[0]

    # Can't share a map with its own owner.
    if target_id == owner_id:
        conn.close()
        return (jsonify({'error': 'The owner already has full access'}), 400), None

    if forbid_user_id and target_id == forbid_user_id:
        conn.close()
        return (jsonify({'error': 'Administrators cannot grant themselves access'}), 403), None

    c.execute(
        "SELECT role FROM map_shares WHERE map_id = ? AND user_id = ?",
        (map_id, target_id),
    )
    previous = c.fetchone()
    old_role = previous[0] if previous else None
    operation = 'created' if previous is None else ('role_changed' if old_role != role else None)
    if operation is None:
        conn.close()
        return jsonify({'success': True, 'user_id': target_id, 'username': urow[1], 'role': role}), None

    # Upsert the share (UNIQUE(map_id,user_id)); role change is an update.
    c.execute('''
        INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?, ?, ?, ?)
        ON CONFLICT(map_id, user_id) DO UPDATE SET role = excluded.role
    ''', (map_id, target_id, role, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'user_id': target_id, 'username': urow[1], 'role': role}), {
        'map_label': map_name,
        'recipient': target_id,
        'recipient_label': urow[1],
        'operation': operation,
        'old_role': old_role,
        'new_role': role,
    }


def _remove_user_share(map_id, user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM map_shares WHERE map_id = ? AND user_id = ?", (map_id, user_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Share not found'}), 404
    return jsonify({'success': True})


def _remove_group_share(map_id, group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM map_group_shares WHERE map_id = ? AND group_id = ?", (map_id, group_id))
    changed = c.rowcount
    conn.commit()
    conn.close()
    if changed == 0:
        return jsonify({'error': 'Share not found'}), 404
    return jsonify({'success': True})


@app.route('/maps/<int:map_id>/collaborators', methods=['GET'])
@require_auth
def get_map_shares(map_id):
    if not is_map_owner(map_id, g.user_id):
        return jsonify({'error': 'Map not found'}), 404
    return _map_shares_json(map_id)


@app.route('/maps/<int:map_id>/collaborators', methods=['PUT'])
@require_auth
def set_map_share(map_id):
    if not is_map_owner(map_id, g.user_id):
        return jsonify({'error': 'Map not found'}), 404
    response, _ = _apply_map_share(map_id, request.get_json(silent=True))
    return response


@app.route('/maps/<int:map_id>/collaborators/<user_id>', methods=['DELETE'])
@require_auth
def delete_map_share(map_id, user_id):
    if not is_map_owner(map_id, g.user_id):
        return jsonify({'error': 'Map not found'}), 404
    return _remove_user_share(map_id, user_id)


# Remove a group share. The extra /group/ path segment keeps this rule unambiguous from
# the user route above (a group id could otherwise be mistaken for a user_id).
@app.route('/maps/<int:map_id>/collaborators/group/<int:group_id>', methods=['DELETE'])
@require_auth
def delete_map_group_share(map_id, group_id):
    if not is_map_owner(map_id, g.user_id):
        return jsonify({'error': 'Map not found'}), 404
    return _remove_group_share(map_id, group_id)


# Bulk share: grant one user OR one group the same role on several maps at once (maps
# 3-dot menu). All-or-nothing — every map must exist and be owned by the caller before
# anything is written. Upsert per map, same semantics as the single-map PUT above.
@app.route('/maps/collaborators', methods=['PUT'])
@require_auth
def set_map_shares_bulk():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    ok, reason, map_ids = id_list(data.get('map_ids'), 'map_ids')
    if not ok:
        return jsonify({'error': reason}), 400
    ok_user, _, username = text_value(data.get('username'), 'username', PROFILE_FIELD_MAX)
    ok_group, _, group_name = text_value(data.get('group'), 'group', NAME_MAX)
    if not ok_user or not ok_group:
        return jsonify({'error': 'Invalid request'}), 400
    username = username or ''
    group_name = group_name or ''
    role = data.get('role')
    if (not username and not group_name) or (username and group_name) or role not in ('viewer', 'editor'):
        return jsonify({'error': "username or group, and role ('viewer'/'editor'), are required"}), 400
    map_ids = list(dict.fromkeys(map_ids))

    conn = get_db()
    c = conn.cursor()

    target_id = None
    group_row = None
    if group_name:
        c.execute("SELECT id, name FROM share_groups WHERE name = ? COLLATE NOCASE", (group_name,))
        group_row = c.fetchone()
        if not group_row:
            conn.close()
            return jsonify({'error': 'Group not found'}), 404
    else:
        # Resolve target user (must be an approved account).
        c.execute("SELECT user_id FROM users WHERE username = ? COLLATE NOCASE AND status = 'approved'", (username,))
        urow = c.fetchone()
        if not urow:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        target_id = urow[0]

        # The caller must own every map, so sharing with themselves is sharing with the owner.
        if target_id == g.user_id:
            conn.close()
            return jsonify({'error': 'The owner already has full access'}), 400

    placeholders = ','.join('?' * len(map_ids))
    c.execute(f"SELECT id, is_base FROM maps WHERE id IN ({placeholders}) AND owner_id = ?", (*map_ids, g.user_id))
    rows = c.fetchall()
    owned = {r[0] for r in rows}
    if any(i not in owned for i in map_ids):
        conn.close()
        return jsonify({'error': 'Map not found'}), 404
    # Base Maps are per-user scaffolding, never shareable (the UI filters them out too).
    if any(r[1] for r in rows):
        conn.close()
        return jsonify({'error': 'Base Map cannot be shared'}), 400

    now = datetime.now().isoformat()
    if group_row:
        for map_id in map_ids:
            c.execute('''
                INSERT INTO map_group_shares (map_id, group_id, role, created) VALUES (?, ?, ?, ?)
                ON CONFLICT(map_id, group_id) DO UPDATE SET role = excluded.role
            ''', (map_id, group_row[0], role, now))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'group_id': group_row[0], 'group': group_row[1], 'role': role, 'shared': len(map_ids)})

    for map_id in map_ids:
        c.execute('''
            INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?, ?, ?, ?)
            ON CONFLICT(map_id, user_id) DO UPDATE SET role = excluded.role
        ''', (map_id, target_id, role, now))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'user_id': target_id, 'username': username, 'role': role, 'shared': len(map_ids)})


# List approved users (for the share picker), excluding the caller.
@app.route('/users', methods=['GET'])
@require_auth
def list_users_for_share():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT user_id, username, first_name, last_name, avatar FROM users WHERE status = 'approved' AND user_id <> ? ORDER BY username COLLATE NOCASE", (g.user_id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        'user_id': r[0],
        'username': r[1],
        'first_name': r[2] or '',
        'last_name': r[3] or '',
        'avatar_url': _avatar_url(r[4], r[0]),
    } for r in rows])


# List share groups (for the share picker). Any authenticated user may see group names
# — owners need them to pick a share target; membership itself stays admin-managed.
# Management groups are NEVER listed here: they are not share targets and their
# existence is superadmin-only knowledge.
@app.route('/groups', methods=['GET'])
@require_auth
def list_share_groups_for_share():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name FROM share_groups ORDER BY name COLLATE NOCASE")
    rows = c.fetchall()
    conn.close()
    return jsonify([{'id': r[0], 'name': r[1]} for r in rows])


# Get all spots of a map
@app.route('/maps/<int:map_id>/spots', methods=['GET'])
@require_auth
def get_spots_for_map(map_id):
    allowed, _, _ = user_can_access_map(map_id, g.user_id)
    if not allowed:
        return jsonify({'error': 'Map not found'}), 404
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT id, map_id, name, lat, lng, listing, subset, notes, created,
               (SELECT COUNT(*) FROM photos p WHERE p.spot_id = spots.id) AS photo_count
        FROM spots
        WHERE map_id = ?
    ''', (map_id,))
    rows = c.fetchall()
    conn.close()

    return jsonify([
        {
            'id': r[0],
            'mapID': r[1],
            'name': r[2],
            'lat': r[3],
            'lng': r[4],
            'listing': r[5],
            'subset': r[6],
            'notes': r[7],
            'created': r[8],
            'photo_count': r[9]
        } for r in rows
    ])


# Get single spot
@app.route('/spots/<int:spot_id>', methods=['GET'])
@require_auth
def get_spot(spot_id):
    map_id = _map_id_for_spot(spot_id)
    if map_id is None:
        return jsonify({'error': 'Spot not found'}), 404
    allowed, _, _ = user_can_access_map(map_id, g.user_id)
    if not allowed:
        return jsonify({'error': 'Spot not found'}), 404
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        SELECT id, map_id, name, lat, lng, listing, subset, notes, created,
               (SELECT COUNT(*) FROM photos p WHERE p.spot_id = spots.id) AS photo_count
        FROM spots
        WHERE id = ?
    ''', (spot_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Spot not found'}), 404

    return jsonify({
        'id': row[0],
        'mapID': row[1],
        'name': row[2],
        'lat': row[3],
        'lng': row[4],
        'listing': row[5],
        'subset': row[6],
        'notes': row[7],
        'created': row[8],
        'photo_count': row[9]
    })


# Add spot
@app.route('/spots', methods=['POST'])
@require_auth
def add_spot():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    mapID = data.get('mapID')
    lat = data.get('lat')
    lng = data.get('lng')
    cleaned = {}
    for label, key, limit, required in (
            ('Marker name', 'name', SPOT_NAME_MAX, True),
            ('Listing', 'listing', LISTING_MAX, False),
            ('Subset', 'subset', LISTING_MAX, False),
            ('Created', 'created', CREATED_MAX, False),
            ('Notes', 'notes', NOTES_MAX, False)):
        ok, reason, value = text_value(data.get(key), label, limit, required=required)
        if not ok:
            return jsonify({'error': reason}), 400
        cleaned[key] = value
    name = cleaned['name']
    listing = (cleaned['listing'] or 'General').upper()
    subset = (cleaned['subset'] or 'Main').upper()
    created = cleaned['created'] or datetime.now().isoformat()
    notes = cleaned['notes']

    if isinstance(mapID, bool) or not isinstance(mapID, int) or lat is None or lng is None:
        return jsonify({'error': 'Missing fields'}), 400

    if not _coord_ok(lat, 90) or not _coord_ok(lng, 180):
        return jsonify({'error': 'Invalid coordinates'}), 400

    allowed, _, _ = user_can_access_map(mapID, g.user_id, need_edit=True)
    if not allowed:
        return jsonify({'error': 'Map not found'}), 404

    conn = get_db()
    c = conn.cursor()
    c.execute(
        'INSERT INTO spots (map_id, name, lat, lng, listing, subset, created, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (mapID, name, lat, lng, listing, subset, created, notes)
    )
    conn.commit()
    spot_id = c.lastrowid
    conn.close()

    return jsonify({
        'id': spot_id,
        'mapID': mapID,
        'name': name,
        'lat': lat,
        'lng': lng,
        'listing': listing,
        'subset': subset,
        'notes': notes,
        'created': created
    })


# Update spot
@app.route('/spots/<int:spot_id>', methods=['PUT'])
@require_auth
def update_spot(spot_id):
    map_id = _map_id_for_spot(spot_id)
    if map_id is None:
        return jsonify({'error': 'Spot not found'}), 404
    allowed, _, _ = user_can_access_map(map_id, g.user_id, need_edit=True)
    if not allowed:
        return jsonify({'error': 'Spot not found'}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    # A name key that is absent still means "unchanged", but a name key that is
    # present must satisfy the same rule POST enforces: text_value returns None for an
    # absent field and '' for an empty one, and testing only `is not None` below wrote
    # the empty string straight through to a NOT NULL column that POST rejects with 400.
    cleaned = {}
    for label, key, limit, required in (
            ('Marker name', 'name', SPOT_NAME_MAX, 'name' in data),
            ('Listing', 'listing', LISTING_MAX, False),
            ('Subset', 'subset', LISTING_MAX, False),
            ('Created', 'created', CREATED_MAX, False),
            ('Notes', 'notes', NOTES_MAX, False)):
        ok, reason, value = text_value(data.get(key), label, limit, required=required)
        if not ok:
            return jsonify({'error': reason}), 400
        cleaned[key] = value
    name = cleaned['name']
    lat = data.get('lat')
    lng = data.get('lng')
    created = cleaned['created']
    notes = cleaned['notes'] if 'notes' in data else None
    listing = cleaned['listing'].upper() if cleaned['listing'] else None
    subset = cleaned['subset'].upper() if cleaned['subset'] else None

    if lat is not None and not _coord_ok(lat, 90):
        return jsonify({'error': 'Invalid coordinates'}), 400
    if lng is not None and not _coord_ok(lng, 180):
        return jsonify({'error': 'Invalid coordinates'}), 400

    conn = get_db()
    c = conn.cursor()

    fields = []
    values = []

    if name is not None:
        fields.append("name=?")
        values.append(name)
    if lat is not None:
        fields.append("lat=?")
        values.append(lat)
    if lng is not None:
        fields.append("lng=?")
        values.append(lng)
    if created is not None:
        fields.append("created=?")
        values.append(created)
    if notes is not None:
        fields.append("notes=?")
        values.append(notes)
    if listing is not None:
        fields.append("listing=?")
        values.append(listing)
    if subset is not None:
        fields.append("subset=?")
        values.append(subset)

    if not fields:
        return jsonify({'error': 'No fields to update'}), 400

    values.append(spot_id)
    c.execute(f"UPDATE spots SET {', '.join(fields)} WHERE id=?", values)
    updated = c.rowcount
    conn.commit()
    conn.close()

    if updated == 0:
        return jsonify({'error': 'Spot not found'}), 404

    return jsonify({'message': f'Spot {spot_id} updated', 'id': spot_id, 'name': name, 'lat': lat, 'lng': lng, 'created': created, 'notes': notes, 'listing': listing, 'subset': subset})


# Copy spot
@app.route('/spots/<int:spot_id>/copy/<int:target_map_id>', methods=['POST'])
@require_auth
def copy_spot(spot_id, target_map_id):
    # Read access to the source, edit access to the target.
    src_map_id = _map_id_for_spot(spot_id)
    if src_map_id is None:
        return jsonify({'error': 'Source spot not found'}), 404
    src_ok, _, _ = user_can_access_map(src_map_id, g.user_id)
    if not src_ok:
        return jsonify({'error': 'Source spot not found'}), 404
    tgt_ok, _, _ = user_can_access_map(target_map_id, g.user_id, need_edit=True)
    if not tgt_ok:
        return jsonify({'error': 'Target map not found'}), 404

    conn = get_db()
    c = conn.cursor()

    # Get source spot
    c.execute("""
        SELECT name, lat, lng, notes, listing, subset
        FROM spots
        WHERE id=?
    """, (spot_id,))
    spot = c.fetchone()
    if not spot:
        conn.close()
        return jsonify({'error': 'Source spot not found'}), 404

    # Prepare new name with "(Copy)" suffix
    base_copy = f"{spot[0]} (Copy)"

    # Get all existing spot names on this map that start with base_copy
    c.execute("""
        SELECT name FROM spots
        WHERE map_id = ? AND name LIKE ?
    """, (target_map_id, f"{base_copy}%"))
    existing = [row[0] for row in c.fetchall()]

    if base_copy not in existing:
        new_name = base_copy
    else:
        n = 2
        while f"{spot[0]} (Copy {n})" in existing:
            n += 1
        new_name = f"{spot[0]} (Copy {n})"

    # Current timestamp for new spot
    created_now = datetime.utcnow().isoformat()

    # Create new spot with current timestamp
    c.execute("""
        INSERT INTO spots (map_id, name, lat, lng, created, notes, listing, subset)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (target_map_id, new_name, spot[1], spot[2], created_now, spot[3], spot[4], spot[5]))
    new_spot_id = c.lastrowid

    # Fetch photos of source spot
    c.execute("SELECT filename FROM photos WHERE spot_id=?", (spot_id,))
    photos = c.fetchall()

    os.makedirs(PHOTOS_FOLDER, exist_ok=True)
    os.makedirs(THUMBS_FOLDER, exist_ok=True)

    new_photo_count = 0

    # R-02: stage every file, publish the complete set, then commit the spot+photo
    # rows. Failure rolls back the rows and removes staged/published files. A crash
    # between publish and commit can leave only invisible orphan files.
    staged_renames = []
    published_destinations = []
    try:
        for (filename,) in photos:
            src_path = os.path.join(PHOTOS_FOLDER, filename)
            src_thumb = os.path.join(THUMBS_FOLDER, filename)

            if not os.path.exists(src_path):
                continue

            # Remove existing trailing UUID (after last underscore); stored photos
            # are canonical JPEG, so the copy keeps the .jpg name (R-01).
            base, _ = os.path.splitext(filename)
            original_base = base.rsplit('_', 1)[0] if '_' in base else base
            new_filename = f"{original_base}_{uuid.uuid4().hex}.jpg"

            staged = os.path.join(PHOTOS_FOLDER, f".{new_filename}.tmp")
            shutil.copy(src_path, staged)
            staged_renames.append((staged, os.path.join(PHOTOS_FOLDER, new_filename)))
            if os.path.exists(src_thumb):
                staged_thumb = os.path.join(THUMBS_FOLDER, f".{new_filename}.tmp")
                shutil.copy(src_thumb, staged_thumb)
                staged_renames.append((staged_thumb, os.path.join(THUMBS_FOLDER, new_filename)))

            c.execute(
                "INSERT INTO photos (spot_id, filename) VALUES (?, ?)",
                (new_spot_id, new_filename)
            )

            new_photo_count += 1

        for staged, destination in staged_renames:
            os.replace(staged, destination)
            published_destinations.append(destination)

        conn.commit()
    except Exception:
        conn.rollback()
        for staged, _ in staged_renames:
            if os.path.exists(staged):
                os.remove(staged)
        for destination in reversed(published_destinations):
            if os.path.exists(destination):
                os.remove(destination)
        conn.close()
        return internal_error('spot.copy', 'Could not copy the marker')
    conn.close()

    new_spot = {
        'id': new_spot_id,
        'map_id': target_map_id,
        'name': new_name,
        'lat': spot[1],
        'lng': spot[2],
        'created': created_now,
        'notes': spot[3],
        'listing': spot[4],
        'subset': spot[5],
        'photo_count': new_photo_count
    }

    return jsonify({
        'message': 'Spot copied',
        'spot': new_spot,
        'photos_copied': new_photo_count
    })


# Move spot
@app.route('/spots/<int:spot_id>/move/<int:target_map_id>', methods=['POST'])
@require_auth
def move_spot(spot_id, target_map_id):
    src_map_id = _map_id_for_spot(spot_id)
    if src_map_id is None:
        return jsonify({'error': 'Spot not found'}), 404
    src_ok, _, _ = user_can_access_map(src_map_id, g.user_id, need_edit=True)
    if not src_ok:
        return jsonify({'error': 'Spot not found'}), 404
    tgt_ok, _, _ = user_can_access_map(target_map_id, g.user_id, need_edit=True)
    if not tgt_ok:
        return jsonify({'error': 'Target map not found'}), 404

    conn = get_db()
    c = conn.cursor()

    # Check spot exists
    c.execute("SELECT id, map_id FROM spots WHERE id=?", (spot_id,))
    spot = c.fetchone()
    if not spot:
        conn.close()
        return jsonify({'error': 'Spot not found'}), 404

    current_map_id = spot[1]

    # If already in that map
    if current_map_id == target_map_id:
        conn.close()
        return jsonify({'message': 'Spot already in target map'}), 200

    # Move spot
    c.execute(
        "UPDATE spots SET map_id=? WHERE id=?",
        (target_map_id, spot_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        'message': 'Spot moved',
        'spot_id': spot_id,
        'new_map_id': target_map_id
    })


# Delete spot
@app.route('/spots/<int:spot_id>', methods=['DELETE'])
@require_auth
def delete_spot(spot_id):
    map_id = _map_id_for_spot(spot_id)
    if map_id is None:
        return jsonify({'error': 'Spot not found'}), 404
    allowed, _, _ = user_can_access_map(map_id, g.user_id, need_edit=True)
    if not allowed:
        return jsonify({'error': 'Spot not found'}), 404

    conn = get_db()
    c = conn.cursor()

    # R-02: collect file paths, commit the DB deletion, then best-effort cleanup —
    # a file-removal failure can no longer misreport a committed deletion.
    c.execute('''
        SELECT s.name, m.name
        FROM spots s
        JOIN maps m ON m.id = s.map_id
        WHERE s.id=? AND s.map_id=?
    ''', (spot_id, map_id))
    spot_row = c.fetchone()
    if not spot_row:
        conn.close()
        return jsonify({'error': 'Spot not found'}), 404
    spot_name, map_name = spot_row
    c.execute('SELECT filename FROM photos WHERE spot_id=?', (spot_id,))
    filenames = [r[0] for r in c.fetchall()]
    c.execute('DELETE FROM spots WHERE id=?', (spot_id,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted == 0:
        return jsonify({'error': 'Spot not found'}), 404

    notify(
        g.user_id,
        'marker.deleted',
        f'Marker “{spot_name}” deleted from “{map_name}”.',
        target_type='marker',
        target_id=spot_id,
        target_label=spot_name,
        detail={
            'map_id': map_id,
            'map_label': map_name,
            'photos': len(filenames),
        },
    )

    for filename in filenames:
        for folder in (PHOTOS_FOLDER, THUMBS_FOLDER):
            path = os.path.join(folder, filename)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                LOGGER.warning("spot.delete: could not remove %s", clean_log_value(path))
    return jsonify({'message': f'Spot {spot_id} deleted'})


# Photos upload endpoint with thumbnail generation
@app.route('/spots/<int:spot_id>/photos', methods=['POST'])
@require_auth
def upload_photo(spot_id):
    denied = _authorize_spot(spot_id, need_edit=True)
    if denied:
        return denied
    # Check for uploaded file
    if 'photo' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Check if spot exists
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM spots WHERE id=?', (spot_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Spot not found'}), 404
    conn.close()

    # Validate through the shared decode-safety gate (S-10)
    img, image_error = open_validated_image(BytesIO(file.read()))
    if image_error:
        return jsonify({'error': image_error}), 400

    # Canonical output name (R-01): the stored bytes are always re-encoded JPEG,
    # so the extension is always .jpg regardless of the uploaded name.
    base, _ = os.path.splitext(sanitize_filename(file.filename))
    filename = f"{base}_{uuid.uuid4().hex}.jpg"
    filepath = os.path.join(PHOTOS_FOLDER, filename)
    thumb_path = os.path.join(THUMBS_FOLDER, filename)
    os.makedirs(PHOTOS_FOLDER, exist_ok=True)
    os.makedirs(THUMBS_FOLDER, exist_ok=True)

    # R-02: stage under temporary names, commit the DB row, then atomically rename;
    # any failure removes the staged files so no half-written photo is served.
    staged_photo = os.path.join(PHOTOS_FOLDER, f".{filename}.tmp")
    staged_thumb = os.path.join(THUMBS_FOLDER, f".{filename}.tmp")
    try:
        img.thumbnail((3072, 3072), Image.Resampling.LANCZOS)
        img.save(staged_photo, format='JPEG', quality=80, optimize=True)
        thumb_img = img.copy()
        thumb_img.thumbnail((800, 800), Image.Resampling.LANCZOS)
        thumb_img.save(staged_thumb, format='JPEG', quality=70, optimize=True)

        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO photos (spot_id, filename) VALUES (?, ?)', (spot_id, filename))
        conn.commit()
        conn.close()

        os.replace(staged_photo, filepath)
        os.replace(staged_thumb, thumb_path)
    except Exception:
        for staged in (staged_photo, staged_thumb):
            if os.path.exists(staged):
                os.remove(staged)
        conn = get_db()
        conn.execute('DELETE FROM photos WHERE spot_id = ? AND filename = ?', (spot_id, filename))
        conn.commit()
        conn.close()
        return internal_error('photo.upload', 'Could not save photo')

    return jsonify({
        'message': 'Photo uploaded',
        'filename': filename,
        'photo_url': sign_photo_url('photos', filename, g.user_id),
        'thumb_url': sign_photo_url('thumbs', filename, g.user_id)
    })


# Get all photos filename for a spot
@app.route('/spots/<int:spot_id>/photos', methods=['GET'])
@require_auth
def get_photos(spot_id):
    denied = _authorize_spot(spot_id, need_edit=False)
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename, caption FROM photos WHERE spot_id=?', (spot_id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([
        {
            'filename': r[0],
            'caption': r[1] or '',
            'photo_url': sign_photo_url('photos', r[0], g.user_id),
            'thumb_url': sign_photo_url('thumbs', r[0], g.user_id)
        }
        for r in rows
    ])


# =====================
# Signed photo/thumb serving. PUBLIC (no @require_auth): a browser <img src> can't carry a
# Bearer token, so authorization comes entirely from the self-authenticating signed URL.
# The uid is recovered from the URL, the HMAC is verified, then that uid's map access is
# re-checked (so revoked sharing stops working even within the URL's TTL).
# =====================
def _serve_signed(kind, internal_prefix, filename):
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    # Photo galleries fire many image requests at once, so this needs the fast PRIVATE
    # bucket (~20 req/s) AND a large burst — a marker with dozens of photos legitimately
    # loads them all in one go. (The PUBLIC bucket used for login/register is the opposite
    # profile and was causing 429s here.) A generous burst still caps a runaway.
    rate_limit(client_ip, now_ts, PHOTO_BUCKET, PRIVATE_REFILL_INTERVAL, burst=200)

    uid = request.args.get('uid')
    if not verify_photo_sig(kind, filename, request.args.get('exp'), uid, request.args.get('sig')):
        abort(403)
    map_id = _map_id_for_photo(filename)
    if map_id is None:
        abort(404)
    allowed, _, _ = user_can_access_map(map_id, uid)
    if not allowed:
        abort(403)
    # Hand the byte transfer to nginx via an internal-only location. nginx keeps the
    # Content-Type we set here. Every stored photo/thumbnail is re-encoded JPEG under a
    # canonical .jpg name (R-01), so the type is a constant, not a filename guess.
    response = make_response()
    response.headers['X-Accel-Redirect'] = f"{internal_prefix}{filename}"
    response.headers['Content-Type'] = 'image/jpeg'
    # Photo filenames change on replacement, so stable signed URLs can use the viewer's
    # private browser cache. Residue after deletion/revocation lasts at most max-age.
    response.headers['Cache-Control'] = 'private, max-age=1800'
    return response


@app.route('/photos/<filename>', methods=['GET'])
def serve_photo(filename):
    return _serve_signed('photos', '/internal_photos/', filename)


@app.route('/thumbs/<filename>', methods=['GET'])
def serve_thumb(filename):
    return _serve_signed('thumbs', '/internal_thumbs/', filename)


@app.route('/avatars/<filename>', methods=['GET'])
def serve_avatar(filename):
    client_ip = get_client_ip()
    now_ts = int(time.time())
    is_ip_allowed(client_ip)
    rate_limit(client_ip, now_ts, PHOTO_BUCKET, PRIVATE_REFILL_INTERVAL, burst=200)

    uid = request.args.get('uid')
    if not verify_photo_sig('avatars', filename, request.args.get('exp'), uid,
                            request.args.get('sig')):
        abort(403)

    # Avatar URLs are public/self-authenticating like photo URLs, but they are not
    # map-scoped. The current DB value prevents a valid old URL from surviving removal.
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT avatar FROM users WHERE user_id = ?", (uid,))
    row = c.fetchone()
    conn.close()
    if not row or row[0] != filename:
        abort(404)
    if not os.path.isfile(os.path.join(AVATARS_FOLDER, filename)):
        abort(404)

    response = make_response()
    response.headers['X-Accel-Redirect'] = f"/internal_avatars/{filename}"
    response.headers['Content-Type'] = 'image/jpeg'
    # Cacheable for the URL-stability window: re-renders and reloads hit the browser
    # cache. Residue: a removed/replaced avatar can persist in a viewer's local cache
    # for up to max-age (server-side revocation via the DB re-check stays immediate).
    response.headers['Cache-Control'] = 'private, max-age=1800'
    return response


# Update photo caption
@app.route('/spots/<int:spot_id>/photos/<filename>/caption', methods=['PUT'])
@require_auth
def update_photo_caption(spot_id, filename):
    denied = _authorize_spot(spot_id, need_edit=True)
    if denied:
        return denied
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    ok, reason, caption = text_value(data.get('caption'), 'Caption', CAPTION_MAX)
    if not ok:
        return jsonify({'error': reason}), 400
    caption = caption or ''

    conn = get_db()
    c = conn.cursor()

    # Make sure the photo exists for this spot
    c.execute('SELECT id FROM photos WHERE spot_id=? AND filename=?', (spot_id, filename))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Photo not found'}), 404

    # Update caption
    c.execute('UPDATE photos SET caption=? WHERE spot_id=? AND filename=?', (caption, spot_id, filename))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Caption updated', 'filename': filename, 'caption': caption})


# ===============================
# Replace an existing photo
# ===============================
@app.route('/spots/<int:spot_id>/photos/<filename>', methods=['PUT'])
@require_auth
def replace_photo(spot_id, filename):
    denied = _authorize_spot(spot_id, need_edit=True)
    if denied:
        return denied
    # Verify the photo belongs to this spot before touching disk
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT filename FROM photos WHERE spot_id=? AND filename=?', (spot_id, filename))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Photo not found'}), 404

    if 'photo' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Validate through the shared decode-safety gate (S-10)
    img, image_error = open_validated_image(file)
    if image_error:
        return jsonify({'error': image_error}), 400

    # Canonical output name (R-01), staged write + DB update + rename (R-02)
    base, _ = os.path.splitext(sanitize_filename(file.filename))
    new_filename = f"{base}_{uuid.uuid4().hex}.jpg"
    new_filepath = os.path.join(PHOTOS_FOLDER, new_filename)
    new_thumb_path = os.path.join(THUMBS_FOLDER, new_filename)
    os.makedirs(PHOTOS_FOLDER, exist_ok=True)
    os.makedirs(THUMBS_FOLDER, exist_ok=True)

    staged_photo = os.path.join(PHOTOS_FOLDER, f".{new_filename}.tmp")
    staged_thumb = os.path.join(THUMBS_FOLDER, f".{new_filename}.tmp")
    try:
        img.thumbnail((3072, 3072), Image.Resampling.LANCZOS)
        img.save(staged_photo, format='JPEG', quality=80, optimize=True)
        thumb_img = img.copy()
        thumb_img.thumbnail((800, 800), Image.Resampling.LANCZOS)
        thumb_img.save(staged_thumb, format='JPEG', quality=70, optimize=True)

        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE photos SET filename=? WHERE spot_id=? AND filename=?',
                  (new_filename, spot_id, filename))
        conn.commit()
        conn.close()

        os.replace(staged_photo, new_filepath)
        os.replace(staged_thumb, new_thumb_path)
    except Exception:
        for staged in (staged_photo, staged_thumb):
            if os.path.exists(staged):
                os.remove(staged)
        conn = get_db()
        conn.execute('UPDATE photos SET filename=? WHERE spot_id=? AND filename=?',
                     (filename, spot_id, new_filename))
        conn.commit()
        conn.close()
        return internal_error('photo.replace', 'Could not replace photo')

    # Delete the replaced files; a leftover here never misreports the committed
    # replacement — the orphan checker surfaces it instead.
    for path in (
        os.path.join(PHOTOS_FOLDER, filename),
        os.path.join(THUMBS_FOLDER, filename)
    ):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            LOGGER.warning("photo.replace: could not remove %s", clean_log_value(path))

    return jsonify({
        'message': 'Photo replaced',
        'filename': new_filename,
        'photo_url': sign_photo_url('photos', new_filename, g.user_id),
        'thumb_url': sign_photo_url('thumbs', new_filename, g.user_id)
    })



# Delete photos on database and disk
@app.route('/spots/<int:spot_id>/photos/<filename>', methods=['DELETE'])
@require_auth
def delete_photo(spot_id, filename):
    denied = _authorize_spot(spot_id, need_edit=True)
    if denied:
        return denied
    conn = get_db()
    c = conn.cursor()

    # Verify the photo and freeze its parent context before deletion.
    c.execute('''
        SELECT p.filename, p.caption, s.name, s.map_id, m.name
        FROM photos p
        JOIN spots s ON s.id = p.spot_id
        JOIN maps m ON m.id = s.map_id
        WHERE p.spot_id=? AND p.filename=?
    ''', (spot_id, filename))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Photo not found'}), 404
    _, caption, spot_name, map_id, map_name = row

    # Delete DB entry
    c.execute('DELETE FROM photos WHERE spot_id=? AND filename=?', (spot_id, filename))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted == 0:
        return jsonify({'error': 'Photo not found'}), 404

    photo_label = caption or filename
    notify(
        g.user_id,
        'photo.deleted',
        f'Photo “{photo_label}” deleted from marker “{spot_name}”.',
        target_type='photo',
        target_id=filename,
        target_label=photo_label,
        detail={
            'marker_id': spot_id,
            'marker_label': spot_name,
            'map_id': map_id,
            'map_label': map_name,
        },
    )

    # Best-effort file cleanup after the committed deletion (R-02)
    for folder in (PHOTOS_FOLDER, THUMBS_FOLDER):
        path = os.path.join(folder, filename)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            LOGGER.warning("photo.delete: could not remove %s", clean_log_value(path))

    return jsonify({'message': f'Photo {filename} deleted from spot {spot_id}'})


# =====================
# KML import: bounded executor with per-user/global admission (S-09)
# =====================
KML_EXECUTOR = ThreadPoolExecutor(max_workers=KML_MAX_WORKERS, thread_name_prefix='kml-import')
KML_JOBS_LOCK = threading.Lock()
KML_ACTIVE_JOBS = {}                     # user_id -> queued+running jobs, for admission


class KmlBudgetError(ValueError):
    # str(error) is the compact failure token stored on the job row (S-09).
    pass


def release_kml_slot(user_id):
    with KML_JOBS_LOCK:
        remaining = KML_ACTIVE_JOBS.get(user_id, 0) - 1
        if remaining > 0:
            KML_ACTIVE_JOBS[user_id] = remaining
        else:
            KML_ACTIVE_JOBS.pop(user_id, None)


@app.route('/import_kml', methods=['POST'])
@require_auth
def import_kml_endpoint():
    if 'kml_file' not in request.files:
        return jsonify({'error': 'No KML file uploaded'}), 400

    file = request.files['kml_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    map_id = request.form.get('map_id')
    if not map_id:
        return jsonify({'error': 'No map selected'}), 400

    # Authorize the target map (must be owned by or editable for this user).
    try:
        map_id_int = int(map_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid map'}), 400
    allowed, _, _ = user_can_access_map(map_id_int, g.user_id, need_edit=True)
    if not allowed:
        return jsonify({'error': 'Map not found'}), 404

    # Admission control: plain counters under one lock bound the queued+running jobs
    # per user and globally; a rejected import is a 429 the frontend already surfaces.
    with KML_JOBS_LOCK:
        if KML_ACTIVE_JOBS.get(g.user_id, 0) >= KML_JOBS_PER_USER:
            return jsonify({'error': 'You already have a KML import in progress'}), 429
        if sum(KML_ACTIVE_JOBS.values()) >= KML_JOBS_GLOBAL:
            return jsonify({'error': 'Too many KML imports are running. Please try again shortly'}), 429
        KML_ACTIVE_JOBS[g.user_id] = KML_ACTIVE_JOBS.get(g.user_id, 0) + 1

    job_id = str(uuid.uuid4())
    temp_path = os.path.join(TEMP_FOLDER, f"{job_id}.kml")
    submitted = False
    try:
        # Exclusive per-job temporary file (S-08): concurrent imports of identically
        # named uploads must never overwrite or delete each other's input. The size
        # re-check backs up nginx's body limit for direct backend exposure.
        os.makedirs(TEMP_FOLDER, exist_ok=True)
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as temp_file:
            file.save(temp_file)
        if os.path.getsize(temp_path) > KML_MAX_BYTES:
            return jsonify({'error': 'The KML file is too large'}), 413

        # The job row binds uploader and target map (R-03). Retention is
        # read-triggered, never timer-driven: each admission clears the requester's
        # earlier finished jobs plus anything terminal older than seven days.
        with get_db() as conn:
            c = conn.cursor()
            c.execute(
                "DELETE FROM import_progress WHERE owner_id=? AND status IN ('done', 'error')",
                (g.user_id,)
            )
            c.execute(
                "DELETE FROM import_progress WHERE status IN ('done', 'error') AND last_updated < datetime('now', '-7 days')"
            )
            c.execute(
                'INSERT INTO import_progress (job_id, owner_id, map_id, imported, total, skipped, photos_failed, photos_budget_skipped, progress, status) VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, ?)',
                (job_id, g.user_id, map_id_int, 'queued')
            )
            conn.commit()

        KML_EXECUTOR.submit(process_kml_job, temp_path, job_id, map_id_int, g.user_id)
        submitted = True
    except Exception:
        return internal_error('import_kml', 'Failed to start the KML import')
    finally:
        # Any non-submitted exit (over-size, insert/submit failure) releases the
        # admission slot and the job file; after submit the worker owns both.
        if not submitted:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            release_kml_slot(g.user_id)

    return jsonify({"job_id": job_id, "message": "KML import started"})


def process_kml_job(path, job_id, map_id, owner_id):
    slot_released = False
    try:
        result = import_kml_file(path, map_id, job_id)
        _notify_kml_job(owner_id, job_id, map_id, **result)
        release_kml_slot(owner_id)
        slot_released = True
        conn = get_db()
        try:
            conn.execute(
                "UPDATE import_progress SET status='done', progress=100, "
                "imported=?, skipped=?, photos_failed=?, photos_budget_skipped=?, "
                "completed=CURRENT_TIMESTAMP, last_updated=CURRENT_TIMESTAMP "
                "WHERE job_id=?",
                (
                    result['imported'],
                    result['skipped'],
                    result['photos_failed'],
                    result['photos_budget_skipped'],
                    job_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        error_token = str(e) if isinstance(e, KmlBudgetError) else 'import_failed'
        correlation_id = None
        if isinstance(e, KmlBudgetError):
            LOGGER.error(
                "area=kml.import KML job %s failed error=%s",
                clean_log_value(job_id),
                clean_log_value(error_token),
            )
        else:
            correlation_id = uuid.uuid4().hex[:12]
            LOGGER.error(
                "area=kml.import KML job %s failed correlation_id=%s error=%s: %s",
                clean_log_value(job_id),
                correlation_id,
                type(e).__name__,
                clean_log_value(e),
            )
        conn = get_db()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT ip.imported, ip.total, ip.skipped, ip.photos_failed, "
                "ip.photos_budget_skipped, m.name FROM import_progress ip "
                "LEFT JOIN maps m ON m.id=ip.map_id WHERE ip.job_id=?",
                (job_id,),
            )
            row = c.fetchone()
        finally:
            conn.close()
        _notify_kml_job(
            owner_id,
            job_id,
            map_id,
            row[5] if row else None,
            imported=row[0] or 0 if row else 0,
            total=row[1] or 0 if row else 0,
            skipped=row[2] or 0 if row else 0,
            photos_failed=row[3] or 0 if row else 0,
            photos_budget_skipped=row[4] or 0 if row else 0,
            error_token=error_token,
            correlation_id=correlation_id,
        )
        if not slot_released:
            release_kml_slot(owner_id)
            slot_released = True
        conn = get_db()
        try:
            conn.execute(
                "UPDATE import_progress SET status='error', error=?, "
                "completed=CURRENT_TIMESTAMP, last_updated=CURRENT_TIMESTAMP "
                "WHERE job_id=?",
                (error_token, job_id),
            )
            conn.commit()
        finally:
            conn.close()
    finally:
        if os.path.exists(path):
            os.remove(path)
        if not slot_released:
            release_kml_slot(owner_id)


@app.route('/import_kml_status/<job_id>')
@require_auth
def import_status(job_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT imported, total, skipped, photos_failed, photos_budget_skipped, progress, status, error, owner_id, map_id FROM import_progress WHERE job_id=?",
        (job_id,)
    )
    row = c.fetchone()
    conn.close()

    # Owner-authorized, not capability-only (R-03): the requester must be the uploader
    # and still have access to the target map. Wrong user, lost access, and unknown
    # job are all the same 404.
    if not row or row[8] != g.user_id:
        return jsonify({'error': 'Job not found'}), 404
    allowed, _, _ = user_can_access_map(row[9], g.user_id)
    if not allowed:
        return jsonify({'error': 'Job not found'}), 404

    # Compact counts only (S-09): finished markers arrive through normal map
    # retrieval, never through a job-row snapshot.
    return jsonify({
        'imported': row[0],
        'total': row[1],
        'skipped': row[2],
        'photos_failed': row[3],
        'photos_budget_skipped': row[4],
        'progress': row[5],
        'status': row[6],
        'error': row[7]
    })


# Read a KML element's text, treating an empty element as an absent one. <name> is
# optional in KML, and <name></name> is what Google Earth / My Maps export for an
# unnamed feature: ElementTree gives it .text of None, which reached spots.name (NOT
# NULL) and aborted the whole import on one unnamed pin. Empty and absent both mean
# "unnamed", so both take the fallback rather than producing two different outcomes.
def _kml_text(element, fallback):
    if element is None or not (element.text or '').strip():
        return fallback
    return element.text


def import_kml_file(kml_file, map_id, job_id):
    # Bounded single-pass parse (S-09): defusedxml blocks entity attacks, and these
    # plain counters bound tree depth/size before any per-placemark work begins.
    depth = 0
    element_count = 0
    events = ET.iterparse(kml_file, events=('start', 'end'))
    for event, element in events:
        if event == 'start':
            depth += 1
            element_count += 1
            if depth > KML_MAX_DEPTH:
                raise KmlBudgetError('kml_too_deep')
            if element_count > KML_MAX_ELEMENTS:
                raise KmlBudgetError('kml_too_many_elements')
        else:
            depth -= 1
    root = events.root
    ns = {"kml": "http://www.opengis.net/kml/2.2"}

    doc_el = root.find("kml:Document/kml:name", ns)
    listing_name = _kml_text(doc_el, "GENERAL").upper()

    downloaded_urls = set()
    downloaded_bytes = 0
    fetch_attempts = 0
    imported_spots = 0
    skipped_spots = 0
    photos_failed = 0
    photos_budget_skipped = 0
    download_budget_exhausted = False
    attempt_budget_exhausted = False
    deadline_exhausted = False
    photo_count_budget_exhausted = False
    affected_spots = []
    deadline = time.monotonic() + KML_MAX_JOB_SECONDS
    placemarks = root.findall(".//kml:Placemark", ns)
    total_spots = len(placemarks)
    if total_spots > KML_MAX_PLACEMARKS:
        raise KmlBudgetError('kml_too_many_placemarks')

    # Map each element to its parent so we can find a placemark's enclosing Folder.
    # (ElementTree has no parent pointers, and nested folders would otherwise cause
    # double-imports while folderless placemarks would be skipped entirely.)
    parent_of = {child: parent for parent in root.iter() for child in parent}
    folder_tag = "{http://www.opengis.net/kml/2.2}Folder"

    def subset_for(placemark):
        node = parent_of.get(placemark)
        while node is not None:
            if node.tag == folder_tag:
                name_el = node.find("kml:name", ns)
                return _kml_text(name_el, "MAIN").upper()
            node = parent_of.get(node)
        return "MAIN"

    # One connection serves the whole job, but every commit stays small: a write
    # transaction spanning a photo download would starve the other worker's commits
    # (SQLite allows one writer), so nothing holds the write lock across network IO.
    conn = get_db()
    try:
        c = conn.cursor()

        # The job leaves the admission queue here: running, with its real total.
        c.execute(
            "UPDATE import_progress SET status='running', total=?, last_updated=CURRENT_TIMESTAMP WHERE job_id=?",
            (total_spots, job_id)
        )
        conn.commit()

        # Iterate every placemark once, deriving its subset from the nearest ancestor Folder.
        for placemark in placemarks:
            subset_name = subset_for(placemark)

            name_el = placemark.find("kml:name", ns)
            # spots.name is NOT NULL and KML's <name> is optional, so an unnamed
            # placemark needs a literal. Deliberately not the listing's fallback,
            # which is also "General" — the two are unrelated, and sharing the word
            # made imported markers look like they had inherited their listing.
            name = _kml_text(name_el, "Unnamed")

            coords_el = placemark.find(".//kml:Point/kml:coordinates", ns)
            if coords_el is None or not coords_el.text:
                skipped_spots += 1
                continue
            try:
                lng, lat, *_ = map(float, coords_el.text.strip().split(','))
            except ValueError:
                # Skip a malformed coordinate rather than aborting the whole import.
                skipped_spots += 1
                continue
            # Imported coordinates obey the same validation as the regular API (R-04):
            # non-finite or out-of-range points are skipped, never stored.
            if not _coord_ok(lat, 90) or not _coord_ok(lng, 180):
                skipped_spots += 1
                continue

            created = datetime.now().replace(microsecond=0).isoformat()
            local_el = placemark.find(".//kml:ExtendedData/kml:Data[@name='Local']/kml:value", ns)
            local_value = _kml_text(local_el, '')
            notes = f"Local: {local_value}" if local_value else ''

            c.execute(
                'INSERT INTO spots (map_id, name, lat, lng, created, notes, listing, subset) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (map_id, name, lat, lng, created, notes, listing_name, subset_name)
            )
            spot_id = c.lastrowid
            conn.commit()

            # --- Download photos ---
            urls = []
            desc_el = placemark.find("kml:description", ns)
            if desc_el is not None and desc_el.text:
                urls.extend(re.findall(r'src="([^"]+)"', desc_el.text))
            gx_links = placemark.findall(".//kml:Data[@name='gx_media_links']/kml:value", ns)
            for link in gx_links:
                if link.text:
                    urls.extend(link.text.split())

            # Photo budgets (S-09): once a per-job byte/attempt/time budget is spent,
            # every remaining unique URL is budget-skipped so marker rows can finish.
            # While job budget remains, the per-spot URL cap counts its excess as failed.
            photo_count = 1
            spot_fetch_attempts = 0
            failed_before = photos_failed
            budget_skipped_before = photos_budget_skipped
            for url in urls:
                if url in downloaded_urls:
                    continue
                downloaded_urls.add(url)
                remaining = deadline - time.monotonic()
                if downloaded_bytes >= KML_MAX_DOWNLOAD_BYTES:
                    download_budget_exhausted = True
                if fetch_attempts >= KML_MAX_FETCH_ATTEMPTS:
                    attempt_budget_exhausted = True
                if remaining <= 0:
                    deadline_exhausted = True
                if (download_budget_exhausted or attempt_budget_exhausted
                        or deadline_exhausted):
                    photos_budget_skipped += 1
                    continue
                if spot_fetch_attempts >= KML_MAX_PHOTOS_PER_SPOT:
                    photo_count_budget_exhausted = True
                    photos_failed += 1
                    continue
                spot_fetch_attempts += 1
                fetch_attempts += 1

                # Canonical .jpg output (R-01): the stored bytes are re-encoded JPEG,
                # never trusted from the remote URL's extension.
                safe_base = sanitize_filename(name)
                filename = f"{safe_base}_{photo_count:02d}_{uuid.uuid4().hex}.jpg"
                filepath = os.path.join(PHOTOS_FOLDER, filename)
                thumb_path = os.path.join(THUMBS_FOLDER, filename)

                response = None
                try:
                    response = fetch_url_safely(url, timeout=min(10, remaining), stream=True)
                    if response.status_code != 200:
                        raise ValueError(f"unexpected response status {response.status_code}")
                    downloaded = 0
                    with open(filepath, "wb") as f:
                        for chunk in response.iter_content(1024):
                            if time.monotonic() > deadline:
                                deadline_exhausted = True
                                raise ValueError("job time budget exhausted")
                            downloaded += len(chunk)
                            downloaded_bytes += len(chunk)
                            if downloaded > MAX_KML_PHOTO_BYTES:
                                raise ValueError(f"Remote photo exceeds {MAX_KML_PHOTO_BYTES} byte limit")
                            if downloaded_bytes > KML_MAX_DOWNLOAD_BYTES:
                                download_budget_exhausted = True
                                raise ValueError("job download budget exhausted")
                            f.write(chunk)

                    # Shared decode-safety gate (S-10).
                    img, image_error = open_validated_image(filepath)
                    if img is None:
                        raise ValueError(image_error)

                    img.thumbnail((3072, 3072), Image.Resampling.LANCZOS)
                    img.save(filepath, format='JPEG', quality=80, optimize=True)

                    thumb_img = img.copy()
                    thumb_img.thumbnail((800, 800), Image.Resampling.LANCZOS)
                    thumb_img.save(thumb_path, format='JPEG', quality=70, optimize=True)

                    c.execute('INSERT INTO photos (spot_id, filename) VALUES (?, ?)', (spot_id, filename))
                    conn.commit()
                    photo_count += 1
                except Exception as e:
                    if time.monotonic() >= deadline:
                        deadline_exhausted = True
                    photos_failed += 1
                    # S-14: structured and truncated; the URL is logged without its
                    # query/fragment, and query fragments inside exception text are
                    # stripped too (remote URLs can carry credentials).
                    LOGGER.warning(
                        "KML job %s: photo failed spot=%s url=%s error=%s: %s",
                        job_id, clean_log_value(name, 80), redact_url(url),
                        type(e).__name__, clean_log_value(re.sub(r'\?\S*', '', str(e)))
                    )
                    for partial in (filepath, thumb_path):
                        if os.path.exists(partial):
                            os.remove(partial)
                finally:
                    if response is not None:
                        response.close()

            if (photos_failed > failed_before
                    or photos_budget_skipped > budget_skipped_before):
                affected_spots.append(name)

            imported_spots += 1

            # calculate progress across processed placemarks, imported or skipped
            progress_percent = round((imported_spots + skipped_spots) / total_spots * 100)
            c.execute(
                'UPDATE import_progress SET imported=?, skipped=?, photos_failed=?, photos_budget_skipped=?, progress=?, last_updated=CURRENT_TIMESTAMP WHERE job_id=?',
                (imported_spots, skipped_spots, photos_failed, photos_budget_skipped, progress_percent, job_id)
            )
            conn.commit()

        # Per-URL skips stay silent; one structured summary names every exhausted
        # budget so photos_budget_skipped remains explainable from the log (S-14).
        exhausted_budgets = []
        if download_budget_exhausted:
            exhausted_budgets.append(f"download_bytes={KML_MAX_DOWNLOAD_BYTES}")
        if attempt_budget_exhausted:
            exhausted_budgets.append(f"fetch_attempts={KML_MAX_FETCH_ATTEMPTS}")
        if deadline_exhausted:
            exhausted_budgets.append(f"deadline_seconds={KML_MAX_JOB_SECONDS}")
        if exhausted_budgets:
            LOGGER.warning(
                "KML job %s: photo budgets exhausted (%s); %s photos skipped without a fetch",
                job_id, ", ".join(exhausted_budgets), photos_budget_skipped
            )

        notification_budgets = []
        if download_budget_exhausted:
            notification_budgets.append('download_bytes')
        if attempt_budget_exhausted:
            notification_budgets.append('fetch_attempts')
        if deadline_exhausted:
            notification_budgets.append('deadline')
        if photo_count_budget_exhausted:
            notification_budgets.append('photos_per_spot')
        return {
            'affected_spots': affected_spots,
            'exhausted_budgets': notification_budgets,
            'imported': imported_spots,
            'photos_budget_skipped': photos_budget_skipped,
            'photos_failed': photos_failed,
            'skipped': skipped_spots,
            'total': total_spots,
        }
    finally:
        conn.close()


# Google Maps link scraping
def expand_url(short_url):
    try:
        # The hostname-form URL, not response.url: the latter carries the pinned IP
        # the socket dialled, which is an implementation detail of the S-15 defence
        # and not something to hand back to a client as the expanded link.
        response, final_url = fetch_url_safely(
            short_url, allowed_hosts=GOOGLE_MAPS_HOSTS, timeout=10, with_final_url=True
        )
        response.close()
        return final_url
    except (requests.RequestException, ValueError) as e:
        return None

def extract_coordinates(url):
    match = re.search(r'@(-?\d+\.\d+),(-?\d+\.\d+)', url)
    if match:
        return float(match.group(1)), float(match.group(2))
    return None, None

@app.route("/parse-maps-link", methods=["POST"])
@require_auth
def parse_maps_link():
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        return jsonify({"error": "Missing 'url' in request body"}), 400

    short_url = data["url"]

    expanded_url = expand_url(short_url)
    if not expanded_url:
        return jsonify({"error": "Failed to expand URL"}), 400

    lat, lng = extract_coordinates(expanded_url)

    return jsonify({
        "expanded_url": expanded_url,
        "latitude": lat,
        "longitude": lng
    })



# =====================
# Run app
# =====================
if __name__ == '__main__':
    app.run(debug=False)
