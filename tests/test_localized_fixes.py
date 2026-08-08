import ast
import importlib.util
import os
import shutil
import statistics
import sys
import tempfile
import time
import uuid

import bcrypt
import jwt

from werkzeug.exceptions import TooManyRequests


WORK = tempfile.mkdtemp(prefix="mv_localized_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy(
    "/workspace/markervault/markervault_config.py",
    os.path.join(WORK, "markervault_config.py"),
)
shutil.copy(
    "/workspace/markervault/username_validation.py",
    os.path.join(WORK, "username_validation.py"),
)
shutil.copy(
    "/workspace/markervault/email_delivery.py",
    os.path.join(WORK, "email_delivery.py"),
)
os.chdir(WORK)
if WORK not in sys.path:
    sys.path.insert(0, WORK)
os.environ["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64

spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)

backend.COOKIE_SECURE = False
app = backend.app
app.testing = True

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


def make_user(username, password):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, first_name, last_name, email) "
        "VALUES (?, ?, ?, 'user', 'approved', ?, 'Stage', 'Three', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            "2026-07-19T00:00:00",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def login_session(username, password):
    client = app.test_client()
    login = client.post("/login", json={"username": username, "password": password})
    refresh = client.post("/auth/refresh")
    token = refresh.get_json().get("access_token") if refresh.status_code == 200 else None
    return client, login, refresh, token


def refresh_count(user_id):
    # Active family heads only: rotation retains consumed predecessor rows for
    # replay detection, so raw row counts no longer equal live sessions.
    conn = backend.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND status = 'active'",
        (user_id,),
    ).fetchone()[0]
    conn.close()
    return count


user_id = make_user("localized", "Localized1!")

print("\n== Login bcrypt invariant ==")
real_checkpw = backend.bcrypt.checkpw
real_hashpw = backend.bcrypt.hashpw
checkpw_calls = []
hashpw_calls = []


def counted_checkpw(password, password_hash):
    checkpw_calls.append((password, password_hash))
    return real_checkpw(password, password_hash)


def counted_hashpw(password, salt):
    hashpw_calls.append((password, salt))
    return real_hashpw(password, salt)


backend.bcrypt.checkpw = counted_checkpw
backend.bcrypt.hashpw = counted_hashpw
backend.PUBLIC_BUCKET.clear()
unknown = app.test_client().post(
    "/login",
    json={"username": "missing-user", "password": "Wrong123!"},
)
unknown_checks = len(checkpw_calls)
unknown_hashes = len(hashpw_calls)

checkpw_calls.clear()
hashpw_calls.clear()
backend.PUBLIC_BUCKET.clear()
known = app.test_client().post(
    "/login",
    json={"username": "localized", "password": "Wrong123!"},
)
known_checks = len(checkpw_calls)
known_hashes = len(hashpw_calls)
backend.bcrypt.checkpw = real_checkpw
backend.bcrypt.hashpw = real_hashpw

check(
    unknown.status_code == 401 and known.status_code == 401,
    "unknown user and wrong password retain the same 401 contract",
)
check(
    unknown_checks == 1 and known_checks == 1,
    f"both failed-login paths perform exactly one bcrypt check ({unknown_checks}, {known_checks})",
)
check(
    unknown_hashes == 0 and known_hashes == 0,
    f"failed-login paths generate no bcrypt hashes ({unknown_hashes}, {known_hashes})",
)

unknown_times = []
known_times = []
for index in range(3):
    backend.PUBLIC_BUCKET.clear()
    started = time.perf_counter()
    app.test_client().post(
        "/login",
        json={"username": f"missing-{index}", "password": "Wrong123!"},
    )
    unknown_times.append(time.perf_counter() - started)

    backend.PUBLIC_BUCKET.clear()
    started = time.perf_counter()
    app.test_client().post(
        "/login",
        json={"username": "localized", "password": "Wrong123!"},
    )
    known_times.append(time.perf_counter() - started)

timing_ratio = statistics.median(unknown_times) / statistics.median(known_times)
check(
    0.60 <= timing_ratio <= 1.67,
    f"failed-login timings stay broadly comparable (ratio {timing_ratio:.2f})",
)

print("\n== Refresh-cookie logout semantics ==")
client, login, refresh, access_token = login_session("localized", "Localized1!")
check(
    login.status_code == 200 and refresh.status_code == 200 and access_token,
    "test session logs in and refreshes",
)
check(refresh_count(user_id) == 1, "one current refresh session exists before logout")

now = int(time.time())
expired_payload = {
    "user_id": user_id,
    "username": "localized",
    "role": "user",
    "iat": now - 120,
    "jti": str(uuid.uuid4()),
    "exp": now - 60,
}
if backend.BIND_TOKEN_TO_IP:
    expired_payload["ip"] = "127.0.0.1"
expired_token = jwt.encode(
    expired_payload,
    backend.ACCESS_TOKEN_SECRET,
    algorithm="HS256",
)
logout = client.post(
    "/auth/logout",
    headers={"Authorization": f"Bearer {expired_token}"},
)
set_cookie = "\n".join(logout.headers.getlist("Set-Cookie"))
check(logout.status_code == 200, "expired access token does not block logout")
check(refresh_count(user_id) == 0, "logout revokes the presented refresh session")
check(
    "refresh_token=" in set_cookie and "Max-Age=0" in set_cookie and "Path=/auth" in set_cookie,
    "logout unconditionally expires the scoped refresh cookie",
)
check(
    client.get_cookie("refresh_token", path="/auth") is None,
    "test client no longer retains the refresh cookie",
)

conn = backend.get_db()
audit_row = conn.execute(
    "SELECT actor_id, actor_username, actor_role, client_ip "
    "FROM audit_log WHERE action = 'auth.logout' ORDER BY id DESC LIMIT 1"
).fetchone()
conn.close()
check(
    audit_row == (user_id, "localized", "user", "127.0.0.1"),
    f"logout audit actor comes from the refresh session (got {audit_row})",
)

copied_bearer = app.test_client().get(
    "/maps",
    headers={"Authorization": f"Bearer {access_token}"},
)
check(
    copied_bearer.status_code == 401,
    "final guarantee: logout kills the family's copied access JWT immediately",
)

print("\n== Independent and absent refresh sessions ==")
first, _, first_refresh, first_access = login_session("localized", "Localized1!")
second, _, second_refresh, _ = login_session("localized", "Localized1!")
check(
    first_refresh.status_code == 200
    and second_refresh.status_code == 200
    and refresh_count(user_id) == 2,
    "two independent refresh sessions coexist",
)
first_logout = first.post(
    "/auth/logout",
    headers={"Authorization": f"Bearer {first_access}"},
)
check(
    first_logout.status_code == 200 and refresh_count(user_id) == 1,
    "logout revokes only the presented refresh session",
)
second_rotated = second.post("/auth/refresh")
check(
    second_rotated.status_code == 200 and refresh_count(user_id) == 1,
    "independent refresh session remains usable",
)

total_before = refresh_count(user_id)
empty_client = app.test_client()
empty_logout = empty_client.post("/auth/logout")
empty_cookie = "\n".join(empty_logout.headers.getlist("Set-Cookie"))
total_after = refresh_count(user_id)
check(
    empty_logout.status_code == 200 and total_after == total_before,
    "logout without a server-side session is idempotent",
)
check(
    "refresh_token=" in empty_cookie and "Max-Age=0" in empty_cookie,
    "logout without a session still clears the browser cookie",
)

print("\n== Rate-limit buckets evict refilled entries (F4) ==")
# Entries are allocated before a request is known to be legitimate, so a stream of
# distinct source addresses used to grow these dicts for the process lifetime.
# Driven directly against rate_limit with a frozen clock so the accounting is exact.
frozen = 1_000_000
bucket = {}
interval = backend.PUBLIC_REFILL_INTERVAL
effective_max = 1 + backend.BURST

with app.test_request_context("/"):
    for index in range(200):
        backend.rate_limit(f"10.0.{index // 256}.{index % 256}", frozen, bucket, interval)
    filled = len(bucket)

    # Nothing has aged yet: every entry spent a token this instant, so none would
    # refill to full and the dict must not shrink.
    backend.rate_limit("10.9.9.9", frozen, bucket, interval)
    unaged = len(bucket)

    # One refill interval later every idle entry is back to full, and a full entry is
    # indistinguishable from an absent one. Each call scans a bounded slice, so the
    # dict drains over subsequent calls rather than in a single O(n) sweep.
    # The caller exhausts its own bucket partway through and starts receiving 429s;
    # that path evicts before aborting, which is what a real flood looks like.
    aged = frozen + interval
    for _ in range(60):
        try:
            backend.rate_limit("10.9.9.9", aged, bucket, interval)
        except TooManyRequests:
            pass
    drained = len(bucket)

check(filled == 200, f"200 distinct source addresses allocate 200 entries ({filled})")
check(
    unaged == 201,
    f"entries that have not yet refilled are kept, not evicted ({unaged})",
)
check(
    drained < filled,
    f"entries that would refill to full are evicted as the limiter runs ({drained})",
)
check(
    drained <= 2,
    f"a bounded per-call scan drains the stale entries, not just a token few ({drained})",
)
check(
    "10.9.9.9" in bucket,
    "the actively calling address keeps its entry while it is still spending tokens",
)

# The predicate must be "would refill to full NOW", not "is stored as full": entries
# are stored below full, so a stored-value test would evict almost nothing.
stale = {"1.2.3.4": {"requests": effective_max - 1, "last_refill": frozen}}
with app.test_request_context("/"):
    backend.rate_limit("5.6.7.8", frozen + interval, stale, interval)
check(
    "1.2.3.4" not in stale,
    "an entry stored below full is evicted once elapsed time would refill it",
)

# Eviction compares against the caller's effective_max, so a bucket shared between two
# different limits would evict entries as full that are not — handing back tokens.
tree = ast.parse(open("/workspace/markervault/backend.py", encoding="utf-8").read())
signatures = {}
for node in ast.walk(tree):
    if not isinstance(node, ast.Call) or getattr(node.func, "id", None) != "rate_limit":
        continue
    if len(node.args) < 4:
        continue
    burst = next(
        (ast.unparse(kw.value) for kw in node.keywords if kw.arg == "burst"),
        "BURST",
    )
    signatures.setdefault(ast.unparse(node.args[2]), set()).add(
        (ast.unparse(node.args[3]), burst)
    )
check(
    len(signatures) == 5 and all(len(pairs) == 1 for pairs in signatures.values()),
    f"each bucket is used with exactly one (interval, burst) pair "
    f"({ {name: sorted(pairs) for name, pairs in signatures.items() if len(pairs) != 1} })",
)

print("\n== Per-username login throttle (F11) ==")
# Every other bucket keys on client IP, so a distributed attempt against one known
# account was bounded only by bcrypt's cost. Each attempt below comes from its own
# source address, which isolates this from the per-IP buckets entirely.
throttle_user = "throttled"
make_user(throttle_user, "Abcd1234!")


def attempt(username, password, source):
    backend.PUBLIC_BUCKET.clear()
    return app.test_client().post(
        "/login",
        json={"username": username, "password": password},
        environ_base={"REMOTE_ADDR": source},
    )


backend.USERNAME_BUCKET.clear()
distributed = [
    attempt(throttle_user, "Wrong123!", f"198.51.100.{index}").status_code
    for index in range(1, 11)
]
blocked = attempt(throttle_user, "Wrong123!", "203.0.113.99")
check(
    distributed == [401] * 10,
    f"the first ten wrong passwords answer 401 as before ({set(distributed)})",
)
check(
    blocked.status_code == 429,
    f"the eleventh is throttled from a source address that never tried ({blocked.status_code})",
)
check(
    blocked.get_json() == {"error": "Too Many Requests"},
    f"the throttle answers in the limiter's existing JSON shape ({blocked.get_json()})",
)

# A correct password must clear the counter, or the one person who knows it can be
# throttled out of their own account.
backend.USERNAME_BUCKET.clear()
for index in range(9):
    attempt(throttle_user, "Wrong123!", f"198.51.100.{index}")
recovered = attempt(throttle_user, "Abcd1234!", "203.0.113.7")
check(
    recovered.status_code == 200 and throttle_user not in backend.USERNAME_BUCKET,
    f"a successful login clears the counter ({recovered.status_code})",
)
after_success = [
    attempt(throttle_user, "Wrong123!", f"198.51.100.{index}").status_code
    for index in range(9)
]
check(
    set(after_success) == {401},
    f"the full failure allowance is available again after that success ({set(after_success)})",
)

# A username that does not exist must throttle identically, or the 429-vs-401
# difference becomes an account-existence oracle.
backend.USERNAME_BUCKET.clear()
ghost = [
    attempt("no-such-account", "Wrong123!", f"198.51.100.{index}").status_code
    for index in range(1, 11)
]
ghost_blocked = attempt("no-such-account", "Wrong123!", "203.0.113.98")
check(
    ghost == [401] * 10 and ghost_blocked.status_code == 429,
    f"a nonexistent username throttles exactly like a real one ({ghost_blocked.status_code})",
)

# Case folding: SQLite matches the account NOCASE, so the counter must not be
# dodgeable by changing capitalization.
backend.USERNAME_BUCKET.clear()
mixed = [
    attempt(name, "Wrong123!", f"198.51.100.{index}").status_code
    for index, name in enumerate(
        ["throttled", "THROTTLED", "Throttled", "tHrOtTlEd", "throttled",
         "THROTTLED", "Throttled", "tHrOtTlEd", "throttled", "THROTTLED"],
        start=1,
    )
]
case_blocked = attempt("ThRoTtLeD", "Wrong123!", "203.0.113.97")
check(
    mixed == [401] * 10 and case_blocked.status_code == 429,
    f"capitalization variants share one bucket ({case_blocked.status_code})",
)
check(
    len(backend.USERNAME_BUCKET) == 1 and "throttled" in backend.USERNAME_BUCKET,
    f"the shared bucket is keyed case-folded ({list(backend.USERNAME_BUCKET)})",
)

# Exhaustion must self-heal without intervention — that is what makes the accepted
# lockout-as-denial-of-service tolerable rather than a way to hold an account down.
backend.USERNAME_BUCKET.clear()
real_time = backend.time.time
frozen_now = real_time()
backend.time.time = lambda: frozen_now
try:
    for index in range(10):
        attempt(throttle_user, "Wrong123!", f"198.51.100.{index}")
    still_blocked = attempt(throttle_user, "Wrong123!", "203.0.113.96").status_code
    backend.time.time = lambda: frozen_now + backend.USERNAME_REFILL_INTERVAL
    healed = attempt(throttle_user, "Wrong123!", "203.0.113.95").status_code
finally:
    backend.time.time = real_time
check(
    still_blocked == 429 and healed == 401,
    f"exhaustion self-heals one attempt per refill interval ({still_blocked} then {healed})",
)

# The keys are attacker-minted, so without F4's eviction this would be a new
# unbounded dict.
backend.USERNAME_BUCKET.clear()
frozen = 2_000_000
for index in range(200):
    backend.charge_username_failure(f"ghost-{index}", frozen)
minted = len(backend.USERNAME_BUCKET)
for _ in range(60):
    backend.charge_username_failure("still-trying", frozen + backend.USERNAME_REFILL_INTERVAL)
check(minted == 200, f"200 distinct submitted usernames allocate 200 entries ({minted})")
check(
    len(backend.USERNAME_BUCKET) <= 2,
    f"the username bucket is drained by F4's eviction too ({len(backend.USERNAME_BUCKET)})",
)
backend.USERNAME_BUCKET.clear()

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
