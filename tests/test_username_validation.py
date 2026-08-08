"""Direct unit coverage for the shared username validator.

HTTP and CLI entry-point integration is added in UV-2. This suite uses the isolated
bootstrap required by backend.py imports.
"""
import importlib.util
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid

import bcrypt
from datetime import datetime


WORK = tempfile.mkdtemp(prefix="mv_uv_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy(
    "/workspace/markervault/username_validation.py",
    os.path.join(WORK, "username_validation.py"),
)
shutil.copy(
    "/workspace/markervault/markervault_config.py",
    os.path.join(WORK, "markervault_config.py"),
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
backend.rate_limit = lambda *a, **k: None
app = backend.app
app.testing = True

from username_validation import USERNAME_MAX, validate_username


PASS = FAIL = 0


def check(cond, label):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def invalid(raw, label, expected=None):
    ok, cleaned, reason = validate_username(raw)
    check(
        not ok and cleaned is None and (expected is None or reason == expected),
        f"{label} rejected cleanly (reason={reason!r})",
    )


def make_user(username, password, role="user", email=None):
    conn = backend.get_db()
    uid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email) VALUES (?,?,?,?,?,?,?,?,?)",
        (
            uid,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            role,
            "approved",
            datetime.now().isoformat(),
            "First",
            "Last",
            email or f"{uuid.uuid4().hex}@x.com",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(uid)
    return uid


def login(username, password):
    cl = app.test_client()
    response = cl.post("/login", json={"username": username, "password": password})
    if response.status_code != 200:
        return cl, None
    refresh = cl.post("/auth/refresh")
    return cl, refresh.get_json().get("access_token")


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def registration(username, email):
    return {
        "username": username,
        "password": "Valid123!",
        "first_name": "Reg",
        "last_name": "User",
        "email": email,
    }


def admin_payload(username, email):
    return {
        "username": username,
        "password": "Valid123!",
        "first_name": "Admin",
        "last_name": "Created",
        "email": email,
        "role": "user",
    }


def profile_payload(username, email):
    return {
        "username": username,
        "first_name": "Edited",
        "last_name": "User",
        "email": email,
        "company": "",
        "department": "",
        "birth_date": "",
        "sex": "",
    }


def run_cli(username):
    work = tempfile.mkdtemp(prefix="mv_uv_cli_")
    env = os.environ.copy()
    env["MARKERVAULT_DB_PATH"] = os.path.join(work, "spots.db")
    result = subprocess.run(
        [
            sys.executable,
            "/workspace/markervault/create_users.py",
            "--username", username,
            "--password", "Valid123!",
            "--role", "user",
            "--first-name", "Cli",
            "--last-name", "User",
            "--email", "cli@x.com",
        ],
        cwd=work,
        env=env,
        text=True,
        input="",
        capture_output=True,
        timeout=20,
    )
    return result, work


print("== Shared username validator ==")
check(USERNAME_MAX == 32, f"USERNAME_MAX is 32 (got {USERNAME_MAX})")

required = "Username is required"
invalid(123, "numeric input", required)
invalid(["a"], "list input", required)
invalid(None, "None input", required)
invalid("", "empty string", required)
invalid("   ", "whitespace-only string", required)

ok, cleaned, reason = validate_username("a" * 32)
check(ok and cleaned == "a" * 32 and reason is None, "32-character boundary accepted")
invalid("a" * 33, "33-character boundary", "Username must be at most 32 characters")

charset_error = "Username may contain only letters, digits, and . _ -"
invalid("bad\nname", "newline", charset_error)
invalid("bad\tname", "tab", charset_error)
invalid("bad\x00name", "NUL control character", charset_error)
invalid("zero\u200bwidth", "zero-width character", charset_error)
invalid("right\u202eleft", "bidi override", charset_error)
invalid("two words", "internal space", charset_error)

ok, cleaned, reason = validate_username("a.b_c-1")
check(ok and cleaned == "a.b_c-1" and reason is None, "allowlisted separators accepted")
ok, cleaned, reason = validate_username("  Trim.Me-1  ")
check(ok and cleaned == "Trim.Me-1" and reason is None, "leading/trailing whitespace trimmed")
ok, cleaned, reason = validate_username("CaseSensitive")
check(ok and cleaned == "CaseSensitive" and reason is None, "casing is preserved")

print("\n== /register integration ==")
client = app.test_client()
check(client.post("/register", json=["not", "an", "object"]).status_code == 400,
      "top-level JSON array -> 400, not 500")
check(client.post("/register", json="scalar").status_code == 400,
      "top-level JSON scalar -> 400, not 500")
check(client.post("/register", json=registration(123, "num@x.com")).status_code == 400,
      "non-string registration username -> 400")
check(client.post("/register", json=registration("r" * 33, "long@x.com")).status_code == 400,
      "registration rejects 33 characters")
check(client.post("/register", json=registration("bad\u200bname", "unicode@x.com")).status_code == 400,
      "registration rejects invalid Unicode")
register_32 = "r" * 32
r = client.post("/register", json=registration(register_32, "r32@x.com"))
check(r.status_code == 200, f"registration accepts 32 characters (got {r.status_code})")
r = client.post("/register", json=registration("  reg.trim-1  ", "trim@x.com"))
stored = backend.get_db().execute(
    "SELECT username FROM users WHERE email = 'trim@x.com'"
).fetchone()
check(r.status_code == 200 and stored[0] == "reg.trim-1", "registration stores trimmed username")

print("\n== /admin/users/create integration ==")
boss_id = make_user("boss", "Boss1234!", "super_admin", "boss@x.com")
boss, boss_t = login("boss", "Boss1234!")
check(bool(boss_t), "super-admin fixture logged in")
check(boss.post("/admin/users/create", headers=headers(boss_t),
                json=admin_payload(["bad"], "list@x.com")).status_code == 400,
      "non-string admin-create username -> 400")
check(boss.post("/admin/users/create", headers=headers(boss_t),
                json=admin_payload("c" * 33, "c33@x.com")).status_code == 400,
      "admin create rejects 33 characters")
check(boss.post("/admin/users/create", headers=headers(boss_t),
                json=admin_payload("bad name", "space@x.com")).status_code == 400,
      "admin create rejects invalid charset")
create_32 = "c" * 32
r = boss.post("/admin/users/create", headers=headers(boss_t),
              json=admin_payload(create_32, "c32@x.com"))
check(r.status_code == 200 and r.get_json().get("username") == create_32,
      f"admin create accepts 32 characters (got {r.status_code})")

print("\n== Admin-mediated rename integration ==")
target_id = make_user("rename_me", "Rename123!", "user", "rename@x.com")
rename_url = f"/admin/users/{target_id}/profile"
check(boss.put(rename_url, headers=headers(boss_t),
               json=profile_payload(999, "rename@x.com")).status_code == 400,
      "non-string rename username -> 400")
check(boss.put(rename_url, headers=headers(boss_t),
               json=profile_payload("e" * 33, "rename@x.com")).status_code == 400,
      "admin rename rejects 33 characters")
check(boss.put(rename_url, headers=headers(boss_t),
               json=profile_payload("bad\u202ename", "rename@x.com")).status_code == 400,
      "admin rename rejects bidi override")
unchanged = backend.get_db().execute(
    "SELECT username FROM users WHERE user_id = ?", (target_id,)
).fetchone()[0]
check(unchanged == "rename_me", "invalid rename attempts do not mutate the username")
rename_32 = "Edit" + ("x" * 28)
r = boss.put(rename_url, headers=headers(boss_t),
             json=profile_payload(f"  {rename_32}  ", "rename@x.com"))
check(r.status_code == 200 and r.get_json().get("username") == rename_32,
      "admin rename accepts 32 characters and trims")
case_only = rename_32.swapcase()
r = boss.put(rename_url, headers=headers(boss_t),
             json=profile_payload(case_only, "rename@x.com"))
stored_case = backend.get_db().execute(
    "SELECT username FROM users WHERE user_id = ?", (target_id,)
).fetchone()[0]
check(r.status_code == 200 and stored_case == case_only, "case-only rename remains supported")
r = boss.put(rename_url, headers=headers(boss_t),
             json=profile_payload(f"  {case_only}  ", "rename@x.com"))
check(r.status_code == 200 and r.get_json().get("username") == case_only,
      "whitespace-normalized same username remains a successful no-op")

print("\n== Deliberately unchanged login and self-profile behavior ==")
make_user("legacy bad", "Legacy123!", "user", "legacy@x.com")
legacy, legacy_t = login("legacy bad", "Legacy123!")
check(bool(legacy_t), "/login remains permissive for a legacy malformed stored username")
target_client, target_t = login(case_only, "Rename123!")
r = target_client.put(
    "/profile",
    headers=headers(target_t),
    json={
        "username": "invalid self rename",
        "first_name": "Self",
        "last_name": "Edit",
        "email": "rename@x.com",
        "company": "",
        "department": "",
        "birth_date": "",
        "sex": "",
    },
)
self_name = backend.get_db().execute(
    "SELECT username FROM users WHERE user_id = ?", (target_id,)
).fetchone()[0]
check(r.status_code == 200 and self_name == case_only,
      "PUT /profile still ignores username and cannot self-rename")

print("\n== create_users.py integration ==")
result, _ = run_cli("q" * 33)
check(result.returncode != 0 and "at most 32" in result.stderr,
      "CLI rejects 33 characters")
result, _ = run_cli("bad\nname")
check(result.returncode != 0 and "only letters" in result.stderr,
      "CLI rejects invalid charset")
result, _ = run_cli("")
check(result.returncode != 0 and "Username is required" in result.stderr
      and "Enter username" not in (result.stdout + result.stderr),
      "explicit empty --username errors without prompting")
cli_32 = "k" * 32
result, cli_work = run_cli(cli_32)
conn = sqlite3.connect(os.path.join(cli_work, "spots.db"))
cli_row = conn.execute("SELECT username FROM users").fetchone()
conn.close()
check(result.returncode == 0 and cli_row == (cli_32,),
      f"CLI accepts and stores 32 characters (rc={result.returncode}, row={cli_row})")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
