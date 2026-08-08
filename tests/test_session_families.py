"""Stage 10.2 home suite: session families and atomic rotation (S-03 + S-05).

Covers family lineage on login/rotation, barrier-based concurrent presentation
(at most one successor per presented token), consumed-token replay revoking the
whole family with the auth.refresh_replay audit event and a cleared cookie,
family-scoped logout (other devices stay in, copied access JWTs die at once),
auth_version bumps on disable/reset/password change, the require_auth identity
gate (family-active + generation + current status), IP-change self-healing, and
the expiry sweep staying inert for ancient tokens.
"""

import importlib.util
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid

import bcrypt
import jwt


WORK = tempfile.mkdtemp(prefix="mv_families_")
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


def make_user(username, password, role="user"):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, first_name, last_name, email) "
        "VALUES (?, ?, ?, ?, 'approved', ?, 'Fam', 'User', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            role,
            "2026-07-19T00:00:00",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def clear_buckets():
    backend.PUBLIC_BUCKET.clear()
    backend.AUTH_BUCKET.clear()
    backend.PRIVATE_BUCKET.clear()


def cookie_value(response):
    for header in response.headers.getlist("Set-Cookie"):
        match = re.match(r"refresh_token=([^;]+)", header)
        if match:
            return match.group(1)
    return None


def login_session(username, password):
    clear_buckets()
    client = app.test_client()
    login = client.post("/login", json={"username": username, "password": password})
    login_cookie = cookie_value(login)
    refresh = client.post("/auth/refresh")
    token = refresh.get_json().get("access_token") if refresh.status_code == 200 else None
    return client, login_cookie, refresh, token


def bare_client_with(cookie):
    client = app.test_client()
    client.set_cookie("refresh_token", cookie, path="/auth")
    return client


def family_rows(family_id):
    conn = backend.get_db()
    rows = conn.execute(
        "SELECT id, status, consumed_at, predecessor_id FROM refresh_tokens "
        "WHERE family_id = ? ORDER BY id",
        (family_id,),
    ).fetchall()
    conn.close()
    return rows


def audit_rows(action):
    conn = backend.get_db()
    rows = conn.execute(
        "SELECT actor_id, actor_username FROM audit_log WHERE action = ? ORDER BY id",
        (action,),
    ).fetchall()
    conn.close()
    return rows


user_a = make_user("fam_a", "FamilyA1!")
user_b = make_user("fam_b", "FamilyB1!")
boss_id = make_user("fam_boss", "FamBoss1!", role="super_admin")

print("== Family lineage on login and rotation ==")
client_a, login_cookie_a, refresh_a, token_a = login_session("fam_a", "FamilyA1!")
payload_a = jwt.decode(token_a, backend.ACCESS_TOKEN_SECRET, algorithms=["HS256"])
family_a = payload_a.get("fam")
check(bool(family_a) and payload_a.get("ver") == 0, "access JWT carries the family id and generation 0")
rows = family_rows(family_a)
check(
    len(rows) == 2
    and rows[0][1] == "consumed" and rows[0][2] is not None and rows[0][3] is None
    and rows[1][1] == "active" and rows[1][2] is None and rows[1][3] == rows[0][0],
    f"rotation retains the consumed predecessor and links the successor (rows {rows})",
)
check(
    client_a.get("/maps", headers={"Authorization": f"Bearer {token_a}"}).status_code == 200,
    "the minted access JWT passes the identity gate",
)

print("\n== Replay revokes the whole family ==")
clear_buckets()
replay = bare_client_with(login_cookie_a).post("/auth/refresh")
replay_cookie = "\n".join(replay.headers.getlist("Set-Cookie"))
check(replay.status_code == 401, "presenting the consumed login token is rejected")
check(family_rows(family_a) == [], "the entire family is revoked, including the live head")
check(
    "refresh_token=;" in replay_cookie and "Max-Age=0" in replay_cookie and "Path=/auth" in replay_cookie,
    "the replayed cookie is cleared in the 401 response",
)
check(
    audit_rows("auth.refresh_replay") == [(user_a, "fam_a")],
    "auth.refresh_replay is written with the family's user as actor",
)
clear_buckets()
check(
    client_a.post("/auth/refresh").status_code == 401,
    "the rotated head token died with its family",
)
check(
    client_a.get("/maps", headers={"Authorization": f"Bearer {token_a}"}).status_code == 401,
    "the family's outstanding access JWT dies at the identity gate",
)
client_a2, _, refresh_a2, token_a2 = login_session("fam_a", "FamilyA1!")
check(
    refresh_a2.status_code == 200
    and client_a2.get("/maps", headers={"Authorization": f"Bearer {token_a2}"}).status_code == 200,
    "a lost-response victim recovers with exactly one new login",
)

print("\n== Barrier concurrency: one presented token, at most one successor ==")
client_c, login_cookie_c, _, _ = login_session("fam_a", "FamilyA1!")
head_cookie = cookie_value(client_c.post("/auth/refresh"))
conn = backend.get_db()
family_c, head_row_id = conn.execute(
    "SELECT family_id, id FROM refresh_tokens WHERE status = 'active' "
    "ORDER BY id DESC LIMIT 1"
).fetchone()
conn.close()
clear_buckets()
barrier = threading.Barrier(6)
statuses = []
lock = threading.Lock()


def presenter():
    presenter_client = bare_client_with(head_cookie)
    barrier.wait()
    status = presenter_client.post("/auth/refresh").status_code
    with lock:
        statuses.append(status)


threads = [threading.Thread(target=presenter) for _ in range(6)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
conn = backend.get_db()
successors = conn.execute(
    "SELECT COUNT(*) FROM refresh_tokens WHERE predecessor_id = ?",
    (head_row_id,),
).fetchone()[0]
conn.close()
check(
    statuses.count(200) == 1 and statuses.count(401) == 5,
    f"exactly one concurrent presenter wins (statuses {sorted(statuses)})",
)
check(successors <= 1, f"the presented token minted at most one successor ({successors})")
check(
    family_rows(family_c) == [],
    "the concurrent double-presentation revoked the family (strict, no grace)",
)

print("\n== Logout is family-scoped ==")
client_d, login_cookie_d, _, token_d = login_session("fam_a", "FamilyA1!")
client_e, _, _, token_e = login_session("fam_a", "FamilyA1!")
family_d = jwt.decode(token_d, backend.ACCESS_TOKEN_SECRET, algorithms=["HS256"])["fam"]
clear_buckets()
logout_d = client_d.post("/auth/logout")
check(logout_d.status_code == 200 and family_rows(family_d) == [], "logout deletes its own family")
check(
    app.test_client().get("/maps", headers={"Authorization": f"Bearer {token_d}"}).status_code == 401,
    "a copied access JWT from the logged-out family dies immediately",
)
check(
    client_e.post("/auth/refresh").status_code == 200
    and app.test_client().get("/maps", headers={"Authorization": f"Bearer {token_e}"}).status_code == 200,
    "the other device's family keeps refreshing and its access JWT stays valid",
)

print("\n== Logout works from a consumed family member ==")
client_f, login_cookie_f, _, _ = login_session("fam_a", "FamilyA1!")
clear_buckets()
consumed_logout = bare_client_with(login_cookie_f).post("/auth/logout")
check(consumed_logout.status_code == 200, "logout accepts a consumed member token")
clear_buckets()
check(
    client_f.post("/auth/refresh").status_code == 401,
    "the consumed-member logout still revoked the live head",
)

print("\n== auth_version bumps: password change ==")
client_b, _, _, token_b = login_session("fam_b", "FamilyB1!")
changed = client_b.post(
    "/changepwd",
    headers={"Authorization": f"Bearer {token_b}"},
    json={"old_password": "FamilyB1!", "new_password": "FamilyB2!", "repeat_password": "FamilyB2!"},
)
check(changed.status_code == 200, "self password change succeeds")
check(
    client_b.get("/maps", headers={"Authorization": f"Bearer {token_b}"}).status_code == 401,
    "the pre-change access JWT dies immediately",
)
clear_buckets()
check(client_b.post("/auth/refresh").status_code == 401, "every family is revoked by the change")
client_b2, _, _, token_b2 = login_session("fam_b", "FamilyB2!")
check(
    jwt.decode(token_b2, backend.ACCESS_TOKEN_SECRET, algorithms=["HS256"])["ver"] == 1,
    "the next session carries the bumped generation",
)

print("\n== auth_version bumps: admin reset and disable ==")
_, _, _, boss_token = login_session("fam_boss", "FamBoss1!")
clear_buckets()
reset = app.test_client().post(
    f"/admin/users/{user_b}/resetpwd",
    headers={"Authorization": f"Bearer {boss_token}"},
    json={"new_password": "FamilyB3!"},
)
check(reset.status_code == 200, "admin password reset succeeds")
check(
    app.test_client().get("/maps", headers={"Authorization": f"Bearer {token_b2}"}).status_code == 401,
    "the target's access JWT dies immediately on admin reset",
)
clear_buckets()
check(client_b2.post("/auth/refresh").status_code == 401, "admin reset revokes the target's families")
client_b3, _, _, token_b3 = login_session("fam_b", "FamilyB3!")
check(token_b3 is not None, "the admin-set password logs in")
clear_buckets()
disable = app.test_client().post(
    f"/admin/users/{user_b}/disable",
    headers={"Authorization": f"Bearer {boss_token}"},
)
check(
    disable.status_code == 200
    and app.test_client().get("/maps", headers={"Authorization": f"Bearer {token_b3}"}).status_code == 401,
    "disable kills the target's access JWT immediately",
)
clear_buckets()
enable = app.test_client().post(
    f"/admin/users/{user_b}/enable",
    headers={"Authorization": f"Bearer {boss_token}"},
)
check(
    enable.status_code == 200
    and app.test_client().get("/maps", headers={"Authorization": f"Bearer {token_b3}"}).status_code == 401,
    "re-enabling does not resurrect pre-disable access JWTs (generation moved on)",
)
client_b4, _, refresh_b4, _ = login_session("fam_b", "FamilyB3!")
check(refresh_b4.status_code == 200, "the re-enabled account starts a fresh session normally")

print("\n== Identity gate: malformed and orphaned tokens ==")
now_ts = int(time.time())
bare_payload = {
    "user_id": user_a,
    "username": "fam_a",
    "role": "user",
    "iat": now_ts,
    "jti": str(uuid.uuid4()),
    "exp": now_ts + 600,
}
bare_token = jwt.encode(bare_payload, backend.ACCESS_TOKEN_SECRET, algorithm="HS256")
clear_buckets()
check(
    app.test_client().get("/maps", headers={"Authorization": f"Bearer {bare_token}"}).status_code == 401,
    "a validly signed token without family/generation claims is rejected",
)
client_g, _, _, token_g = login_session("fam_a", "FamilyA1!")
family_g = jwt.decode(token_g, backend.ACCESS_TOKEN_SECRET, algorithms=["HS256"])["fam"]
conn = backend.get_db()
conn.execute(
    "UPDATE refresh_tokens SET expires = 1 WHERE family_id = ? AND status = 'active'",
    (family_g,),
)
conn.commit()
conn.close()
check(
    client_g.get("/maps", headers={"Authorization": f"Bearer {token_g}"}).status_code == 401,
    "an access JWT whose family head expired fails the gate",
)

print("\n== Expiry sweep leaves ancient tokens inert ==")
client_h, login_cookie_h, _, _ = login_session("fam_a", "FamilyA1!")
family_h = None
conn = backend.get_db()
family_h = conn.execute(
    "SELECT family_id FROM refresh_tokens WHERE token = ?",
    (backend.hashlib.sha256(login_cookie_h.encode()).hexdigest(),),
).fetchone()[0]
conn.execute(
    "UPDATE refresh_tokens SET expires = 1 WHERE family_id = ? AND status = 'consumed'",
    (family_h,),
)
conn.commit()
conn.close()
clear_buckets()
replay_count_before = len(audit_rows("auth.refresh_replay"))
sweep_refresh = client_h.post("/auth/refresh")
check(sweep_refresh.status_code == 200, "refresh succeeds while sweeping the expired predecessor")
ancient = bare_client_with(login_cookie_h).post("/auth/refresh")
check(
    ancient.status_code == 401
    and len(audit_rows("auth.refresh_replay")) == replay_count_before,
    "a swept ancient token is a plain 401, not a replay event",
)
clear_buckets()
check(
    client_h.post("/auth/refresh").status_code == 200,
    "the live family survived the ancient-token presentation",
)

print("\n== IP-change self-healing (BIND_TOKEN_TO_IP) ==")
original_bind = backend.BIND_TOKEN_TO_IP
backend.BIND_TOKEN_TO_IP = True
try:
    clear_buckets()
    client_i = app.test_client()
    client_i.post("/login", json={"username": "fam_a", "password": "FamilyA1!"},
                  environ_base={"REMOTE_ADDR": "10.0.0.9"})
    bound = client_i.post("/auth/refresh", environ_base={"REMOTE_ADDR": "10.0.0.9"})
    bound_token = bound.get_json()["access_token"]
    check(
        client_i.get("/maps", headers={"Authorization": f"Bearer {bound_token}"},
                     environ_base={"REMOTE_ADDR": "10.0.0.9"}).status_code == 200,
        "an IP-bound token works from its own address",
    )
    check(
        client_i.get("/maps", headers={"Authorization": f"Bearer {bound_token}"},
                     environ_base={"REMOTE_ADDR": "10.0.0.10"}).status_code == 401,
        "the same token is rejected from a new address",
    )
    clear_buckets()
    healed = client_i.post("/auth/refresh", environ_base={"REMOTE_ADDR": "10.0.0.10"})
    healed_token = healed.get_json().get("access_token") if healed.status_code == 200 else None
    check(
        healed.status_code == 200
        and client_i.get("/maps", headers={"Authorization": f"Bearer {healed_token}"},
                         environ_base={"REMOTE_ADDR": "10.0.0.10"}).status_code == 200,
        "one refresh from the new address self-heals the session",
    )
finally:
    backend.BIND_TOKEN_TO_IP = original_bind

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
