import os, sys, shutil, tempfile, importlib.util, uuid

# Copy backend.py into an isolated dir with a temp DB so we don't touch the real one.
WORK = tempfile.mkdtemp(prefix="mv_p1_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy("/workspace/markervault/username_validation.py", os.path.join(WORK, "username_validation.py"))
shutil.copy("/workspace/markervault/markervault_config.py", os.path.join(WORK, "markervault_config.py"))
shutil.copy("/workspace/markervault/email_delivery.py", os.path.join(WORK, "email_delivery.py"))
os.chdir(WORK)
if WORK not in sys.path: sys.path.insert(0, WORK)
os.environ["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64

spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)

backend.COOKIE_SECURE = False  # allow cookies over http test client
app = backend.app
app.testing = True
client = app.test_client()

import bcrypt, sqlite3
from datetime import datetime

PASS = 0
FAIL = 0
def check(cond, label):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")

def make_user(username, password, role, status):
    conn = backend.get_db()
    c = conn.cursor()
    c.execute("INSERT INTO users (user_id, username, password_hash, role, status, created) VALUES (?,?,?,?,?,?)",
              (str(uuid.uuid4()), username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role, status, datetime.now().isoformat()))
    conn.commit()
    uid = c.execute("SELECT user_id FROM users WHERE username=?", (username,)).fetchone()[0]
    conn.close()
    return uid

def login(username, password):
    """Return (status_code, access_token or None, cookies-carried-by-client)."""
    r = client.post("/login", json={"username": username, "password": password})
    if r.status_code != 200:
        return r.status_code, None
    # refresh cookie is now in the client jar; get an access token via /auth/refresh
    rr = client.post("/auth/refresh")
    tok = rr.get_json().get("access_token") if rr.status_code == 200 else None
    return r.status_code, tok

def auth_hdr(tok):
    return {"Authorization": f"Bearer {tok}"}

print("\n== 1. Registration creates a pending user, cannot log in ==")
r = client.post("/register", json={"username": "alice", "password": "Abcdef1!", "first_name": "Alice", "last_name": "A", "email": "alice@x.com"})
check(r.status_code == 200, f"/register returns 200 (got {r.status_code})")
conn = backend.get_db(); status = conn.execute("SELECT status FROM users WHERE username='alice'").fetchone()[0]; conn.close()
check(status == "pending", f"alice status is pending (got {status})")
sc, tok = login("alice", "Abcdef1!")
check(sc == 403, f"pending user login blocked with 403 (got {sc})")

print("\n== 2. Weak password + duplicate username rejected ==")
r = client.post("/register", json={"username": "bob", "password": "weak"})
check(r.status_code == 400, f"weak password -> 400 (got {r.status_code})")
r = client.post("/register", json={"username": "ALICE", "password": "Abcdef1!", "first_name": "Alice", "last_name": "A", "email": "alice2@x.com"})
check(r.status_code == 400, f"duplicate username (case-insensitive) -> 400 (got {r.status_code})")

print("\n== 3. Admin (CLI-style, pre-approved) can log in and approve ==")
# The primary actor is a SUPER-admin (admin-management — promote/demote/etc. — is super-only).
admin_id = make_user("admin", "Admin123!", "super_admin", "approved")
client_reset = app.test_client()  # fresh cookie jar for admin
def login2(cl, u, p):
    r = cl.post("/login", json={"username": u, "password": p})
    if r.status_code != 200: return r.status_code, None
    rr = cl.post("/auth/refresh")
    return r.status_code, (rr.get_json().get("access_token") if rr.status_code==200 else None)
sc, admin_tok = login2(client_reset, "admin", "Admin123!")
check(sc == 200 and admin_tok, f"admin login + token (sc={sc}, tok={'yes' if admin_tok else 'no'})")
# admin refresh payload should carry role
rp = client_reset.post("/auth/refresh").get_json()
check(rp.get("role") == "super_admin", f"refresh response includes role=super_admin (got {rp.get('role')})")

# list users
r = client_reset.get("/admin/users", headers=auth_hdr(admin_tok))
check(r.status_code == 200, f"admin can list users (got {r.status_code})")
users = r.get_json()
alice = next((u for u in users if u["username"] == "alice"), None)
check(alice is not None and alice["status"] == "pending", "alice shows as pending in admin list")

# approve alice
r = client_reset.post(f"/admin/users/{alice['user_id']}/approve", headers=auth_hdr(admin_tok))
check(r.status_code == 200, f"approve alice -> 200 (got {r.status_code})")
sc, alice_tok = login2(app.test_client(), "alice", "Abcdef1!")
check(sc == 200 and alice_tok, f"approved alice can now log in (sc={sc})")

print("\n== 4. Non-admin cannot reach admin routes ==")
alice_cl = app.test_client()
sc, alice_tok = login2(alice_cl, "alice", "Abcdef1!")
r = alice_cl.get("/admin/users", headers=auth_hdr(alice_tok))
check(r.status_code == 403, f"regular user hitting /admin/users -> 403 (got {r.status_code})")

print("\n== 5. Data routes require auth ==")
r = client.get("/maps")  # no token
check(r.status_code == 401, f"/maps with no token -> 401 (got {r.status_code})")
r = alice_cl.get("/maps", headers=auth_hdr(alice_tok))
check(r.status_code == 200, f"/maps with valid token -> 200 (got {r.status_code})")

print("\n== 6. Promote/demote (super-only), last-admin guard, disable ==")
# super promotes alice to admin
r = client_reset.post(f"/admin/users/{alice['user_id']}/role", headers=auth_hdr(admin_tok), json={"role": "admin"})
check(r.status_code == 200, f"super promotes alice to admin (got {r.status_code})")
# a regular admin (alice) CANNOT promote/demote anyone
alice_admin_cl = app.test_client()
_, alice_admin_tok = login2(alice_admin_cl, "alice", "Abcdef1!")
r = alice_admin_cl.post(f"/admin/users/{alice['user_id']}/role", headers=auth_hdr(alice_admin_tok), json={"role": "user"})
check(r.status_code == 403, f"regular admin cannot demote (super-only) -> 403 (got {r.status_code})")
# super demotes alice back to user
r = client_reset.post(f"/admin/users/{alice['user_id']}/role", headers=auth_hdr(admin_tok), json={"role": "user"})
check(r.status_code == 200, f"super demotes alice to user (got {r.status_code})")
# super is now the last admin-level account; the super cannot self-demote via UI anyway
# (super role is UI-immutable), so demoting it returns 403
r = client_reset.post(f"/admin/users/{admin_id}/role", headers=auth_hdr(admin_tok), json={"role": "user"})
check(r.status_code == 403, f"super role is UI-immutable -> 403 (got {r.status_code})")

# a regular admin CAN disable/enable a regular user
r = client_reset.post(f"/admin/users/{alice['user_id']}/disable", headers=auth_hdr(admin_tok))
check(r.status_code == 200, f"disable a user -> 200 (got {r.status_code})")
sc, _ = login("alice", "Abcdef1!")
check(sc == 403, f"disabled user login blocked -> 403 (got {sc})")
r = client_reset.post(f"/admin/users/{alice['user_id']}/enable", headers=auth_hdr(admin_tok))
check(r.status_code == 200, f"enable -> 200 (got {r.status_code})")
sc, _ = login2(app.test_client(), "alice", "Abcdef1!")
check(sc == 200, f"re-enabled user can log in (got {sc})")

print("\n== 7. reject removes a pending user ==")
client.post("/register", json={"username": "carol", "password": "Carol123!", "first_name": "Carol", "last_name": "C", "email": "carol@x.com"})
carol = next(u for u in client_reset.get("/admin/users", headers=auth_hdr(admin_tok)).get_json() if u["username"]=="carol")
r = client_reset.post(f"/admin/users/{carol['user_id']}/reject", headers=auth_hdr(admin_tok))
check(r.status_code == 200, f"reject carol -> 200 (got {r.status_code})")
conn = backend.get_db(); gone = conn.execute("SELECT 1 FROM users WHERE username='carol'").fetchone(); conn.close()
check(gone is None, "carol removed from DB after reject")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
