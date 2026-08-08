"""Admin profile edit (incl. username) — PUT /admin/users/<id>/profile.

Governance = _guard_admin_target, same as resetpwd: regular admins only on users they
control; supers unscoped INCLUDING admin-level targets and their own row (explicit
decision). Username follows the /register rules (stripped, non-empty, unique NOCASE
excluding the target). No session revocation: identity keys on user_id, so renames
must not disturb controllers, group memberships, or map shares.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_pe_")
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
backend.COOKIE_SECURE = False
backend.rate_limit = lambda *a, **k: None
app = backend.app
app.testing = True

import bcrypt
from datetime import datetime

PASS = FAIL = 0
def check(cond, label):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {label}")
    else: FAIL += 1; print(f"  FAIL  {label}")

def make_user(username, password, role, status, email=None):
    conn = backend.get_db(); c = conn.cursor()
    uid = str(uuid.uuid4())
    c.execute("INSERT INTO users (user_id, username, password_hash, role, status, created, email) VALUES (?,?,?,?,?,?,?)",
              (uid, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role, status, datetime.now().isoformat(), email))
    conn.commit(); conn.close()
    return uid

def login(u, p):
    cl = app.test_client()
    cl.post("/login", json={"username": u, "password": p})
    rr = cl.post("/auth/refresh")
    return cl, rr.get_json().get("access_token")

def H(t): return {"Authorization": f"Bearer {t}"}

def payload(username, email, first="First", last="Last", **kw):
    body = {"username": username, "first_name": first, "last_name": last, "email": email,
            "company": "", "department": "", "birth_date": "", "sex": ""}
    body.update(kw)
    return body

def edit(cl, t, uid, body):
    return cl.put(f"/admin/users/{uid}/profile", headers=H(t), json=body)

def user_row(uid):
    conn = backend.get_db()
    r = conn.execute("SELECT username, first_name, last_name, email, company, department, birth_date, sex FROM users WHERE user_id = ?", (uid,)).fetchone()
    conn.close()
    return r

now = datetime.now().isoformat()
boss_id = make_user("boss", "Boss1234!", "super_admin", "approved", "boss@x.com")
admA_id = make_user("admA", "AdmA1234!", "admin", "approved", "adma@x.com")
admB_id = make_user("admB", "AdmB1234!", "admin", "approved", "admb@x.com")
ua_id   = make_user("ua",   "Ua123456!", "user", "approved", "ua@x.com")    # A's user
nol_id  = make_user("nol",  "Nol12345!", "user", "approved", "nol@x.com")   # nobody-land
for uid in (boss_id, admA_id, admB_id, ua_id, nol_id):
    backend.create_base_map(uid)

conn = backend.get_db(); c = conn.cursor()
c.execute("INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?,?,?)", (ua_id, admA_id, now))
# Relations that must survive a rename: a group membership and a map share for ua.
c.execute("INSERT INTO share_groups (name, created, created_by) VALUES ('Team', ?, ?)", (now, boss_id))
gid = c.lastrowid
c.execute("INSERT INTO share_group_members (group_id, user_id, created) VALUES (?,?,?)", (gid, ua_id, now))
c.execute("INSERT INTO maps (owner_id, name, is_base, created) VALUES (?, 'BossMap', 0, ?)", (boss_id, now))
mid = c.lastrowid
c.execute("INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?,?,?,?)", (mid, ua_id, "viewer", now))
conn.commit(); conn.close()

boss, boss_t = login("boss", "Boss1234!")
admA, admA_t = login("admA", "AdmA1234!")

print("== scoped edits (regular admin) ==")
r = edit(admA, admA_t, ua_id, payload("ua", "ua@x.com", first="Anna", last="Alpha", company="ACME", department="Ops", birth_date="1990-05-01", sex="female"))
check(r.status_code == 200, "admA edits controlled user's profile fields -> 200")
row = user_row(ua_id)
check(row == ("ua", "Anna", "Alpha", "ua@x.com", "ACME", "Ops", "1990-05-01", "female"), "row updated with all fields")

r = edit(admA, admA_t, ua_id, payload("ua2", "ua@x.com", first="Anna", last="Alpha"))
check(r.status_code == 200 and r.get_json().get("username") == "ua2", "admA renames ua -> ua2, 200")
cl = app.test_client()
check(cl.post("/login", json={"username": "ua2", "password": "Ua123456!"}).status_code == 200, "login works with NEW username")
check(cl.post("/login", json={"username": "ua", "password": "Ua123456!"}).status_code == 401, "old username 401s")

print("== rename disturbs no user_id-keyed relation ==")
conn = backend.get_db()
check(conn.execute("SELECT 1 FROM user_controllers WHERE user_id=? AND admin_id=?", (ua_id, admA_id)).fetchone() is not None, "controls() row survives rename")
check(conn.execute("SELECT 1 FROM share_group_members WHERE group_id=? AND user_id=?", (gid, ua_id)).fetchone() is not None, "group membership survives rename")
check(conn.execute("SELECT 1 FROM map_shares WHERE map_id=? AND user_id=?", (mid, ua_id)).fetchone() is not None, "map share survives rename")
conn.close()

print("== scope walls ==")
check(edit(admA, admA_t, nol_id, payload("nol", "nol@x.com")).status_code == 403, "admA -> nobody-land user 403")
check(edit(admA, admA_t, admB_id, payload("admB", "admb@x.com")).status_code == 403, "admA -> other admin 403")
check(edit(admA, admA_t, boss_id, payload("boss", "boss@x.com")).status_code == 403, "admA -> super 403")
check(edit(admA, admA_t, admA_id, payload("admA", "adma@x.com")).status_code == 403, "admA -> own row 403 (admins are never controlled)")

print("== super is unscoped, own row included ==")
check(edit(boss, boss_t, admA_id, payload("admA", "adma@x.com", first="Al", last="Adams")).status_code == 200, "boss edits an admin -> 200")
check(edit(boss, boss_t, boss_id, payload("chief", "boss@x.com")).status_code == 200, "boss renames own row -> 200")
check(edit(boss, boss_t, boss_id, payload("boss", "boss@x.com")).status_code == 200, "boss renames back -> 200")
check(edit(boss, boss_t, ua_id, payload("ua2", "ua@x.com", first="Anna", last="Alpha")).status_code == 200, "boss edits another admin's controlled user -> 200")

print("== validation ==")
check(edit(boss, boss_t, ua_id, payload("NOL", "ua@x.com")).status_code == 400, "username taken by another user (case-insensitive) -> 400")
check(edit(boss, boss_t, ua_id, payload("UA2", "ua@x.com", first="Anna", last="Alpha")).status_code == 200, "keeping own username in different case -> 200")
check(user_row(ua_id)[0] == "UA2", "case-only self-rename applied")
check(edit(boss, boss_t, ua_id, payload("", "ua@x.com")).status_code == 400, "empty username -> 400")
check(edit(boss, boss_t, ua_id, payload("UA2", "nol@x.com")).status_code == 400, "email collision with another user -> 400")
check(edit(boss, boss_t, ua_id, payload("UA2", "ua@x.com", first="Anna", last="Alpha")).status_code == 200, "keeping own email -> 200")
check(edit(boss, boss_t, ua_id, payload("UA2", "ua@x.com", first="")).status_code == 400, "missing first_name -> 400")
check(edit(boss, boss_t, ua_id, payload("UA2", "not-an-email")).status_code == 400, "bad email format -> 400")
check(edit(boss, boss_t, ua_id, payload("UA2", "ua@x.com", birth_date="05/01/1990")).status_code == 400, "bad birth_date format -> 400")
check(edit(boss, boss_t, str(uuid.uuid4()), payload("ghost", "g@x.com")).status_code == 404, "unknown target -> 404")
r = boss.put(f"/admin/users/{ua_id}/profile", headers=H(boss_t), json={"first_name": "X"})
check(r.status_code == 400, "payload without username key -> 400")

print("== non-admin caller ==")
ua_cl, ua_t = login("UA2", "Ua123456!")
check(edit(ua_cl, ua_t, nol_id, payload("nol", "nol@x.com")).status_code == 403, "regular user calling the route -> 403")

print(f"==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
