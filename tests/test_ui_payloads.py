"""UI-polish payload additions: GET /maps `shared` flag (owned map has >=1 collaborator,
direct or group) + GET /admin/groups `created`/`created_by_username` facts.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_ui_")
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

def make_user(username, password, role, status, email=None, first_name='', last_name=''):
    conn = backend.get_db(); c = conn.cursor()
    uid = str(uuid.uuid4())
    c.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created, "
        "email, first_name, last_name) VALUES (?,?,?,?,?,?,?,?,?)",
        (uid, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role,
         status, datetime.now().isoformat(), email, first_name, last_name),
    )
    conn.commit(); conn.close()
    return uid

def login(u, p):
    cl = app.test_client()
    cl.post("/login", json={"username": u, "password": p})
    rr = cl.post("/auth/refresh")
    return cl, rr.get_json().get("access_token")

def H(t): return {"Authorization": f"Bearer {t}"}

now = datetime.now().isoformat()
boss_id = make_user("boss", "Boss1234!", "super_admin", "approved", "boss@x.com", "Boss", "Operator")
admA_id = make_user("admA", "AdmA1234!", "admin", "approved", "adma@x.com", "Admin", "Alpha")
ua_id   = make_user("ua",   "Ua123456!", "user", "approved", "ua@x.com")
ub_id   = make_user("ub",   "Ub123456!", "user", "approved", "ub@x.com")
for uid in (boss_id, admA_id, ua_id, ub_id):
    backend.create_base_map(uid)

conn = backend.get_db(); c = conn.cursor()
c.execute("INSERT INTO maps (owner_id, name, is_base, created) VALUES (?, 'Plain', 0, ?)", (ua_id, now))
plain_id = c.lastrowid
c.execute("INSERT INTO maps (owner_id, name, is_base, created) VALUES (?, 'Direct', 0, ?)", (ua_id, now))
direct_id = c.lastrowid
c.execute("INSERT INTO maps (owner_id, name, is_base, created) VALUES (?, 'Grouped', 0, ?)", (ua_id, now))
grouped_id = c.lastrowid
c.execute("INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?,?,?,?)", (direct_id, ub_id, "viewer", now))
c.execute("INSERT INTO share_groups (name, created, created_by) VALUES ('Team', ?, ?)", (now, admA_id))
gA = c.lastrowid
c.execute("INSERT INTO share_group_owners (group_id, admin_id, created) VALUES (?,?,?)", (gA, admA_id, now))
c.execute("INSERT INTO map_group_shares (map_id, group_id, role, created) VALUES (?,?,?,?)", (grouped_id, gA, "editor", now))
c.execute("INSERT INTO share_groups (name, created, created_by) VALUES ('SuperG', ?, ?)", (now, boss_id))
conn.commit(); conn.close()

boss, boss_t = login("boss", "Boss1234!")
admA, admA_t = login("admA", "AdmA1234!")
ua, ua_t = login("ua", "Ua123456!")

print("== GET /maps shared flag ==")
maps = {m["name"]: m for m in ua.get("/maps", headers=H(ua_t)).get_json()}
check(maps["Plain"]["shared"] is False, "owned unshared map -> shared:false")
check(maps["Direct"]["shared"] is True, "owned map with a direct share -> shared:true")
check(maps["Grouped"]["shared"] is True, "owned map with a group share -> shared:true")
check(maps["Base Map"]["shared"] is False, "Base Map -> shared:false")
ub, ub_t = login("ub", "Ub123456!")
ub_maps = {m["name"]: m for m in ub.get("/maps", headers=H(ub_t)).get_json()}
check(ub_maps["Direct"]["role"] == "viewer" and ub_maps["Direct"]["shared"] is True,
      "recipient still sees the map with role, flag present")

print("== GET /admin/groups creation facts ==")
gs = {x["name"]: x for x in boss.get("/admin/groups", headers=H(boss_t)).get_json()}
check(bool(gs["Team"]["created"]), "created timestamp present")
check(gs["Team"]["created_by_username"] == "admA", "admin-created group names its creator")
check(gs["SuperG"]["created_by_username"] == "boss", "super-created group names the super")
check((gs["Team"]["created_by_first"], gs["Team"]["created_by_last"]) == ("Admin", "Alpha") and
      (gs["SuperG"]["created_by_first"], gs["SuperG"]["created_by_last"]) == ("Boss", "Operator"),
      "creator payloads retain first/last name parts")
check(gs["Team"]["owners"] == [{
          "admin_id": admA_id,
          "username": "admA",
          "first_name": "Admin",
          "last_name": "Alpha",
      }],
      "owner payload retains username and real-name parts")
gs_admA = {x["name"]: x for x in admA.get("/admin/groups", headers=H(admA_t)).get_json()}
check(gs_admA["Team"]["created_by_username"] == "admA", "scoped admin view carries the same fact")

# Creator deletion: created_by is ON DELETE SET NULL -> username resolves to null.
boss.delete(f"/admin/users/{admA_id}", headers=H(boss_t))
gs = {x["name"]: x for x in boss.get("/admin/groups", headers=H(boss_t)).get_json()}
check(gs["Team"]["created_by_username"] is None, "deleted creator -> created_by_username null")
check(gs["Team"]["created_by_first"] == "" and gs["Team"]["created_by_last"] == "",
      "deleted creator -> empty real-name parts for frontend fallback")

print(f"==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
