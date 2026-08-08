import os, sys, shutil, tempfile, importlib.util, uuid
WORK = tempfile.mkdtemp(prefix="mv_acctdel_")
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
backend = importlib.util.module_from_spec(spec); sys.modules["backend"] = backend
spec.loader.exec_module(backend)
backend.COOKIE_SECURE = False; backend.rate_limit = lambda *a, **k: None
app = backend.app; app.testing = True
import bcrypt
from datetime import datetime

PASS = FAIL = 0
def check(c, l):
    global PASS, FAIL
    if c: PASS += 1; print(f"  PASS  {l}")
    else: FAIL += 1; print(f"  FAIL  {l}")
def mk(u, p, role="user"):
    conn = backend.get_db(); uid = str(uuid.uuid4())
    conn.execute("INSERT INTO users (user_id, username, password_hash, role, status, created, first_name, last_name) VALUES (?,?,?,?,?,?,?,?)",
                 (uid, u, bcrypt.hashpw(p.encode(), bcrypt.gensalt()), role, "approved", datetime.now().isoformat(), "F", "L"))
    conn.commit(); conn.close(); backend.create_base_map(uid); return uid
def login(u, p):
    cl = app.test_client(); cl.post("/login", json={"username": u, "password": p})
    return cl, cl.post("/auth/refresh").get_json()["access_token"]
def H(t): return {"Authorization": f"Bearer {t}"}
def exists(u):
    conn = backend.get_db(); r = conn.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(u,)).fetchone(); conn.close(); return bool(r)
def uid_of(u):
    conn = backend.get_db(); r = conn.execute("SELECT user_id FROM users WHERE username=? COLLATE NOCASE",(u,)).fetchone(); conn.close(); return r[0] if r else None
def add_avatar(user_id):
    filename = f"{user_id}.jpg"
    path = os.path.join(backend.AVATARS_FOLDER, filename)
    with open(path, "wb") as avatar:
        avatar.write(b"avatar")
    conn = backend.get_db()
    conn.execute("UPDATE users SET avatar=? WHERE user_id=?", (filename, user_id))
    conn.commit(); conn.close()
    return path

adm1 = mk("adm1", "Admin123!", role="admin")
adm2 = mk("adm2", "Admin123!", role="admin")
bob  = mk("bob", "Bob12345!")
bob_avatar = add_avatar(bob)

print("\n== requires auth ==")
check(app.test_client().delete("/account", json={"confirm_username":"bob"}).status_code == 401, "no token -> 401")

print("\n== confirmation must match own username ==")
bc, bt = login("bob", "Bob12345!")
check(bc.delete("/account", headers=H(bt), json={"confirm_username":"wrong"}).status_code == 400, "wrong confirm -> 400")
check(bc.delete("/account", headers=H(bt), json={}).status_code == 400, "missing confirm -> 400")
check(exists("bob"), "bob still exists after failed confirms")
check(os.path.isfile(bob_avatar), "bob's avatar survives failed confirmation")

print("\n== successful self-delete wipes user + their maps ==")
m = bc.post("/maps", headers=H(bt), json={"name":"BobMap"}).get_json()
bc.post("/spots", headers=H(bt), json={"mapID":m["id"],"name":"s","lat":1,"lng":1})
before = backend.get_db().execute("SELECT COUNT(*) FROM maps WHERE owner_id=?",(bob,)).fetchone()[0]
check(before >= 2, f"bob owns maps before ({before})")
r = bc.delete("/account", headers=H(bt), json={"confirm_username":"bob"})
check(r.status_code == 200, f"self-delete -> 200 (got {r.status_code})")
check(not exists("bob"), "bob gone")
check(not os.path.exists(bob_avatar), "self-delete removes bob's avatar file")
after = backend.get_db().execute("SELECT COUNT(*) FROM maps WHERE owner_id=?",(bob,)).fetchone()[0]
check(after == 0, f"bob's maps cascade-deleted ({after})")

print("\n== confirm is case-insensitive ==")
carol = mk("carol", "Carol123!")
carol_avatar = os.path.join(backend.AVATARS_FOLDER, f"{carol}.jpg")
with open(carol_avatar, "wb") as avatar:
    avatar.write(b"orphaned-avatar")
cc, ct = login("carol", "Carol123!")
check(cc.delete("/account", headers=H(ct), json={"confirm_username":"CAROL"}).status_code == 200, "CAROL confirms carol -> 200")
check(not exists("carol"), "carol gone")
check(not os.path.exists(carol_avatar), "self-delete removes stable avatar file when DB value is null")

print("\n== last admin cannot self-delete; a non-last admin can ==")
a1c, a1t = login("adm1", "Admin123!")
check(a1c.delete("/account", headers=H(a1t), json={"confirm_username":"adm1"}).status_code == 200, "adm1 self-deletes (adm2 remains) -> 200")
check(not exists("adm1"), "adm1 gone")
# adm2 is now the only admin
a2c, a2t = login("adm2", "Admin123!")
r = a2c.delete("/account", headers=H(a2t), json={"confirm_username":"adm2"})
check(r.status_code == 400, "last admin self-delete blocked -> 400")
check(exists("adm2"), "last admin still exists")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
