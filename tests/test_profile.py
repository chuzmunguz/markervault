import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_prof_")
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

def approve(uid):
    conn = backend.get_db()
    conn.execute("UPDATE users SET status='approved' WHERE user_id=?", (uid,))
    conn.commit(); conn.close()

def uid_of(username):
    conn = backend.get_db()
    r = conn.execute("SELECT user_id FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
    conn.close()
    return r[0] if r else None

def login(u, p):
    cl = app.test_client()
    cl.post("/login", json={"username": u, "password": p})
    rr = cl.post("/auth/refresh")
    return cl, rr

def H(t): return {"Authorization": f"Bearer {t}"}

REG = {"username": "alice", "password": "Alice123!",
       "first_name": "Alice", "last_name": "Smith", "email": "alice@x.com",
       "company": "Acme", "department": "Ops", "birth_date": "1990-05-04", "sex": "female"}

print("\n== 1. Schema: profile columns exist on the users table ==")
cols = {r[1] for r in backend.get_db().execute("PRAGMA table_info(users)").fetchall()}
for col in ('first_name', 'last_name', 'email', 'company', 'department', 'birth_date', 'sex'):
    check(col in cols, f"column {col} present")

print("\n== 2. Register requires first + last name + email ==")
c = app.test_client()
r = c.post("/register", json={"username": "bob", "password": "Bob12345!"})
check(r.status_code == 400 and "name" in r.get_json().get("error", "").lower(), "register w/o names -> 400")
r = c.post("/register", json={"username": "bob", "password": "Bob12345!", "first_name": "Bob", "last_name": ""})
check(r.status_code == 400, "register w/ blank last name -> 400")
r = c.post("/register", json={"username": "bob", "password": "Bob12345!", "first_name": "Bob", "last_name": "B"})
check(r.status_code == 400 and "email" in r.get_json().get("error", "").lower(), "register w/o email -> 400")
r = c.post("/register", json={"username": "bob", "password": "Bob12345!", "first_name": "Bob", "last_name": "B", "email": "not-an-email"})
check(r.status_code == 400, "register w/ bad email format -> 400")

print("\n== 3. Register stores all profile fields incl. email ==")
r = c.post("/register", json=REG)
check(r.status_code == 200, f"valid register -> 200 (got {r.status_code})")
row = backend.get_db().execute(
    "SELECT first_name, last_name, email, company, department, birth_date, sex, status FROM users WHERE username='alice'").fetchone()
check(row == ("Alice", "Smith", "alice@x.com", "Acme", "Ops", "1990-05-04", "female", "pending"), f"stored fields + pending status ({row})")

print("\n== 3b. Email must be unique ==")
r = c.post("/register", json={**REG, "username": "dupemail"})  # same email as alice
check(r.status_code == 400 and "email" in r.get_json().get("error", "").lower(), "duplicate email -> 400")
r = c.post("/register", json={**REG, "username": "dupemail", "email": "ALICE@X.COM"})  # case-insensitive
check(r.status_code == 400, "duplicate email (case-insensitive) -> 400")

print("\n== 4. Register rejects bad sex / bad birth_date ==")
r = c.post("/register", json={**REG, "username": "carol", "email": "carol@x.com", "sex": "wizard"})
check(r.status_code == 400, "bad sex -> 400")
r = c.post("/register", json={**REG, "username": "carol", "email": "carol@x.com", "birth_date": "05/04/1990"})
check(r.status_code == 400, "bad birth_date format -> 400")
r = c.post("/register", json={**REG, "username": "carol", "email": "carol@x.com", "sex": "", "birth_date": ""})
check(r.status_code == 200, "empty sex + empty birth_date allowed -> 200")

print("\n== 5. auth_refresh carries first/last name ==")
approve(uid_of("alice"))
alice, rr = login("alice", "Alice123!")
j = rr.get_json()
check(j.get("first_name") == "Alice" and j.get("last_name") == "Smith", f"refresh returns name ({j.get('first_name')} {j.get('last_name')})")
tok = j["access_token"]

print("\n== 6. GET /profile returns the fields (username/role/email too) ==")
r = alice.get("/profile", headers=H(tok))
p = r.get_json()
check(r.status_code == 200, "GET /profile -> 200")
check(p.get("username") == "alice" and p.get("role") == "user", "profile has username + role")
check(p.get("email") == "alice@x.com", "profile has email")
check(p.get("company") == "Acme" and p.get("sex") == "female", "profile has optional fields")

print("\n== 7. PUT /profile updates the fields incl. email; persists ==")
r = alice.put("/profile", headers=H(tok), json={
    "first_name": "Alicia", "last_name": "Jones", "email": "alicia@x.com", "company": "NewCo",
    "department": "Eng", "birth_date": "1991-01-01", "sex": "other"})
check(r.status_code == 200, f"PUT /profile -> 200 (got {r.status_code})")
pj = r.get_json()
check(pj.get("first_name") == "Alicia" and pj.get("last_name") == "Jones", "response reflects update")
check(pj.get("email") == "alicia@x.com", "email updated")
r2 = alice.get("/profile", headers=H(tok)).get_json()
check(r2.get("company") == "NewCo" and r2.get("department") == "Eng" and r2.get("sex") == "other", "persisted after re-GET")
# keeping the same email on your own record is allowed (excludes self)
check(alice.put("/profile", headers=H(tok), json={"first_name": "Alicia", "last_name": "Jones", "email": "alicia@x.com"}).status_code == 200, "keeping own email -> 200")

print("\n== 8. PUT /profile cannot change username/role/password ==")
before = backend.get_db().execute("SELECT username, role, password_hash FROM users WHERE user_id=?", (uid_of("alice"),)).fetchone()
r = alice.put("/profile", headers=H(tok), json={
    "first_name": "Alicia", "last_name": "Jones", "email": "alicia@x.com",
    "username": "hacker", "role": "admin", "password": "Zzz99999!"})
check(r.status_code == 200, "PUT with extra fields -> 200 (extras ignored)")
after = backend.get_db().execute("SELECT username, role, password_hash FROM users WHERE user_id=?", (uid_of("alice"),)).fetchone()
check(after[0] == "alice" and after[1] == "user", "username + role unchanged")
check(after[2] == before[2], "password_hash unchanged")

print("\n== 9. PUT /profile still enforces required names/email + validation ==")
check(alice.put("/profile", headers=H(tok), json={"first_name": "", "last_name": "Jones", "email": "a@b.com"}).status_code == 400, "blank first name -> 400")
check(alice.put("/profile", headers=H(tok), json={"first_name": "A", "last_name": "B", "email": ""}).status_code == 400, "blank email -> 400")
check(alice.put("/profile", headers=H(tok), json={"first_name": "A", "last_name": "B", "email": "a@b.com", "sex": "nope"}).status_code == 400, "bad sex on PUT -> 400")

print("\n== 10. /profile requires auth ==")
anon = app.test_client()
check(anon.get("/profile").status_code == 401, "GET /profile w/o token -> 401")
check(anon.put("/profile", json={"first_name": "x", "last_name": "y"}).status_code == 401, "PUT /profile w/o token -> 401")

print("\n== 11. Admin user list surfaces names ==")
# Super-admin fixture: a regular admin's list holds only controlled users, so use the
# unscoped list (which includes the caller's own row) to verify the payload fields.
admin_id = str(uuid.uuid4())
conn = backend.get_db()
conn.execute("INSERT INTO users (user_id, username, password_hash, role, status, created, first_name, last_name) VALUES (?,?,?,?,?,?,?,?)",
             (admin_id, "adm", bcrypt.hashpw(b"Admin123!", bcrypt.gensalt()), "super_admin", "approved", datetime.now().isoformat(), "Ada", "Root"))
conn.commit(); conn.close()
adm, arr = login("adm", "Admin123!")
atok = arr.get_json()["access_token"]
lst = adm.get("/admin/users", headers=H(atok)).get_json()
me = next((u for u in lst if u["username"] == "adm"), None)
check(me and me.get("first_name") == "Ada" and me.get("last_name") == "Root", "admin list includes first/last name")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
