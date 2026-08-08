import os, sys, shutil, tempfile, importlib.util, uuid
WORK = tempfile.mkdtemp(prefix="mv_own_")
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
def mk(u, p, role="user", first="", last=""):
    conn = backend.get_db(); uid = str(uuid.uuid4())
    conn.execute("INSERT INTO users (user_id, username, password_hash, role, status, created, first_name, last_name) VALUES (?,?,?,?,?,?,?,?)",
                 (uid, u, bcrypt.hashpw(p.encode(), bcrypt.gensalt()), role, "approved", datetime.now().isoformat(), first, last))
    conn.commit(); conn.close(); backend.create_base_map(uid); return uid
def login(u, p):
    cl = app.test_client(); cl.post("/login", json={"username": u, "password": p})
    return cl, cl.post("/auth/refresh").get_json()["access_token"]
def H(t): return {"Authorization": f"Bearer {t}"}

# alice has a full name, zed has no name; bob is a plain viewer; admin sees all
alice = mk("alice", "Alice123!", first="Alice", last="Smith")
zed   = mk("zed",   "Zed12345!")  # no name on file
bob   = mk("bob",   "Bob12345!")
admin = mk("adm",   "Admin123!", role="admin")

ac, at = login("alice", "Alice123!")
zc, zt = login("zed", "Zed12345!")
bc, bt = login("bob", "Bob12345!")
adc, adt = login("adm", "Admin123!")

# alice + zed each make a named map and share it with bob (viewer)
am = ac.post("/maps", headers=H(at), json={"name": "AliceMap"}).get_json()
zm = zc.post("/maps", headers=H(zt), json={"name": "ZedMap"}).get_json()
ac.put(f"/maps/{am['id']}/collaborators", headers=H(at), json={"username": "bob", "role": "viewer"})
zc.put(f"/maps/{zm['id']}/collaborators", headers=H(zt), json={"username": "bob", "role": "viewer"})

print("\n== bob's /maps carries owner identity on shared maps ==")
bmaps = bc.get("/maps", headers=H(bt)).get_json()
byid = {m["name"]: m for m in bmaps}
check(byid["AliceMap"]["owner_name"] == "Alice Smith", f"named owner -> 'Alice Smith' (got {byid['AliceMap'].get('owner_name')!r})")
check(byid["AliceMap"]["owner_username"] == "alice", "owner_username present")
check(byid["ZedMap"]["owner_name"] == "zed", f"nameless owner -> falls back to username 'zed' (got {byid['ZedMap'].get('owner_name')!r})")

print("\n== bob's OWN base map still owner_name = himself, owned True ==")
mine = next(m for m in bmaps if m["owned"])
check(mine["role"] == "owner" and mine["owner_username"] == "bob", "own map: role owner + owner_username bob")

print("\n== admin sees only own maps (blanket visibility removed) ==")
amaps = adc.get("/maps", headers=H(adt)).get_json()
names = {m["name"] for m in amaps}
check("AliceMap" not in names and "ZedMap" not in names, f"admin's /maps has no foreign maps (got {names})")
check(all(m["owned"] and m["role"] == "owner" for m in amaps), "all of admin's maps are owned, role=owner")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
