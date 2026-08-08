import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_p5_")
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
backend.rate_limit = lambda *a, **k: None   # disable rate limiter for the harness
app = backend.app
app.testing = True

import bcrypt
from datetime import datetime

PASS = FAIL = 0
def check(cond, label):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {label}")
    else: FAIL += 1; print(f"  FAIL  {label}")

def make_user(username, password, role, status):
    conn = backend.get_db(); c = conn.cursor()
    uid = str(uuid.uuid4())
    c.execute("INSERT INTO users (user_id, username, password_hash, role, status, created) VALUES (?,?,?,?,?,?)",
              (uid, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role, status, datetime.now().isoformat()))
    conn.commit(); conn.close()
    return uid

def login(u, p):
    cl = app.test_client()
    cl.post("/login", json={"username": u, "password": p})
    rr = cl.post("/auth/refresh")
    return cl, rr.get_json().get("access_token")

def H(t): return {"Authorization": f"Bearer {t}"}

# owner (alice), sharee (bob), admin, outsider (dave)
alice_id = make_user("alice", "Alice123!", "user", "approved")
bob_id   = make_user("bob",   "Bob12345!", "user", "approved")
admin_id = make_user("admin", "Admin123!", "admin", "approved")
dave_id  = make_user("dave",  "Dave1234!", "user", "approved")
for uid in (alice_id, bob_id, admin_id, dave_id):
    backend.create_base_map(uid)

alice, alice_t = login("alice", "Alice123!")
bob, bob_t     = login("bob", "Bob12345!")
admin, admin_t = login("admin", "Admin123!")
dave, dave_t   = login("dave", "Dave1234!")

# alice makes a map with a spot + photo-less marker
m = alice.post("/maps", headers=H(alice_t), json={"name": "Shared Map"}).get_json()
map_id = m["id"]
s = alice.post("/spots", headers=H(alice_t), json={"mapID": map_id, "name": "s1", "lat": 10, "lng": 10}).get_json()
spot_id = s["id"]

print("\n== 1. Before sharing: bob has no access ==")
check(all(x["id"] != map_id for x in bob.get("/maps", headers=H(bob_t)).get_json()), "map absent from bob's /maps")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 404, "bob GET spots -> 404")

print("\n== 2. /users picker excludes self, lists approved ==")
users = alice.get("/users", headers=H(alice_t)).get_json()
names = {u["username"] for u in users}
check("alice" not in names and {"bob","admin","dave"} <= names, f"picker excludes self, lists others ({names})")

print("\n== 3. Share as VIEWER: read yes, write no ==")
r = alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "viewer"})
check(r.status_code == 200, f"alice shares as viewer (got {r.status_code})")
bmaps = bob.get("/maps", headers=H(bob_t)).get_json()
bmap = next((x for x in bmaps if x["id"] == map_id), None)
check(bmap is not None and bmap["role"] == "viewer" and not bmap["owned"], "map now in bob's list w/ role=viewer")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 200, "viewer bob GET spots -> 200")
check(bob.get(f"/spots/{spot_id}", headers=H(bob_t)).status_code == 200, "viewer bob GET spot -> 200")
check(bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "x", "lat": 1, "lng": 1}).status_code == 404,
      "viewer bob POST spot -> 404")
check(bob.put(f"/spots/{spot_id}", headers=H(bob_t), json={"name": "hacked"}).status_code == 404,
      "viewer bob PUT spot -> 404")
check(bob.delete(f"/spots/{spot_id}", headers=H(bob_t)).status_code == 404, "viewer bob DELETE spot -> 404")

print("\n== 4. Upgrade to EDITOR: content writes yes, map-entity no ==")
r = alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "editor"})
check(r.status_code == 200, f"alice re-shares as editor (got {r.status_code})")
r = bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "byBob", "lat": 2, "lng": 2})
check(r.status_code == 200, f"editor bob adds spot -> 200 (got {r.status_code})")
bob_spot = r.get_json()["id"]
check(bob.put(f"/spots/{bob_spot}", headers=H(bob_t), json={"name": "edited"}).status_code == 200, "editor bob edits spot -> 200")
check(bob.delete(f"/spots/{bob_spot}", headers=H(bob_t)).status_code == 200, "editor bob deletes spot -> 200")
# editor MAY edit the map entity (rename etc.), but cannot delete it or manage shares
r = bob.put(f"/maps/{map_id}", headers=H(bob_t), json={"name": "Bob Renamed"})
check(r.status_code == 200, f"editor bob PUT map (rename) -> 200 (got {r.status_code})")
check(bob.delete(f"/maps/{map_id}", headers=H(bob_t)).status_code == 404, "editor bob DELETE map -> 404")
check(bob.get(f"/maps/{map_id}/collaborators", headers=H(bob_t)).status_code == 404, "editor bob GET shares -> 404")
check(bob.put(f"/maps/{map_id}/collaborators", headers=H(bob_t), json={"username":"dave","role":"viewer"}).status_code == 404,
      "editor bob cannot re-share -> 404")

print("\n== 5. Copy/move honor edit rights ==")
# bob (editor) copies from shared map into his own base map
bob_base = next(x for x in bob.get("/maps", headers=H(bob_t)).get_json() if x["is_base"])
r = bob.post(f"/spots/{spot_id}/copy/{bob_base['id']}", headers=H(bob_t))
check(r.status_code == 200, f"editor bob copies shared spot into own map -> 200 (got {r.status_code})")
# dave (no access) cannot copy from alice's map
r = dave.post(f"/spots/{spot_id}/copy/{next(x for x in dave.get('/maps',headers=H(dave_t)).get_json() if x['is_base'])['id']}", headers=H(dave_t))
check(r.status_code == 404, f"outsider dave copy from alice's spot -> 404 (got {r.status_code})")

print("\n== 6. Share-management is owner only ==")
check(dave.get(f"/maps/{map_id}/collaborators", headers=H(dave_t)).status_code == 404, "outsider GET shares -> 404")
check(alice.get(f"/maps/{map_id}/collaborators", headers=H(alice_t)).status_code == 200, "owner GET shares -> 200")
check(admin.get(f"/maps/{map_id}/collaborators", headers=H(admin_t)).status_code == 404, "admin GET shares -> 404 (no bypass)")
# can't share with self or the owner
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username":"alice","role":"viewer"}).status_code == 400,
      "share with owner -> 400")
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username":"nobody","role":"viewer"}).status_code == 404,
      "share with unknown user -> 404")
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username":"bob","role":"boss"}).status_code == 400,
      "bad role -> 400")

print("\n== 7. Unshare revokes access ==")
r = alice.delete(f"/maps/{map_id}/collaborators/{bob_id}", headers=H(alice_t))
check(r.status_code == 200, f"alice unshares bob (got {r.status_code})")
check(all(x["id"] != map_id for x in bob.get("/maps", headers=H(bob_t)).get_json()), "map gone from bob's list after unshare")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 404, "bob GET spots -> 404 after unshare")

print("\n== 8. Admin cannot manage another owner's shares; base map NOT shareable ==")
r = admin.put(f"/maps/{map_id}/collaborators", headers=H(admin_t), json={"username": "dave", "role": "viewer"})
check(r.status_code == 404, f"admin cannot share alice's map -> 404 (got {r.status_code})")
alice_base = next(x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["is_base"])
r = alice.put(f"/maps/{alice_base['id']}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "viewer"})
check(r.status_code == 400, f"owner cannot share their Base Map -> 400 (got {r.status_code})")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
