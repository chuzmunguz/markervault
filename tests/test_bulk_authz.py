"""Harness for the Jul 11 admin-visibility removal + editor map-edit + bulk share.

Covers what the updated older harnesses don't:
- PUT /maps/collaborators (bulk): happy path, upsert, all-or-nothing, owner-only,
  self-share, unknown user, payload validation, dedupe, no admin bypass.
- edit_map matrix: editor 200, viewer 404, base map 400 for owner AND editor.
- stale-share semantics after a role change (explicit shares survive; nothing else).
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_bulk_")
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

def make_user(username, password, role, status="approved"):
    conn = backend.get_db(); c = conn.cursor()
    uid = str(uuid.uuid4())
    c.execute("INSERT INTO users (user_id, username, password_hash, role, status, created) VALUES (?,?,?,?,?,?)",
              (uid, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role, status, datetime.now().isoformat()))
    conn.commit(); conn.close()
    backend.create_base_map(uid)
    return uid

def login(u, p):
    cl = app.test_client()
    cl.post("/login", json={"username": u, "password": p})
    rr = cl.post("/auth/refresh")
    return cl, rr.get_json().get("access_token")

def H(t): return {"Authorization": f"Bearer {t}"}

alice_id = make_user("alice", "Alice123!", "user")
bob_id   = make_user("bob",   "Bob12345!", "user")
carol_id = make_user("carol", "Carol123!", "user")
admin_id = make_user("admin", "Admin123!", "admin")
super_id = make_user("root",  "Root1234!", "super_admin")

alice, alice_t = login("alice", "Alice123!")
bob, bob_t     = login("bob", "Bob12345!")
carol, carol_t = login("carol", "Carol123!")
admin, admin_t = login("admin", "Admin123!")

m1 = alice.post("/maps", headers=H(alice_t), json={"name": "M1"}).get_json()["id"]
m2 = alice.post("/maps", headers=H(alice_t), json={"name": "M2"}).get_json()["id"]
bob_map = bob.post("/maps", headers=H(bob_t), json={"name": "BobMap"}).get_json()["id"]

print("\n== 1. Bulk share happy path ==")
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, m2], "username": "bob", "role": "viewer"})
check(r.status_code == 200 and r.get_json().get("shared") == 2, f"alice bulk-shares 2 maps -> 200, shared=2 (got {r.status_code})")
bmaps = {x["id"]: x for x in bob.get("/maps", headers=H(bob_t)).get_json()}
check(m1 in bmaps and m2 in bmaps and bmaps[m1]["role"] == "viewer" and bmaps[m2]["role"] == "viewer",
      "bob sees both maps as viewer")

print("\n== 2. Bulk re-share upserts the role ==")
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, m2], "username": "bob", "role": "editor"})
check(r.status_code == 200, f"bulk re-share as editor -> 200 (got {r.status_code})")
bmaps = {x["id"]: x for x in bob.get("/maps", headers=H(bob_t)).get_json()}
check(bmaps[m1]["role"] == "editor" and bmaps[m2]["role"] == "editor", "bob upgraded to editor on both")

print("\n== 3. All-or-nothing: one foreign map poisons the whole request ==")
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, bob_map], "username": "carol", "role": "viewer"})
check(r.status_code == 404, f"bulk incl. bob's map -> 404 (got {r.status_code})")
cmaps = {x["id"] for x in carol.get("/maps", headers=H(carol_t)).get_json()}
check(m1 not in cmaps, "no partial write: carol did NOT gain m1")

print("\n== 4. Owner-only: an editor cannot bulk-share the map ==")
r = bob.put("/maps/collaborators", headers=H(bob_t), json={"map_ids": [m1], "username": "carol", "role": "viewer"})
check(r.status_code == 404, f"editor bob bulk-shares m1 -> 404 (got {r.status_code})")

print("\n== 5. Admin has no bulk-share bypass ==")
r = admin.put("/maps/collaborators", headers=H(admin_t), json={"map_ids": [m1], "username": "carol", "role": "viewer"})
check(r.status_code == 404, f"admin bulk-shares alice's map -> 404 (got {r.status_code})")

print("\n== 6. Payload validation ==")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "username": "alice", "role": "viewer"}).status_code == 400,
      "share with self -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "username": "nobody", "role": "viewer"}).status_code == 404,
      "unknown user -> 404")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "username": "bob", "role": "boss"}).status_code == 400,
      "bad role -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [], "username": "bob", "role": "viewer"}).status_code == 400,
      "empty map_ids -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": ["1"], "username": "bob", "role": "viewer"}).status_code == 400,
      "non-int map id -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"username": "bob", "role": "viewer"}).status_code == 400,
      "missing map_ids -> 400")
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, m1, m1], "username": "carol", "role": "viewer"})
check(r.status_code == 200 and r.get_json().get("shared") == 1, f"duplicate ids deduped, shared=1 (got {r.get_json().get('shared')})")

print("\n== 7. edit_map matrix: editor 200 / viewer 404 / base 400 ==")
r = bob.put(f"/maps/{m1}", headers=H(bob_t), json={"description": "by editor"})
check(r.status_code == 200, f"editor edits map entity -> 200 (got {r.status_code})")
r = carol.put(f"/maps/{m1}", headers=H(carol_t), json={"description": "by viewer"})
check(r.status_code == 404, f"viewer edits map entity -> 404 (got {r.status_code})")
alice_base = next(x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["is_base"])
r = alice.put(f"/maps/{alice_base['id']}", headers=H(alice_t), json={"name": "nope"})
check(r.status_code == 400, f"owner edits own Base Map -> 400 (got {r.status_code})")

print("\n== 7b. Base Maps are never shareable ==")
r = alice.put(f"/maps/{alice_base['id']}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "editor"})
check(r.status_code == 400, f"single-share a Base Map -> 400 (got {r.status_code})")
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, alice_base["id"]], "username": "bob", "role": "viewer"})
check(r.status_code == 400, f"bulk-share incl. a Base Map -> 400 (got {r.status_code})")
bmaps = {x["id"]: x for x in bob.get("/maps", headers=H(bob_t)).get_json()}
check(bmaps[m1]["role"] == "editor", "no partial write: bob still editor on m1 (not downgraded)")
# Defense in depth: a share row forced onto a base map (bypassing the routes) grants NOTHING.
conn = backend.get_db()
conn.execute("INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?,?,?,?)",
             (alice_base["id"], bob_id, "editor", datetime.now().isoformat()))
conn.commit(); conn.close()
check(all(x["id"] != alice_base["id"] for x in bob.get("/maps", headers=H(bob_t)).get_json()),
      "forced base-map share row: absent from bob's /maps")
check(bob.get(f"/maps/{alice_base['id']}/spots", headers=H(bob_t)).status_code == 404,
      "forced base-map share row: spots still 404")

print("\n== 8. Role changes don't leak map access; explicit shares survive ==")
# promote carol to admin (super does it): still no access beyond her explicit viewer share on m1
sup, sup_t = login("root", "Root1234!")
r = sup.post(f"/admin/users/{carol_id}/role", headers=H(sup_t), json={"role": "admin"})
check(r.status_code == 200, f"super promotes carol to admin -> 200 (got {r.status_code})")
cmaps = {x["id"]: x for x in carol.get("/maps", headers=H(carol_t)).get_json()}
check(m1 in cmaps and cmaps[m1]["role"] == "viewer", "as admin, carol still sees m1 only via her explicit viewer share")
check(m2 not in cmaps and bob_map not in cmaps, "as admin, carol gains NO other maps")
# demote back: the explicit share still works
r = sup.post(f"/admin/users/{carol_id}/role", headers=H(sup_t), json={"role": "user"})
check(r.status_code == 200, f"super demotes carol back -> 200 (got {r.status_code})")
check(carol.get(f"/maps/{m1}/spots", headers=H(carol_t)).status_code == 200, "demoted carol keeps her explicit viewer share")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
