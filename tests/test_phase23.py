import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_p23_")
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
# The harness fires many requests from one IP in quick succession. Rate limiting is not
# what these tests exercise (it's covered in the Phase 1 harness / field test), so disable
# it here so 429s can't mask the ownership logic under test.
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

def make_user(username, password, role, status):
    conn = backend.get_db(); c = conn.cursor()
    uid = str(uuid.uuid4())
    c.execute("INSERT INTO users (user_id, username, password_hash, role, status, created) VALUES (?,?,?,?,?,?)",
              (uid, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()), role, status, datetime.now().isoformat()))
    conn.commit(); conn.close()
    return uid

def login(u, p):
    cl = app.test_client()
    r = cl.post("/login", json={"username": u, "password": p})
    if r.status_code != 200: return cl, None
    rr = cl.post("/auth/refresh")
    return cl, (rr.get_json().get("access_token") if rr.status_code == 200 else None)

def H(tok): return {"Authorization": f"Bearer {tok}"}

# --- Set up: admin + super (for the approval flow) + two regular users, approved w/ base maps ---
admin_id = make_user("admin", "Admin123!", "admin", "approved")
super_id = make_user("boss",  "Boss1234!", "super_admin", "approved")
alice_id = make_user("alice", "Alice123!", "user", "approved")
bob_id   = make_user("bob",   "Bob12345!", "user", "approved")
for uid in (admin_id, super_id, alice_id, bob_id):
    backend.create_base_map(uid)

admin_cl, admin_tok = login("admin", "Admin123!")
super_cl, super_tok = login("boss", "Boss1234!")
alice_cl, alice_tok = login("alice", "Alice123!")
bob_cl, bob_tok     = login("bob", "Bob12345!")

print("\n== 1. Each user gets exactly one Base Map ==")
for name, cl, tok in [("alice", alice_cl, alice_tok), ("bob", bob_cl, bob_tok)]:
    maps = cl.get("/maps", headers=H(tok)).get_json()
    bases = [m for m in maps if m["is_base"]]
    check(len(maps) == 1 and len(bases) == 1, f"{name} sees 1 map, is_base=1 (got {len(maps)} maps, {len(bases)} base)")

print("\n== 2. Ownership isolation: alice can't see or touch bob's map ==")
bob_map = bob_cl.get("/maps", headers=H(bob_tok)).get_json()[0]
# alice's /maps must not include bob's map
alice_maps = alice_cl.get("/maps", headers=H(alice_tok)).get_json()
check(all(m["id"] != bob_map["id"] for m in alice_maps), "bob's map absent from alice's /maps")
# alice adds a marker to a NEW map she owns
r = alice_cl.post("/maps", headers=H(alice_tok), json={"name": "Alice Map"})
check(r.status_code == 200, f"alice creates a map (got {r.status_code})")
alice_map_id = r.get_json()["id"]
# bob cannot read alice's map spots
r = bob_cl.get(f"/maps/{alice_map_id}/spots", headers=H(bob_tok))
check(r.status_code == 404, f"bob GET alice's map spots -> 404 (got {r.status_code})")
# bob cannot add a spot to alice's map
r = bob_cl.post("/spots", headers=H(bob_tok), json={"mapID": alice_map_id, "name": "x", "lat": 10, "lng": 10})
check(r.status_code == 404, f"bob POST spot to alice's map -> 404 (got {r.status_code})")
# bob cannot delete alice's map
r = bob_cl.delete(f"/maps/{alice_map_id}", headers=H(bob_tok))
check(r.status_code == 404, f"bob DELETE alice's map -> 404 (got {r.status_code})")

print("\n== 3. Owner CAN act on own map/spots ==")
r = alice_cl.post("/spots", headers=H(alice_tok), json={"mapID": alice_map_id, "name": "spotA", "lat": 10, "lng": 10})
check(r.status_code == 200, f"alice adds spot to own map (got {r.status_code})")
alice_spot_id = r.get_json()["id"]
r = bob_cl.get(f"/spots/{alice_spot_id}", headers=H(bob_tok))
check(r.status_code == 404, f"bob GET alice's spot -> 404 (got {r.status_code})")
r = bob_cl.delete(f"/spots/{alice_spot_id}", headers=H(bob_tok))
check(r.status_code == 404, f"bob DELETE alice's spot -> 404 (got {r.status_code})")
r = alice_cl.delete(f"/spots/{alice_spot_id}", headers=H(alice_tok))
check(r.status_code == 200, f"alice deletes own spot (got {r.status_code})")

print("\n== 4. Base Map cannot be deleted (owner) or edited ==")
alice_base = next(m for m in alice_cl.get("/maps", headers=H(alice_tok)).get_json() if m["is_base"])
r = alice_cl.delete(f"/maps/{alice_base['id']}", headers=H(alice_tok))
check(r.status_code == 400, f"alice cannot delete own Base Map -> 400 (got {r.status_code})")
r = alice_cl.put(f"/maps/{alice_base['id']}", headers=H(alice_tok), json={"name": "Renamed"})
check(r.status_code == 400, f"alice cannot edit own Base Map -> 400 (got {r.status_code})")

print("\n== 5. Admin has NO map bypass (blanket visibility removed) ==")
# admin sees ONLY their own maps (their base map) — nobody else's
admin_maps = admin_cl.get("/maps", headers=H(admin_tok)).get_json()
check(len(admin_maps) == 1 and all(m["owned"] for m in admin_maps),
      f"admin sees only own maps (got {len(admin_maps)})")
# admin cannot read alice's map spots
r = admin_cl.get(f"/maps/{alice_map_id}/spots", headers=H(admin_tok))
check(r.status_code == 404, f"admin reads alice's map spots -> 404 (got {r.status_code})")
# admin cannot add a spot to alice's map
r = admin_cl.post("/spots", headers=H(admin_tok), json={"mapID": alice_map_id, "name": "byAdmin", "lat": 5, "lng": 5})
check(r.status_code == 404, f"admin adds spot to alice's map -> 404 (got {r.status_code})")
# admin cannot delete alice's (non-base) map
r = admin_cl.delete(f"/maps/{alice_map_id}", headers=H(admin_tok))
check(r.status_code == 404, f"admin deletes alice's non-base map -> 404 (got {r.status_code})")
# alice's map is untouched by the attempt
r = alice_cl.get(f"/maps/{alice_map_id}/spots", headers=H(alice_tok))
check(r.status_code == 200, f"alice's map survives admin delete attempt (got {r.status_code})")
# admin can't even see alice's Base Map
r = admin_cl.delete(f"/maps/{alice_base['id']}", headers=H(admin_tok))
check(r.status_code == 404, f"admin delete alice's Base Map -> 404 (got {r.status_code})")

print("\n== 6. Base map is created on approval (super-only flow) ==")
# register a fresh pending user via the route, approve as SUPER, confirm base map exists
rr = app.test_client().post("/register", json={"username": "carol", "password": "Carol123!", "first_name": "Carol", "last_name": "C", "email": "carol@x.com"})
check(rr.status_code == 200, f"carol registers -> 200 (got {rr.status_code})")
users = super_cl.get("/admin/users", headers=H(super_tok)).get_json()
carol = next((u for u in users if isinstance(u, dict) and u.get("username") == "carol"), None)
check(carol is not None, "carol appears in the SUPER's user list (pending is super-only)")
if carol:
    ar = super_cl.post(f"/admin/users/{carol['user_id']}/approve", headers=H(super_tok))
    check(ar.status_code == 200, f"super approves carol -> 200 (got {ar.status_code})")
    conn = backend.get_db()
    n = conn.execute("SELECT COUNT(*) FROM maps WHERE owner_id=? AND is_base=1", (carol["user_id"],)).fetchone()[0]
    conn.close()
    check(n == 1, f"approved carol has exactly 1 base map (got {n})")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
