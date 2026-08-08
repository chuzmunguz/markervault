"""Admin map-metadata + super-admin share-management harness.

GET /admin/users/<id>/maps keeps metadata visibility scoped by controls(), but seals
all relationship data from regular admins. Super-admins retain the complete owned and
shared metadata view, including collaborator rosters. Contents remain sealed for both.

/admin/maps/<id>/collaborators (GET/PUT/DELETE + group DELETE) is super-admin-only.
The super-admin may target accounts globally but may not grant THEMSELVES access,
directly or via a group they belong to. Owner-facing share routes are unchanged.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_am_")
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

alice_id  = make_user("alice",  "Alice123!", "user", "approved")
bob_id    = make_user("bob",    "Bob12345!", "user", "approved")
admin_id  = make_user("admin",  "Admin123!", "admin", "approved")
admin2_id = make_user("admin2", "Admin223!", "admin", "approved")
super_id  = make_user("boss",   "Boss1234!", "super_admin", "approved")
conn = backend.get_db()
conn.execute("UPDATE users SET first_name='Alice', last_name='Owner' WHERE user_id = ?", (alice_id,))
conn.commit(); conn.close()
for uid in (alice_id, bob_id, admin_id, admin2_id, super_id):
    backend.create_base_map(uid)
# Fixture: alice+bob are delegated to 'admin' (controls()); carol (created later) stays
# out of scope on purpose. Regular-admin metadata scope remains under test even though
# only the super-admin may use the global share-target surface.
conn = backend.get_db(); c = conn.cursor()
for uid in (alice_id, bob_id):
    c.execute("INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?, ?, datetime('now'))", (uid, admin_id))
conn.commit(); conn.close()

alice, alice_t = login("alice", "Alice123!")
admin, admin_t = login("admin", "Admin123!")
boss, boss_t   = login("boss", "Boss1234!")

# alice: a map with 2 spots + 3 photos (photo rows inserted directly — the counting is
# what's under test, not the upload pipeline) + a description that must stay sealed.
m = alice.post("/maps", headers=H(alice_t), json={"name": "Field Work", "description": "SECRET", "notes": "SECRET"}).get_json()
map_id = m["id"]
s1 = alice.post("/spots", headers=H(alice_t), json={"mapID": map_id, "name": "s1", "lat": 1, "lng": 1}).get_json()["id"]
s2 = alice.post("/spots", headers=H(alice_t), json={"mapID": map_id, "name": "s2", "lat": 2, "lng": 2}).get_json()["id"]
conn = backend.get_db(); c = conn.cursor()
for i, sid in enumerate([s1, s1, s2]):
    c.execute("INSERT INTO photos (spot_id, filename) VALUES (?, ?)", (sid, f"p{i}.jpg"))
conn.commit(); conn.close()

# shares: bob directly (editor) + group Team (viewer)
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "editor"})
gid = admin.post("/admin/groups", headers=H(admin_t), json={"name": "Team"}).get_json()["id"]
admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "bob"})
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"})

print("\n== 1. Admin sees metadata for a regular user ==")
r = admin.get(f"/admin/users/{alice_id}/maps", headers=H(admin_t))
check(r.status_code == 200, f"admin GET user maps -> 200 (got {r.status_code})")
data = r.get_json()
check(set(data.keys()) == {"owned", "sharing_visible"} and data["sharing_visible"] is False,
      f"regular-admin payload is sealed (got {set(data.keys())}, sharing_visible={data.get('sharing_visible')})")
rows = data["owned"]
names = {x["name"] for x in rows}
check(names == {"Base Map", "Field Work"}, f"both maps listed ({names})")
fw = next(x for x in rows if x["name"] == "Field Work")
base = next(x for x in rows if x["name"] == "Base Map")
expected_owned_keys = {"id", "name", "created", "is_base", "markers", "photos"}
check(all(set(x.keys()) == expected_owned_keys for x in rows),
      f"regular-admin owned rows contain metadata only (got {[set(x.keys()) for x in rows]})")
check(fw["markers"] == 2 and fw["photos"] == 3, f"counts right (markers={fw['markers']}, photos={fw['photos']})")
check(base["is_base"] and not fw["is_base"], "is_base flag right")
check(bool(fw["created"]), "created date present")
check(all("description" not in x and "notes" not in x for x in rows), "description/notes NOT in payload (contents sealed)")

super_data = boss.get(f"/admin/users/{alice_id}/maps", headers=H(boss_t)).get_json()
check(set(super_data.keys()) == {"owned", "shared", "sharing_visible"} and super_data["sharing_visible"] is True,
      f"super-admin payload includes sharing metadata (got {set(super_data.keys())})")
super_rows = super_data["owned"]
super_fw = next(x for x in super_rows if x["name"] == "Field Work")
super_base = next(x for x in super_rows if x["name"] == "Base Map")
collab = {(x["type"], x["name"], x["role"]) for x in super_fw["collaborators"]}
check(collab == {("user", "bob", "editor"), ("group", "Team", "viewer")}, f"collaborators listed ({collab})")
check(super_base["collaborators"] == [], "base map has no collaborators")
check(all("description" not in x and "notes" not in x for x in super_rows), "super metadata also keeps contents sealed")
ulist = admin.get("/admin/users", headers=H(admin_t)).get_json()
by_name = {x["username"]: x for x in ulist}
check(by_name["bob"]["share_groups"] == ["Team"] and by_name["alice"]["share_groups"] == [], "admin user list carries group memberships")

print("\n== 1b. Maps shared WITH a user (direct + via group, aggregated per map) ==")
check(super_data["shared"] == [], "alice (owner side) has nothing shared WITH her")
# Being a member of a group that receives the owner's own map must not make that map
# appear as both owned and shared with the same user in the super-admin detail pane.
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t),
                json={"username": "alice"}).status_code == 200,
      "owner can also be added to the map's recipient group")
owner_view = boss.get(f"/admin/users/{alice_id}/maps", headers=H(boss_t)).get_json()
check(owner_view["shared"] == [],
      "owner's map shared to one of their groups stays out of Shared with this user")
r = admin.get(f"/admin/users/{bob_id}/maps", headers=H(admin_t))
bd = r.get_json()
check(r.status_code == 200 and set(bd.keys()) == {"owned", "sharing_visible"} and bd["sharing_visible"] is False,
      "regular admin gets bob's sealed metadata payload")
check([x["name"] for x in bd["owned"]] == ["Base Map"], "bob owns only his Base Map")
bd = boss.get(f"/admin/users/{bob_id}/maps", headers=H(boss_t)).get_json()
check(len(bd["shared"]) == 1 and bd["shared"][0]["name"] == "Field Work" and bd["shared"][0]["owner"] == "alice",
      f"Field Work shared with bob, owner alice (got {bd['shared']})")
check(bd["shared"][0]["owner_first"] == "Alice" and bd["shared"][0]["owner_last"] == "Owner",
      "super-only shared-map owner payload carries first/last name")
paths = {(p["type"], p.get("group"), p["role"]) for p in bd["shared"][0]["paths"]}
check(paths == {("direct", None, "editor"), ("group", "Team", "viewer")},
      f"both access paths listed (got {paths})")
check(all("markers" not in x and "photos" not in x and "description" not in x for x in bd["shared"]),
      "shared rows carry name/owner/role metadata only")
# A forced share row on a Base Map (grants nothing, P8 rule) must not surface here.
conn = backend.get_db(); c = conn.cursor()
c.execute("SELECT id FROM maps WHERE owner_id = ? AND is_base = 1", (alice_id,))
alice_base_id = c.fetchone()[0]
c.execute("INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?,?,?,?)",
          (alice_base_id, bob_id, "viewer", datetime.now().isoformat()))
conn.commit()
bd = boss.get(f"/admin/users/{bob_id}/maps", headers=H(boss_t)).get_json()
check([x["name"] for x in bd["shared"]] == ["Field Work"], "forced base-map share row does not surface")
c.execute("DELETE FROM map_shares WHERE map_id = ?", (alice_base_id,))
conn.commit(); conn.close()

print("\n== 2. Governance: regular admin inspects ONLY controlled users ==")
check(admin.get(f"/admin/users/{admin2_id}/maps", headers=H(admin_t)).status_code == 403, "admin -> other admin: 403")
check(admin.get(f"/admin/users/{super_id}/maps", headers=H(admin_t)).status_code == 403, "admin -> super: 403")
r = admin.get(f"/admin/users/{admin_id}/maps", headers=H(admin_t))
check(r.status_code == 403, f"admin -> SELF: 403 (own maps live in the app, got {r.status_code})")
r = boss.get(f"/admin/users/{admin2_id}/maps", headers=H(boss_t))
check(r.status_code == 200, f"super -> admin: 200 (got {r.status_code})")
check(boss.get(f"/admin/users/{alice_id}/maps", headers=H(boss_t)).status_code == 200, "super -> user: 200")

print("\n== 3. Non-admin / unknown target ==")
check(alice.get(f"/admin/users/{bob_id}/maps", headers=H(alice_t)).status_code == 403, "non-admin -> 403")
check(admin.get("/admin/users/no-such-id/maps", headers=H(admin_t)).status_code == 404, "unknown user -> 404")

print("\n== 4. Contents stay sealed for admins ==")
check(admin.get(f"/maps/{map_id}/spots", headers=H(admin_t)).status_code == 404, "admin GET spots of inspected map -> still 404")
check(admin.get(f"/spots/{s1}", headers=H(admin_t)).status_code == 404, "admin GET spot -> still 404")
check(admin.get(f"/maps/{map_id}/collaborators", headers=H(admin_t)).status_code == 404, "admin GET collaborators (owner route) -> still 404")

# --- extra fixtures for share management: carol (grant target), admin2's own map ---
carol_id = make_user("carol", "Carol123!", "user", "approved")
backend.create_base_map(carol_id)
carol, carol_t = login("carol", "Carol123!")
admin2, admin2_t = login("admin2", "Admin223!")
admin2_map = admin2.post("/maps", headers=H(admin2_t), json={"name": "Admin2 Map"}).get_json()["id"]
alice_base = next(x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["is_base"])

print("\n== 5. Regular admins cannot inspect or mutate map shares ==")
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t),
                json={"username": "carol", "role": "viewer"}).status_code == 200,
      "owner grants out-of-scope carol viewer through the unchanged owner route")
check(carol.get(f"/maps/{map_id}/spots", headers=H(carol_t)).status_code == 200,
      "carol can read before the blocked admin mutations")
check(admin.get(f"/admin/maps/{map_id}/collaborators", headers=H(admin_t)).status_code == 403,
      "regular admin GET collaborators -> 403")
check(admin.put(f"/admin/maps/{map_id}/collaborators", headers=H(admin_t),
                json={"username": "carol", "role": "editor"}).status_code == 403,
      "regular admin PUT collaborator -> 403")
check(admin.delete(f"/admin/maps/{map_id}/collaborators/{carol_id}", headers=H(admin_t)).status_code == 403,
      "regular admin DELETE user collaborator -> 403")
check(admin.delete(f"/admin/maps/{map_id}/collaborators/group/{gid}", headers=H(admin_t)).status_code == 403,
      "regular admin DELETE group collaborator -> 403")
check(carol.get(f"/maps/{map_id}/spots", headers=H(carol_t)).status_code == 200,
      "blocked admin DELETE does not revoke the existing share")
rows = boss.get(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t)).get_json()
check({(x["type"], x.get("username") or x.get("name"), x["role"]) for x in rows}
      == {("user", "bob", "editor"), ("user", "carol", "viewer"), ("group", "Team", "viewer")},
      f"super-admin still sees the complete untouched roster (got {rows})")

print("\n== 6. Super-admin validation and role-before-existence precedence ==")
check(boss.put(f"/admin/maps/{alice_base['id']}/collaborators", headers=H(boss_t),
               json={"username": "carol", "role": "viewer"}).status_code == 400,
      "super cannot share a base map -> 400")
check(boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t),
               json={"username": "alice", "role": "viewer"}).status_code == 400,
      "super cannot share with the owner -> 400")
regular_missing = [
    admin.get("/admin/maps/99999/collaborators", headers=H(admin_t)),
    admin.put("/admin/maps/99999/collaborators", headers=H(admin_t),
              json={"username": "carol", "role": "viewer"}),
    admin.delete(f"/admin/maps/99999/collaborators/{carol_id}", headers=H(admin_t)),
    admin.delete(f"/admin/maps/99999/collaborators/group/{gid}", headers=H(admin_t)),
]
check(all(x.status_code == 403 for x in regular_missing),
      f"regular admin gets 403 before map existence on all four routes (got {[x.status_code for x in regular_missing]})")
super_missing = [
    boss.get("/admin/maps/99999/collaborators", headers=H(boss_t)),
    boss.put("/admin/maps/99999/collaborators", headers=H(boss_t),
             json={"username": "carol", "role": "viewer"}),
    boss.delete(f"/admin/maps/99999/collaborators/{carol_id}", headers=H(boss_t)),
    boss.delete(f"/admin/maps/99999/collaborators/group/{gid}", headers=H(boss_t)),
]
check(all(x.status_code == 404 and x.get_json() == {"error": "Map not found"} for x in super_missing),
      f"super gets exact map-not-found contract on all four routes (got {[(x.status_code, x.get_json()) for x in super_missing]})")
check(boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t),
               json={"username": "nobody", "role": "viewer"}).status_code == 404,
      "unknown user -> 404")
check(boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t),
               json={"group": "nogroup", "role": "viewer"}).status_code == 404,
      "unknown group -> 404")
check(alice.put(f"/admin/maps/{map_id}/collaborators", headers=H(alice_t), json={"username": "carol", "role": "viewer"}).status_code == 403,
      "non-admin on admin route -> 403")

print("\n== 7. Super-admin self-grant is blocked ==")
check(boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t),
               json={"username": "boss", "role": "viewer"}).status_code == 403,
      "super grants self directly -> 403")
gid_super = admin.post("/admin/groups", headers=H(admin_t), json={"name": "SuperMembers"}).get_json()["id"]
check(boss.put(f"/admin/groups/{gid_super}/members", headers=H(boss_t),
               json={"username": "boss"}).status_code == 200,
      "super may be a member of a share group")
check(boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t),
               json={"group": "SuperMembers", "role": "viewer"}).status_code == 403,
      "super grants a group containing self -> 403")
r = boss.put(f"/admin/maps/{map_id}/collaborators", headers=H(boss_t), json={"username": "admin", "role": "viewer"})
check(r.status_code == 200, "super may grant another admin (only self-grant is blocked)")
boss.delete(f"/admin/maps/{map_id}/collaborators/{admin_id}", headers=H(boss_t))
check(admin.get(f"/maps/{map_id}/spots", headers=H(admin_t)).status_code == 404,
      "after all share management, admin still has NO content access")

print("\n== 8. Super-only gate is independent of map ownership ==")
check(admin.get(f"/admin/maps/{admin2_map}/collaborators", headers=H(admin_t)).status_code == 403, "admin GET on admin2's map -> 403")
check(admin.put(f"/admin/maps/{admin2_map}/collaborators", headers=H(admin_t), json={"username": "carol", "role": "viewer"}).status_code == 403,
      "admin PUT on admin2's map -> 403")
check(boss.get(f"/admin/maps/{admin2_map}/collaborators", headers=H(boss_t)).status_code == 200, "super GET on admin2's map -> 200")
r = boss.put(f"/admin/maps/{admin2_map}/collaborators", headers=H(boss_t), json={"username": "carol", "role": "viewer"})
check(r.status_code == 200, "super PUT on admin2's map -> 200")
boss.delete(f"/admin/maps/{admin2_map}/collaborators/{carol_id}", headers=H(boss_t))
# An admin's own maps still go through the owner routes, not the sealed admin routes.
check(admin2.get(f"/admin/maps/{admin2_map}/collaborators", headers=H(admin2_t)).status_code == 403,
      "admin route on their OWN map -> 403 (use the owner routes)")
r = admin2.put(f"/maps/{admin2_map}/collaborators", headers=H(admin2_t), json={"username": "carol", "role": "viewer"})
check(r.status_code == 200, f"owner route on their OWN map still works (got {r.status_code})")
check(admin2.delete(f"/maps/{admin2_map}/collaborators/{carol_id}", headers=H(admin2_t)).status_code == 200,
      "owner DELETE share on their OWN map -> 200")

print("\n== 9. Relationship metadata is omitted, not filtered, for regular admins ==")
# admin2 shares their own map with bob; the regular-admin response has no relationship
# channel at all, while the super-admin still sees the complete global result.
r = admin2.put(f"/maps/{admin2_map}/collaborators", headers=H(admin2_t), json={"username": "bob", "role": "viewer"})
check(r.status_code == 200, f"admin2 shares own map with bob (got {r.status_code})")
bd = admin.get(f"/admin/users/{bob_id}/maps", headers=H(admin_t)).get_json()
check(set(bd.keys()) == {"owned", "sharing_visible"} and bd["sharing_visible"] is False,
      f"regular admin has no shared-with field to filter (got {bd.keys()})")
bd = boss.get(f"/admin/users/{bob_id}/maps", headers=H(boss_t)).get_json()
check(any(x["name"] == "Admin2 Map" and x["owner"] == "admin2" for x in bd["shared"]),
      f"super DOES see the admin2-owned share (got {[x['name'] for x in bd['shared']]})")

print(f"\n=== {PASS} passed, {FAIL} failed ===")
sys.exit(1 if FAIL else 0)
