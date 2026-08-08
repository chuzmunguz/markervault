"""Groups harness: admin-managed groups + group-based map sharing.

Covers: group CRUD authorization (admin-only), membership CRUD, /groups picker route,
group shares granting viewer/editor access to members, best-of role resolution
(direct + group), instant revocation on member-remove / share-remove / group-delete,
Base Map exclusion, bulk group share, collaborator listing with group rows.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_grp_")
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

alice_id = make_user("alice", "Alice123!", "user", "approved")   # map owner
bob_id   = make_user("bob",   "Bob12345!", "user", "approved")   # group member
carol_id = make_user("carol", "Carol123!", "user", "approved")   # group member
dave_id  = make_user("dave",  "Dave1234!", "user", "approved")   # outsider
admin_id = make_user("admin", "Admin123!", "admin", "approved")
pend_id  = make_user("pend",  "Pend1234!", "user", "pending")
conn = backend.get_db()
conn.execute("UPDATE users SET first_name='Group', last_name='Admin' WHERE user_id = ?", (admin_id,))
conn.commit(); conn.close()
for uid in (alice_id, bob_id, carol_id, dave_id, admin_id):
    backend.create_base_map(uid)
# Fixture: the regular users are delegated to the fixture admin (controls() = user_controllers);
# management scoping itself is covered by test_admin_scope.py.
conn = backend.get_db()
conn.execute("INSERT INTO user_controllers (user_id, admin_id, created) SELECT user_id, ?, datetime('now') FROM users WHERE role = 'user' AND status = 'approved'", (admin_id,))
conn.commit(); conn.close()

alice, alice_t = login("alice", "Alice123!")
bob, bob_t     = login("bob", "Bob12345!")
carol, carol_t = login("carol", "Carol123!")
dave, dave_t   = login("dave", "Dave1234!")
admin, admin_t = login("admin", "Admin123!")

m = alice.post("/maps", headers=H(alice_t), json={"name": "Group Map"}).get_json()
map_id = m["id"]
s = alice.post("/spots", headers=H(alice_t), json={"mapID": map_id, "name": "s1", "lat": 10, "lng": 10}).get_json()
spot_id = s["id"]
alice_base = next(x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["is_base"])

print("\n== 1. Group CRUD is admin-only ==")
check(alice.post("/admin/groups", headers=H(alice_t), json={"name": "Nope"}).status_code == 403, "non-admin create group -> 403")
check(alice.get("/admin/groups", headers=H(alice_t)).status_code == 403, "non-admin list admin groups -> 403")
r = admin.post("/admin/groups", headers=H(admin_t), json={"name": "Team"})
check(r.status_code == 200, f"admin creates group (got {r.status_code})")
gid = r.get_json()["id"]
check(admin.post("/admin/groups", headers=H(admin_t), json={"name": "team"}).status_code == 400, "duplicate name (case-insensitive) -> 400")
check(admin.post("/admin/groups", headers=H(admin_t), json={"name": "  "}).status_code == 400, "blank name -> 400")
groups = admin.get("/admin/groups", headers=H(admin_t)).get_json()
check(any(x["id"] == gid and x["members"] == [] for x in groups), "admin list shows new empty group")
team = next(x for x in groups if x["id"] == gid)
check(team["created_by_username"] == "admin" and
      team["created_by_first"] == "Group" and team["created_by_last"] == "Admin" and
      team["owners"] == [{
          "admin_id": admin_id,
          "username": "admin",
          "first_name": "Group",
          "last_name": "Admin",
      }],
      "share-group creator and owner payloads carry real-name parts")

print("\n== 2. /groups picker route (any authenticated user) ==")
r = alice.get("/groups", headers=H(alice_t))
check(r.status_code == 200 and any(x["id"] == gid and x["name"] == "Team" for x in r.get_json()), "non-admin sees group names via /groups")
check(set(r.get_json()[0].keys()) == {"id", "name"}, "/groups exposes id+name only")

print("\n== 3. Rename ==")
r = admin.post("/admin/groups", headers=H(admin_t), json={"name": "Other"})
gid2 = r.get_json()["id"]
check(admin.put(f"/admin/groups/{gid}", headers=H(admin_t), json={"name": "Crew"}).status_code == 200, "rename -> 200")
check(admin.put(f"/admin/groups/{gid}", headers=H(admin_t), json={"name": "other"}).status_code == 400, "rename onto existing name -> 400")
check(admin.put("/admin/groups/99999", headers=H(admin_t), json={"name": "X"}).status_code == 404, "rename unknown group -> 404")
admin.put(f"/admin/groups/{gid}", headers=H(admin_t), json={"name": "Team"})

print("\n== 4. Membership CRUD ==")
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "bob"}).status_code == 200, "add bob -> 200")
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "BOB"}).status_code == 200, "re-add (case-insensitive) idempotent -> 200")
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "carol"}).status_code == 200, "add carol -> 200")
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "nobody"}).status_code == 404, "unknown user -> 404")
check(admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "pend"}).status_code == 404, "pending user -> 404")
check(admin.put("/admin/groups/99999/members", headers=H(admin_t), json={"username": "bob"}).status_code == 404, "unknown group -> 404")
check(alice.put(f"/admin/groups/{gid}/members", headers=H(alice_t), json={"username": "dave"}).status_code == 403, "non-admin add member -> 403")
grp = next(x for x in admin.get("/admin/groups", headers=H(admin_t)).get_json() if x["id"] == gid)
check({u["username"] for u in grp["members"]} == {"bob", "carol"}, "member list = bob+carol (no dupes)")

print("\n== 5. Group share grants member access ==")
r = alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"})
check(r.status_code == 200, f"owner shares map with group as viewer (got {r.status_code})")
bmap = next((x for x in bob.get("/maps", headers=H(bob_t)).get_json() if x["id"] == map_id), None)
check(bmap is not None and bmap["role"] == "viewer" and not bmap["owned"], "map in member bob's /maps w/ role=viewer")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 200, "member bob reads spots -> 200")
check(bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "x", "lat": 1, "lng": 1}).status_code == 404, "viewer-member bob writes spot -> 404")
check(carol.get(f"/maps/{map_id}/spots", headers=H(carol_t)).status_code == 200, "member carol reads spots -> 200")
check(dave.get(f"/maps/{map_id}/spots", headers=H(dave_t)).status_code == 404, "non-member dave -> 404")
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "nogroup", "role": "viewer"}).status_code == 404, "share with unknown group -> 404")
check(alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "username": "bob", "role": "viewer"}).status_code == 400, "both username and group -> 400")
rows = alice.get(f"/maps/{map_id}/collaborators", headers=H(alice_t)).get_json()
check(any(x.get("type") == "group" and x.get("name") == "Team" and x["role"] == "viewer" for x in rows), "collaborator list has the group row")

print("\n== 6. Editor via group + best-of role resolution ==")
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "editor"})
r = bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "byBob", "lat": 2, "lng": 2})
check(r.status_code == 200, f"editor-member bob adds spot -> 200 (got {r.status_code})")
check(bob.put(f"/maps/{map_id}", headers=H(bob_t), json={"name": "Group Map"}).status_code == 200, "editor-member bob edits map entity -> 200")
check(bob.delete(f"/maps/{map_id}", headers=H(bob_t)).status_code == 404, "editor-member bob cannot delete map")
check(bob.get(f"/maps/{map_id}/collaborators", headers=H(bob_t)).status_code == 404, "editor-member bob cannot see/manage shares")
# direct viewer + group editor -> effective editor; group viewer + direct viewer -> viewer
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username": "bob", "role": "viewer"})
bmap = next(x for x in bob.get("/maps", headers=H(bob_t)).get_json() if x["id"] == map_id)
check(bmap["role"] == "editor", "direct viewer + group editor -> /maps role=editor")
check(bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "y", "lat": 3, "lng": 3}).status_code == 200, "best-of grants editor writes")
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"})
bmap = next(x for x in bob.get("/maps", headers=H(bob_t)).get_json() if x["id"] == map_id)
check(bmap["role"] == "viewer", "direct viewer + group viewer -> viewer")
check(bob.post("/spots", headers=H(bob_t), json={"mapID": map_id, "name": "z", "lat": 4, "lng": 4}).status_code == 404, "viewer best-of blocks writes")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 200, "viewer best-of still reads")
# spot count not multiplied by the two grants (direct + group) in /maps
spots_n = len(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).get_json())
check(bmap["markers"] == spots_n, f"/maps marker count not inflated by multiple grants ({bmap['markers']} == {spots_n})")
alice.delete(f"/maps/{map_id}/collaborators/{bob_id}", headers=H(alice_t))   # drop direct share again

print("\n== 7. Revocation propagates instantly ==")
admin.delete(f"/admin/groups/{gid}/members/{bob_id}", headers=H(admin_t))
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 404, "removed member loses access")
check(all(x["id"] != map_id for x in bob.get("/maps", headers=H(bob_t)).get_json()), "map gone from removed member's /maps")
check(admin.delete(f"/admin/groups/{gid}/members/{bob_id}", headers=H(admin_t)).status_code == 404, "remove again -> 404")
check(carol.get(f"/maps/{map_id}/spots", headers=H(carol_t)).status_code == 200, "other member unaffected")
admin.put(f"/admin/groups/{gid}/members", headers=H(admin_t), json={"username": "bob"})
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 200, "re-added member regains access")
r = alice.delete(f"/maps/{map_id}/collaborators/group/{gid}", headers=H(alice_t))
check(r.status_code == 200, "owner removes the group share")
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 404, "share removal revokes members")
check(alice.delete(f"/maps/{map_id}/collaborators/group/{gid}", headers=H(alice_t)).status_code == 404, "remove again -> 404")
check(bob.delete(f"/maps/{map_id}/collaborators/group/{gid}", headers=H(bob_t)).status_code == 404, "non-owner cannot remove group share")
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"})
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 200, "re-shared -> member access back")
admin.delete(f"/admin/groups/{gid}", headers=H(admin_t))
check(bob.get(f"/maps/{map_id}/spots", headers=H(bob_t)).status_code == 404, "group DELETE revokes members (cascade)")
conn = backend.get_db(); c = conn.cursor()
c.execute("SELECT COUNT(*) FROM map_group_shares WHERE group_id = ?", (gid,))
check(c.fetchone()[0] == 0, "group delete cascaded its map shares")
conn.close()

print("\n== 8. Base Maps stay outside group sharing ==")
gid3 = admin.post("/admin/groups", headers=H(admin_t), json={"name": "Team"}).get_json()["id"]
admin.put(f"/admin/groups/{gid3}/members", headers=H(admin_t), json={"username": "bob"})
check(alice.put(f"/maps/{alice_base['id']}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"}).status_code == 400,
      "group-share a Base Map -> 400")
# a forced share row on a base map must still grant nothing
conn = backend.get_db(); c = conn.cursor()
c.execute("INSERT INTO map_group_shares (map_id, group_id, role, created) VALUES (?,?,?,?)",
          (alice_base["id"], gid3, "editor", datetime.now().isoformat()))
conn.commit(); conn.close()
check(bob.get(f"/maps/{alice_base['id']}/spots", headers=H(bob_t)).status_code == 404, "forced base-map group share grants nothing")
check(all(x["id"] != alice_base["id"] for x in bob.get("/maps", headers=H(bob_t)).get_json()), "base map absent from member's /maps")
conn = backend.get_db(); c = conn.cursor()
c.execute("DELETE FROM map_group_shares WHERE map_id = ?", (alice_base["id"],))
conn.commit(); conn.close()

print("\n== 9. Owner in the group keeps role=owner ==")
admin.put(f"/admin/groups/{gid3}/members", headers=H(admin_t), json={"username": "alice"})
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"group": "Team", "role": "viewer"})
amap = next(x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["id"] == map_id)
check(amap["role"] == "owner" and amap["owned"], "owner's role unaffected by group membership")
check(len([x for x in alice.get("/maps", headers=H(alice_t)).get_json() if x["id"] == map_id]) == 1,
      "owner's map listed once despite owner+group grant")

print("\n== 10. Bulk group share ==")
m1 = alice.post("/maps", headers=H(alice_t), json={"name": "Bulk A"}).get_json()["id"]
m2 = alice.post("/maps", headers=H(alice_t), json={"name": "Bulk B"}).get_json()["id"]
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, m2], "group": "Team", "role": "viewer"})
check(r.status_code == 200 and r.get_json().get("shared") == 2, f"bulk group share -> 200/shared=2 (got {r.status_code})")
bids = {x["id"] for x in bob.get("/maps", headers=H(bob_t)).get_json()}
check(m1 in bids and m2 in bids, "member sees both bulk-shared maps")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "group": "Team", "username": "bob", "role": "viewer"}).status_code == 400,
      "bulk with both targets -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "role": "viewer"}).status_code == 400,
      "bulk with neither target -> 400")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1], "group": "nogroup", "role": "viewer"}).status_code == 404,
      "bulk unknown group -> 404")
check(alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, alice_base["id"]], "group": "Team", "role": "viewer"}).status_code == 400,
      "bulk incl. base map -> 400")
bob_map = bob.post("/maps", headers=H(bob_t), json={"name": "Bobs"}).get_json()["id"]
r = alice.put("/maps/collaborators", headers=H(alice_t), json={"map_ids": [m1, bob_map], "group": "Team", "role": "editor"})
check(r.status_code == 404, "bulk incl. non-owned map -> 404 (all-or-nothing)")
bmap1 = next(x for x in bob.get("/maps", headers=H(bob_t)).get_json() if x["id"] == m1)
check(bmap1["role"] == "viewer", "failed bulk wrote nothing (m1 still viewer)")

print("\n== 11. Addendum-4 second-named residual: creator delete severs INVISIBLE inbound edges ==")
# permissions-model-addendum-4 §"Why share-group operations stay" pins this as an
# ACCEPTED, UNGATED residual: a regular-admin group CREATOR may delete their group even
# when its only out-of-scope connection is an inbound map->group share from an owner the
# creator cannot see (inflow is sealed under Addendum 4). The delete must NOT be gated on
# that invisible edge (gating would leak the sealed fact through the 403 itself); it
# succeeds and cascades the edge away. §7 above covers the in-scope cascade; this covers
# the deliberately-blind out-of-scope one, which no prior test exercised.
resid_creator_id = make_user("resid_creator", "Resid123!", "admin", "approved")
resid_member_id = make_user("resid_member", "Resid123!", "user", "approved")
resid_outsider_id = make_user("resid_outsider", "Resid123!", "user", "approved")
for uid in (resid_creator_id, resid_member_id, resid_outsider_id):
    backend.create_base_map(uid)
# The creator controls ONLY the in-scope member — the outsider is entirely outside scope.
conn = backend.get_db()
conn.execute("INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?,?,?)",
             (resid_member_id, resid_creator_id, datetime.now().isoformat()))
conn.commit(); conn.close()
resid_creator, resid_creator_t = login("resid_creator", "Resid123!")
resid_outsider, resid_outsider_t = login("resid_outsider", "Resid123!")
resid_member, resid_member_t = login("resid_member", "Resid123!")

resid_gid = resid_creator.post("/admin/groups", headers=H(resid_creator_t),
                               json={"name": "Residual Group"}).get_json()["id"]
check(resid_creator.put(f"/admin/groups/{resid_gid}/members", headers=H(resid_creator_t),
                        json={"username": "resid_member"}).status_code == 200,
      "creator adds the in-scope member")
# The out-of-scope outsider owns a map and shares it TO the creator's group (inbound edge).
resid_omap = resid_outsider.post("/maps", headers=H(resid_outsider_t),
                                 json={"name": "Outsider Map"}).get_json()["id"]
check(resid_outsider.put(f"/maps/{resid_omap}/collaborators", headers=H(resid_outsider_t),
                         json={"group": "Residual Group", "role": "viewer"}).status_code == 200,
      "out-of-scope owner shares a map to the group (creates the invisible inbound edge)")
check(resid_member.get(f"/maps/{resid_omap}/spots", headers=H(resid_member_t)).status_code == 200,
      "member reaches the outsider's map through the group")
conn = backend.get_db(); c = conn.cursor()
c.execute("SELECT COUNT(*) FROM map_group_shares WHERE group_id = ?", (resid_gid,))
check(c.fetchone()[0] == 1, "inbound map_group_shares edge exists before delete")
conn.close()
# ★ Creator deletes the group. The ONLY connection outside the creator's scope is the
# inbound share it cannot see. Per the addendum this is ungated -> 200 (not a leaking 403).
resid_del = resid_creator.delete(f"/admin/groups/{resid_gid}", headers=H(resid_creator_t))
check(resid_del.status_code == 200,
      f"creator delete succeeds despite the invisible out-of-scope inbound share (got {resid_del.status_code})")
conn = backend.get_db(); c = conn.cursor()
c.execute("SELECT COUNT(*) FROM map_group_shares WHERE group_id = ?", (resid_gid,))
resid_edges_after = c.fetchone()[0]
c.execute("SELECT 1 FROM share_groups WHERE id = ?", (resid_gid,))
resid_group_gone = c.fetchone() is None
conn.close()
check(resid_edges_after == 0 and resid_group_gone,
      "delete cascaded the invisible inbound edge and removed the group")
check(resid_member.get(f"/maps/{resid_omap}/spots", headers=H(resid_member_t)).status_code == 404,
      "member loses the severed access")
check(resid_outsider.get(f"/maps/{resid_omap}/spots", headers=H(resid_outsider_t)).status_code == 200,
      "the out-of-scope owner's own map itself survives the group delete")

print(f"\n=== {PASS} passed, {FAIL} failed ===")
sys.exit(1 if FAIL else 0)
