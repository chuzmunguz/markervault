"""Admin management-scope harness — documentation/permissions-model.md + multi-control addendum.

controls(admin, user) = user_controllers rows; owns_group(admin, group) = group_owners
rows (both many-to-many; multi-control itself is covered in test_multi_control.py).
A regular admin manages ONLY delegated/self-created users and groups; pending users are
super-only; nobody-land (zero controller rows) is superadmin-assignable, NOT claimable;
delete user is super-only; group delete needs created_by (sole owner) + owner + all
members in the owners' scope; membership add/remove needs controls() on the member.
Regular admins retain scoped map-metadata visibility but no map-share administration;
super-admin map-share administration remains global, including global share targets.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_as_")
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

def listed(cl, t):
    return {x["username"] for x in cl.get("/admin/users", headers=H(t)).get_json()}

def controllers_of(uid):
    conn = backend.get_db()
    rows = conn.execute("SELECT admin_id FROM user_controllers WHERE user_id = ?", (uid,)).fetchall()
    conn.close()
    return {r[0] for r in rows}

def group_owners_of(gid):
    conn = backend.get_db()
    rows = conn.execute("SELECT admin_id FROM share_group_owners WHERE group_id = ?", (gid,)).fetchall()
    conn.close()
    return {r[0] for r in rows}

boss_id  = make_user("boss",  "Boss1234!", "super_admin", "approved")
adm1_id  = make_user("adm1",  "Adm11234!", "admin", "approved")
adm2_id  = make_user("adm2",  "Adm21234!", "admin", "approved")
alice_id = make_user("alice", "Alice123!", "user", "approved")   # will be delegated to adm1
bob_id   = make_user("bob",   "Bob12345!", "user", "approved")   # will be delegated to adm2
nol_id   = make_user("nol",   "Nol12345!", "user", "approved")   # stays in nobody-land
pend_id  = make_user("pend",  "Pend1234!", "user", "pending")
conn = backend.get_db()
conn.execute("UPDATE users SET first_name='Admin', last_name='One' WHERE user_id = ?", (adm1_id,))
conn.commit(); conn.close()
for uid in (boss_id, adm1_id, adm2_id, alice_id, bob_id, nol_id):
    backend.create_base_map(uid)

boss, boss_t = login("boss", "Boss1234!")
adm1, adm1_t = login("adm1", "Adm11234!")
adm2, adm2_t = login("adm2", "Adm21234!")
alice, alice_t = login("alice", "Alice123!")

print("\n== 1. Assignment (controls delegation) is super-only ==")
check(adm1.put(f"/admin/users/{nol_id}/controllers", headers=H(adm1_t), json={"admin_id": adm1_id}).status_code == 403,
      "admin self-claim from nobody-land -> 403")
check(controllers_of(nol_id) == set(), "nobody-land user stays unassigned after claim attempt")
check(alice.put(f"/admin/users/{nol_id}/controllers", headers=H(alice_t), json={"admin_id": adm1_id}).status_code == 403,
      "non-admin assign -> 403")
r = boss.put(f"/admin/users/{alice_id}/controllers", headers=H(boss_t), json={"admin_id": adm1_id})
check(r.status_code == 200, f"super assigns alice -> adm1 (got {r.status_code})")
check(controllers_of(alice_id) == {adm1_id}, "controls(adm1, alice) recorded")
boss.put(f"/admin/users/{bob_id}/controllers", headers=H(boss_t), json={"admin_id": adm2_id})

print("\n== 1b. Assignment validation ==")
check(boss.put(f"/admin/users/{adm2_id}/controllers", headers=H(boss_t), json={"admin_id": adm1_id}).status_code == 400,
      "assigning an ADMIN to an admin -> 400 (admins are never controlled)")
check(boss.put(f"/admin/users/{pend_id}/controllers", headers=H(boss_t), json={"admin_id": adm1_id}).status_code == 400,
      "assigning a PENDING user -> 400 (approve first)")
check(boss.put(f"/admin/users/{nol_id}/controllers", headers=H(boss_t), json={"admin_id": alice_id}).status_code == 400,
      "controller must be an admin (user id -> 400)")
check(boss.put(f"/admin/users/{nol_id}/controllers", headers=H(boss_t), json={"admin_id": boss_id}).status_code == 400,
      "controller must be a regular admin (super id -> 400)")
check(boss.put("/admin/users/no-such/controllers", headers=H(boss_t), json={"admin_id": adm1_id}).status_code == 404,
      "unknown target -> 404")
check(boss.put(f"/admin/users/{nol_id}/controllers", headers=H(boss_t), json={}).status_code == 400,
      "missing admin_id -> 400")
check(boss.delete(f"/admin/users/{nol_id}/controllers/{adm1_id}", headers=H(boss_t)).status_code == 404,
      "revoking a grant that does not exist -> 404")

print("\n== 2. /admin/users visibility = the scope ==")
check(listed(boss, boss_t) == {"boss", "adm1", "adm2", "alice", "bob", "nol", "pend"},
      "super sees everyone (pending included)")
check(listed(adm1, adm1_t) == {"alice"},
      f"adm1 sees ONLY controlled users (got {listed(adm1, adm1_t)})")
check(listed(adm2, adm2_t) == {"bob"}, "adm2 sees only bob")
srow = next(x for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "alice")
expected_adm1 = {
    "admin_id": adm1_id,
    "username": "adm1",
    "first_name": "Admin",
    "last_name": "One",
}
check(srow["controllers"] == [expected_adm1],
      "super's list carries controller id, username, and real-name parts")
arow = next(x for x in adm1.get("/admin/users", headers=H(adm1_t)).get_json() if x["username"] == "alice")
expected_manager = {
    "username": "adm1",
    "first_name": "Admin",
    "last_name": "One",
}
check(arow["managers"] == [expected_manager]
      and "controllers" not in arow
      and "group_managers" not in arow,
      "regular-admin payload carries one source-agnostic manager list only")

print("\n== 3. Pending registrations are super-only ==")
rr = app.test_client().post("/register", json={"username": "carol", "password": "Carol123!",
                                               "first_name": "C", "last_name": "C", "email": "carol@x.com"})
check(rr.status_code == 200, "carol registers")
carol_id = next(x["user_id"] for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "carol")
check("carol" not in listed(adm1, adm1_t), "pending carol invisible to admins")
check(adm1.post(f"/admin/users/{carol_id}/approve", headers=H(adm1_t)).status_code == 403, "admin approve -> 403")
check(adm1.post(f"/admin/users/{carol_id}/reject", headers=H(adm1_t)).status_code == 403, "admin reject -> 403")
r = boss.post(f"/admin/users/{carol_id}/approve", headers=H(boss_t))
check(r.status_code == 200, "super approve -> 200")
check(controllers_of(carol_id) == set(), "approval lands carol in nobody-land (no auto-claim)")
check("carol" not in listed(adm1, adm1_t), "nobody-land carol STILL invisible to admins")
conn = backend.get_db()
n = conn.execute("SELECT COUNT(*) FROM maps WHERE owner_id=? AND is_base=1", (carol_id,)).fetchone()[0]
conn.close()
check(n == 1, "approval created carol's base map")

print("\n== 4. Admin actions honor controls() ==")
check(adm1.post(f"/admin/users/{alice_id}/disable", headers=H(adm1_t)).status_code == 200, "adm1 disables own user")
check(adm1.post(f"/admin/users/{alice_id}/enable", headers=H(adm1_t)).status_code == 200, "adm1 enables own user")
check(adm1.post(f"/admin/users/{alice_id}/resetpwd", headers=H(adm1_t), json={"new_password": "Alice123!"}).status_code == 200,
      "adm1 resets own user's password")
# Stage 10.2: disable/reset revoke alice's sessions and access JWTs immediately, so
# the suite must re-establish her session before using it again.
alice, alice_t = login("alice", "Alice123!")
check(alice_t is not None,
      "alice re-establishes her session after the immediate revocation")
for label, tid in [("other admin's user", bob_id), ("nobody-land user", nol_id), ("an admin", adm2_id), ("a super", boss_id)]:
    check(adm1.post(f"/admin/users/{tid}/disable", headers=H(adm1_t)).status_code == 403, f"adm1 disable {label} -> 403")
    check(adm1.post(f"/admin/users/{tid}/resetpwd", headers=H(adm1_t), json={"new_password": "Zzz99999!"}).status_code == 403,
          f"adm1 resetpwd {label} -> 403")
check(boss.post(f"/admin/users/{nol_id}/disable", headers=H(boss_t)).status_code == 200, "super disables a nobody-land user")
boss.post(f"/admin/users/{nol_id}/enable", headers=H(boss_t))

print("\n== 5. Delete user is super-only ==")
check(adm1.delete(f"/admin/users/{alice_id}", headers=H(adm1_t)).status_code == 403,
      "admin delete even their OWN user -> 403")
victim_id = make_user("victim", "Victim12!", "user", "approved")
check(boss.delete(f"/admin/users/{victim_id}", headers=H(boss_t)).status_code == 200, "super delete -> 200")

print("\n== 6. Create user: auto-grant only for the creating ADMIN ==")
base = {"password": "Made1234!", "first_name": "M", "last_name": "K"}
r = adm1.post("/admin/users/create", headers=H(adm1_t), json={**base, "username": "amade", "email": "am@x.com"})
check(r.status_code == 200, "admin creates a user")
amade_id = r.get_json()["user_id"]
check(controllers_of(amade_id) == {adm1_id}, "created user auto-assigned to creator (no nobody-land stopover)")
check("amade" in listed(adm1, adm1_t) and "amade" not in listed(adm2, adm2_t),
      "created user visible to creator only")
r = boss.post("/admin/users/create", headers=H(boss_t), json={**base, "username": "smade", "email": "sm@x.com"})
smade_id = r.get_json()["user_id"]
check(controllers_of(smade_id) == set(), "super-created user starts in nobody-land (supers need no grant)")

print("\n== 7. Revocation returns the user to nobody-land ==")
check(adm1.delete(f"/admin/users/{amade_id}/controllers/{adm1_id}", headers=H(adm1_t)).status_code == 403,
      "revocation is super-only (even of the caller's own grant)")
r = boss.delete(f"/admin/users/{amade_id}/controllers/{adm1_id}", headers=H(boss_t))
check(r.status_code == 200 and controllers_of(amade_id) == set(),
      "super revokes controls() -> nobody-land, regardless of create-origin")
check("amade" not in listed(adm1, adm1_t), "revoked user vanishes from the ex-controller's list")
check(adm1.post(f"/admin/users/{amade_id}/disable", headers=H(adm1_t)).status_code == 403,
      "ex-controller can no longer act")
check(adm1.put(f"/admin/users/{amade_id}/controllers", headers=H(adm1_t), json={"admin_id": adm1_id}).status_code == 403,
      "…and cannot self-claim the user back")

print("\n== 8. Maps metadata window honors controls() ==")
check(adm1.get(f"/admin/users/{alice_id}/maps", headers=H(adm1_t)).status_code == 200, "adm1 -> own user's maps: 200")
check(adm1.get(f"/admin/users/{bob_id}/maps", headers=H(adm1_t)).status_code == 403, "adm1 -> other admin's user: 403")
check(adm1.get(f"/admin/users/{nol_id}/maps", headers=H(adm1_t)).status_code == 403, "adm1 -> nobody-land user: 403")
check(adm1.get(f"/admin/users/{adm1_id}/maps", headers=H(adm1_t)).status_code == 403,
      "adm1 -> SELF: 403 (own maps live in the app, not the admin window)")
check(adm1.get(f"/admin/users/{adm2_id}/maps", headers=H(adm1_t)).status_code == 403, "adm1 -> other admin: 403")
check(boss.get(f"/admin/users/{adm1_id}/maps", headers=H(boss_t)).status_code == 200, "super -> admin: 200 (unscoped)")

print("\n== 9. Map-share administration is super-only and globally targeted ==")
am = alice.post("/maps", headers=H(alice_t), json={"name": "AliceMap"}).get_json()["id"]
check(adm2.get(f"/admin/maps/{am}/collaborators", headers=H(adm2_t)).status_code == 403,
      "admin without controls(owner) cannot inspect shares")
check(adm1.get(f"/admin/maps/{am}/collaborators", headers=H(adm1_t)).status_code == 403,
      "controlling admin cannot inspect shares either")
check(adm1.put(f"/admin/maps/{am}/collaborators", headers=H(adm1_t),
               json={"username": "nol", "role": "viewer"}).status_code == 403,
      "controlling admin cannot grant an outside user")
check(adm1.put(f"/admin/maps/{am}/collaborators", headers=H(adm1_t),
               json={"username": "adm2", "role": "viewer"}).status_code == 403,
      "controlling admin cannot grant an admin target")
check(boss.get(f"/admin/maps/{am}/collaborators", headers=H(boss_t)).status_code == 200,
      "super-admin inspects shares globally")
check(boss.put(f"/admin/maps/{am}/collaborators", headers=H(boss_t),
               json={"username": "nol", "role": "viewer"}).status_code == 200,
      "super-admin may target a user outside every regular-admin scope")
check(boss.put(f"/admin/maps/{am}/collaborators", headers=H(boss_t),
               json={"username": "adm2", "role": "viewer"}).status_code == 200,
      "super-admin may target an approved admin")
check(boss.put(f"/admin/maps/{am}/collaborators", headers=H(boss_t),
               json={"username": "boss", "role": "viewer"}).status_code == 403,
      "super-admin self-grant stays blocked")
check(boss.delete(f"/admin/maps/{am}/collaborators/{nol_id}", headers=H(boss_t)).status_code == 200
      and boss.delete(f"/admin/maps/{am}/collaborators/{adm2_id}", headers=H(boss_t)).status_code == 200,
      "super-admin removes both global-target shares")

print("\n== 10. Groups: creation grants ownership; visibility = ownership ==")
g1 = adm1.post("/admin/groups", headers=H(adm1_t), json={"name": "TeamA"}).get_json()
check(g1["owners"] == [{"admin_id": adm1_id, "username": "adm1"}] and g1["deletable"],
      "admin-created group: owner=creator, deletable")
g2 = boss.post("/admin/groups", headers=H(boss_t), json={"name": "SuperG"}).get_json()
check(g2["owners"] == [], "super-created group: superadmin-owned (no owner rows)")
adm1_groups = {x["name"] for x in adm1.get("/admin/groups", headers=H(adm1_t)).get_json()}
check(adm1_groups == {"TeamA"}, f"adm1 lists ONLY owned groups (got {adm1_groups})")
adm2_groups = {x["name"] for x in adm2.get("/admin/groups", headers=H(adm2_t)).get_json()}
check("TeamA" not in adm2_groups and "SuperG" not in adm2_groups,
      "other admin sees neither TeamA nor the superadmin-owned group")
boss_groups = boss.get("/admin/groups", headers=H(boss_t)).get_json()
check({x["name"] for x in boss_groups} >= {"TeamA", "SuperG"}, "super sees all groups")
team_a = next(x for x in boss_groups if x["name"] == "TeamA")
check(team_a["owners"] == [expected_adm1],
      "super's list shows enriched owner identity")
check(team_a["created_by_username"] == "adm1" and
      team_a["created_by_first"] == "Admin" and team_a["created_by_last"] == "One",
      "share-group creator keeps username plus real-name parts")
r = alice.get("/groups", headers=H(alice_t))
check(any(x["name"] == "TeamA" for x in r.get_json()), "share picker /groups stays GLOBAL (invariant 2)")

print("\n== 11. Group edit/membership honor owns_group + controls ==")
gid = g1["id"]
check(adm2.put(f"/admin/groups/{gid}", headers=H(adm2_t), json={"name": "Stolen"}).status_code == 403,
      "non-owner admin rename -> 403")
check(adm2.put(f"/admin/groups/{gid}/members", headers=H(adm2_t), json={"username": "bob"}).status_code == 403,
      "non-owner admin add-member -> 403")
check(adm1.put(f"/admin/groups/{gid}", headers=H(adm1_t), json={"name": "TeamA1"}).status_code == 200, "owner renames")
adm1.put(f"/admin/groups/{gid}", headers=H(adm1_t), json={"name": "TeamA"})
check(adm1.put(f"/admin/groups/{gid}/members", headers=H(adm1_t), json={"username": "alice"}).status_code == 200,
      "owner adds a CONTROLLED user")
check(adm1.put(f"/admin/groups/{gid}/members", headers=H(adm1_t), json={"username": "nol"}).status_code == 403,
      "owner adding a nobody-land user -> 403 (controls needed)")
check(adm1.put(f"/admin/groups/{gid}/members", headers=H(adm1_t), json={"username": "bob"}).status_code == 403,
      "owner adding another admin's user -> 403")
check(adm1.put(f"/admin/groups/{gid}/members", headers=H(adm1_t), json={"username": "adm1"}).status_code == 403,
      "admin self-add -> 403 (nobody controls themselves)")
check(boss.put(f"/admin/groups/{gid}/members", headers=H(boss_t), json={"username": "boss"}).status_code == 200,
      "SUPER self-add -> 200 (supers are unscoped; decided Jul 12)")
check(boss.put(f"/admin/groups/{gid}/members", headers=H(boss_t), json={"username": "nol"}).status_code == 200,
      "super adds an out-of-scope member to a delegated group")
members = {m["username"]: m for m in next(x for x in adm1.get("/admin/groups", headers=H(adm1_t)).get_json() if x["id"] == gid)["members"]}
check(members["alice"]["managed"] and not members["nol"]["managed"],
      "per-member 'managed' flag reflects the caller's controls()")

print("\n== 12. Member removal needs controls() on the member ==")
check(adm1.delete(f"/admin/groups/{gid}/members/{nol_id}", headers=H(adm1_t)).status_code == 403,
      "owner removing an out-of-scope member -> 403 (super-placed members stay)")
check(adm1.delete(f"/admin/groups/{gid}/members/{alice_id}", headers=H(adm1_t)).status_code == 200,
      "owner removes a controlled member")
adm1.put(f"/admin/groups/{gid}/members", headers=H(adm1_t), json={"username": "alice"})
check(boss.delete(f"/admin/groups/{gid}/members/{nol_id}", headers=H(boss_t)).status_code == 200,
      "super removes the out-of-scope member")
boss.delete(f"/admin/groups/{gid}/members/{boss_id}", headers=H(boss_t))

print("\n== 13. Group delete: self-created + owned + members all in scope ==")
glist = adm1.get("/admin/groups", headers=H(adm1_t)).get_json()
check(next(x for x in glist if x["id"] == gid)["deletable"], "all members controlled -> deletable flag true")
boss.put(f"/admin/groups/{gid}/members", headers=H(boss_t), json={"username": "nol"})
glist = adm1.get("/admin/groups", headers=H(adm1_t)).get_json()
check(not next(x for x in glist if x["id"] == gid)["deletable"], "outside member -> deletable flag false")
check(adm1.delete(f"/admin/groups/{gid}", headers=H(adm1_t)).status_code == 403,
      "delete with an outside member -> 403 (super territory)")
boss.delete(f"/admin/groups/{gid}/members/{nol_id}", headers=H(boss_t))
check(adm1.delete(f"/admin/groups/{gid}", headers=H(adm1_t)).status_code == 200,
      "delete own group, all members in scope -> 200")

print("\n== 14. Group delegation (owns_group) is super-only ==")
sgid = g2["id"]
check(adm1.put(f"/admin/groups/{sgid}/owners", headers=H(adm1_t), json={"admin_id": adm1_id}).status_code == 403,
      "admin cannot grab a group")
r = boss.put(f"/admin/groups/{sgid}/owners", headers=H(boss_t), json={"admin_id": adm1_id})
check(r.status_code == 200 and group_owners_of(sgid) == {adm1_id}, "super delegates SuperG -> adm1")
check(any(x["id"] == sgid for x in adm1.get("/admin/groups", headers=H(adm1_t)).get_json()),
      "delegated group appears in the admin's list")
check(adm1.put(f"/admin/groups/{sgid}", headers=H(adm1_t), json={"name": "SuperG2"}).status_code == 200,
      "delegated group is editable (same fact, same check, any origin)")
adm1.put(f"/admin/groups/{sgid}", headers=H(adm1_t), json={"name": "SuperG"})
check(adm1.delete(f"/admin/groups/{sgid}", headers=H(adm1_t)).status_code == 403,
      "…but NOT deletable by the sole delegated owner (not self-created)")
check(not next(x for x in adm1.get("/admin/groups", headers=H(adm1_t)).get_json() if x["id"] == sgid)["deletable"],
      "deletable flag false on a sole-delegated group")
check(adm1.delete(f"/admin/groups/{sgid}/owners/{adm1_id}", headers=H(adm1_t)).status_code == 403,
      "revocation is super-only (even of the caller's own grant)")
r = boss.delete(f"/admin/groups/{sgid}/owners/{adm1_id}", headers=H(boss_t))
check(r.status_code == 200 and group_owners_of(sgid) == set(),
      "revocation reverts ownership to the superadmin (never a claim pool)")
check(all(x["id"] != sgid for x in adm1.get("/admin/groups", headers=H(adm1_t)).get_json()),
      "reverted group vanishes from the ex-owner's list")
check(boss.delete(f"/admin/groups/{sgid}/owners/{adm1_id}", headers=H(boss_t)).status_code == 404,
      "revoking a delegation that does not exist -> 404")
check(boss.put(f"/admin/groups/{sgid}/owners", headers=H(boss_t), json={"admin_id": alice_id}).status_code == 400,
      "group owner must be an approved admin")
check(boss.put("/admin/groups/99999/owners", headers=H(boss_t), json={"admin_id": adm1_id}).status_code == 404,
      "unknown group -> 404")

print("\n== 15. Role changes clean delegation up ==")
# Promote a controlled user: the new admin sheds their controllers.
boss.put(f"/admin/users/{carol_id}/controllers", headers=H(boss_t), json={"admin_id": adm1_id})
boss.post(f"/admin/users/{carol_id}/role", headers=H(boss_t), json={"role": "admin"})
check(controllers_of(carol_id) == set(), "promotion clears the promoted user's controllers")
# Give carol (now admin) a user and a group, then demote her.
cheld_id = make_user("cheld", "Cheld123!", "user", "approved")
boss.put(f"/admin/users/{cheld_id}/controllers", headers=H(boss_t), json={"admin_id": carol_id})
carol_cl, carol_t = login("carol", "Carol123!")
cg = carol_cl.post("/admin/groups", headers=H(carol_t), json={"name": "CarolG"}).get_json()
boss.post(f"/admin/users/{carol_id}/role", headers=H(boss_t), json={"role": "user"})
check(controllers_of(cheld_id) == set(), "demotion returns the ex-admin's users to nobody-land")
check(group_owners_of(cg["id"]) == set(), "demotion reverts the ex-admin's groups to the superadmin")

print("\n== 16. Group membership stays administratively inert (invariant 1) ==")
# adm2 and alice share a group; that must give adm2 NO authority or view over alice.
gi = boss.post("/admin/groups", headers=H(boss_t), json={"name": "Mixed"}).get_json()["id"]
boss.put(f"/admin/groups/{gi}/members", headers=H(boss_t), json={"username": "adm2"})
boss.put(f"/admin/groups/{gi}/members", headers=H(boss_t), json={"username": "alice"})
check("alice" not in listed(adm2, adm2_t), "co-membership adds nothing to the admin's list")
check(adm2.post(f"/admin/users/{alice_id}/disable", headers=H(adm2_t)).status_code == 403,
      "co-membership grants no management authority")
check(adm2.get(f"/admin/users/{alice_id}/maps", headers=H(adm2_t)).status_code == 403,
      "co-membership grants no maps view")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
