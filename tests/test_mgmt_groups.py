"""Management-groups harness — documentation/permissions-model-addendum-3-management-groups.md.

Management groups are the second source of controls(): effective_controls(admin, user)
= direct user_controllers OR (user ∈ mgmt_group AND manage_mgmt_group(admin, group)).
Everything about the groups themselves is superadmin-only end to end (create, rename,
delete, membership, manager delegation — no admin self-serve path of any kind).
Members are regular users only, never admin-level accounts. Downstream checks (admin
user list, account-action guards, map metadata, share-group scoping and the creator
delete rule) must treat both controls() sources identically. Addendum 4 deliberately
removes regular-admin map-share administration regardless of the controls() source;
the superadmin tooling is the only place where source is visible.
Cascades: promoting a member to admin clears their memberships (admins are never
controlled); demoting/deleting a manager drops only that admin's manager grants.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_mg_")
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

def members_of(gid):
    conn = backend.get_db()
    rows = conn.execute("SELECT user_id FROM mgmt_group_members WHERE group_id = ?", (gid,)).fetchall()
    conn.close()
    return {r[0] for r in rows}

def managers_of(gid):
    conn = backend.get_db()
    rows = conn.execute("SELECT admin_id FROM mgmt_group_managers WHERE group_id = ?", (gid,)).fetchall()
    conn.close()
    return {r[0] for r in rows}

def mgroup_row(gid):
    return next((x for x in boss.get("/admin/mgmt-groups", headers=H(boss_t)).get_json() if x["id"] == gid), None)

boss_id = make_user("boss", "Boss1234!", "super_admin", "approved")
admA_id = make_user("admA", "AdmA1234!", "admin", "approved")
admB_id = make_user("admB", "AdmB1234!", "admin", "approved")
admC_id = make_user("admC", "AdmC1234!", "admin", "approved")
bob_id  = make_user("bob",  "Bob12345!", "user", "approved")
carol_id = make_user("carol", "Carol123!", "user", "approved")
dave_id = make_user("dave", "Dave1234!", "user", "approved")
pend_id = make_user("pend", "Pend1234!", "user", "pending")
off_id  = make_user("off",  "Off12345!", "user", "disabled")
disadm_id = make_user("disadm", "Disadm12!", "admin", "disabled")
conn = backend.get_db()
for uid, first, last in (
    (boss_id, "Boss", "Operator"),
    (admA_id, "Admin", "Alpha"),
    (admB_id, "Admin", "Beta"),
    (admC_id, "Admin", "Gamma"),
):
    conn.execute("UPDATE users SET first_name=?, last_name=? WHERE user_id = ?", (first, last, uid))
conn.commit(); conn.close()
for uid in (boss_id, admA_id, admB_id, admC_id, bob_id, carol_id, dave_id):
    backend.create_base_map(uid)

boss, boss_t = login("boss", "Boss1234!")
admA, admA_t = login("admA", "AdmA1234!")
admB, admB_t = login("admB", "AdmB1234!")
bob, bob_t = login("bob", "Bob12345!")

print("\n== 1. Superadmin-only end to end: every route 403s a regular admin ==")
r = boss.post("/admin/mgmt-groups", headers=H(boss_t), json={"name": "Ops"})
gid = r.get_json()["id"]
check(r.status_code == 200, "super creates a management group")
check(admA.get("/admin/mgmt-groups", headers=H(admA_t)).status_code == 403, "admin cannot even LIST management groups")
check(admA.post("/admin/mgmt-groups", headers=H(admA_t), json={"name": "Rogue"}).status_code == 403, "admin cannot create")
check(admA.put(f"/admin/mgmt-groups/{gid}", headers=H(admA_t), json={"name": "X"}).status_code == 403, "admin cannot rename")
check(admA.delete(f"/admin/mgmt-groups/{gid}", headers=H(admA_t)).status_code == 403, "admin cannot delete")
check(admA.put(f"/admin/mgmt-groups/{gid}/members", headers=H(admA_t), json={"username": "bob"}).status_code == 403,
      "admin cannot add members")
check(admA.delete(f"/admin/mgmt-groups/{gid}/members/{bob_id}", headers=H(admA_t)).status_code == 403,
      "admin cannot remove members")
check(admA.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(admA_t), json={"admin_id": admA_id}).status_code == 403,
      "admin cannot self-assign as manager (no claim path)")
check(admA.delete(f"/admin/mgmt-groups/{gid}/managers/{admB_id}", headers=H(admA_t)).status_code == 403,
      "admin cannot revoke a manager")
check(bob.get("/admin/mgmt-groups", headers=H(bob_t)).status_code == 403, "regular user blocked (require_admin)")

print("\n== 2. Group CRUD basics (super) ==")
check(boss.post("/admin/mgmt-groups", headers=H(boss_t), json={"name": "ops"}).status_code == 400,
      "duplicate name rejected case-insensitively")
check(boss.post("/admin/mgmt-groups", headers=H(boss_t), json={"name": "  "}).status_code == 400, "blank name rejected")
check(boss.put(f"/admin/mgmt-groups/{gid}", headers=H(boss_t), json={"name": "Ops Team"}).status_code == 200, "super renames")
check(boss.put("/admin/mgmt-groups/99999", headers=H(boss_t), json={"name": "Ghost"}).status_code == 404,
      "rename of a missing group -> 404")
row = mgroup_row(gid)
check(row["name"] == "Ops Team" and row["created_by_username"] == "boss" and
      row["created_by_first"] == "Boss" and row["created_by_last"] == "Operator" and
      row["managers"] == [] and row["members"] == [],
      "list payload: name, enriched creator, empty managers/members")

print("\n== 3. Members are regular users only ==")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "admA"}).status_code == 400,
      "admin cannot be a member")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "boss"}).status_code == 400,
      "superadmin cannot be a member")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "pend"}).status_code == 400,
      "pending user must be approved first")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "ghost"}).status_code == 404,
      "unknown username -> 404")
check(boss.put("/admin/mgmt-groups/99999/members", headers=H(boss_t), json={"username": "bob"}).status_code == 404,
      "missing group -> 404")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "bob"}).status_code == 200,
      "approved regular user added")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "off"}).status_code == 200,
      "disabled user may be a member (control enables re-enabling)")
check(boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "bob"}).status_code == 200
      and members_of(gid) == {bob_id, off_id},
      "re-adding an existing member is an idempotent no-op")

print("\n== 4. Manager delegation: approved regular admins only, additive, targeted revoke ==")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": bob_id}).status_code == 400,
      "regular user cannot be a manager")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": boss_id}).status_code == 400,
      "superadmin never gets a grant (needs none)")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": disadm_id}).status_code == 400,
      "disabled admin rejected")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": admA_id}).status_code == 200,
      "super delegates admA as manager")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": admC_id}).status_code == 200
      and managers_of(gid) == {admA_id, admC_id},
      "second manager is additive, admA undisturbed")
check(boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": admA_id}).status_code == 200
      and managers_of(gid) == {admA_id, admC_id},
      "re-delegating an existing manager is an idempotent no-op")
check(boss.delete(f"/admin/mgmt-groups/{gid}/managers/{admC_id}", headers=H(boss_t)).status_code == 200
      and managers_of(gid) == {admA_id},
      "revocation is targeted: admC out, admA stays")
check(boss.delete(f"/admin/mgmt-groups/{gid}/managers/{admC_id}", headers=H(boss_t)).status_code == 404,
      "revoking a non-grant -> 404")
manager = mgroup_row(gid)["managers"][0]
check(manager == {
          "admin_id": admA_id,
          "username": "admA",
          "first_name": "Admin",
          "last_name": "Alpha",
      },
      "management-group manager payload carries username and real-name parts")

print("\n== 5. Effective controls: membership x manager grant = controls() everywhere ==")
check("bob" in listed(admA, admA_t), "member appears in the manager's user list")
check("bob" not in listed(admB, admB_t), "non-manager admin still doesn't see the member")
check(admA.post(f"/admin/users/{bob_id}/disable", headers=H(admA_t)).status_code == 200, "manager disables the member")
check(admA.post(f"/admin/users/{bob_id}/enable", headers=H(admA_t)).status_code == 200, "manager enables the member")
check(admA.post(f"/admin/users/{bob_id}/resetpwd", headers=H(admA_t), json={"new_password": "Bob12345!"}).status_code == 200,
      "manager resets the member's password")
r = admA.put(f"/admin/users/{bob_id}/profile", headers=H(admA_t),
             json={"username": "bob", "first_name": "Bob", "last_name": "Builder", "email": "bob@x.com"})
check(r.status_code == 200, "manager edits the member's profile")
check(admA.get(f"/admin/users/{bob_id}/maps", headers=H(admA_t)).status_code == 200, "manager views the member's maps metadata")
check(admB.post(f"/admin/users/{bob_id}/disable", headers=H(admB_t)).status_code == 403, "non-manager admin still 403s")
bob, bob_t = login("bob", "Bob12345!")
bob_map = bob.post("/maps", headers=H(bob_t), json={"name": "BobMap"}).get_json()["id"]
check(admA.put(f"/admin/maps/{bob_map}/collaborators", headers=H(admA_t),
               json={"username": "carol", "role": "viewer"}).status_code == 403,
      "group-derived control does not grant map-share administration")
check(admA.delete(f"/admin/maps/{bob_map}/collaborators/{carol_id}", headers=H(admA_t)).status_code == 403,
      "regular-admin map-share DELETE is sealed too")

print("\n== 6. Source split in the superadmin payload; flat union for admins ==")
boss.put(f"/admin/users/{bob_id}/controllers", headers=H(boss_t), json={"admin_id": admB_id})
srow = next(x for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "bob")
check([c["username"] for c in srow["controllers"]] == ["admB"],
      "controllers carries ONLY the direct grant (revocable chips)")
check([c["username"] for c in srow["group_managers"]] == ["admA"],
      "group_managers carries ONLY the group-derived manager")
check((srow["controllers"][0]["first_name"], srow["controllers"][0]["last_name"]) ==
      ("Admin", "Beta") and
      (srow["group_managers"][0]["first_name"], srow["group_managers"][0]["last_name"]) ==
      ("Admin", "Alpha"),
      "both control-source payloads carry real-name parts")
arow = next(x for x in admA.get("/admin/users", headers=H(admA_t)).get_json() if x["username"] == "bob")
expected_managers = [
    {"username": "admA", "first_name": "Admin", "last_name": "Alpha"},
    {"username": "admB", "first_name": "Admin", "last_name": "Beta"},
]
check(arow["managers"] == expected_managers
      and "controllers" not in arow
      and "group_managers" not in arow,
      "admin payload exposes a source-agnostic manager union and no source keys")
# The same admin can hold both a direct and a group-derived grant. The regular-admin
# wire contract must still list that person once, without revealing the overlap.
boss.put(f"/admin/users/{bob_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id})
arow = next(x for x in admA.get("/admin/users", headers=H(admA_t)).get_json() if x["username"] == "bob")
check(arow["managers"] == expected_managers,
      "regular-admin manager union deduplicates an admin with both grant sources")
boss.delete(f"/admin/users/{bob_id}/controllers/{admA_id}", headers=H(boss_t))
check("bob" in listed(admB, admB_t), "direct grant and group grant coexist: admB sees bob too")
check(admB.post(f"/admin/users/{bob_id}/disable", headers=H(admB_t)).status_code == 200
      and admA.post(f"/admin/users/{bob_id}/enable", headers=H(admA_t)).status_code == 200,
      "co-controllers from different sources act independently")
# Stage 10.2: the disable revoked bob's sessions and access JWTs immediately, so
# the suite must re-establish his session before using it again.
bob, bob_t = login("bob", "Bob12345!")

print("\n== 7. Removal from the group revokes ONLY that source ==")
check(boss.delete(f"/admin/mgmt-groups/{gid}/members/{bob_id}", headers=H(boss_t)).status_code == 200,
      "super removes bob from the group")
check("bob" in listed(admB, admB_t), "direct co-controller admB is untouched")
check("bob" not in listed(admA, admA_t), "admA's group-derived reach is gone")
check(admA.post(f"/admin/users/{bob_id}/disable", headers=H(admA_t)).status_code == 403, "ex-manager can no longer act on bob")
check(boss.delete(f"/admin/users/{bob_id}/controllers/{admB_id}", headers=H(boss_t)).status_code == 200,
      "revoking the last direct grant...")
srow = next(x for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "bob")
check(srow["controllers"] == [] and srow["group_managers"] == [], "...lands bob in nobody-land (both sources empty)")
boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "bob"})
check("bob" in listed(admA, admA_t), "re-adding the member restores admA's reach")

print("\n== 8. Share-group actions honor group-derived control ==")
r = admA.post("/admin/groups", headers=H(admA_t), json={"name": "FieldSG"})
sgid = r.get_json()["id"]
check(r.status_code == 200, "admA creates a share group (self-serve, unchanged)")
check(admA.put(f"/admin/groups/{sgid}/members", headers=H(admA_t), json={"username": "bob"}).status_code == 200,
      "admA adds bob to the share group (controls via mgmt group)")
check(admA.put(f"/admin/groups/{sgid}/members", headers=H(admA_t), json={"username": "carol"}).status_code == 403,
      "carol stays out of admA's reach -> 403")
sgrow = next(x for x in admA.get("/admin/groups", headers=H(admA_t)).get_json() if x["id"] == sgid)
bob_member = next(m for m in sgrow["members"] if m["username"] == "bob")
check(bob_member["managed"] is True, "members payload 'managed' flag honors group-derived control")
check(sgrow["deletable"] is True, "creator delete rule counts group-derived members as in-scope")
boss.put(f"/admin/groups/{sgid}/members", headers=H(boss_t), json={"username": "carol"})
sgrow = next(x for x in admA.get("/admin/groups", headers=H(admA_t)).get_json() if x["id"] == sgid)
check(sgrow["deletable"] is False, "an outside member (carol) flips deletable off")
check(admA.delete(f"/admin/groups/{sgid}", headers=H(admA_t)).status_code == 403,
      "and the backend enforces it on DELETE")
check(admA.delete(f"/admin/groups/{sgid}/members/{bob_id}", headers=H(admA_t)).status_code == 200,
      "admA removes bob from the share group (scoped removal via mgmt control)")
check(admA.delete(f"/admin/groups/{sgid}/members/{carol_id}", headers=H(admA_t)).status_code == 403,
      "but not carol (outside admA's control)")

print("\n== 9. Visibility: membership is super-admin detail only, management groups never leak ==")
r = bob.get("/groups", headers=H(bob_t))
check(all(x["name"] != "Ops Team" for x in r.get_json()), "share picker /groups lists no management groups")
r = admA.get("/admin/groups", headers=H(admA_t))
check(all(x["name"] != "Ops Team" for x in r.get_json()), "share-groups admin list has no management groups")
srow = next(x for x in admA.get("/admin/users", headers=H(admA_t)).get_json() if x["username"] == "bob")
check(srow["share_groups"] == [], "share_groups fact still lists share groups only")
check("management_groups" not in srow,
      "regular admin's payload omits the management_groups key entirely")
brow = next(x for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "bob")
check(brow["management_groups"] == ["Ops Team"],
      "super-admin details name the member's management groups")

print("\n== 10. Cascade: promoting a member to admin clears their memberships ==")
boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "carol"})
check(boss.post(f"/admin/users/{carol_id}/role", headers=H(boss_t), json={"role": "admin"}).status_code == 200,
      "super promotes carol (a member) to admin")
check(carol_id not in members_of(gid), "carol's membership row is gone (admins are never controlled)")
check("carol" not in listed(admA, admA_t), "admA's group-derived reach over carol ended with the promotion")
boss.post(f"/admin/users/{carol_id}/role", headers=H(boss_t), json={"role": "user"})
check(carol_id not in members_of(gid), "demoting carol back does NOT restore the membership (re-delegation is explicit)")

print("\n== 11. Cascade: demoting/deleting a manager drops only that admin's grants ==")
boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": admC_id})
check(boss.post(f"/admin/users/{admC_id}/role", headers=H(boss_t), json={"role": "user"}).status_code == 200,
      "super demotes co-manager admC")
check(managers_of(gid) == {admA_id}, "admC's manager grant dissolved; admA keeps theirs")
check(members_of(gid) == {bob_id, off_id}, "membership rows are untouched by the demotion")
admD_id = make_user("admD", "AdmD1234!", "admin", "approved")
boss.put(f"/admin/mgmt-groups/{gid}/managers", headers=H(boss_t), json={"admin_id": admD_id})
check(boss.delete(f"/admin/users/{admD_id}", headers=H(boss_t)).status_code == 200, "super deletes manager admD")
check(managers_of(gid) == {admA_id}, "the FK cascade dropped admD's grant only")
boss.put(f"/admin/mgmt-groups/{gid}/members", headers=H(boss_t), json={"username": "dave"})
check(boss.delete(f"/admin/users/{dave_id}", headers=H(boss_t)).status_code == 200
      and dave_id not in members_of(gid),
      "deleting a member user cascades their membership row away")

print("\n== 12. Deleting the group ends every group-derived grant at once ==")
check("bob" in listed(admA, admA_t), "before: admA reaches bob via the group")
check(boss.delete(f"/admin/mgmt-groups/{gid}", headers=H(boss_t)).status_code == 200, "super deletes the group")
check(boss.delete(f"/admin/mgmt-groups/{gid}", headers=H(boss_t)).status_code == 404, "second delete -> 404")
check("bob" not in listed(admA, admA_t), "admA's reach over bob is gone with the group")
conn = backend.get_db()
leftovers = conn.execute("SELECT COUNT(*) FROM mgmt_group_members").fetchone()[0] + \
            conn.execute("SELECT COUNT(*) FROM mgmt_group_managers").fetchone()[0]
bob_alive = conn.execute("SELECT 1 FROM users WHERE user_id = ?", (bob_id,)).fetchone()
conn.close()
check(leftovers == 0 and bob_alive is not None, "membership/manager rows cascaded; the users themselves survive")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
