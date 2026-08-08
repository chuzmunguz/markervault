"""Multi-admin control harness — documentation/permissions-model-addendum-multi-control.md.

controls() and owns_group() are many-to-many (user_controllers / group_owners rows).
Assignment is additive, revocation targeted; co-controllers/co-owners act independently
within the regular-admin management surface. Addendum 4 seals map-share administration
to super-admins regardless of co-control. Group delete belongs to the creator alone
(creator AND still-owner AND every member in the creator's OWN control list — Addendum
2, co-owners never gain it); demote/delete of one admin removes only that admin's grants;
zero rows = nobody-land / superadmin-owned, exactly as before.
"""
import os, sys, shutil, tempfile, importlib.util, uuid

WORK = tempfile.mkdtemp(prefix="mv_mc_")
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

def group_row(cl, t, gid):
    return next(x for x in cl.get("/admin/groups", headers=H(t)).get_json() if x["id"] == gid)

boss_id = make_user("boss", "Boss1234!", "super_admin", "approved")
admA_id = make_user("admA", "AdmA1234!", "admin", "approved")
admB_id = make_user("admB", "AdmB1234!", "admin", "approved")
ua_id   = make_user("ua",   "Ua123456!", "user", "approved")   # A's user
ub_id   = make_user("ub",   "Ub123456!", "user", "approved")   # B's user
uc_id   = make_user("uc",   "Uc123456!", "user", "approved")   # co-managed by A+B
nol_id  = make_user("nol",  "Nol12345!", "user", "approved")   # nobody-land
conn = backend.get_db()
conn.execute("UPDATE users SET first_name='Admin', last_name='Alpha' WHERE user_id = ?", (admA_id,))
conn.execute("UPDATE users SET first_name='Admin', last_name='Beta' WHERE user_id = ?", (admB_id,))
conn.commit(); conn.close()
for uid in (boss_id, admA_id, admB_id, ua_id, ub_id, uc_id, nol_id):
    backend.create_base_map(uid)

boss, boss_t = login("boss", "Boss1234!")
admA, admA_t = login("admA", "AdmA1234!")
admB, admB_t = login("admB", "AdmB1234!")

boss.put(f"/admin/users/{ua_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id})
boss.put(f"/admin/users/{ub_id}/controllers", headers=H(boss_t), json={"admin_id": admB_id})

print("\n== 1. Assignment is additive: nobody-land -> co-managed in successive steps ==")
check(boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id}).status_code == 200,
      "first grant: uc -> admA")
check(boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admB_id}).status_code == 200,
      "second grant: uc -> admB, admA undisturbed")
check(controllers_of(uc_id) == {admA_id, admB_id}, "both controls() rows recorded")
check(boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id}).status_code == 200
      and controllers_of(uc_id) == {admA_id, admB_id},
      "re-granting an existing controller is an idempotent no-op")
srow = next(x for x in boss.get("/admin/users", headers=H(boss_t)).get_json() if x["username"] == "uc")
check([c["username"] for c in srow["controllers"]] == ["admA", "admB"],
      "the list payload carries ALL controllers")
check([(c["first_name"], c["last_name"]) for c in srow["controllers"]] ==
      [("Admin", "Alpha"), ("Admin", "Beta")],
      "controller payload carries real-name parts in stable username order")

print("\n== 2. A co-managed user is in EVERY controller's scope ==")
check("uc" in listed(admA, admA_t) and "uc" in listed(admB, admB_t),
      "uc appears in both admins' lists (overlapping scopes)")
check("ua" not in listed(admB, admB_t), "non-shared users still partition normally")

print("\n== 3. Co-controllers act independently within the regular-admin surface ==")
check(admA.post(f"/admin/users/{uc_id}/disable", headers=H(admA_t)).status_code == 200, "admA disables uc")
check(admB.post(f"/admin/users/{uc_id}/enable", headers=H(admB_t)).status_code == 200, "admB enables uc (no coordination)")
check(admA.post(f"/admin/users/{uc_id}/resetpwd", headers=H(admA_t), json={"new_password": "Uc123456!"}).status_code == 200,
      "admA resets uc's password")
check(admB.get(f"/admin/users/{uc_id}/maps", headers=H(admB_t)).status_code == 200, "admB views uc's maps metadata")
uc_map = None
uc_cl, uc_t = login("uc", "Uc123456!")
uc_map = uc_cl.post("/maps", headers=H(uc_t), json={"name": "UcMap"}).get_json()["id"]
check(admA.put(f"/admin/maps/{uc_map}/collaborators", headers=H(admA_t), json={"username": "nol", "role": "viewer"}).status_code == 403,
      "co-control does not grant regular-admin map-share administration")
check(admB.delete(f"/admin/maps/{uc_map}/collaborators/{nol_id}", headers=H(admB_t)).status_code == 403,
      "the second co-controller is sealed from map-share DELETE too")

print("\n== 4. Revocation is targeted, never a wipe ==")
check(boss.delete(f"/admin/users/{uc_id}/controllers/{admA_id}", headers=H(boss_t)).status_code == 200,
      "super revokes only admA's grant on uc")
check(controllers_of(uc_id) == {admB_id}, "admB's co-grant survives the revoke")
check("uc" not in listed(admA, admA_t) and "uc" in listed(admB, admB_t),
      "uc leaves admA's scope but stays in admB's")
check(admA.post(f"/admin/users/{uc_id}/disable", headers=H(admA_t)).status_code == 403, "ex-co-controller can no longer act")
check(boss.delete(f"/admin/users/{uc_id}/controllers/{admB_id}", headers=H(boss_t)).status_code == 200
      and controllers_of(uc_id) == set(),
      "revoking the LAST grant lands uc in nobody-land")
boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id})
boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admB_id})

print("\n== 5. Group co-ownership: additive delegation, independent management ==")
gid = admA.post("/admin/groups", headers=H(admA_t), json={"name": "TeamG"}).get_json()["id"]
check(boss.put(f"/admin/groups/{gid}/owners", headers=H(boss_t), json={"admin_id": admB_id}).status_code == 200,
      "super adds admB as co-owner (admA undisturbed)")
check(group_owners_of(gid) == {admA_id, admB_id}, "both owns_group() rows recorded")
check(any(x["id"] == gid for x in admB.get("/admin/groups", headers=H(admB_t)).get_json()),
      "co-owned group appears in BOTH owners' lists")
owner_rows = group_row(boss, boss_t, gid)["owners"]
check([(o["username"], o["first_name"], o["last_name"]) for o in owner_rows] ==
      [("admA", "Admin", "Alpha"), ("admB", "Admin", "Beta")],
      "co-owner payload keeps usernames and real-name parts")
check(admB.put(f"/admin/groups/{gid}", headers=H(admB_t), json={"name": "TeamG2"}).status_code == 200,
      "co-owner renames independently")
admB.put(f"/admin/groups/{gid}", headers=H(admB_t), json={"name": "TeamG"})
check(admA.put(f"/admin/groups/{gid}/members", headers=H(admA_t), json={"username": "ua"}).status_code == 200,
      "admA adds their own controlled user")
check(admB.put(f"/admin/groups/{gid}/members", headers=H(admB_t), json={"username": "ub"}).status_code == 200,
      "admB adds theirs")
check(admB.put(f"/admin/groups/{gid}/members", headers=H(admB_t), json={"username": "ua"}).status_code == 403,
      "co-ownership does NOT extend controls(): admB cannot add admA's user")
mA = {m["username"]: m for m in group_row(admA, admA_t, gid)["members"]}
check(mA["ua"]["managed"] and not mA["ub"]["managed"], "per-member 'managed' stays per-CALLER")
check(admA.delete(f"/admin/groups/{gid}/members/{ub_id}", headers=H(admA_t)).status_code == 403,
      "removal too: admA cannot remove admB's member")
check(admB.delete(f"/admin/groups/{gid}/members/{ub_id}", headers=H(admB_t)).status_code == 200,
      "admB removes their own member")
admB.put(f"/admin/groups/{gid}/members", headers=H(admB_t), json={"username": "ub"})

print("\n== 6. Delete belongs to the creator alone, own-scope membership (Addendum 2) ==")
check(not group_row(admB, admB_t, gid)["deletable"],
      "non-creator co-owner: deletable=false (co-ownership never grants delete)")
check(admB.delete(f"/admin/groups/{gid}", headers=H(admB_t)).status_code == 403,
      "non-creator co-owner cannot delete, clean membership or not")
check(not group_row(admA, admA_t, gid)["deletable"],
      "creator blocked too: ub is outside the creator's OWN control list (individual, not collective)")
check(admA.delete(f"/admin/groups/{gid}", headers=H(admA_t)).status_code == 403,
      "creator delete with a co-owner's member -> 403")
admB.delete(f"/admin/groups/{gid}/members/{ub_id}", headers=H(admB_t))
check(group_row(admA, admA_t, gid)["deletable"], "ub removed: creator deletable=true")
boss.put(f"/admin/groups/{gid}/members", headers=H(boss_t), json={"username": "nol"})
check(not group_row(admA, admA_t, gid)["deletable"], "an outside member flips deletable off")
check(admA.delete(f"/admin/groups/{gid}", headers=H(admA_t)).status_code == 403,
      "outside member -> 403 even for the creator")
boss.delete(f"/admin/groups/{gid}/members/{nol_id}", headers=H(boss_t))
check(admA.delete(f"/admin/groups/{gid}", headers=H(admA_t)).status_code == 200,
      "creator deletes: every member within their own control")

print("\n== 7. Revoking the creator's grant removes delete authority ==")
g2 = admA.post("/admin/groups", headers=H(admA_t), json={"name": "SoloG"}).get_json()["id"]
boss.put(f"/admin/groups/{g2}/owners", headers=H(boss_t), json={"admin_id": admB_id})
boss.delete(f"/admin/groups/{g2}/owners/{admA_id}", headers=H(boss_t))
check(group_owners_of(g2) == {admB_id}, "creator's grant revoked; admB is now the SOLE owner")
check(admA.delete(f"/admin/groups/{g2}", headers=H(admA_t)).status_code == 403,
      "ex-owner creator can no longer delete (revocation is the kill-switch)")
check(not group_row(admB, admB_t, g2)["deletable"], "sole non-creator owner: deletable=false")
check(admB.delete(f"/admin/groups/{g2}", headers=H(admB_t)).status_code == 403,
      "sole delegated owner cannot delete (not the creator)")
boss.put(f"/admin/groups/{g2}/owners", headers=H(boss_t), json={"admin_id": admA_id})
check(admA.delete(f"/admin/groups/{g2}", headers=H(admA_t)).status_code == 200,
      "re-delegated creator-owner: delete allowed again")

print("\n== 8. Demoting one co-controller removes only THEIR grants ==")
g3 = admA.post("/admin/groups", headers=H(admA_t), json={"name": "KeepG"}).get_json()["id"]
boss.put(f"/admin/groups/{g3}/owners", headers=H(boss_t), json={"admin_id": admB_id})
boss.post(f"/admin/users/{admA_id}/role", headers=H(boss_t), json={"role": "user"})
check(controllers_of(uc_id) == {admB_id}, "uc keeps admB after admA's demotion")
check(controllers_of(ua_id) == set(), "admA's exclusive user falls back to nobody-land")
check(group_owners_of(g3) == {admB_id}, "co-owned group keeps admB (no superadmin fallback needed)")
boss.post(f"/admin/users/{admA_id}/role", headers=H(boss_t), json={"role": "admin"})
check(group_owners_of(g3) == {admB_id}, "re-promotion does NOT restore old grants (re-delegation is explicit)")

print("\n== 9. Deleting a co-controlling admin cascades only their rows ==")
boss.put(f"/admin/users/{uc_id}/controllers", headers=H(boss_t), json={"admin_id": admA_id})
boss.put(f"/admin/groups/{g3}/owners", headers=H(boss_t), json={"admin_id": admA_id})
check(boss.delete(f"/admin/users/{admB_id}", headers=H(boss_t)).status_code == 200, "super deletes admB")
check(controllers_of(uc_id) == {admA_id}, "uc keeps admA; admB's row cascaded away")
check(group_owners_of(g3) == {admA_id}, "g3 keeps admA as owner")
check(controllers_of(ub_id) == set(), "admB's exclusive user is in nobody-land")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
