import os, sys, shutil, tempfile, importlib.util, uuid
WORK = tempfile.mkdtemp(prefix="mv_acrud_")
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

def mk(u, p, role="user", first="F", last="L"):
    conn = backend.get_db(); uid = str(uuid.uuid4())
    conn.execute("INSERT INTO users (user_id, username, password_hash, role, status, created, first_name, last_name) VALUES (?,?,?,?,?,?,?,?)",
                 (uid, u, bcrypt.hashpw(p.encode(), bcrypt.gensalt()), role, "approved", datetime.now().isoformat(), first, last))
    conn.commit(); conn.close(); backend.create_base_map(uid); return uid
def login(u, p):
    cl = app.test_client(); cl.post("/login", json={"username": u, "password": p})
    return cl, cl.post("/auth/refresh").get_json()["access_token"]
def H(t): return {"Authorization": f"Bearer {t}"}
def uid_of(u):
    conn = backend.get_db(); r = conn.execute("SELECT user_id FROM users WHERE username=? COLLATE NOCASE",(u,)).fetchone(); conn.close()
    return r[0] if r else None
def exists(u):
    conn = backend.get_db(); r = conn.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE",(u,)).fetchone(); conn.close()
    return bool(r)
def add_avatar(user_id):
    filename = f"{user_id}.jpg"
    path = os.path.join(backend.AVATARS_FOLDER, filename)
    with open(path, "wb") as avatar:
        avatar.write(b"avatar")
    conn = backend.get_db()
    conn.execute("UPDATE users SET avatar=? WHERE user_id=?", (filename, user_id))
    conn.commit(); conn.close()
    return path

# Actors are SUPER-admins: creating/deleting admins is super-only under the governance model.
adm1 = mk("adm1", "Admin123!", role="super_admin")
adm2 = mk("adm2", "Admin123!", role="super_admin")
bob  = mk("bob", "Bob12345!")
bob_avatar = add_avatar(bob)
adc, adt = login("adm1", "Admin123!")
bc, bt = login("bob", "Bob12345!")

VALID = {"username":"newbie","password":"Newbie12!","first_name":"New","last_name":"Bie","email":"newbie@x.com",
         "company":"Acme","department":"QA","birth_date":"1995-03-03","sex":"female","role":"user"}

print("\n== CREATE ==")
r = adc.post("/admin/users/create", headers=H(adt), json=VALID)
check(r.status_code == 200, f"admin create -> 200 (got {r.status_code})")
row = backend.get_db().execute("SELECT status, role, first_name, last_name FROM users WHERE username='newbie'").fetchone()
check(row == ("approved","user","New","Bie"), f"created user approved+fields ({row})")
# base map created?
nid = uid_of("newbie")
bm = backend.get_db().execute("SELECT COUNT(*) FROM maps WHERE owner_id=? AND is_base=1",(nid,)).fetchone()[0]
check(bm == 1, "created user has a base map")
# created user can log in immediately
nc, nt = login("newbie", "Newbie12!")
check(bool(nt), "created user can log in right away")

print("\n== CREATE validation ==")
check(adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"x2","email":"x2@x.com","password":"weak"}).status_code==400, "weak password -> 400")
check(adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"x3","email":"x3@x.com","first_name":""}).status_code==400, "missing first name -> 400")
check(adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"x3b","email":"newbie@x.com"}).status_code==400, "duplicate email -> 400")
check(adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"newbie","email":"other@x.com"}).status_code==400, "duplicate username -> 400")
check(adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"x4","email":"x4@x.com","role":"superuser"}).status_code==400, "bad role -> 400")
# create an admin
r = adc.post("/admin/users/create", headers=H(adt), json={**VALID,"username":"adm3","email":"adm3@x.com","role":"admin"})
check(r.status_code==200 and backend.get_db().execute("SELECT role FROM users WHERE username='adm3'").fetchone()[0]=="admin", "can create an admin")

print("\n== CREATE authz: non-admin blocked ==")
check(bc.post("/admin/users/create", headers=H(bt), json={**VALID,"username":"x5","email":"x5@x.com"}).status_code==403, "non-admin create -> 403")

print("\n== DELETE ==")
# give bob a map + spot to prove cascade
m = bc.post("/maps", headers=H(bt), json={"name":"BobMap"}).get_json()
bc.post("/spots", headers=H(bt), json={"mapID":m["id"],"name":"s","lat":1,"lng":1})
mcount_before = backend.get_db().execute("SELECT COUNT(*) FROM maps WHERE owner_id=?",(bob,)).fetchone()[0]
check(mcount_before >= 2, f"bob owns maps before delete ({mcount_before})")
r = adc.delete(f"/admin/users/{bob}", headers=H(adt))
check(r.status_code==200, f"delete bob -> 200 (got {r.status_code})")
check(not exists("bob"), "bob gone from users")
check(not os.path.exists(bob_avatar), "admin delete removes bob's avatar file")
mcount_after = backend.get_db().execute("SELECT COUNT(*) FROM maps WHERE owner_id=?",(bob,)).fetchone()[0]
check(mcount_after == 0, f"bob's maps cascade-deleted ({mcount_after})")

print("\n== DELETE guards ==")
check(adc.delete(f"/admin/users/{adm1}", headers=H(adt)).status_code==400, "cannot delete self -> 400")
check(exists("adm1"), "self still exists after blocked delete")
check(adc.delete("/admin/users/does-not-exist", headers=H(adt)).status_code==404, "delete missing user -> 404")

print("\n== last-admin delete guard ==")
# adm2 is currently an admin too. Have adm2 (logged in) delete adm1, leaving adm2 the sole admin.
a2c, a2t = login("adm2", "Admin123!")
check(a2c.delete(f"/admin/users/{adm1}", headers=H(a2t)).status_code==200, "an admin can delete another admin (2 present)")
# Now adm2 is the only admin. adm3 was created as admin earlier — demote it so adm2 is truly sole.
a2c.post(f"/admin/users/{uid_of('adm3')}/role", headers=H(a2t), json={"role":"user"})
# Deleting adm2 now must be blocked: it's self AND the last admin. Prove the last-admin path
# by disabling self-check: create a throwaway admin, delete adm2 from it, expect last-admin? No —
# with the throwaway present there are 2 admins. Simplest: assert adm2 (sole admin) can't be deleted by itself.
check(a2c.delete(f"/admin/users/{adm2}", headers=H(a2t)).status_code==400, "sole admin cannot be deleted (self+last-admin)")
check(exists("adm2"), "sole admin still exists")

print("\n== non-admin cannot delete ==")
newbie_id = uid_of("newbie")
check(bc.delete(f"/admin/users/{newbie_id}", headers=H(bt)).status_code in (401,403), "non-admin delete blocked")

print("\n== RESET PASSWORD ==")
# newbie exists (created approved via VALID). Admin resets their password.
check(a2c.post(f"/admin/users/{newbie_id}/resetpwd", headers=H(a2t), json={"new_password":"weak"}).status_code==400, "weak new password -> 400")
check(a2c.post(f"/admin/users/{newbie_id}/resetpwd", headers=H(a2t), json={}).status_code==400, "missing new_password -> 400")
check(a2c.post("/admin/users/nope/resetpwd", headers=H(a2t), json={"new_password":"Fresh123!"}).status_code==404, "missing user -> 404")
# old password no longer works after a successful reset; new one does
oldc = app.test_client(); oldc.post("/login", json={"username":"newbie","password":"Newbie12!"})
r = a2c.post(f"/admin/users/{newbie_id}/resetpwd", headers=H(a2t), json={"new_password":"Fresh123!"})
check(r.status_code==200, f"reset ok -> 200 (got {r.status_code})")
check(app.test_client().post("/login", json={"username":"newbie","password":"Newbie12!"}).status_code==401, "old password rejected after reset")
nc2 = app.test_client(); lr = nc2.post("/login", json={"username":"newbie","password":"Fresh123!"})
check(lr.status_code==200, "new password works")
# reset revokes existing sessions: the pre-reset client can't refresh into a token
check(oldc.post("/auth/refresh").status_code==401, "target's pre-reset session revoked")

print("\n== reset password authz: non-admin blocked ==")
nc3, nt3 = login("newbie", "Fresh123!")
check(nc3.post(f"/admin/users/{newbie_id}/resetpwd", headers=H(nt3), json={"new_password":"Other123!"}).status_code==403, "non-admin reset -> 403")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
