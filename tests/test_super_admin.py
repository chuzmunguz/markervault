import os, sys, shutil, tempfile, importlib.util, uuid
WORK = tempfile.mkdtemp(prefix="mv_super_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy("/workspace/markervault/username_validation.py", os.path.join(WORK, "username_validation.py"))
shutil.copy("/workspace/markervault/markervault_config.py", os.path.join(WORK, "markervault_config.py"))
shutil.copy("/workspace/markervault/email_delivery.py", os.path.join(WORK, "email_delivery.py"))
os.chdir(WORK)
if WORK not in sys.path: sys.path.insert(0, WORK)
os.environ["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x"*64
spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec); sys.modules["backend"]=backend
spec.loader.exec_module(backend)
backend.COOKIE_SECURE=False; backend.rate_limit=lambda *a,**k: None
app=backend.app; app.testing=True
import bcrypt
from datetime import datetime

PASS=FAIL=0
def check(c,l):
    global PASS,FAIL
    if c: PASS+=1; print(f"  PASS  {l}")
    else: FAIL+=1; print(f"  FAIL  {l}")
def mk(u,p,role="user",status="approved"):
    conn=backend.get_db(); uid=str(uuid.uuid4())
    conn.execute("INSERT INTO users (user_id,username,password_hash,role,status,created,first_name,last_name,email) VALUES (?,?,?,?,?,?,?,?,?)",
                 (uid,u,bcrypt.hashpw(p.encode(),bcrypt.gensalt()),role,status,datetime.now().isoformat(),"F","L",u+"@x.com"))
    conn.commit(); conn.close(); backend.create_base_map(uid); return uid
def login(u,p):
    cl=app.test_client(); cl.post("/login",json={"username":u,"password":p})
    return cl, cl.post("/auth/refresh").get_json()["access_token"]
def H(t): return {"Authorization":f"Bearer {t}"}
def role_of(uid):
    conn=backend.get_db(); r=conn.execute("SELECT role FROM users WHERE user_id=?",(uid,)).fetchone(); conn.close(); return r[0] if r else None
def status_of(uid):
    conn=backend.get_db(); r=conn.execute("SELECT status FROM users WHERE user_id=?",(uid,)).fetchone(); conn.close(); return r[0] if r else None
def exists(uid):
    conn=backend.get_db(); r=conn.execute("SELECT 1 FROM users WHERE user_id=?",(uid,)).fetchone(); conn.close(); return bool(r)

sup   = mk("sup",  "Super123!", role="super_admin")
adm   = mk("adm",  "Admin123!", role="admin")
adm2  = mk("adm2", "Admin123!", role="admin")
bob   = mk("bob",  "Bob12345!", role="user")
pend  = mk("pend", "Pend1234!", role="user", status="pending")
# Fixture: bob is delegated to adm (controls()); scoping details live in test_admin_scope.py.
conn = backend.get_db(); conn.execute("INSERT INTO user_controllers (user_id, admin_id, created) VALUES (?, ?, datetime('now'))", (bob, adm)); conn.commit(); conn.close()

supc, supt = login("sup","Super123!")
admc, admt = login("adm","Admin123!")

print("\n== super-admin is treated as an admin (admin powers; NO map superuser anymore) ==")
check(supc.get("/admin/users", headers=H(supt)).status_code==200, "super can list users")

print("\n== regular admin CANNOT act on another admin ==")
check(admc.post(f"/admin/users/{adm2}/disable", headers=H(admt)).status_code==403, "admin disable admin -> 403")
check(admc.post(f"/admin/users/{adm2}/resetpwd", headers=H(admt), json={"new_password":"Zzz99999!"}).status_code==403, "admin reset admin pwd -> 403")
check(admc.delete(f"/admin/users/{adm2}", headers=H(admt)).status_code==403, "admin delete admin -> 403")
check(status_of(adm2)=="approved", "target admin untouched")

print("\n== regular admin CANNOT act on a super-admin ==")
check(admc.post(f"/admin/users/{sup}/disable", headers=H(admt)).status_code==403, "admin disable super -> 403")
check(admc.post(f"/admin/users/{sup}/resetpwd", headers=H(admt), json={"new_password":"Zzz99999!"}).status_code==403, "admin reset super pwd -> 403")
check(admc.delete(f"/admin/users/{sup}", headers=H(admt)).status_code==403, "admin delete super -> 403")

print("\n== regular admin CANNOT promote/demote at all (super-only) ==")
check(admc.post(f"/admin/users/{bob}/role", headers=H(admt), json={"role":"admin"}).status_code==403, "admin promote user -> 403")
check(role_of(bob)=="user", "bob not promoted")
check(admc.post(f"/admin/users/{adm2}/role", headers=H(admt), json={"role":"user"}).status_code==403, "admin demote admin -> 403")

print("\n== regular admin CAN act on THEIR OWN users; approval is super-only ==")
check(admc.post(f"/admin/users/{pend}/approve", headers=H(admt)).status_code==403, "admin approve pending user -> 403 (super-only)")
check(supc.post(f"/admin/users/{pend}/approve", headers=H(supt)).status_code==200, "super approve pending user -> 200")
check(admc.post(f"/admin/users/{bob}/disable", headers=H(admt)).status_code==200, "admin disable controlled user -> 200")
check(admc.post(f"/admin/users/{bob}/enable", headers=H(admt)).status_code==200, "admin enable controlled user -> 200")
check(admc.post(f"/admin/users/{bob}/resetpwd", headers=H(admt), json={"new_password":"Newpass1!"}).status_code==200, "admin reset controlled user pwd -> 200")

print("\n== regular admin CANNOT create an admin, CAN create a user ==")
base={"password":"Made1234!","first_name":"M","last_name":"K","email":"made@x.com"}
check(admc.post("/admin/users/create", headers=H(admt), json={**base,"username":"madeadmin","email":"ma@x.com","role":"admin"}).status_code==403, "admin create admin -> 403")
check(admc.post("/admin/users/create", headers=H(admt), json={**base,"username":"madeuser","email":"mu@x.com","role":"user"}).status_code==200, "admin create user -> 200")
# 'super_admin' is never accepted via the UI create route, even for a super-admin
check(supc.post("/admin/users/create", headers=H(supt), json={**base,"username":"nope","email":"n@x.com","role":"super_admin"}).status_code==400, "create super via UI -> 400 (CLI only)")

print("\n== super-admin CAN act on admins ==")
check(supc.post(f"/admin/users/{bob}/role", headers=H(supt), json={"role":"admin"}).status_code==200, "super promotes user->admin")
check(role_of(bob)=="admin", "bob is now admin")
conn=backend.get_db(); cb=conn.execute("SELECT COUNT(*) FROM user_controllers WHERE user_id=?",(bob,)).fetchone()[0]; conn.close()
check(cb == 0, "promotion cleared bob's controllers (admins are never controlled)")
check(supc.post(f"/admin/users/{bob}/role", headers=H(supt), json={"role":"user"}).status_code==200, "super demotes admin->user")
check(supc.post(f"/admin/users/{adm2}/disable", headers=H(supt)).status_code==200, "super disables an admin")
check(supc.delete(f"/admin/users/{adm}", headers=H(supt)).status_code==200, "super deletes an admin")
check(not exists(adm), "deleted admin gone")

print("\n== a super-admin cannot be demoted/deleted through the UI (even by another super) ==")
sup2 = mk("sup2","Super123!", role="super_admin")
s2c, s2t = login("sup2","Super123!")
check(s2c.post(f"/admin/users/{sup}/role", headers=H(s2t), json={"role":"admin"}).status_code==403, "demote a super via UI -> 403")
check(role_of(sup)=="super_admin", "super role intact")
# but a super CAN delete another super (they're admin-level; only self + last-admin guards apply)
check(s2c.delete(f"/admin/users/{sup}", headers=H(s2t)).status_code==200, "super can delete another super")

print("\n== last-admin guard counts supers + admins together ==")
# now only sup2 remains admin-level; it can't self-delete-account as the last one
conn=backend.get_db(); n=conn.execute("SELECT COUNT(*) FROM users WHERE role IN ('admin','super_admin') AND status='approved'").fetchone()[0]; conn.close()
check(n==1, f"exactly one admin-level account remains ({n})")
r=s2c.delete("/account", headers=H(s2t), json={"confirm_username":"sup2"})
check(r.status_code==400, "last admin-level self-delete blocked -> 400")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
