"""Audit foundation coverage: schema, writer semantics, and fresh admin identity."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime

import bcrypt


WORK = tempfile.mkdtemp(prefix="mv_audit_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy(
    "/workspace/markervault/username_validation.py",
    os.path.join(WORK, "username_validation.py"),
)
shutil.copy(
    "/workspace/markervault/markervault_config.py",
    os.path.join(WORK, "markervault_config.py"),
)
shutil.copy(
    "/workspace/markervault/email_delivery.py",
    os.path.join(WORK, "email_delivery.py"),
)
os.chdir(WORK)
if WORK not in sys.path:
    sys.path.insert(0, WORK)
os.environ["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64

spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)
backend.COOKIE_SECURE = False
backend.rate_limit = lambda *args, **kwargs: None
app = backend.app
app.testing = True


PASS = FAIL = 0


def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def make_user(username, password, role="user", status="approved", email=None):
    conn = backend.get_db()
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email, company, department, birth_date, sex) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            role,
            status,
            datetime.now().isoformat(),
            "First",
            "Last",
            email or f"{uuid.uuid4().hex}@x.com",
            "",
            "",
            "",
            "",
        ),
    )
    conn.commit()
    conn.close()
    return user_id


def login(username, password):
    client = app.test_client()
    client.post("/login", json={"username": username, "password": password})
    response = client.post("/auth/refresh")
    return client, response.get_json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def audit_rows(action):
    conn = backend.get_db()
    rows = conn.execute(
        "SELECT id, actor_id, actor_username, actor_role, action, target_type, "
        "target_id, target_label, detail, client_ip "
        "FROM audit_log WHERE action = ? ORDER BY id",
        (action,),
    ).fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "actor_id": row[1],
            "actor_username": row[2],
            "actor_role": row[3],
            "action": row[4],
            "target_type": row[5],
            "target_id": row[6],
            "target_label": row[7],
            "detail": json.loads(row[8]) if row[8] is not None else None,
            "client_ip": row[9],
        }
        for row in rows
    ]


@app.route("/_test/admin-identity")
@backend.require_admin
def admin_identity():
    return backend.jsonify(
        {
            "user_id": backend.g.user_id,
            "username": backend.g.username,
            "role": backend.g.role,
        }
    )


print("== Audit schema ==")
conn = backend.get_db()
columns = [row[1:3] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
foreign_keys = conn.execute("PRAGMA foreign_key_list(audit_log)").fetchall()
indexes = {row[1] for row in conn.execute("PRAGMA index_list(audit_log)").fetchall()}
conn.close()

check(
    columns
    == [
        ("id", "INTEGER"),
        ("ts", "TEXT"),
        ("actor_id", "TEXT"),
        ("actor_username", "TEXT"),
        ("actor_role", "TEXT"),
        ("action", "TEXT"),
        ("target_type", "TEXT"),
        ("target_id", "TEXT"),
        ("target_label", "TEXT"),
        ("detail", "TEXT"),
        ("client_ip", "TEXT"),
    ],
    f"table has the documented denormalized shape (got {columns})",
)
check(foreign_keys == [], f"audit_log has no foreign keys (got {foreign_keys})")
check("idx_audit_ts" in indexes, f"timestamp index exists (got {indexes})")


print("\n== Writer defaults, timestamps, and JSON detail ==")
with app.test_request_context("/_test/audit"):
    backend.g.user_id = "actor-1"
    backend.g.username = "alice"
    backend.g.role = "admin"
    backend.g.client_ip = "203.0.113.8"
    backend.audit(
        "test.default_actor",
        target_type="map",
        target_id=42,
        target_label="Field Notes",
        old="viewer",
        new="editor",
    )

conn = backend.get_db()
row = conn.execute(
    "SELECT ts, actor_id, actor_username, actor_role, action, target_type, "
    "target_id, target_label, detail, client_ip FROM audit_log "
    "WHERE action = 'test.default_actor'"
).fetchone()
conn.close()
check(row is not None, "audit() writes a row")
check(
    row[1:8] == (
        "actor-1",
        "alice",
        "admin",
        "test.default_actor",
        "map",
        "42",
        "Field Notes",
    ),
    f"g actor and target snapshots are stored (got {row[1:8]})",
)
check(
    row[9] == "203.0.113.8",
    f"client IP defaults from g (got {row[9]!r})",
)
try:
    parsed_ts = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
    timestamp_ok = row[0].endswith("Z") and parsed_ts.utcoffset().total_seconds() == 0
except (TypeError, ValueError, AttributeError):
    timestamp_ok = False
check(timestamp_ok, f"timestamp is parseable UTC ending in Z (got {row[0]!r})")
check(
    json.loads(row[8]) == {"old": "viewer", "new": "editor"},
    f"detail is serialized JSON (got {row[8]!r})",
)


print("\n== Explicit actor overrides ==")
with app.test_request_context("/_test/audit"):
    backend.g.user_id = "wrong-id"
    backend.g.username = "wrong-name"
    backend.g.role = "user"
    backend.g.client_ip = "192.0.2.1"
    backend.audit(
        "test.explicit_actor",
        actor_id="resolved-id",
        actor_username="CanonicalName",
        actor_role="super_admin",
        client_ip="198.51.100.4",
    )

conn = backend.get_db()
override_row = conn.execute(
    "SELECT actor_id, actor_username, actor_role, client_ip, detail "
    "FROM audit_log WHERE action = 'test.explicit_actor'"
).fetchone()
conn.close()
check(
    override_row[:4]
    == ("resolved-id", "CanonicalName", "super_admin", "198.51.100.4"),
    f"explicit actor fields override g (got {override_row[:4]})",
)
check(override_row[4] is None, "empty detail is stored as NULL")


print("\n== Fresh require_admin identity ==")
admin_id = make_user("before_rename", "Admin123!", "admin")
client, token = login("before_rename", "Admin123!")
conn = backend.get_db()
conn.execute(
    "UPDATE users SET username = ? WHERE user_id = ?",
    ("after_rename", admin_id),
)
conn.commit()
conn.close()
response = client.get("/_test/admin-identity", headers=headers(token))
identity = response.get_json()
check(response.status_code == 200, f"renamed admin token remains authorized (got {response.status_code})")
check(
    identity
    == {"user_id": admin_id, "username": "after_rename", "role": "admin"},
    f"require_admin refreshes canonical username and role (got {identity})",
)


print("\n== Fail-open connection cleanup ==")


class ThrowingConnection:
    def __init__(self):
        self.closed = False

    def execute(self, *args, **kwargs):
        raise RuntimeError("simulated audit insert failure")

    def close(self):
        self.closed = True


throwing = ThrowingConnection()
real_get_db = backend.get_db
backend.get_db = lambda: throwing
raised = None
try:
    with app.test_request_context("/_test/audit"):
        backend.g.user_id = "actor"
        backend.audit("test.failure")
except Exception as exc:
    raised = exc
finally:
    backend.get_db = real_get_db

check(raised is None, f"audit insert failure is swallowed (got {raised!r})")
check(throwing.closed, "throwing audit connection is still closed")


print("\n== User-governance events ==")
boss_id = make_user("audit_boss", "Boss1234!", "super_admin", email="boss@audit.test")
boss, boss_token = login("audit_boss", "Boss1234!")

pending_id = make_user(
    "pending_approval",
    "Pending1!",
    status="pending",
    email="pending@audit.test",
)
response = boss.post(
    f"/admin/users/{pending_id}/approve",
    headers=headers(boss_token),
)
approval = audit_rows("user.approve")
check(response.status_code == 200 and len(approval) == 1, "approval writes exactly one audit row")
check(
    approval[0]["actor_id"] == boss_id
    and approval[0]["actor_username"] == "audit_boss"
    and approval[0]["actor_role"] == "super_admin"
    and approval[0]["target_id"] == pending_id
    and approval[0]["target_label"] == "pending_approval",
    f"approval freezes actor and target identity (got {approval[0]})",
)

rejected_id = make_user(
    "pending_reject",
    "Pending1!",
    status="pending",
    email="reject@audit.test",
)
response = boss.post(
    f"/admin/users/{rejected_id}/reject",
    headers=headers(boss_token),
)
rejection = audit_rows("user.reject")
conn = backend.get_db()
rejected_exists = conn.execute(
    "SELECT 1 FROM users WHERE user_id = ?",
    (rejected_id,),
).fetchone()
conn.close()
check(
    response.status_code == 200
    and rejected_exists is None
    and len(rejection) == 1
    and rejection[0]["target_label"] == "pending_reject",
    f"reject label survives target deletion (got {rejection})",
)

create_payload = {
    "username": "governed_user",
    "password": "Created1!",
    "role": "user",
    "first_name": "Governed",
    "last_name": "User",
    "email": "governed@audit.test",
    "company": "Acme",
    "department": "Ops",
    "birth_date": "1990-01-02",
    "sex": "other",
}
response = boss.post(
    "/admin/users/create",
    headers=headers(boss_token),
    json=create_payload,
)
governed_id = response.get_json()["user_id"]
created = audit_rows("user.create")
check(
    response.status_code == 200
    and len(created) == 1
    and created[0]["target_id"] == governed_id
    and created[0]["target_label"] == "governed_user"
    and created[0]["detail"] == {"role": "user"},
    f"create records role and target snapshot (got {created})",
)

role_count = len(audit_rows("user.role"))
same_role = boss.post(
    f"/admin/users/{governed_id}/role",
    headers=headers(boss_token),
    json={"role": "user"},
)
check(
    same_role.status_code == 200 and len(audit_rows("user.role")) == role_count,
    "same-value role request writes no audit row",
)
response = boss.post(
    f"/admin/users/{governed_id}/role",
    headers=headers(boss_token),
    json={"role": "admin"},
)
role_rows = audit_rows("user.role")
check(
    response.status_code == 200
    and len(role_rows) == role_count + 1
    and role_rows[-1]["detail"] == {"old": "user", "new": "admin"}
    and role_rows[-1]["target_label"] == "governed_user",
    f"role change records old and new values (got {role_rows[-1]})",
)

before_guard = len(audit_rows("user.disable"))
guarded = client.post(
    f"/admin/users/{governed_id}/disable",
    headers=headers(token),
)
check(
    guarded.status_code == 403 and len(audit_rows("user.disable")) == before_guard,
    "guarded regular-admin mutation writes no audit row",
)

conn = backend.get_db()
conn.execute(
    "INSERT INTO refresh_tokens (user_id, family_id, token, expires, created) "
    "VALUES (?, ?, ?, ?, ?)",
    (governed_id, "fam-approved", "approved-user-token", 9999999999, 1),
)
conn.commit()
conn.close()
response = boss.post(
    f"/admin/users/{governed_id}/disable",
    headers=headers(boss_token),
)
conn = backend.get_db()
tokens_after_disable = conn.execute(
    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?",
    (governed_id,),
).fetchone()[0]
conn.execute(
    "INSERT INTO refresh_tokens (user_id, family_id, token, expires, created) "
    "VALUES (?, ?, ?, ?, ?)",
    (governed_id, "fam-disabled", "disabled-user-token", 9999999999, 1),
)
conn.commit()
conn.close()
duplicate_disable = boss.post(
    f"/admin/users/{governed_id}/disable",
    headers=headers(boss_token),
)
conn = backend.get_db()
tokens_after_duplicate = conn.execute(
    "SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?",
    (governed_id,),
).fetchone()[0]
conn.close()
disabled = audit_rows("user.disable")
check(
    response.status_code == 200
    and duplicate_disable.status_code == 404
    and tokens_after_disable == 0
    and tokens_after_duplicate == 1
    and len(disabled) == before_guard + 1
    and disabled[-1]["target_label"] == "governed_user",
    "disable revokes sessions once; zero-row retry preserves state and writes no audit",
)
response = boss.post(
    f"/admin/users/{governed_id}/enable",
    headers=headers(boss_token),
)
enabled = audit_rows("user.enable")
check(
    response.status_code == 200
    and len(enabled) == 1
    and enabled[0]["target_label"] == "governed_user",
    f"enable records the named target (got {enabled})",
)

new_password = "Changed1!"
response = boss.post(
    f"/admin/users/{governed_id}/resetpwd",
    headers=headers(boss_token),
    json={"new_password": new_password},
)
reset = audit_rows("user.resetpwd")
conn = backend.get_db()
password_leaked = conn.execute(
    "SELECT 1 FROM audit_log WHERE detail LIKE ? OR target_label LIKE ?",
    (f"%{new_password}%", f"%{new_password}%"),
).fetchone()
conn.close()
check(
    response.status_code == 200
    and len(reset) == 1
    and reset[0]["detail"] is None
    and password_leaked is None,
    f"password reset logs the event but never the password (got {reset})",
)

no_change_profile = {
    **create_payload,
    "username": "  governed_user  ",
}
no_change_profile.pop("password")
no_change_profile.pop("role")
profile_count = len(audit_rows("user.profile_edit"))
response = boss.put(
    f"/admin/users/{governed_id}/profile",
    headers=headers(boss_token),
    json=no_change_profile,
)
check(
    response.status_code == 200
    and len(audit_rows("user.profile_edit")) == profile_count,
    "cleaned no-op profile request writes no audit row",
)

changed_profile = {
    **no_change_profile,
    "username": "GOVERNED_USER",
    "company": "New Company",
}
response = boss.put(
    f"/admin/users/{governed_id}/profile",
    headers=headers(boss_token),
    json=changed_profile,
)
profile_rows = audit_rows("user.profile_edit")
check(
    response.status_code == 200
    and len(profile_rows) == profile_count + 1
    and profile_rows[-1]["target_label"] == "GOVERNED_USER"
    and profile_rows[-1]["detail"]
    == {
        "username": {"old": "governed_user", "new": "GOVERNED_USER"},
        "company": {"old": "Acme", "new": "New Company"},
    },
    f"profile edit records cleaned old/new values only (got {profile_rows[-1]})",
)

controller_target_id = make_user(
    "controller_target",
    "Target123!",
    email="controller-target@audit.test",
)
before_add = len(audit_rows("user.controller.add"))
first_add = boss.put(
    f"/admin/users/{controller_target_id}/controllers",
    headers=headers(boss_token),
    json={"admin_id": admin_id},
)
duplicate_add = boss.put(
    f"/admin/users/{controller_target_id}/controllers",
    headers=headers(boss_token),
    json={"admin_id": admin_id},
)
controller_add = audit_rows("user.controller.add")
check(
    first_add.status_code == 200
    and duplicate_add.status_code == 200
    and len(controller_add) == before_add + 1
    and controller_add[-1]["target_label"] == "controller_target"
    and controller_add[-1]["detail"]
    == {"admin_id": admin_id, "admin_label": "after_rename"},
    f"duplicate controller add logs once with both labels (got {controller_add[-1]})",
)

response = boss.delete(
    f"/admin/users/{controller_target_id}/controllers/{admin_id}",
    headers=headers(boss_token),
)
controller_remove = audit_rows("user.controller.remove")
check(
    response.status_code == 200
    and len(controller_remove) == 1
    and controller_remove[0]["target_label"] == "controller_target"
    and controller_remove[0]["detail"]
    == {"admin_id": admin_id, "admin_label": "after_rename"},
    f"controller removal freezes both parties (got {controller_remove})",
)

conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (admin_id,))
conn.commit()
conn.close()
surviving_add = audit_rows("user.controller.add")[-1]
check(
    surviving_add["actor_username"] == "audit_boss"
    and surviving_add["target_label"] == "controller_target"
    and surviving_add["detail"]["admin_label"] == "after_rename",
    f"relationship row stays readable after counterparty deletion (got {surviving_add})",
)

delete_target_id = make_user(
    "delete_target",
    "Delete123!",
    email="delete-target@audit.test",
)
response = boss.delete(
    f"/admin/users/{delete_target_id}",
    headers=headers(boss_token),
)
deleted = audit_rows("user.delete")
conn = backend.get_db()
delete_target_exists = conn.execute(
    "SELECT 1 FROM users WHERE user_id = ?",
    (delete_target_id,),
).fetchone()
conn.close()
check(
    response.status_code == 200
    and delete_target_exists is None
    and deleted[-1]["target_label"] == "delete_target",
    f"delete target label survives the deleted user (got {deleted[-1]})",
)


print("\n== Share-group events ==")
response = boss.post(
    "/admin/groups",
    headers=headers(boss_token),
    json={"name": "Audit Team"},
)
group_id = response.get_json()["id"]
group_create = audit_rows("share_group.create")
check(
    response.status_code == 200
    and len(group_create) == 1
    and group_create[0]["target_id"] == str(group_id)
    and group_create[0]["target_label"] == "Audit Team"
    and group_create[0]["detail"] == {"name": "Audit Team"},
    f"group create records its frozen name (got {group_create})",
)

rename_count = len(audit_rows("share_group.rename"))
same_name = boss.put(
    f"/admin/groups/{group_id}",
    headers=headers(boss_token),
    json={"name": "Audit Team"},
)
check(
    same_name.status_code == 200
    and len(audit_rows("share_group.rename")) == rename_count,
    "same-name group rename writes no audit row",
)
response = boss.put(
    f"/admin/groups/{group_id}",
    headers=headers(boss_token),
    json={"name": "Audit Crew"},
)
group_rename = audit_rows("share_group.rename")
check(
    response.status_code == 200
    and len(group_rename) == rename_count + 1
    and group_rename[-1]["target_label"] == "Audit Crew"
    and group_rename[-1]["detail"]
    == {"old_name": "Audit Team", "new_name": "Audit Crew"},
    f"group rename records both names (got {group_rename[-1]})",
)

race_group = boss.post(
    "/admin/groups",
    headers=headers(boss_token),
    json={"name": "Rename Race"},
)
race_group_id = race_group.get_json()["id"]
race_rename_count = len(audit_rows("share_group.rename"))
conn = backend.get_db()
conn.execute(f"""
    CREATE TRIGGER delete_share_group_during_rename
    BEFORE UPDATE OF name ON share_groups
    WHEN OLD.id = {race_group_id}
    BEGIN
        DELETE FROM share_groups WHERE id = OLD.id;
    END
""")
conn.commit()
conn.close()
race_rename = boss.put(
    f"/admin/groups/{race_group_id}",
    headers=headers(boss_token),
    json={"name": "Rename Race Lost"},
)
conn = backend.get_db()
conn.execute("DROP TRIGGER IF EXISTS delete_share_group_during_rename")
race_group_exists = conn.execute(
    "SELECT 1 FROM share_groups WHERE id = ?",
    (race_group_id,),
).fetchone()
conn.commit()
conn.close()
check(
    race_rename.status_code == 404
    and race_group_exists is None
    and len(audit_rows("share_group.rename")) == race_rename_count,
    "share-group rename returns 404 and emits no audit when the UPDATE loses a delete race",
)

group_member_id = make_user(
    "group_member",
    "Member123!",
    email="group-member@audit.test",
)
member_add_count = len(audit_rows("share_group.member.add"))
first_member_add = boss.put(
    f"/admin/groups/{group_id}/members",
    headers=headers(boss_token),
    json={"username": "GROUP_MEMBER"},
)
duplicate_member_add = boss.put(
    f"/admin/groups/{group_id}/members",
    headers=headers(boss_token),
    json={"username": "group_member"},
)
member_add = audit_rows("share_group.member.add")
check(
    first_member_add.status_code == 200
    and duplicate_member_add.status_code == 200
    and len(member_add) == member_add_count + 1
    and member_add[-1]["target_label"] == "Audit Crew"
    and member_add[-1]["detail"]
    == {"user_id": group_member_id, "user_label": "group_member"},
    f"duplicate member add logs once with canonical label (got {member_add[-1]})",
)

response = boss.delete(
    f"/admin/groups/{group_id}/members/{group_member_id}",
    headers=headers(boss_token),
)
member_remove = audit_rows("share_group.member.remove")
check(
    response.status_code == 200
    and len(member_remove) == 1
    and member_remove[0]["target_label"] == "Audit Crew"
    and member_remove[0]["detail"]
    == {"user_id": group_member_id, "user_label": "group_member"},
    f"member removal freezes group and member labels (got {member_remove})",
)
conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (group_member_id,))
conn.commit()
conn.close()
surviving_member = audit_rows("share_group.member.add")[-1]
check(
    surviving_member["target_label"] == "Audit Crew"
    and surviving_member["detail"]["user_label"] == "group_member",
    f"member relationship remains readable after user deletion (got {surviving_member})",
)

group_owner_id = make_user(
    "group_owner",
    "Owner123!",
    role="admin",
    email="group-owner@audit.test",
)
owner_add_count = len(audit_rows("share_group.owner.add"))
first_owner_add = boss.put(
    f"/admin/groups/{group_id}/owners",
    headers=headers(boss_token),
    json={"admin_id": group_owner_id},
)
duplicate_owner_add = boss.put(
    f"/admin/groups/{group_id}/owners",
    headers=headers(boss_token),
    json={"admin_id": group_owner_id},
)
owner_add = audit_rows("share_group.owner.add")
check(
    first_owner_add.status_code == 200
    and duplicate_owner_add.status_code == 200
    and len(owner_add) == owner_add_count + 1
    and owner_add[-1]["target_label"] == "Audit Crew"
    and owner_add[-1]["detail"]
    == {"admin_id": group_owner_id, "admin_label": "group_owner"},
    f"duplicate owner add logs once with both labels (got {owner_add[-1]})",
)

response = boss.delete(
    f"/admin/groups/{group_id}/owners/{group_owner_id}",
    headers=headers(boss_token),
)
owner_remove = audit_rows("share_group.owner.remove")
check(
    response.status_code == 200
    and len(owner_remove) == 1
    and owner_remove[0]["target_label"] == "Audit Crew"
    and owner_remove[0]["detail"]
    == {"admin_id": group_owner_id, "admin_label": "group_owner"},
    f"owner removal freezes group and owner labels (got {owner_remove})",
)
conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (group_owner_id,))
conn.commit()
conn.close()
surviving_owner = audit_rows("share_group.owner.add")[-1]
check(
    surviving_owner["target_label"] == "Audit Crew"
    and surviving_owner["detail"]["admin_label"] == "group_owner",
    f"owner relationship remains readable after admin deletion (got {surviving_owner})",
)

response = boss.delete(
    f"/admin/groups/{group_id}",
    headers=headers(boss_token),
)
group_delete = audit_rows("share_group.delete")
conn = backend.get_db()
group_exists = conn.execute(
    "SELECT 1 FROM share_groups WHERE id = ?",
    (group_id,),
).fetchone()
conn.close()
check(
    response.status_code == 200
    and group_exists is None
    and len(group_delete) == 1
    and group_delete[0]["target_label"] == "Audit Crew"
    and group_delete[0]["detail"] == {"name": "Audit Crew"},
    f"group delete label survives the deleted group (got {group_delete})",
)


print("\n== Management-group events ==")
response = boss.post(
    "/admin/mgmt-groups",
    headers=headers(boss_token),
    json={"name": "Audit Management"},
)
mgmt_group_id = response.get_json()["id"]
mgmt_create = audit_rows("mgmt_group.create")
check(
    response.status_code == 200
    and len(mgmt_create) == 1
    and mgmt_create[0]["target_id"] == str(mgmt_group_id)
    and mgmt_create[0]["target_label"] == "Audit Management"
    and mgmt_create[0]["detail"] == {"name": "Audit Management"},
    f"management-group create records its name (got {mgmt_create})",
)

mgmt_rename_count = len(audit_rows("mgmt_group.rename"))
same_name = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}",
    headers=headers(boss_token),
    json={"name": "Audit Management"},
)
check(
    same_name.status_code == 200
    and len(audit_rows("mgmt_group.rename")) == mgmt_rename_count,
    "same-name management-group rename writes no audit row",
)
response = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}",
    headers=headers(boss_token),
    json={"name": "Audit Delegation"},
)
mgmt_rename = audit_rows("mgmt_group.rename")
check(
    response.status_code == 200
    and len(mgmt_rename) == mgmt_rename_count + 1
    and mgmt_rename[-1]["target_label"] == "Audit Delegation"
    and mgmt_rename[-1]["detail"]
    == {"old_name": "Audit Management", "new_name": "Audit Delegation"},
    f"management-group rename records both names (got {mgmt_rename[-1]})",
)

mgmt_member_id = make_user(
    "mgmt_member",
    "Member123!",
    email="mgmt-member@audit.test",
)
mgmt_member_add_count = len(audit_rows("mgmt_group.member.add"))
first_mgmt_member = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}/members",
    headers=headers(boss_token),
    json={"username": "MGMT_MEMBER"},
)
duplicate_mgmt_member = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}/members",
    headers=headers(boss_token),
    json={"username": "mgmt_member"},
)
mgmt_member_add = audit_rows("mgmt_group.member.add")
check(
    first_mgmt_member.status_code == 200
    and duplicate_mgmt_member.status_code == 200
    and len(mgmt_member_add) == mgmt_member_add_count + 1
    and mgmt_member_add[-1]["target_label"] == "Audit Delegation"
    and mgmt_member_add[-1]["detail"]
    == {"user_id": mgmt_member_id, "user_label": "mgmt_member"},
    f"duplicate management member logs once with labels (got {mgmt_member_add[-1]})",
)

response = boss.delete(
    f"/admin/mgmt-groups/{mgmt_group_id}/members/{mgmt_member_id}",
    headers=headers(boss_token),
)
mgmt_member_remove = audit_rows("mgmt_group.member.remove")
check(
    response.status_code == 200
    and len(mgmt_member_remove) == 1
    and mgmt_member_remove[0]["target_label"] == "Audit Delegation"
    and mgmt_member_remove[0]["detail"]
    == {"user_id": mgmt_member_id, "user_label": "mgmt_member"},
    f"management member removal freezes both labels (got {mgmt_member_remove})",
)
conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (mgmt_member_id,))
conn.commit()
conn.close()
surviving_mgmt_member = audit_rows("mgmt_group.member.add")[-1]
check(
    surviving_mgmt_member["target_label"] == "Audit Delegation"
    and surviving_mgmt_member["detail"]["user_label"] == "mgmt_member",
    f"management member row survives user deletion (got {surviving_mgmt_member})",
)

mgmt_manager_id = make_user(
    "mgmt_manager",
    "Manager1!",
    role="admin",
    email="mgmt-manager@audit.test",
)
mgmt_manager_add_count = len(audit_rows("mgmt_group.manager.add"))
first_mgmt_manager = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}/managers",
    headers=headers(boss_token),
    json={"admin_id": mgmt_manager_id},
)
duplicate_mgmt_manager = boss.put(
    f"/admin/mgmt-groups/{mgmt_group_id}/managers",
    headers=headers(boss_token),
    json={"admin_id": mgmt_manager_id},
)
mgmt_manager_add = audit_rows("mgmt_group.manager.add")
check(
    first_mgmt_manager.status_code == 200
    and duplicate_mgmt_manager.status_code == 200
    and len(mgmt_manager_add) == mgmt_manager_add_count + 1
    and mgmt_manager_add[-1]["target_label"] == "Audit Delegation"
    and mgmt_manager_add[-1]["detail"]
    == {"admin_id": mgmt_manager_id, "admin_label": "mgmt_manager"},
    f"duplicate management manager logs once with labels (got {mgmt_manager_add[-1]})",
)

response = boss.delete(
    f"/admin/mgmt-groups/{mgmt_group_id}/managers/{mgmt_manager_id}",
    headers=headers(boss_token),
)
mgmt_manager_remove = audit_rows("mgmt_group.manager.remove")
check(
    response.status_code == 200
    and len(mgmt_manager_remove) == 1
    and mgmt_manager_remove[0]["target_label"] == "Audit Delegation"
    and mgmt_manager_remove[0]["detail"]
    == {"admin_id": mgmt_manager_id, "admin_label": "mgmt_manager"},
    f"management manager removal freezes both labels (got {mgmt_manager_remove})",
)
conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (mgmt_manager_id,))
conn.commit()
conn.close()
surviving_mgmt_manager = audit_rows("mgmt_group.manager.add")[-1]
check(
    surviving_mgmt_manager["target_label"] == "Audit Delegation"
    and surviving_mgmt_manager["detail"]["admin_label"] == "mgmt_manager",
    f"management manager row survives admin deletion (got {surviving_mgmt_manager})",
)

response = boss.delete(
    f"/admin/mgmt-groups/{mgmt_group_id}",
    headers=headers(boss_token),
)
mgmt_delete = audit_rows("mgmt_group.delete")
conn = backend.get_db()
mgmt_group_exists = conn.execute(
    "SELECT 1 FROM management_groups WHERE id = ?",
    (mgmt_group_id,),
).fetchone()
conn.close()
check(
    response.status_code == 200
    and mgmt_group_exists is None
    and len(mgmt_delete) == 1
    and mgmt_delete[0]["target_label"] == "Audit Delegation"
    and mgmt_delete[0]["detail"] == {"name": "Audit Delegation"},
    f"management-group delete label survives the group (got {mgmt_delete})",
)


print("\n== Super-admin map-share events ==")
map_owner_id = make_user(
    "map_owner",
    "Owner123!",
    email="map-owner@audit.test",
)
backend.create_base_map(map_owner_id)
map_owner, map_owner_token = login("map_owner", "Owner123!")
response = map_owner.post(
    "/maps",
    headers=headers(map_owner_token),
    json={"name": "Audit Map"},
)
audit_map_id = response.get_json()["id"]
map_recipient_id = make_user(
    "map_recipient",
    "Recipient1!",
    email="map-recipient@audit.test",
)

direct_grant_count = len(audit_rows("map_share.direct.grant"))
created_share = boss.put(
    f"/admin/maps/{audit_map_id}/collaborators",
    headers=headers(boss_token),
    json={"username": "MAP_RECIPIENT", "role": "viewer"},
)
direct_grants = audit_rows("map_share.direct.grant")
check(
    created_share.status_code == 200
    and len(direct_grants) == direct_grant_count + 1
    and direct_grants[-1]["target_label"] == "Audit Map"
    and direct_grants[-1]["detail"]
    == {
        "recipient": map_recipient_id,
        "recipient_label": "map_recipient",
        "operation": "created",
        "old_role": None,
        "new_role": "viewer",
    },
    f"direct access grant records canonical recipient and roles (got {direct_grants[-1]})",
)

direct_change_count = len(audit_rows("map_share.direct.change"))
same_share = boss.put(
    f"/admin/maps/{audit_map_id}/collaborators",
    headers=headers(boss_token),
    json={"username": "map_recipient", "role": "viewer"},
)
check(
    same_share.status_code == 200
    and len(audit_rows("map_share.direct.grant")) == direct_grant_count + 1
    and len(audit_rows("map_share.direct.change")) == direct_change_count,
    "setting the current direct-share role writes no audit row",
)

changed_share = boss.put(
    f"/admin/maps/{audit_map_id}/collaborators",
    headers=headers(boss_token),
    json={"username": "map_recipient", "role": "editor"},
)
direct_changes = audit_rows("map_share.direct.change")
check(
    changed_share.status_code == 200
    and len(direct_changes) == direct_change_count + 1
    and direct_changes[-1]["detail"]["operation"] == "role_changed"
    and direct_changes[-1]["detail"]["old_role"] == "viewer"
    and direct_changes[-1]["detail"]["new_role"] == "editor",
    f"direct access change records old and new roles (got {direct_changes[-1]})",
)

response = boss.post(
    "/admin/groups",
    headers=headers(boss_token),
    json={"name": "Map Audit Group"},
)
map_group_id = response.get_json()["id"]
group_grant_count = len(audit_rows("map_share.group.grant"))
group_share = boss.put(
    f"/admin/maps/{audit_map_id}/collaborators",
    headers=headers(boss_token),
    json={"group": "MAP AUDIT GROUP", "role": "viewer"},
)
group_grants = audit_rows("map_share.group.grant")
check(
    group_share.status_code == 200
    and len(group_grants) == group_grant_count + 1
    and group_grants[-1]["target_label"] == "Audit Map"
    and group_grants[-1]["detail"]
    == {
        "group": map_group_id,
        "group_label": "Map Audit Group",
        "operation": "created",
        "old_role": None,
        "new_role": "viewer",
    },
    f"group access grant records group id and label (got {group_grants[-1]})",
)

group_change_count = len(audit_rows("map_share.group.change"))
changed_group_share = boss.put(
    f"/admin/maps/{audit_map_id}/collaborators",
    headers=headers(boss_token),
    json={"group": "Map Audit Group", "role": "editor"},
)
group_changes = audit_rows("map_share.group.change")
check(
    changed_group_share.status_code == 200
    and len(group_changes) == group_change_count + 1
    and group_changes[-1]["detail"]["operation"] == "role_changed"
    and group_changes[-1]["detail"]["old_role"] == "viewer"
    and group_changes[-1]["detail"]["new_role"] == "editor",
    f"group access change records old and new roles (got {group_changes[-1]})",
)

remove_count = len(audit_rows("map_share.direct.remove"))
removed_share = boss.delete(
    f"/admin/maps/{audit_map_id}/collaborators/{map_recipient_id}",
    headers=headers(boss_token),
)
missing_share = boss.delete(
    f"/admin/maps/{audit_map_id}/collaborators/{map_recipient_id}",
    headers=headers(boss_token),
)
map_remove = audit_rows("map_share.direct.remove")
check(
    removed_share.status_code == 200
    and missing_share.status_code == 404
    and len(map_remove) == remove_count + 1
    and map_remove[-1]["target_label"] == "Audit Map"
    and map_remove[-1]["detail"]
    == {
        "recipient": map_recipient_id,
        "recipient_label": "map_recipient",
    },
    f"direct removal logs only the successful delete (got {map_remove[-1]})",
)

remove_group_count = len(audit_rows("map_share.group.remove"))
removed_group_share = boss.delete(
    f"/admin/maps/{audit_map_id}/collaborators/group/{map_group_id}",
    headers=headers(boss_token),
)
missing_group_share = boss.delete(
    f"/admin/maps/{audit_map_id}/collaborators/group/{map_group_id}",
    headers=headers(boss_token),
)
map_remove_group = audit_rows("map_share.group.remove")
check(
    removed_group_share.status_code == 200
    and missing_group_share.status_code == 404
    and len(map_remove_group) == remove_group_count + 1
    and map_remove_group[-1]["target_label"] == "Audit Map"
    and map_remove_group[-1]["detail"]
    == {"group": map_group_id, "group_label": "Map Audit Group"},
    f"group removal logs only the successful delete (got {map_remove_group[-1]})",
)

map_access_actions = (
    "map_share.direct.grant",
    "map_share.direct.change",
    "map_share.direct.remove",
    "map_share.group.grant",
    "map_share.group.change",
    "map_share.group.remove",
)
owner_audit_counts = {
    action: len(audit_rows(action))
    for action in map_access_actions
}
owner_set = map_owner.put(
    f"/maps/{audit_map_id}/collaborators",
    headers=headers(map_owner_token),
    json={"username": "map_recipient", "role": "viewer"},
)
owner_remove = map_owner.delete(
    f"/maps/{audit_map_id}/collaborators/{map_recipient_id}",
    headers=headers(map_owner_token),
)
owner_group_set = map_owner.put(
    f"/maps/{audit_map_id}/collaborators",
    headers=headers(map_owner_token),
    json={"group": "Map Audit Group", "role": "viewer"},
)
owner_group_remove = map_owner.delete(
    f"/maps/{audit_map_id}/collaborators/group/{map_group_id}",
    headers=headers(map_owner_token),
)
check(
    all(
        response.status_code == 200
        for response in (owner_set, owner_remove, owner_group_set, owner_group_remove)
    )
    and all(
        len(audit_rows(action)) == count
        for action, count in owner_audit_counts.items()
    ),
    "owner-side share PUT/DELETE routes remain deliberately unaudited",
)

conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id = ?", (map_recipient_id,))
conn.execute("DELETE FROM share_groups WHERE id = ?", (map_group_id,))
conn.commit()
conn.close()
surviving_direct_share = audit_rows("map_share.direct.grant")[-1]
surviving_group_share = audit_rows("map_share.group.grant")[-1]
check(
    surviving_direct_share["detail"]["recipient_label"] == "map_recipient"
    and surviving_group_share["detail"]["group_label"] == "Map Audit Group",
    "map-share rows remain readable after recipient and group deletion",
)


print("\n== Authentication and self account-security events ==")
auth_user_id = make_user(
    "AuthCase",
    "Auth1234!",
    email="auth-case@audit.test",
)
login_count = len(audit_rows("auth.login"))
auth_client = app.test_client()
successful_login = auth_client.post(
    "/login",
    json={"username": "authcase", "password": "Auth1234!"},
)
auth_login = audit_rows("auth.login")
check(
    successful_login.status_code == 200
    and len(auth_login) == login_count + 1
    and auth_login[-1]["actor_id"] == auth_user_id
    and auth_login[-1]["actor_username"] == "AuthCase"
    and auth_login[-1]["actor_role"] == "user"
    and auth_login[-1]["client_ip"] == "127.0.0.1",
    f"successful login uses canonical explicit actor fields (got {auth_login[-1]})",
)

failed_count = len(audit_rows("auth.login_failed"))
bad_password = app.test_client().post(
    "/login",
    json={"username": "AUTHCASE", "password": "Wrong123!"},
)
failed_login = audit_rows("auth.login_failed")
check(
    bad_password.status_code == 401
    and len(failed_login) == failed_count + 1
    and failed_login[-1]["actor_id"] == auth_user_id
    and failed_login[-1]["actor_username"] == "AUTHCASE"
    and failed_login[-1]["actor_role"] == "user"
    and failed_login[-1]["detail"] == {"reason": "bad_password"},
    f"known-user failure records attempted name without claiming identity (got {failed_login[-1]})",
)

long_attempt = "x" * 160
unknown_login = app.test_client().post(
    "/login",
    json={"username": long_attempt, "password": "Wrong123!"},
)
failed_login = audit_rows("auth.login_failed")
check(
    unknown_login.status_code == 401
    and len(failed_login) == failed_count + 2
    and failed_login[-1]["actor_id"] is None
    and failed_login[-1]["actor_role"] is None
    and failed_login[-1]["actor_username"] == long_attempt[:128]
    and failed_login[-1]["detail"] == {"reason": "unknown_user"},
    f"unknown-user failure truncates the attempted name to 128 characters (got {failed_login[-1]})",
)

malformed_failed_count = len(failed_login)
malformed_logins = [
    app.test_client().post(
        "/login",
        json={"username": ["AuthCase"], "password": "Auth1234!"},
    ),
    app.test_client().post(
        "/login",
        json={"username": {"value": "AuthCase"}, "password": "Auth1234!"},
    ),
    app.test_client().post(
        "/login",
        json={"username": "AuthCase", "password": 123},
    ),
    app.test_client().post(
        "/login",
        json={"username": "AuthCase", "password": None},
    ),
    app.test_client().post("/login", json="username password"),
]
check(
    all(response.status_code == 400 for response in malformed_logins)
    and len(audit_rows("auth.login_failed")) == malformed_failed_count,
    "non-object and non-string login credentials return 400 without auth audit rows",
)

unapproved_id = make_user(
    "not_approved",
    "Pending1!",
    status="pending",
    email="not-approved@audit.test",
)
unapproved_login = app.test_client().post(
    "/login",
    json={"username": "not_approved", "password": "Pending1!"},
)
failed_login = audit_rows("auth.login_failed")
check(
    unapproved_login.status_code == 403
    and len(failed_login) == failed_count + 3
    and failed_login[-1]["actor_id"] == unapproved_id
    and failed_login[-1]["actor_username"] == "not_approved"
    and failed_login[-1]["detail"] == {"reason": "approval_pending"},
    f"unapproved-account login records the resolved account and reason (got {failed_login[-1]})",
)

refresh = auth_client.post("/auth/refresh")
auth_token = refresh.get_json()["access_token"]
logout_count = len(audit_rows("auth.logout"))
logout = auth_client.post("/auth/logout", headers=headers(auth_token))
auth_logout_rows = audit_rows("auth.logout")
check(
    logout.status_code == 200
    and len(auth_logout_rows) == logout_count + 1
    and auth_logout_rows[-1]["actor_id"] == auth_user_id
    and auth_logout_rows[-1]["actor_username"] == "AuthCase"
    and auth_logout_rows[-1]["detail"] is None,
    f"logout emits a best-effort actor snapshot (got {auth_logout_rows[-1]})",
)

security_user_id = make_user(
    "security_user",
    "Before123!",
    email="security-user@audit.test",
)
security_client, security_token = login("security_user", "Before123!")
changepwd_count = len(audit_rows("account.changepwd"))
changed_password = security_client.post(
    "/changepwd",
    headers=headers(security_token),
    json={
        "old_password": "Before123!",
        "new_password": "After123!",
        "repeat_password": "After123!",
    },
)
changepwd_rows = audit_rows("account.changepwd")
check(
    changed_password.status_code == 200
    and len(changepwd_rows) == changepwd_count + 1
    and changepwd_rows[-1]["actor_id"] == security_user_id
    and changepwd_rows[-1]["actor_username"] == "security_user"
    and changepwd_rows[-1]["detail"] is None,
    f"self password change records no secret values (got {changepwd_rows[-1]})",
)

# Stage 10.2: the password change revoked this session and its access JWT
# immediately, so the profile edit needs a fresh login with the new password.
security_client, security_token = login("security_user", "After123!")
profile_action_count = len(audit_rows("account.profile_edit"))
profile_update = security_client.put(
    "/profile",
    headers=headers(security_token),
    json={
        "first_name": "Security",
        "last_name": "User",
        "email": "security-user@audit.test",
        "company": "Updated",
        "department": "",
        "birth_date": "",
        "sex": "",
    },
)
check(
    profile_update.status_code == 200
    and len(audit_rows("account.profile_edit")) == profile_action_count,
    "ordinary self-service profile edits remain unaudited",
)

delete_self_id = make_user(
    "delete_self",
    "Delete123!",
    email="delete-self@audit.test",
)
delete_self_client, delete_self_token = login("delete_self", "Delete123!")
delete_count = len(audit_rows("account.delete"))
wrong_delete = delete_self_client.delete(
    "/account",
    headers=headers(delete_self_token),
    json={"confirm_username": "wrong"},
)
check(
    wrong_delete.status_code == 400
    and len(audit_rows("account.delete")) == delete_count,
    "failed self-delete writes no account.delete row",
)
deleted_self = delete_self_client.delete(
    "/account",
    headers=headers(delete_self_token),
    json={"confirm_username": "DELETE_SELF"},
)
account_delete = audit_rows("account.delete")
conn = backend.get_db()
deleted_self_exists = conn.execute(
    "SELECT 1 FROM users WHERE user_id = ?",
    (delete_self_id,),
).fetchone()
conn.close()
check(
    deleted_self.status_code == 200
    and deleted_self_exists is None
    and len(account_delete) == delete_count + 1
    and account_delete[-1]["actor_id"] == delete_self_id
    and account_delete[-1]["actor_username"] == "delete_self"
    and account_delete[-1]["detail"] is None,
    f"self-delete row survives deletion of its actor account (got {account_delete[-1]})",
)


print("\n== Super-only audit read endpoint ==")
reader_admin_id = make_user(
    "audit_reader_admin",
    "Reader123!",
    role="admin",
    email="audit-reader@audit.test",
)
reader_admin, reader_admin_token = login("audit_reader_admin", "Reader123!")
regular_read = reader_admin.get(
    "/admin/audit",
    headers=headers(reader_admin_token),
)
check(regular_read.status_code == 403, "regular admin cannot read the cross-scope audit log")

with app.test_request_context("/_test/audit"):
    backend.g.user_id = boss_id
    backend.g.username = "audit_boss"
    backend.g.role = "super_admin"
    backend.g.client_ip = "127.0.0.1"
    backend.audit("test.endpoint_detail", probe=True)

endpoint_page = boss.get(
    "/admin/audit?limit=5",
    headers=headers(boss_token),
)
endpoint_payload = endpoint_page.get_json()
endpoint_ids = [entry["id"] for entry in endpoint_payload["entries"]]
check(
    endpoint_page.status_code == 200
    and endpoint_ids == sorted(endpoint_ids, reverse=True)
    and endpoint_payload["entries"][0]["action"] == "test.endpoint_detail"
    and endpoint_payload["entries"][0]["detail"] == {"probe": True},
    f"endpoint returns newest-first rows with detail as JSON (got {endpoint_payload['entries'][0]})",
)

malformed_results = [
    boss.get("/admin/audit?limit=foo", headers=headers(boss_token)),
    boss.get("/admin/audit?limit=-5", headers=headers(boss_token)),
    boss.get("/admin/audit?before=foo", headers=headers(boss_token)),
    boss.get("/admin/audit?before=-1", headers=headers(boss_token)),
]
check(
    all(response.status_code == 400 for response in malformed_results),
    f"malformed or negative pagination values return 400 (got {[r.status_code for r in malformed_results]})",
)
clamped_low = boss.get(
    "/admin/audit?limit=0",
    headers=headers(boss_token),
)
check(
    clamped_low.status_code == 200
    and len(clamped_low.get_json()["entries"]) == 1,
    "limit=0 is clamped to the minimum page size of 1",
)

print("\n== Audit endpoint filters combine across the complete record ==")
conn = backend.get_db()
filter_rows = [
    (
        "2030-01-10T12:00:00Z",
        "filter-actor-one",
        "user.disable",
        "user",
        "filter-target-one",
        json.dumps({"note": "Needle%_Literal"}),
        "203.0.113.31",
    ),
    (
        "2030-01-11T12:00:00Z",
        "filter-actor-two",
        "user.disable",
        "user",
        "filter-target-two",
        json.dumps({"note": "ordinary value"}),
        "203.0.113.32",
    ),
    (
        "2030-01-12T12:00:00Z",
        "filter-actor-three",
        "user.enable",
        "user",
        "filter-target-three",
        json.dumps({"note": "Needle%_Literal"}),
        "203.0.113.33",
    ),
]
conn.executemany(
    "INSERT INTO audit_log "
    "(ts, actor_username, action, target_type, target_label, detail, client_ip) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)",
    filter_rows,
)
conn.commit()
filter_ids = [
    row[0]
    for row in conn.execute(
        "SELECT id FROM audit_log WHERE actor_username LIKE 'filter-actor-%' ORDER BY id"
    ).fetchall()
]
conn.close()

combined_filter = boss.get(
    "/admin/audit",
    query_string={
        "event": "user.disable",
        "begin": "2030-01-10T00:00:00.000Z",
        "end": "2030-01-12T00:00:00.000Z",
        "search": "Needle%_Literal",
    },
    headers=headers(boss_token),
)
combined_entries = combined_filter.get_json()["entries"]
check(
    combined_filter.status_code == 200
    and [entry["id"] for entry in combined_entries] == [filter_ids[0]],
    "event, inclusive begin/exclusive end, and literal detail search combine",
)

record_search = boss.get(
    "/admin/audit",
    query_string={"search": "filter-target-two"},
    headers=headers(boss_token),
).get_json()["entries"]
check(
    [entry["id"] for entry in record_search] == [filter_ids[1]],
    "search covers labeled record metadata as well as detail JSON",
)

alias_entries = boss.get(
    "/admin/audit",
    query_string={"event": "map_collab.direct.grant"},
    headers=headers(boss_token),
).get_json()["entries"]
check(
    alias_entries
    and all(entry["action"] == "map_share.direct.grant" for entry in alias_entries),
    "collab-aliased event filter matches the stored share-spelled actions",
)

filtered_first = boss.get(
    "/admin/audit",
    query_string={"limit": 1, "event": "user.disable"},
    headers=headers(boss_token),
).get_json()
filtered_second = boss.get(
    "/admin/audit",
    query_string={
        "limit": 1,
        "event": "user.disable",
        "before": filtered_first["next_before"],
    },
    headers=headers(boss_token),
).get_json()
check(
    filtered_first["next_before"] is not None
    and filtered_first["entries"][0]["action"] == "user.disable"
    and filtered_second["entries"][0]["action"] == "user.disable"
    and filtered_first["entries"][0]["id"] > filtered_second["entries"][0]["id"],
    "keyset pagination stays inside the active event filter",
)

invalid_filters = [
    boss.get("/admin/audit?begin=not-a-date", headers=headers(boss_token)),
    boss.get("/admin/audit?begin=2030-01-12T00:00:00Z&end=2030-01-10T00:00:00Z",
             headers=headers(boss_token)),
    boss.get("/admin/audit", query_string={"search": "x" * 201},
             headers=headers(boss_token)),
    boss.get("/admin/audit", query_string={"event": "x" * 101},
             headers=headers(boss_token)),
]
check(
    all(response.status_code == 400 for response in invalid_filters),
    f"malformed, reversed, and oversized filters return 400 "
    f"(got {[response.status_code for response in invalid_filters]})",
)

first_page = boss.get(
    "/admin/audit?limit=10",
    headers=headers(boss_token),
).get_json()
first_ids = [entry["id"] for entry in first_page["entries"]]
cursor = first_page["next_before"]
with app.test_request_context("/_test/audit"):
    backend.g.user_id = boss_id
    backend.g.username = "audit_boss"
    backend.g.role = "super_admin"
    backend.g.client_ip = "127.0.0.1"
    backend.audit("test.concurrent_insert")
concurrent_id = audit_rows("test.concurrent_insert")[-1]["id"]
second_page = boss.get(
    f"/admin/audit?limit=10&before={cursor}",
    headers=headers(boss_token),
).get_json()
second_ids = [entry["id"] for entry in second_page["entries"]]
check(
    cursor is not None
    and concurrent_id > cursor
    and all(entry_id < cursor for entry_id in second_ids)
    and not set(first_ids).intersection(second_ids)
    and concurrent_id not in second_ids,
    "id<before keyset pagination stays stable across concurrent inserts",
)

conn = backend.get_db()
conn.executemany(
    "INSERT INTO audit_log (ts, action) VALUES (?, ?)",
    [("2026-07-16T00:00:00Z", "test.bulk") for _ in range(520)],
)
conn.commit()
conn.close()
capped = boss.get(
    "/admin/audit?limit=99999",
    headers=headers(boss_token),
)
capped_payload = capped.get_json()
capped_ids = [entry["id"] for entry in capped_payload["entries"]]
check(
    capped.status_code == 200
    and len(capped_ids) == 500
    and capped_ids == sorted(capped_ids, reverse=True)
    and capped_payload["next_before"] == capped_ids[-1],
    "oversized limit is capped at 500 with a valid next cursor",
)


print("\n== Endpoint deserializes a detail-less row to null on the wire ==")
# The object-case (detail present) is covered above; pin the null-case through the
# live GET /admin/audit response, not just via the audit_rows() DB helper. A
# user.approve event carries no detail, so the endpoint must emit detail: null.
null_detail_pending_id = make_user(
    "null_detail_pending",
    "Pending1!",
    status="pending",
    email="null-detail@audit.test",
)
boss.post(
    f"/admin/users/{null_detail_pending_id}/approve",
    headers=headers(boss_token),
)
null_detail_page = boss.get(
    "/admin/audit?limit=500",
    headers=headers(boss_token),
).get_json()
null_detail_entry = next(
    entry
    for entry in null_detail_page["entries"]
    if entry["action"] == "user.approve"
    and entry["target_label"] == "null_detail_pending"
)
check(
    "detail" in null_detail_entry and null_detail_entry["detail"] is None,
    f"endpoint serializes a detail-less row as JSON null (got {null_detail_entry!r})",
)


print("\n== Audit read endpoint rejects an unauthenticated caller ==")
# The 403 (regular admin) path is covered above; this pins the auth gate itself —
# a tokenless caller must be stopped at require_auth (401), never reaching the route.
anon_read = app.test_client().get("/admin/audit")
check(
    anon_read.status_code == 401,
    f"no-token GET /admin/audit -> 401 at the auth gate (got {anon_read.status_code})",
)


print("\n== Attempted-username truncation at the exact 128-char boundary ==")
# The 160 -> 128 case above proves truncation happens well past the edge; pin the
# boundary itself: 128 is kept whole, 129 is trimmed to 128.
boundary_cases = {}
for length in (128, 129):
    marker = "q" + "b" * (length - 1)  # unique per length, all bad-charset
    app.test_client().post(
        "/login",
        json={"username": marker, "password": "Wrong123!"},
    )
    conn = backend.get_db()
    stored = conn.execute(
        "SELECT actor_username FROM audit_log "
        "WHERE action = 'auth.login_failed' AND actor_username LIKE 'q%' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    boundary_cases[length] = stored[0] if stored else None
check(
    boundary_cases[128] is not None and len(boundary_cases[128]) == 128,
    f"an exactly-128-char attempt is stored whole (got len {len(boundary_cases[128] or '')})",
)
check(
    boundary_cases[129] is not None and len(boundary_cases[129]) == 128,
    f"a 129-char attempt is truncated to 128 (got len {len(boundary_cases[129] or '')})",
)


print("\n== Case-only admin rename is a real, logged username diff ==")
# documentation/username-validation.md item "Audited admin profile edits": a case-only rename
# ("Bob" -> "bob") is a real string change under COLLATE NOCASE uniqueness, so it
# must produce a user.profile_edit row whose ONLY changed field is the username,
# with an old/new that differ solely by case. Isolated from the bundled-field case
# above so the username diff is proven on its own.
case_rename_id = make_user(
    "Caseflip",
    "Caseflip1!",
    email="caseflip@audit.test",
)
case_rename_before = len(audit_rows("user.profile_edit"))
case_rename_resp = boss.put(
    f"/admin/users/{case_rename_id}/profile",
    headers=headers(boss_token),
    json={
        "username": "caseflip",
        "first_name": "First",
        "last_name": "Last",
        "email": "caseflip@audit.test",
        "company": "",
        "department": "",
        "birth_date": "",
        "sex": "",
    },
)
case_rename_rows = audit_rows("user.profile_edit")
conn = backend.get_db()
stored_case = conn.execute(
    "SELECT username FROM users WHERE user_id = ?",
    (case_rename_id,),
).fetchone()[0]
conn.close()
check(
    case_rename_resp.status_code == 200
    and stored_case == "caseflip"
    and len(case_rename_rows) == case_rename_before + 1
    and case_rename_rows[-1]["target_label"] == "caseflip"
    and case_rename_rows[-1]["detail"]
    == {"username": {"old": "Caseflip", "new": "caseflip"}},
    f"case-only rename logs exactly the username diff (got {case_rename_rows[-1]})",
)


print("\n== Editing a CLI-created user (NULL optionals) is not a spurious change ==")
# create_users.py inserts only first/last/email, so company/department/birth_date/sex are
# stored as NULL for every CLI-created account (incl. the bootstrap super-admin). The
# validated new values are blank strings (''), and NULL vs '' both mean "unset" — so an
# edit that leaves them unset must NOT register as a change. Regression guard: without the
# NULL->'' normalization, the first edit of any CLI user emitted a spurious
# {"company":{"old":null,"new":""}, ...} diff (and a needless UPDATE).
cli_user_id = str(uuid.uuid4())
conn = backend.get_db()
conn.execute(
    "INSERT INTO users (user_id, username, password_hash, role, status, created, "
    "first_name, last_name, email) "
    "VALUES (?,?,?,?,?,?,?,?,?)",
    (
        cli_user_id,
        "cli_style",
        bcrypt.hashpw(b"CliStyle1!", bcrypt.gensalt()),
        "user",
        "approved",
        datetime.now().isoformat(),
        "Cli",
        "Style",
        "cli-style@audit.test",
    ),
)
conn.commit()
null_optionals = conn.execute(
    "SELECT company, department, birth_date, sex FROM users WHERE user_id = ?",
    (cli_user_id,),
).fetchone()
conn.close()
cli_edit_before = len(audit_rows("user.profile_edit"))
cli_noop = boss.put(
    f"/admin/users/{cli_user_id}/profile",
    headers=headers(boss_token),
    json={
        "username": "cli_style",
        "first_name": "Cli",
        "last_name": "Style",
        "email": "cli-style@audit.test",
        "company": "",
        "department": "",
        "birth_date": "",
        "sex": "",
    },
)
check(
    all(value is None for value in null_optionals)
    and cli_noop.status_code == 200
    and len(audit_rows("user.profile_edit")) == cli_edit_before,
    "editing a CLI user's NULL optionals with blanks writes no spurious audit row",
)
# A genuine set of a previously-NULL field records a clean old:'' (not null), only that field.
cli_real = boss.put(
    f"/admin/users/{cli_user_id}/profile",
    headers=headers(boss_token),
    json={
        "username": "cli_style",
        "first_name": "Cli",
        "last_name": "Style",
        "email": "cli-style@audit.test",
        "company": "Acme",
        "department": "",
        "birth_date": "",
        "sex": "",
    },
)
cli_real_rows = audit_rows("user.profile_edit")
check(
    cli_real.status_code == 200
    and len(cli_real_rows) == cli_edit_before + 1
    and cli_real_rows[-1]["detail"] == {"company": {"old": "", "new": "Acme"}},
    f"setting a previously-NULL field records old '' and only that field (got {cli_real_rows[-1]})",
)


print("\n== Avatar routes stay outside the audit event boundary ==")
# documentation/audit-logging-plan.md 3c and avatar-upload-plan.md both settle that POST/DELETE
# /profile/avatar emit no audit rows. test_avatar.py proves this around the image
# pipeline; assert it here too, in the audit suite that owns the taxonomy, using the
# Pillow-free DELETE path so no image machinery is duplicated.
avatar_user_id = make_user(
    "avatar_noaudit",
    "Avatar123!",
    email="avatar-noaudit@audit.test",
)
avatar_client, avatar_token = login("avatar_noaudit", "Avatar123!")
conn = backend.get_db()
audit_total_before_avatar = conn.execute(
    "SELECT COUNT(*) FROM audit_log"
).fetchone()[0]
conn.close()
avatar_delete = avatar_client.delete(
    "/profile/avatar",
    headers=headers(avatar_token),
)
conn = backend.get_db()
audit_total_after_avatar = conn.execute(
    "SELECT COUNT(*) FROM audit_log"
).fetchone()[0]
conn.close()
check(
    avatar_delete.status_code == 200
    and audit_total_after_avatar == audit_total_before_avatar,
    f"avatar removal writes no audit row (before {audit_total_before_avatar}, "
    f"after {audit_total_after_avatar})",
)


print(f"\nRESULT: {PASS} passed, {FAIL} failed")
shutil.rmtree(WORK)
sys.exit(1 if FAIL else 0)
