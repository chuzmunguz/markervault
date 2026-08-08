"""Stage 8 home suite: canonical schema equivalence (D-10), composite relationship
keys (R-06), shared typed field limits and the bcrypt byte boundary (S-13/D-09)."""
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid

import bcrypt


WORK = tempfile.mkdtemp(prefix="mv_limits_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy(
    "/workspace/markervault/markervault_config.py",
    os.path.join(WORK, "markervault_config.py"),
)
shutil.copy(
    "/workspace/markervault/username_validation.py",
    os.path.join(WORK, "username_validation.py"),
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
backend.rate_limit = lambda *a, **k: None
app = backend.app
app.testing = True

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


def make_user(username, password, role="user"):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, first_name, last_name, email) "
        "VALUES (?, ?, ?, ?, 'approved', ?, 'Field', 'Limits', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            role,
            "2026-07-19T00:00:00",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def login(username, password):
    client = app.test_client()
    client.post("/login", json={"username": username, "password": password})
    token = client.post("/auth/refresh").get_json()["access_token"]
    return client, {"Authorization": f"Bearer {token}"}


print("== Canonical schema (D-10) ==")


def schema_rows(db_path):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT type, name, COALESCE(sql, '') FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    conn.close()
    return rows


cli_db = os.path.join(WORK, "cli", "spots.db")
cli_env = os.environ.copy()
cli_env["MARKERVAULT_DB_PATH"] = cli_db
cli_run = subprocess.run(
    [
        sys.executable, "/workspace/markervault/create_users.py",
        "--username", "cliboss", "--password", "Abcd1234!", "--role", "super_admin",
        "--first-name", "Cli", "--last-name", "Boss", "--email", "cliboss@example.test",
    ],
    cwd=WORK,
    env=cli_env,
    text=True,
    capture_output=True,
)
check(cli_run.returncode == 0, "CLI provisions a fresh database via the shared initializer")
check(
    schema_rows(cli_db) == schema_rows(backend.DB_FILE),
    "CLI-created and backend-created schemas are identical",
)

conn = sqlite3.connect(backend.DB_FILE)
for table, key_columns in (
    ("map_shares", ["map_id", "user_id"]),
    ("share_group_members", ["group_id", "user_id"]),
    ("map_group_shares", ["map_id", "group_id"]),
    ("mgmt_group_members", ["group_id", "user_id"]),
):
    info = conn.execute(f"PRAGMA table_info({table})").fetchall()
    columns = [row[1] for row in info]
    primary = [row[1] for row in sorted(info, key=lambda r: r[5]) if row[5] > 0]
    check(
        "id" not in columns and primary == key_columns,
        f"{table} has no surrogate id and uses PRIMARY KEY ({', '.join(key_columns)})",
    )
conn.close()

print("\n== Password policy and bcrypt byte boundary (S-13/D-09) ==")
vectors = json.load(open("/workspace/markervault/tests/password_contract_vectors.json"))
mismatched = [
    v["password"] for v in vectors
    if backend.validate_password_policy(v["password"])[0] is not v["valid"]
]
check(not mismatched, f"all {len(vectors)} shared contract vectors match the backend policy")

owner_id = make_user("owner", "Abcd1234!")
owner, oh = login("owner", "Abcd1234!")
super_id = make_user("boss", "Abcd1234!", role="super_admin")
sclient, sh = login("boss", "Abcd1234!")

over_limit = "Aa1!" + "x" * 80
r = app.test_client().post("/login", json={"username": "owner", "password": over_limit})
check(
    r.status_code == 401 and "Invalid username" in r.get_json()["error"],
    "an over-72-byte login password fails as ordinary bad credentials, not a 500",
)
boundary = "Aa1!" + "é" * 34
r = app.test_client().post("/register", json={
    "username": "boundary", "password": boundary,
    "first_name": "B", "last_name": "B", "email": "boundary@example.test",
})
check(r.status_code == 200, "a 72-byte Unicode password registers successfully")
r = app.test_client().post("/register", json={
    "username": "toolong", "password": "Aa1!" + "é" * 35,
    "first_name": "B", "last_name": "B", "email": "toolong@example.test",
})
check(
    r.status_code == 400 and "72 bytes" in r.get_json()["error"],
    "a 74-byte password is rejected with the byte-limit message",
)
r = owner.post("/changepwd", headers=oh, json={
    "old_password": {"a": 1}, "new_password": "Abcd1234!", "repeat_password": "Abcd1234!",
})
check(r.status_code == 400, "non-string change-password fields return 400")
r = owner.post("/changepwd", headers=oh, json={
    "old_password": over_limit, "new_password": "NewAbcd1234!", "repeat_password": "NewAbcd1234!",
})
check(
    r.status_code == 400 and r.get_json()["error"] == "Old password is incorrect",
    "an over-limit old password is an ordinary mismatch",
)

print("\n== Profile typed validation ==")
r = owner.put("/profile", headers=oh, json={
    "first_name": ["not", "text"], "last_name": "L", "email": "owner@example.test",
})
check(r.status_code == 400, "a non-string profile field returns 400 instead of crashing")
r = owner.put("/profile", headers=oh, json={
    "first_name": "F" * 101, "last_name": "L", "email": "owner@example.test",
})
check(r.status_code == 400 and "too long" in r.get_json()["error"], "over-limit profile fields return 400")

print("\n== Map field limits ==")
r = owner.post("/maps", headers=oh, json={"name": {"x": 1}})
check(r.status_code == 400, "a non-string map name returns 400")
r = owner.post("/maps", headers=oh, json={"name": "M" * 101})
check(r.status_code == 400, "an over-limit map name returns 400")
map_name = "M" * 49 + "  " + "M" * 49
map_notes = "n" * 10000
r = owner.post("/maps", headers=oh, json={
    "name": f"  {map_name}\t", "notes": f"\n{map_notes}  ", "description": "d" * 2000,
})
check(r.status_code == 200, "maximum ordinary map payload is accepted")
map_id = r.get_json()["id"]
stored_map = next(row for row in owner.get("/maps", headers=oh).get_json() if row["id"] == map_id)
check(
    stored_map["name"] == map_name and stored_map["notes"] == map_notes,
    "map creation stores stripped limit values without changing interior whitespace",
)
r = owner.post("/maps", headers=oh, json={"name": "N", "notes": "n" * 10001})
check(r.status_code == 400, "over-limit map notes return 400")
r = owner.put(f"/maps/{map_id}", headers=oh, json={"description": 7})
check(r.status_code == 400, "a non-string map description returns 400 on edit")
edited_map_notes = "e" * 4999 + "  " + "e" * 4999
r = owner.put(f"/maps/{map_id}", headers=oh, json={"notes": f"  {edited_map_notes}\n"})
stored_map = next(row for row in owner.get("/maps", headers=oh).get_json() if row["id"] == map_id)
check(
    r.status_code == 200 and stored_map["notes"] == edited_map_notes,
    "map editing stores stripped limit values without changing interior whitespace",
)

print("\n== Spot field limits ==")
spot_name = "S" * 99 + "  " + "S" * 99
spot_notes = "s" * 10000
r = owner.post("/spots", headers=oh, json={
    "mapID": map_id, "name": f" {spot_name}\n", "lat": 1, "lng": 2,
    "notes": f"\t{spot_notes} ",
})
check(r.status_code == 200, "maximum ordinary marker payload is accepted")
spot_id = r.get_json()["id"]
stored_spot = owner.get(f"/spots/{spot_id}", headers=oh).get_json()
check(
    stored_spot["name"] == spot_name and stored_spot["notes"] == spot_notes,
    "marker creation stores stripped limit values without changing interior whitespace",
)
r = owner.post("/spots", headers=oh, json={"mapID": map_id, "name": "S" * 201, "lat": 1, "lng": 2})
check(r.status_code == 400, "an over-limit marker name returns 400")
r = owner.post("/spots", headers=oh, json={"mapID": map_id, "name": "S", "lat": 1, "lng": 2, "listing": {"x": 1}})
check(r.status_code == 400, "a non-string listing returns 400 instead of storing coerced junk")
r = owner.post("/spots", headers=oh, json={"mapID": True, "name": "S", "lat": 1, "lng": 2})
check(r.status_code == 400, "a boolean mapID is rejected")
r = owner.post("/spots", headers=oh, json={"mapID": str(map_id), "name": "S", "lat": 1, "lng": 2})
check(r.status_code == 400, "a string mapID is rejected")
r = owner.put(f"/spots/{spot_id}", headers=oh, json={"notes": ["x"]})
check(r.status_code == 400, "a non-string marker notes value returns 400 on update")
edited_spot_notes = "u" * 4999 + "  " + "u" * 4999
r = owner.put(f"/spots/{spot_id}", headers=oh, json={"notes": f"\n{edited_spot_notes}\t"})
stored_spot = owner.get(f"/spots/{spot_id}", headers=oh).get_json()
check(
    r.status_code == 200 and stored_spot["notes"] == edited_spot_notes,
    "marker editing stores stripped limit values without changing interior whitespace",
)

print("\n== POST/PUT parity for required names (F5) ==")
# text_value returns None for an absent field and '' for an empty one, and the PUT
# handlers tested only `is not None` — so an explicit empty string was written through
# to a NOT NULL column that POST rejects with 400. Absent still means unchanged.
for label, request_json, expected in (
    ("empty marker name on create", {"mapID": map_id, "name": "", "lat": 1, "lng": 2}, 400),
    ("whitespace marker name on create", {"mapID": map_id, "name": "   ", "lat": 1, "lng": 2}, 400),
):
    check(
        owner.post("/spots", headers=oh, json=request_json).status_code == expected,
        f"POST rejects an {label}",
    )
# The null cases carry a second field on purpose: a lone {"name": None} would be
# rejected by the unrelated "No fields to update" path and prove nothing here.
for label, request_json in (
    ("empty", {"name": ""}),
    ("whitespace-only", {"name": "   "}),
    ("null alongside another field", {"name": None, "notes": "n"}),
):
    r = owner.put(f"/spots/{spot_id}", headers=oh, json=request_json)
    check(r.status_code == 400, f"PUT rejects a {label} marker name, matching POST")
r = owner.post("/maps", headers=oh, json={"name": ""})
check(r.status_code == 400, "POST rejects an empty map name")
for label, request_json in (
    ("empty", {"name": ""}),
    ("whitespace-only", {"name": "   "}),
    ("null alongside another field", {"name": None, "description": "d"}),
):
    r = owner.put(f"/maps/{map_id}", headers=oh, json=request_json)
    check(r.status_code == 400, f"PUT rejects a {label} map name, matching POST")

# The absent-means-unchanged contract must survive the change.
surviving_spot = owner.get(f"/spots/{spot_id}", headers=oh).get_json()
r = owner.put(f"/spots/{spot_id}", headers=oh, json={"notes": "untouched name"})
check(
    r.status_code == 200
    and owner.get(f"/spots/{spot_id}", headers=oh).get_json()["name"] == surviving_spot["name"],
    "a PUT omitting the name still leaves it unchanged",
)
surviving_map = next(row for row in owner.get("/maps", headers=oh).get_json() if row["id"] == map_id)
r = owner.put(f"/maps/{map_id}", headers=oh, json={"description": "no name key"})
check(
    r.status_code == 200
    and next(row for row in owner.get("/maps", headers=oh).get_json()
             if row["id"] == map_id)["name"] == surviving_map["name"],
    "a map PUT omitting the name still leaves it unchanged",
)

print("\n== Bulk share list limits ==")
r = owner.put("/maps/collaborators", headers=oh, json={"map_ids": [True], "username": "boss", "role": "viewer"})
check(r.status_code == 400, "booleans are rejected where integer map ids are expected")
r = owner.put("/maps/collaborators", headers=oh, json={"map_ids": list(range(501)), "username": "boss", "role": "viewer"})
check(r.status_code == 400 and "too many" in r.get_json()["error"], "over-limit bulk map_ids lists return 400")
r = owner.put("/maps/collaborators", headers=oh, json={"map_ids": [map_id], "username": 42, "role": "viewer"})
check(r.status_code == 400, "a non-string bulk share username returns 400")
r = owner.put("/maps/collaborators", headers=oh, json={"map_ids": [map_id], "username": "boss", "role": "viewer"})
check(r.status_code == 200, "an ordinary bulk share still succeeds")

print("\n== Composite-key upsert behavior (R-06) ==")
r = owner.put("/maps/collaborators", headers=oh, json={"map_ids": [map_id], "username": "boss", "role": "editor"})
check(r.status_code == 200, "re-sharing the same map upserts on the composite key")
conn = backend.get_db()
rows = conn.execute(
    "SELECT role FROM map_shares WHERE map_id = ? AND user_id = ?",
    (map_id, super_id),
).fetchall()
conn.close()
check(rows == [("editor",)], "the composite primary key keeps exactly one row with the updated role")

print("\n== Caption and group name limits ==")
r = owner.put(f"/spots/{spot_id}/photos/none.jpg/caption", headers=oh, json={"caption": {"x": 1}})
check(r.status_code == 400, "a non-string caption returns 400 before the photo lookup")
r = owner.put(f"/spots/{spot_id}/photos/none.jpg/caption", headers=oh, json={"caption": "c" * 501})
check(r.status_code == 400, "an over-limit caption returns 400")
r = sclient.post("/admin/groups", headers=sh, json={"name": {"x": 1}})
check(r.status_code == 400, "a non-string group name returns 400")
r = sclient.post("/admin/groups", headers=sh, json={"name": "G" * 101})
check(r.status_code == 400, "an over-limit group name returns 400")
r = sclient.post("/admin/groups", headers=sh, json={"name": "G" * 100})
check(r.status_code == 200, "a maximum-length group name is accepted")
group_id = r.get_json()["id"]
r = sclient.put(f"/admin/groups/{group_id}/members", headers=sh, json={"username": ["x"]})
check(r.status_code == 400, "a non-string member username returns 400")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
