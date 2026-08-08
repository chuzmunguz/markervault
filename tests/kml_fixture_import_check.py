"""Import kml_empty_name_fixture.kml through the real backend and check the result.

    tests/venv/bin/python tests/kml_fixture_import_check.py

The fixture exists to confirm the F3 fix on a real host by hand (see tests/README.md).
This makes the same check scriptable against a throwaway database, so the expected
outcome is executable rather than a prose description someone has to eyeball.

Every assertion below corresponds to one empty element in the fixture:
  <Placemark><name></name>  -> the marker's own "Unnamed" fallback
  <Document><name></name>   -> listing "General"      (empty used to store NULL)
  <Folder><name></name>     -> subset  "Main"         (empty used to store NULL)
  <value></value>           -> empty notes            (used to store "Local: None")

Before the F3 commits this fixture imported 0 of 4 — one empty <name> reached
spots.name (NOT NULL) and failed the whole job, taking three valid placemarks with it.

Exit 0 when every expectation holds, 1 otherwise.
"""
import importlib.util
import io
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid

import bcrypt


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests/kml_empty_name_fixture.kml")

# name -> (listing, subset, notes)
EXPECTED = {
    "Unnamed": ("General", "Main", ""),
    "Marco Valido": ("General", "Main", ""),
    "Sem Local": ("General", "Zona Sul", ""),
    "Com Local": ("General", "Zona Sul", "Local: Alfama"),
}

WORK = tempfile.mkdtemp(prefix="mv_kml_fixture_")
for module in ("backend.py", "markervault_schema.py", "request_validation.py",
               "markervault_config.py", "username_validation.py", "email_delivery.py"):
    shutil.copy(os.path.join(ROOT, module), os.path.join(WORK, module))
os.chdir(WORK)
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


user_id = str(uuid.uuid4())
conn = backend.get_db()
conn.execute(
    "INSERT INTO users (user_id, username, password_hash, role, status, created, "
    "first_name, last_name, email) VALUES (?, ?, ?, 'user', 'approved', ?, 'K', 'F', ?)",
    (user_id, "fixture", bcrypt.hashpw(b"Abcd1234!", bcrypt.gensalt()),
     "2026-07-26T00:00:00", "fixture@example.test"),
)
conn.commit()
conn.close()
backend.create_base_map(user_id)

client = app.test_client()
client.post("/login", json={"username": "fixture", "password": "Abcd1234!"})
headers = {
    "Authorization": f"Bearer {client.post('/auth/refresh').get_json()['access_token']}"
}
map_id = client.post("/maps", headers=headers, json={"name": "Fixture"}).get_json()["id"]

response = client.post(
    "/import_kml",
    headers=headers,
    data={
        "kml_file": (io.BytesIO(open(FIXTURE, "rb").read()), "kml_empty_name_fixture.kml"),
        "map_id": str(map_id),
    },
    content_type="multipart/form-data",
)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""

status = None
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    status = client.get(f"/import_kml_status/{job_id}", headers=headers).get_json()
    if status and status["status"] in ("done", "error"):
        break
    time.sleep(0.05)

check(
    status is not None and status["status"] == "done",
    f"the import finishes as done, not error ({status and status['status']})",
)
check(
    status and (status["imported"], status["total"], status["skipped"]) == (4, 4, 0),
    f"all four placemarks import with nothing skipped "
    f"({status and status['imported']}/{status and status['total']}, "
    f"skipped {status and status['skipped']})",
)

conn = sqlite3.connect(backend.DB_FILE)
rows = {
    row[0]: (row[1], row[2], row[3])
    for row in conn.execute(
        "SELECT name, listing, subset, notes FROM spots WHERE map_id=?", (map_id,)
    )
}
conn.close()

check(
    set(rows) == set(EXPECTED),
    f"the four expected marker names are stored ({sorted(rows)})",
)
for name, expected in EXPECTED.items():
    check(rows.get(name) == expected, f"{name}: listing/subset/notes {expected} (got {rows.get(name)})")
check(
    all(listing is not None and subset is not None for listing, subset, _ in rows.values()),
    "no row stores NULL listing or subset",
)

shutil.rmtree(WORK, ignore_errors=True)
print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
