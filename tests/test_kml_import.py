"""Stage 11 home suite. 11.1: KML job isolation and correctness — exclusive per-job
temporary files under concurrent identical filenames (S-08), owner-authorized job
progress (R-03), imported-coordinate validation with compact skip/error counts
(R-04), per-job cleanup, and the D-02/D-03 schema groundwork. 11.2: bounded
executor with per-user/global admission, KML and photo budgets, compact progress,
read-triggered retention with a boot sweep (S-09), redacted structured logging at
the KML call sites (S-14), and the vetted-IP pinned HTTPS transport (S-15)."""
import http.server
import importlib.util
import io
import json
import logging
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import bcrypt
import requests

from PIL import Image


WORK = tempfile.mkdtemp(prefix="mv_kml_")
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
# The S-15 transport checks talk to local TLS/plain servers; a sandbox proxy
# environment would intercept them.
for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
    os.environ.pop(variable, None)

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


def make_user(username, password):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, first_name, last_name, email) "
        "VALUES (?, ?, ?, 'user', 'approved', ?, 'Kml', 'Import', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            "2026-07-20T00:00:00",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def auth_client(username, password):
    client = app.test_client()
    client.post("/login", json={"username": username, "password": password})
    token = client.post("/auth/refresh").get_json()["access_token"]
    return client, {"Authorization": f"Bearer {token}"}


def placemark(name, coords=None, description=None):
    point = f"<Point><coordinates>{coords}</coordinates></Point>" if coords is not None else ""
    desc = f"<description><![CDATA[{description}]]></description>" if description else ""
    return f"<Placemark><name>{name}</name>{desc}{point}</Placemark>"


def kml_doc(placemarks, folders_prefix="", folders_suffix=""):
    body = folders_prefix + "".join(placemarks) + folders_suffix
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<kml xmlns="http://www.opengis.net/kml/2.2">'
        f"<Document><name>Imported</name>{body}</Document></kml>"
    )


def start_import(client, headers, map_id, kml_text, filename="import.kml"):
    return client.post(
        "/import_kml",
        headers=headers,
        data={"kml_file": (io.BytesIO(kml_text.encode()), filename), "map_id": str(map_id)},
        content_type="multipart/form-data",
    )


def wait_finished(client, headers, job_id, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"/import_kml_status/{job_id}", headers=headers)
        status = response.get_json() if response.status_code == 200 else None
        if status and status["status"] in ("done", "error"):
            return status
        time.sleep(0.05)
    return None


def map_spot_names(map_id):
    conn = sqlite3.connect(backend.DB_FILE)
    rows = conn.execute("SELECT name, lat, lng FROM spots WHERE map_id=?", (map_id,)).fetchall()
    conn.close()
    return {row[0]: (row[1], row[2]) for row in rows}


def temp_kml_files():
    if not os.path.isdir(backend.TEMP_FOLDER):
        return []
    return os.listdir(backend.TEMP_FOLDER)


def job_row(job_id, columns):
    conn = sqlite3.connect(backend.DB_FILE)
    row = conn.execute(
        f"SELECT {columns} FROM import_progress WHERE job_id=?", (job_id,)
    ).fetchone()
    conn.close()
    return row


def notification_row(job_id):
    conn = sqlite3.connect(backend.DB_FILE)
    row = conn.execute(
        "SELECT event, target_type, target_id, target_label, message, detail, "
        "correlation_id FROM notif_history WHERE target_id=? ORDER BY id DESC LIMIT 1",
        (job_id,),
    ).fetchone()
    conn.close()
    return row


alice_id = make_user("alice", "Abcd1234!")
bob_id = make_user("bob", "Abcd1234!")
carol_id = make_user("carol", "Abcd1234!")
dave_id = make_user("dave", "Abcd1234!")
alice, ah = auth_client("alice", "Abcd1234!")
bob, bh = auth_client("bob", "Abcd1234!")
carol, ch = auth_client("carol", "Abcd1234!")
dave, dh = auth_client("dave", "Abcd1234!")

alice_map = alice.post("/maps", headers=ah, json={"name": "Alice KML"}).get_json()["id"]
bob_map = bob.post("/maps", headers=bh, json={"name": "Bob KML"}).get_json()["id"]
carol_map = carol.post("/maps", headers=ch, json={"name": "Carol KML"}).get_json()["id"]
dave_map = dave.post("/maps", headers=dh, json={"name": "Dave KML"}).get_json()["id"]

print("== Imported-coordinate validation and skip counts (R-04) ==")
matrix_kml = kml_doc([
    placemark("valid-1", "8.6,41.1,0"),
    placemark("boundary-max", "180,90"),
    placemark("boundary-min", "-180,-90"),
    placemark("lat-over", "0,90.0001"),
    placemark("lng-over", "180.5,0"),
    placemark("nan-coords", "nan,nan"),
    placemark("inf-coords", "inf,0"),
    placemark("malformed", "not,coords"),
    placemark("short", "1.0"),
    placemark("no-point"),
])
response = start_import(alice, ah, alice_map, matrix_kml)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""
status = wait_finished(alice, ah, job_id)
check(status is not None and status["status"] == "done", "the matrix import completes")
check(
    status and status["imported"] == 3 and status["total"] == 10,
    f"3 of 10 placemarks import ({status and status['imported']}/{status and status['total']})",
)
check(
    status and status["skipped"] == 7,
    f"invalid/point-less placemarks surface as a compact skip count ({status and status['skipped']})",
)
check(status and status["photos_failed"] == 0, "a photo-less import reports zero photo failures")
check(
    status and set(status) == {"imported", "total", "skipped", "photos_failed", "photos_budget_skipped", "progress", "status", "error"},
    "the status payload carries compact counts only — no marker snapshot (S-09)",
)
spots = map_spot_names(alice_map)
check(
    set(spots) == {"valid-1", "boundary-max", "boundary-min"},
    f"only in-range finite coordinates are stored ({sorted(spots)})",
)
check(
    all(backend._coord_ok(lat, 90) and backend._coord_ok(lng, 180) for lat, lng in spots.values()),
    "every stored coordinate passes the regular-API validator",
)
check(spots.get("valid-1") == (41.1, 8.6), "lat/lng keep KML lng,lat order")
retrieved = alice.get(f"/maps/{alice_map}/spots", headers=ah).get_json()
check(
    {spot["name"] for spot in retrieved} >= {"valid-1", "boundary-max", "boundary-min"},
    "finished markers arrive through normal map retrieval",
)
row = job_row(job_id, "owner_id, map_id, created, completed, last_updated")
check(
    row is not None and row[0] == alice_id and row[1] == alice_map,
    "the job row is bound to its uploader and target map",
)
check(
    row is not None and all(isinstance(row[index], str) and row[index] for index in (2, 3, 4)),
    "created/completed/last_updated are maintained as real timestamps (D-03)",
)
check(temp_kml_files() == [], "the job's temporary file is removed after completion")
row = notification_row(job_id)
check(
    row is not None
    and row[:4] == ("kml.import_done", "kml_job", job_id, "Alice KML")
    and json.loads(row[5]) == {
        "affected_spots": [],
        "affected_spots_omitted": 0,
        "exhausted_budgets": [],
        "imported": 3,
        "job_id": job_id,
        "map_id": alice_map,
        "photos_budget_skipped": 0,
        "photos_failed": 0,
        "skipped": 7,
        "total": 10,
    },
    "a clean terminal job writes one complete KML notification",
)

print("\n== Empty <name> elements import under the fallback (F3) ==")
# <name> is optional in KML and <name></name> is what Google Earth exports for an
# unnamed feature. It used to reach spots.name (NOT NULL) as None and abort the whole
# import, losing every valid placemark alongside it.
empty_name_map = alice.post("/maps", headers=ah, json={"name": "Alice Empty Names"}).get_json()["id"]
empty_name_kml = kml_doc([
    placemark("", "8.6,41.1"),
    placemark("named-after-empty", "8.7,41.2"),
])
response = start_import(alice, ah, empty_name_map, empty_name_kml)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""
status = wait_finished(alice, ah, job_id)
check(
    status is not None and status["status"] == "done",
    f"an empty-named placemark finishes the job as done, not error ({status and status['status']})",
)
check(
    status and status["imported"] == 2 and status["total"] == 2,
    f"the empty-named placemark and the valid one both import ({status and status['imported']}/2)",
)
check(
    status and status["skipped"] == 0,
    f"an empty name is not a skip — the skip count is unchanged ({status and status['skipped']})",
)
empty_spots = map_spot_names(empty_name_map)
check(
    set(empty_spots) == {"Unnamed", "named-after-empty"},
    f"the empty-named placemark stores the same fallback an absent <name> gets ({sorted(empty_spots)})",
)

# The silent half of the same defect: empty Document/Folder names stored NULL
# listing/subset, which flows into the frontend's grouping.
empty_group_map = alice.post("/maps", headers=ah, json={"name": "Alice Empty Groups"}).get_json()["id"]
empty_group_kml = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<kml xmlns="http://www.opengis.net/kml/2.2">'
    "<Document><name></name>"
    "<Folder><name></name>"
    f'{placemark("grouped", "8.8,41.3")}'
    "</Folder></Document></kml>"
)
response = start_import(alice, ah, empty_group_map, empty_group_kml)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""
status = wait_finished(alice, ah, job_id)
check(
    status is not None and status["status"] == "done" and status["imported"] == 1,
    "an empty Document/Folder name still imports its placemarks",
)
conn = sqlite3.connect(backend.DB_FILE)
group_rows = conn.execute(
    "SELECT name, listing, subset FROM spots WHERE map_id=?", (empty_group_map,)
).fetchall()
conn.close()
check(
    group_rows == [("grouped", "General", "Main")],
    f"empty Document/Folder names take their fallbacks instead of storing NULL ({group_rows})",
)
check(
    all(row[1] is not None and row[2] is not None for row in group_rows),
    "listing and subset are never NULL after an import",
)

# The marker-name fallback and the listing fallback are unrelated constants. They used
# to share the word "General", which made an unnamed marker look like it had inherited
# its listing; a named Document is what separates them.
named_doc_map = alice.post("/maps", headers=ah, json={"name": "Alice Named Doc"}).get_json()["id"]
named_doc_kml = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<kml xmlns="http://www.opengis.net/kml/2.2">'
    "<Document><name>Utilities</name>"
    f'{placemark("", "8.9,41.4")}'
    "</Document></kml>"
)
response = start_import(alice, ah, named_doc_map, named_doc_kml)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""
wait_finished(alice, ah, job_id)
conn = sqlite3.connect(backend.DB_FILE)
named_doc_rows = conn.execute(
    "SELECT name, listing FROM spots WHERE map_id=?", (named_doc_map,)
).fetchall()
conn.close()
check(
    named_doc_rows == [("Unnamed", "Utilities")],
    f"an unnamed marker keeps its own fallback and never adopts the listing "
    f"({named_doc_rows})",
)

# Same root cause in the ExtendedData 'Local' value, which is interpolated into the
# marker's notes: an empty <value/> used to store the literal text "Local: None".
def local_placemark(name, coords, local):
    value = "" if local is None else f"<value>{local}</value>"
    return (
        f"<Placemark><name>{name}</name>"
        f"<ExtendedData><Data name=\"Local\">{value}</Data></ExtendedData>"
        f"<Point><coordinates>{coords}</coordinates></Point></Placemark>"
    )


local_map = alice.post("/maps", headers=ah, json={"name": "Alice Local Notes"}).get_json()["id"]
local_kml = kml_doc([
    local_placemark("with-local", "8.6,41.1", "Ponte"),
    local_placemark("empty-local", "8.7,41.2", ""),
    local_placemark("no-local", "8.8,41.3", None),
])
response = start_import(alice, ah, local_map, local_kml)
job_id = response.get_json().get("job_id", "") if response.status_code == 200 else ""
status = wait_finished(alice, ah, job_id)
conn = sqlite3.connect(backend.DB_FILE)
local_notes = dict(conn.execute(
    "SELECT name, notes FROM spots WHERE map_id=?", (local_map,)
).fetchall())
conn.close()
check(
    status is not None and status["status"] == "done" and status["imported"] == 3,
    "markers carrying ExtendedData import cleanly",
)
check(
    local_notes.get("with-local") == "Local: Ponte",
    f"a real ExtendedData Local value still reaches the notes field ({local_notes.get('with-local')!r})",
)
check(
    local_notes.get("empty-local") == "" and local_notes.get("no-local") == "",
    f"an empty Local value leaves notes empty instead of storing 'Local: None' "
    f"({local_notes.get('empty-local')!r}/{local_notes.get('no-local')!r})",
)

print("\n== Exclusive per-job temporary files under concurrency (S-08) ==")
barrier = threading.Barrier(2)
results = {}


def concurrent_import(label, username, password, map_id, names):
    client, headers = auth_client(username, password)
    kml_text = kml_doc([placemark(name, "8.6,41.1") for name in names])
    barrier.wait()
    response = start_import(client, headers, map_id, kml_text, filename="same.kml")
    payload = response.get_json() if response.status_code == 200 else {}
    results[label] = wait_finished(client, headers, payload.get("job_id", ""))


alice_names = ["alice-1", "alice-2", "alice-3"]
bob_names = ["bob-1", "bob-2", "bob-3"]
threads = [
    threading.Thread(target=concurrent_import, args=("alice", "alice", "Abcd1234!", alice_map, alice_names)),
    threading.Thread(target=concurrent_import, args=("bob", "bob", "Abcd1234!", bob_map, bob_names)),
]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
check(
    all(results.get(label) and results[label]["status"] == "done" and results[label]["imported"] == 3
        for label in ("alice", "bob")),
    "both same-filename imports complete with their full placemark count",
)
check(
    set(alice_names) <= set(map_spot_names(alice_map)) and not set(bob_names) & set(map_spot_names(alice_map)),
    "alice's map holds only alice's markers",
)
check(
    set(map_spot_names(bob_map)) == set(bob_names),
    "bob's map holds only bob's markers",
)
check(temp_kml_files() == [], "no temporary files survive the concurrent jobs")

print("\n== Owner-authorized job progress (R-03) ==")
own_job = start_import(alice, ah, alice_map, kml_doc([placemark("own-1", "8.6,41.1")])).get_json()["job_id"]
wait_finished(alice, ah, own_job)
own_response = alice.get(f"/import_kml_status/{own_job}", headers=ah)
check(own_response.status_code == 200, "the uploader can read their own job")
cross = bob.get(f"/import_kml_status/{own_job}", headers=bh)
check(cross.status_code == 404, "another user's job read is a 404")
unknown = bob.get(f"/import_kml_status/{uuid.uuid4()}", headers=bh)
check(unknown.status_code == 404, "an unknown job is a 404")
check(
    cross.get_json() == unknown.get_json(),
    "cross-user and unknown-job responses are indistinguishable",
)
check(
    app.test_client().get(f"/import_kml_status/{own_job}").status_code == 401,
    "unauthenticated status reads stay 401",
)

conn = sqlite3.connect(backend.DB_FILE)
conn.execute(
    "INSERT INTO map_shares (map_id, user_id, role, created) VALUES (?, ?, 'editor', ?)",
    (alice_map, bob_id, "2026-07-20T00:00:00"),
)
conn.commit()
conn.close()
shared_response = start_import(bob, bh, alice_map, kml_doc([placemark("bob-shared", "8.6,41.1")]))
shared_job = shared_response.get_json()["job_id"]
shared_status = wait_finished(bob, bh, shared_job)
check(
    shared_status is not None and shared_status["status"] == "done",
    "an editor-shared user can import and follow their job",
)
check(
    alice.get(f"/import_kml_status/{shared_job}", headers=ah).status_code == 404,
    "map access alone never grants another uploader's job",
)
conn = sqlite3.connect(backend.DB_FILE)
conn.execute("DELETE FROM map_shares WHERE map_id=? AND user_id=?", (alice_map, bob_id))
conn.commit()
conn.close()
check(
    bob.get(f"/import_kml_status/{shared_job}", headers=bh).status_code == 404,
    "losing map access revokes the uploader's own job read",
)

print("\n== Failure detail, cleanup, and schema groundwork (D-02/D-03) ==")
broken = start_import(alice, ah, alice_map, "this is not xml at all")
broken_job = broken.get_json()["job_id"]
broken_status = wait_finished(alice, ah, broken_job)
check(
    broken_status is not None and broken_status["status"] == "error"
    and broken_status["error"] == "import_failed",
    "an unparseable KML ends in a bounded error with a compact failure token",
)
broken_row = job_row(broken_job, "completed")
check(
    broken_row is not None and broken_row[0],
    "a failed job records its completion timestamp",
)
check(temp_kml_files() == [], "a failed job still removes its temporary file")
check(not hasattr(backend, "JOB_QUEUES"), "the unused JOB_QUEUES registry is gone")
row = notification_row(broken_job)
check(
    row is not None
    and row[0] == "kml.import_error"
    and json.loads(row[5])["error"] == "import_failed"
    and row[6]
    and row[6] in row[4],
    "an unexpected worker failure stores one correlated generic notification",
)

print("\n== Photo download outcomes feed the compact counts ==")
jpeg_stream = io.BytesIO()
Image.new("RGB", (64, 64), (40, 120, 40)).save(jpeg_stream, format="JPEG")
jpeg_bytes = jpeg_stream.getvalue()
fake_closes = []


class FakeResponse:
    status_code = 200

    def iter_content(self, chunk_size):
        for index in range(0, len(jpeg_bytes), chunk_size):
            yield jpeg_bytes[index:index + chunk_size]

    def close(self):
        fake_closes.append(1)


class ScriptedClock:
    def __init__(self, values):
        self.values = list(values)
        self.last = self.values[-1]

    def monotonic(self):
        if self.values:
            self.last = self.values.pop(0)
        return self.last

    def __getattr__(self, name):
        return getattr(time, name)


real_fetch = backend.fetch_url_safely
backend.fetch_url_safely = lambda *a, **k: FakeResponse()
photo_kml = kml_doc([
    placemark("photo-spot", "8.6,41.1", description='<img src="http://photos.test/one.jpg">'),
])
photo_job = start_import(alice, ah, alice_map, photo_kml).get_json()["job_id"]
photo_status = wait_finished(alice, ah, photo_job)
backend.fetch_url_safely = real_fetch
conn = sqlite3.connect(backend.DB_FILE)
photo_row = conn.execute(
    "SELECT photos.filename FROM photos JOIN spots ON spots.id = photos.spot_id "
    "WHERE spots.map_id=? AND spots.name='photo-spot'",
    (alice_map,),
).fetchone()
conn.close()
check(
    photo_status is not None and photo_status["status"] == "done"
    and photo_status["imported"] == 1 and photo_status["photos_failed"] == 0,
    "a downloadable photo imports without failure counts",
)
check(
    photo_row is not None and photo_row[0].endswith(".jpg")
    and os.path.exists(os.path.join(backend.PHOTOS_FOLDER, photo_row[0]))
    and os.path.exists(os.path.join(backend.THUMBS_FOLDER, photo_row[0])),
    "the imported photo lands as canonical .jpg photo+thumb",
)
check(fake_closes == [1], "the photo response is explicitly closed (S-09)")

blocked_kml = kml_doc([
    placemark("blocked-photo", "8.6,41.1", description='<img src="http://127.0.0.1:9/x.jpg">'),
])
blocked_job = start_import(alice, ah, alice_map, blocked_kml).get_json()["job_id"]
blocked_status = wait_finished(alice, ah, blocked_job)
conn = sqlite3.connect(backend.DB_FILE)
blocked_photos = conn.execute(
    "SELECT COUNT(*) FROM photos JOIN spots ON spots.id = photos.spot_id "
    "WHERE spots.map_id=? AND spots.name='blocked-photo'",
    (alice_map,),
).fetchone()[0]
conn.close()
check(
    blocked_status is not None and blocked_status["status"] == "done"
    and blocked_status["imported"] == 1,
    "a blocked photo URL never aborts the marker import",
)
check(
    blocked_status and blocked_status["photos_failed"] == 1 and blocked_photos == 0,
    "the SSRF-blocked download surfaces as a compact photo failure",
)
row = notification_row(blocked_job)
check(
    row is not None
    and row[0] == "kml.import_degraded"
    and json.loads(row[5])["affected_spots"] == ["blocked-photo"]
    and json.loads(row[5])["photos_failed"] == 1,
    "a degraded job identifies the affected marker and terminal counters",
)

print("\n== Bounded executor and admission control (S-09) ==")
hold = threading.Event()
started = threading.Semaphore(0)


def blocking_fetch(*a, **k):
    started.release()
    hold.wait(timeout=30)
    raise ValueError("released")


backend.fetch_url_safely = blocking_fetch
hold_desc = '<img src="http://photos.test/hold.jpg">'
bob_hold = start_import(bob, bh, bob_map, kml_doc([placemark("hold-bob", "8.6,41.1", description=hold_desc)])).get_json()["job_id"]
carol_hold = start_import(carol, ch, carol_map, kml_doc([placemark("hold-carol", "8.6,41.1", description=hold_desc)])).get_json()["job_id"]
check(
    started.acquire(timeout=10) and started.acquire(timeout=10),
    "both executor workers are busy inside their photo downloads",
)
alice_queued = start_import(alice, ah, alice_map, kml_doc([placemark("queued-spot", "8.6,41.1")])).get_json()["job_id"]
time.sleep(0.2)
queued_status = alice.get(f"/import_kml_status/{alice_queued}", headers=ah).get_json()
check(
    queued_status["status"] == "queued",
    f"a job beyond the worker pool waits as 'queued' ({queued_status['status']})",
)
second_bob = start_import(bob, bh, bob_map, kml_doc([placemark("extra", "8.6,41.1")]))
check(
    second_bob.status_code == 429
    and "already have" in second_bob.get_json()["error"],
    "a second concurrent import by the same user is a per-user 429",
)
with backend.KML_JOBS_LOCK:
    backend.KML_ACTIVE_JOBS["ghost"] = 1
dave_response = start_import(dave, dh, dave_map, kml_doc([placemark("dave-1", "8.6,41.1")]))
check(
    dave_response.status_code == 429
    and "Too many KML imports" in dave_response.get_json()["error"],
    "a full global queue rejects new users with a 429",
)
with backend.KML_JOBS_LOCK:
    backend.KML_ACTIVE_JOBS.pop("ghost")
hold.set()
finished = [
    wait_finished(bob, bh, bob_hold),
    wait_finished(carol, ch, carol_hold),
    wait_finished(alice, ah, alice_queued),
]
check(
    all(state is not None and state["status"] == "done" for state in finished),
    "held and queued jobs all complete once the workers are released",
)
check(backend.KML_ACTIVE_JOBS == {}, "every admission slot is released after completion")
check(temp_kml_files() == [], "no temporary files survive the executor cycle")
backend.fetch_url_safely = real_fetch

print("\n== KML and photo budgets (S-09) ==")
real_budgets = (backend.KML_MAX_DEPTH, backend.KML_MAX_ELEMENTS, backend.KML_MAX_PLACEMARKS,
                backend.KML_MAX_BYTES, backend.KML_MAX_PHOTOS_PER_SPOT,
                backend.KML_MAX_DOWNLOAD_BYTES, backend.KML_MAX_FETCH_ATTEMPTS,
                backend.KML_MAX_JOB_SECONDS)
budget_records = []
budget_handler = logging.Handler()
budget_handler.emit = lambda record: budget_records.append(record.getMessage())
backend.LOGGER.addHandler(budget_handler)

backend.KML_MAX_DEPTH = 6
deep_kml = kml_doc([placemark("deep", "8.6,41.1")], folders_prefix="<Folder>" * 3, folders_suffix="</Folder>" * 3)
deep_job = start_import(alice, ah, alice_map, deep_kml).get_json()["job_id"]
deep_status = wait_finished(alice, ah, deep_job)
check(
    deep_status is not None and deep_status["status"] == "error"
    and deep_status["error"] == "kml_too_deep",
    "an over-deep KML stops with a bounded kml_too_deep error",
)
backend.KML_MAX_DEPTH = real_budgets[0]

backend.KML_MAX_ELEMENTS = 8
wide_job = start_import(alice, ah, alice_map, kml_doc([placemark(f"e{i}", "8.6,41.1") for i in range(5)])).get_json()["job_id"]
wide_status = wait_finished(alice, ah, wide_job)
check(
    wide_status is not None and wide_status["error"] == "kml_too_many_elements",
    "an element-flood KML stops with kml_too_many_elements",
)
backend.KML_MAX_ELEMENTS = real_budgets[1]

backend.KML_MAX_PLACEMARKS = 2
many_job = start_import(alice, ah, alice_map, kml_doc([placemark(f"p{i}", "8.6,41.1") for i in range(3)])).get_json()["job_id"]
many_status = wait_finished(alice, ah, many_job)
check(
    many_status is not None and many_status["error"] == "kml_too_many_placemarks",
    "a placemark-flood KML stops with kml_too_many_placemarks",
)
backend.KML_MAX_PLACEMARKS = real_budgets[2]

backend.KML_MAX_BYTES = 100
oversized = start_import(alice, ah, alice_map, matrix_kml)
check(
    oversized.status_code == 413
    and oversized.get_json()["error"] == "The KML file is too large",
    "an over-size KML is rejected synchronously with 413",
)
check(temp_kml_files() == [], "the rejected upload's temporary file is removed")
backend.KML_MAX_BYTES = real_budgets[3]
followup = start_import(alice, ah, alice_map, kml_doc([placemark("after-413", "8.6,41.1")]))
followup_state = wait_finished(alice, ah, followup.get_json().get("job_id", ""))
check(
    followup.status_code == 200 and followup_state is not None and followup_state["status"] == "done",
    "the admission slot is released after a synchronous rejection",
)

fake_closes.clear()
backend.fetch_url_safely = lambda *a, **k: FakeResponse()
backend.KML_MAX_PHOTOS_PER_SPOT = 2
cap_kml = kml_doc([placemark(
    "photo-cap", "8.6,41.1",
    description="".join(f'<img src="http://photos.test/cap{i}.jpg">' for i in range(4)),
)])
cap_job = start_import(alice, ah, alice_map, cap_kml).get_json()["job_id"]
cap_status = wait_finished(alice, ah, cap_job)
conn = sqlite3.connect(backend.DB_FILE)
cap_photos = conn.execute(
    "SELECT COUNT(*) FROM photos JOIN spots ON spots.id = photos.spot_id "
    "WHERE spots.map_id=? AND spots.name='photo-cap'",
    (alice_map,),
).fetchone()[0]
conn.close()
check(
    cap_status is not None and cap_status["status"] == "done"
    and cap_status["photos_failed"] == 2 and cap_photos == 2,
    "the per-spot photo cap imports the budget and counts the excess",
)
check(len(fake_closes) == 2, "capped spots never fetch beyond their budget")
backend.KML_MAX_PHOTOS_PER_SPOT = real_budgets[4]

fake_closes.clear()
backend.KML_MAX_DOWNLOAD_BYTES = len(jpeg_bytes) + 10
budget_kml = kml_doc([placemark(
    "dl-budget", "8.6,41.1",
    description='<img src="http://photos.test/b1.jpg"><img src="http://photos.test/b2.jpg">'
                '<img src="http://photos.test/b3.jpg">',
)])
budget_job = start_import(alice, ah, alice_map, budget_kml).get_json()["job_id"]
budget_status = wait_finished(alice, ah, budget_job)
conn = sqlite3.connect(backend.DB_FILE)
budget_photos = conn.execute(
    "SELECT COUNT(*) FROM photos JOIN spots ON spots.id = photos.spot_id "
    "WHERE spots.map_id=? AND spots.name='dl-budget'",
    (alice_map,),
).fetchone()[0]
conn.close()
check(
    budget_status is not None and budget_status["status"] == "done"
    and budget_status["photos_failed"] == 1 and budget_photos == 1,
    "the download that crosses the aggregate budget aborts and counts as failed",
)
check(
    budget_status is not None and budget_status["photos_budget_skipped"] == 1,
    "URLs after budget exhaustion surface as a distinct budget-skip count",
)
check(len(fake_closes) == 2, "budget-skipped photos are never fetched")
backend.KML_MAX_DOWNLOAD_BYTES = real_budgets[5]

attempted_urls = []


def capped_fetch(url, *args, **kwargs):
    attempted_urls.append(url)
    raise ValueError("induced failed attempt")


backend.fetch_url_safely = capped_fetch
backend.KML_MAX_FETCH_ATTEMPTS = 2
attempt_kml = kml_doc([
    placemark(
        "attempt-cap-first", "8.6,41.1",
        description='<img src="http://photos.test/a1.jpg"><img src="http://photos.test/a2.jpg">',
    ),
    placemark(
        "attempt-cap-second", "8.7,41.2",
        description='<img src="http://photos.test/a3.jpg"><img src="http://photos.test/a4.jpg">',
    ),
])
attempt_job = start_import(alice, ah, alice_map, attempt_kml).get_json()["job_id"]
attempt_status = wait_finished(alice, ah, attempt_job)
check(
    attempt_status is not None and attempt_status["status"] == "done"
    and attempt_status["imported"] == 2 and attempt_status["photos_failed"] == 2
    and attempt_status["photos_budget_skipped"] == 2,
    "failed fetches consume the attempt cap and remaining marker rows still import",
)
check(
    len(attempted_urls) == 2
    and {"attempt-cap-first", "attempt-cap-second"}.issubset(map_spot_names(alice_map)),
    "the attempt cap stops remote fetches exactly at its configured boundary",
)
row = notification_row(attempt_job)
check(
    row is not None
    and row[0] == "kml.import_degraded"
    and json.loads(row[5])["affected_spots"]
    == ["attempt-cap-first", "attempt-cap-second"]
    and json.loads(row[5])["exhausted_budgets"] == ["fetch_attempts"],
    "attempt exhaustion is attributable to both affected markers and its budget",
)
backend.KML_MAX_FETCH_ATTEMPTS = real_budgets[6]

bounded_names = [f"affected-{index}" for index in range(12)]
backend._notify_kml_job(
    alice_id,
    "bounded-affected-list",
    alice_map,
    "Alice KML",
    imported=12,
    total=12,
    photos_failed=12,
    affected_spots=bounded_names,
)
row = notification_row("bounded-affected-list")
detail = json.loads(row[5]) if row else {}
check(
    row is not None
    and detail.get("affected_spots") == bounded_names[:10]
    and detail.get("affected_spots_omitted") == 2
    and "and 2 more…" in row[4],
    "affected-marker output keeps the first ten names and exact omitted count",
)

real_backend_time = backend.time
unexpected_fetches = []
backend.fetch_url_safely = lambda *args, **kwargs: unexpected_fetches.append(args[0])
backend.KML_MAX_JOB_SECONDS = 1
backend.time = ScriptedClock([100, 101])
try:
    deadline_kml = kml_doc([
        placemark(
            "deadline-first", "8.6,41.1",
            description='<img src="http://photos.test/d1.jpg">',
        ),
        placemark(
            "deadline-second", "8.7,41.2",
            description="".join(
                f'<img src="http://photos.test/d{index}.jpg">'
                for index in range(2, 24)
            ),
        ),
    ])
    deadline_job = start_import(alice, ah, alice_map, deadline_kml).get_json()["job_id"]
    deadline_status = wait_finished(alice, ah, deadline_job)
finally:
    backend.time = real_backend_time
check(
    deadline_status is not None and deadline_status["status"] == "done"
    and deadline_status["imported"] == 2 and deadline_status["photos_failed"] == 0
    and deadline_status["photos_budget_skipped"] == 23,
    "an expired deadline budget-skips every remaining photo and finishes every marker row",
)
check(
    not unexpected_fetches
    and {"deadline-first", "deadline-second"}.issubset(map_spot_names(alice_map)),
    "the pre-fetch deadline makes no remote request",
)

stream_closes = []
stream_timeouts = []


class DripResponse:
    status_code = 200

    def iter_content(self, chunk_size):
        yield b"partial"

    def close(self):
        stream_closes.append(1)


def dripping_fetch(url, *args, **kwargs):
    stream_timeouts.append(kwargs["timeout"])
    return DripResponse()


photo_files_before = set(os.listdir(backend.PHOTOS_FOLDER))
thumb_files_before = set(os.listdir(backend.THUMBS_FOLDER))
backend.fetch_url_safely = dripping_fetch
backend.KML_MAX_JOB_SECONDS = 5
backend.time = ScriptedClock([200, 201, 206])
try:
    stream_kml = kml_doc([placemark(
        "deadline-stream", "8.6,41.1",
        description='<img src="http://photos.test/s1.jpg"><img src="http://photos.test/s2.jpg">',
    )])
    stream_job = start_import(alice, ah, alice_map, stream_kml).get_json()["job_id"]
    stream_status = wait_finished(alice, ah, stream_job)
finally:
    backend.time = real_backend_time
    backend.KML_MAX_JOB_SECONDS = real_budgets[7]
    backend.fetch_url_safely = real_fetch
    backend.LOGGER.removeHandler(budget_handler)
check(
    stream_status is not None and stream_status["status"] == "done"
    and stream_status["imported"] == 1 and stream_status["photos_failed"] == 1
    and stream_status["photos_budget_skipped"] == 1,
    f"an in-stream deadline fails the active photo, skips the remainder, and finishes the marker ({stream_status})",
)
check(
    len(stream_timeouts) == 1 and 0 < stream_timeouts[0] <= 4,
    f"the fetch timeout is capped to the deadline remainder ({stream_timeouts})",
)
check(
    stream_closes == [1]
    and set(os.listdir(backend.PHOTOS_FOLDER)) == photo_files_before
    and set(os.listdir(backend.THUMBS_FOLDER)) == thumb_files_before,
    f"an in-stream deadline closes the response and removes partial files ({stream_closes})",
)
budget_summaries = [line for line in budget_records if "photo budgets exhausted" in line]
check(
    any("fetch_attempts=2" in line for line in budget_summaries)
    and any("deadline_seconds=1" in line for line in budget_summaries),
    "the exhaustion summary names the attempt and deadline budgets",
)

print("\n== Read-triggered retention and boot sweep (S-09) ==")
conn = sqlite3.connect(backend.DB_FILE)
conn.execute(
    "INSERT INTO import_progress (job_id, owner_id, map_id, imported, total, skipped, photos_failed, progress, status) "
    "VALUES ('stale-running', ?, ?, 0, 0, 0, 0, 0, 'running')",
    (alice_id, alice_map),
)
conn.commit()
conn.close()
backend.init_db()
stale = job_row("stale-running", "status, error, completed")
check(
    stale is not None and stale[0] == "error" and stale[1] == "interrupted" and stale[2],
    "boot marks orphaned running jobs as interrupted errors",
)
row = notification_row("stale-running")
check(
    row is not None
    and row[0] == "kml.import_error"
    and json.loads(row[5])["error"] == "interrupted",
    "boot recovery writes the interrupted owner's terminal notification",
)
backend.init_db()
conn = sqlite3.connect(backend.DB_FILE)
interrupted_notifications = conn.execute(
    "SELECT COUNT(*) FROM notif_history WHERE target_id='stale-running'"
).fetchone()[0]
conn.close()
check(
    interrupted_notifications == 1,
    "repeated startup recovery is idempotent",
)

conn = sqlite3.connect(backend.DB_FILE)
conn.execute(
    "INSERT INTO import_progress (job_id, owner_id, map_id, imported, total, skipped, photos_failed, progress, status, last_updated) "
    "VALUES ('bob-ancient', ?, ?, 1, 1, 0, 0, 100, 'done', datetime('now', '-8 days'))",
    (bob_id, bob_map),
)
conn.commit()
conn.close()
retention_job = start_import(alice, ah, alice_map, kml_doc([placemark("retention", "8.6,41.1")])).get_json()["job_id"]
retention_status = wait_finished(alice, ah, retention_job)
conn = sqlite3.connect(backend.DB_FILE)
remaining_jobs = {row[0] for row in conn.execute("SELECT job_id FROM import_progress WHERE owner_id IN (?, ?)", (alice_id, bob_id))}
conn.close()
check(
    retention_status is not None and retention_status["status"] == "done"
    and "stale-running" not in remaining_jobs,
    "admission clears the requester's earlier terminal jobs",
)
check("bob-ancient" not in remaining_jobs, "admission clears week-old terminal jobs of any user")
check(retention_job in remaining_jobs, "the fresh job's row is retained until the next admission")

print("\n== Redacted structured logging at the KML call sites (S-14) ==")
check(
    backend.redact_url("https://alice:secret@example.test:8443/photo.jpg?token=hidden#fragment")
    == "https://example.test:8443/photo.jpg",
    "URL redaction strips userinfo/query/fragment while preserving an explicit port",
)
check(
    backend.redact_url("http://[2001:db8::1]/photo.jpg")
    == "http://[2001:db8::1]/photo.jpg"
    and backend.redact_url("http://[2001:db8::1]:8080/photo.jpg")
    == "http://[2001:db8::1]:8080/photo.jpg",
    "URL redaction brackets IPv6 authorities with and without an explicit port",
)
check(
    backend.redact_url("https://alice:secret@example.test:notaport/photo.jpg")
    == "",
    "URL redaction never throws or exposes userinfo from a malformed port",
)
records = []


class ListHandler(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


handler = ListHandler()
backend.LOGGER.addHandler(handler)
injection_kml = kml_doc([placemark(
    "line1\nline2-" + "x" * 200, "8.6,41.1",
    description='<img src="http://alice:usersecret@127.0.0.1:9/x.jpg?token=querysecret">',
)])
log_job = start_import(alice, ah, alice_map, injection_kml).get_json()["job_id"]
wait_finished(alice, ah, log_job)
failure_job = start_import(alice, ah, alice_map, "<kml **broken").get_json()["job_id"]
wait_finished(alice, ah, failure_job)
backend.LOGGER.removeHandler(handler)
photo_lines = [line for line in records if "photo failed" in line]
check(
    photo_lines and "http://127.0.0.1:9/x.jpg" in photo_lines[0]
    and "alice" not in "".join(records) and "usersecret" not in "".join(records)
    and "querysecret" not in "".join(records),
    "photo failure logs strip URL userinfo and query credentials",
)
check(
    photo_lines and "line1line2" in photo_lines[0] and "\n" not in photo_lines[0].replace("\n", ""),
    "control characters in KML names never reach the log line",
)
check(
    photo_lines and "x" * 81 not in photo_lines[0],
    "untrusted log fields are truncated",
)
check(
    any(f"KML job {failure_job} failed" in line for line in records),
    "a failed job logs a structured server-side record",
)

print("\n== Vetted-IP pinned HTTPS transport (S-15) ==")
captured_hosts = []


class CapturedResponse:
    status_code = 200


real_requests_get = requests.get
real_resolve = backend._resolve_public_ip
backend._resolve_public_ip = lambda host: "2001:db8::2"
requests.get = lambda url, **kwargs: captured_hosts.append(kwargs["headers"]["Host"]) or CapturedResponse()
try:
    backend.fetch_url_safely("http://plain.test/photo")
    backend.fetch_url_safely("http://plain.test:8080/photo")
    backend.fetch_url_safely("http://[2001:db8::1]:8080/photo")
    backend.fetch_url_safely("http://alice:secret@plain.test:8080/photo")
finally:
    requests.get = real_requests_get
    backend._resolve_public_ip = real_resolve
check(
    captured_hosts == ["plain.test", "plain.test:8080", "[2001:db8::1]:8080", "plain.test:8080"],
    f"outbound Host headers preserve safe authorities and strip userinfo ({captured_hosts})",
)

subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
     "-keyout", "key.pem", "-out", "cert.pem", "-days", "2",
     "-subj", "/CN=kml-test.local", "-addext", "subjectAltName=DNS:kml-test.local"],
    check=True, capture_output=True,
)
seen = {"sni": [], "hosts": []}


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen["hosts"].append(self.headers.get("Host", ""))
        body = b"pinned-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


tls_server = http.server.HTTPServer(("127.0.0.1", 0), RecordingHandler)
tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls_context.load_cert_chain("cert.pem", "key.pem")
tls_context.sni_callback = lambda sock, server_name, context: seen["sni"].append(server_name)
tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
tls_port = tls_server.server_address[1]
threading.Thread(target=tls_server.serve_forever, daemon=True).start()
plain_server = http.server.HTTPServer(("127.0.0.1", 0), RecordingHandler)
plain_port = plain_server.server_address[1]
threading.Thread(target=plain_server.serve_forever, daemon=True).start()

real_resolve = backend._resolve_public_ip
real_getaddrinfo = socket.getaddrinfo


def poisoned_getaddrinfo(host, *a, **k):
    if isinstance(host, str) and host.endswith(".local"):
        raise AssertionError(f"transport re-resolved {host} after validation")
    return real_getaddrinfo(host, *a, **k)


backend._resolve_public_ip = lambda host: "127.0.0.1"
socket.getaddrinfo = poisoned_getaddrinfo
os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(WORK, "cert.pem")
try:
    pinned = backend.fetch_url_safely(f"https://kml-test.local:{tls_port}/photo", timeout=5)
    check(
        pinned.status_code == 200 and pinned.content == b"pinned-ok",
        "HTTPS connects to the vetted IP without re-resolving DNS",
    )
    check(
        seen["sni"] == ["kml-test.local"],
        f"TLS preserves the original hostname for SNI ({seen['sni']})",
    )
    check(
        seen["hosts"][-1] == f"kml-test.local:{tls_port}",
        "the HTTP Host header carries the original hostname",
    )
    userinfo = backend.fetch_url_safely(
        f"https://alice:supersecret@kml-test.local:{tls_port}/photo",
        timeout=5,
    )
    check(
        userinfo.status_code == 200 and seen["hosts"][-1] == f"kml-test.local:{tls_port}"
        and "@" not in seen["hosts"][-1],
        "the real pinned HTTPS path never sends URL userinfo in Host",
    )
    try:
        backend.fetch_url_safely(f"https://wrong-name.local:{tls_port}/photo", timeout=5)
        check(False, "certificate verification still checks the original hostname")
    except requests.exceptions.SSLError:
        check(True, "certificate verification still checks the original hostname")
    plain = backend.fetch_url_safely(f"http://kml-test.local:{plain_port}/photo", timeout=5)
    check(
        plain.status_code == 200 and seen["hosts"][-1] == f"kml-test.local:{plain_port}",
        "plain HTTP keeps the same pinned-IP + Host-header behavior",
    )

    # F6: the netloc rewrite is an implementation detail of the pinning defence, so
    # response.url reports the IP the socket dialled. Anything handed back to a client
    # must carry the hostname instead — while the socket still goes to the vetted IP.
    logical_url = f"https://kml-test.local:{tls_port}/photo"
    reported, final_url = backend.fetch_url_safely(
        logical_url, timeout=5, with_final_url=True
    )
    check(
        final_url == logical_url,
        f"with_final_url reports the hostname form, not the pinned IP ({final_url})",
    )
    check(
        "127.0.0.1" in reported.url and "kml-test.local" not in reported.url,
        f"the socket still went to the vetted IP ({reported.url})",
    )
    check(
        seen["sni"][-1] == "kml-test.local" and seen["hosts"][-1] == f"kml-test.local:{tls_port}",
        "reporting the hostname changes nothing about SNI or the Host header",
    )
    check(
        backend.fetch_url_safely(logical_url, timeout=5).status_code == 200,
        "the default single-return contract is unchanged for existing callers",
    )

    # And the caller F6 was actually about: /parse-maps-link reported an IP-form
    # expanded_url back to the browser.
    real_hosts = backend.GOOGLE_MAPS_HOSTS
    backend.GOOGLE_MAPS_HOSTS = ("kml-test.local",)
    try:
        expanded = backend.expand_url(logical_url)
    finally:
        backend.GOOGLE_MAPS_HOSTS = real_hosts
    check(
        expanded == logical_url,
        f"expand_url returns the hostname-form link, not the pinned IP ({expanded})",
    )
finally:
    backend._resolve_public_ip = real_resolve
    socket.getaddrinfo = real_getaddrinfo
    os.environ.pop("REQUESTS_CA_BUNDLE", None)
    tls_server.shutdown()
    plain_server.shutdown()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
