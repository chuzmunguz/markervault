"""Stage 9 home suite: canonical JPEG naming/MIME (R-01), decode-safety limits (S-10),
DB/filesystem atomicity and cleanup (R-02), derived photo counts (R-05), and the
generic-error/structured-logging primitives (S-14)."""
import importlib.util
import io
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid

import bcrypt

from PIL import Image


WORK = tempfile.mkdtemp(prefix="mv_media_")
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
real_rate_limit = backend.rate_limit
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
        "VALUES (?, ?, ?, 'user', 'approved', ?, 'Media', 'Integrity', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
            "2026-07-19T00:00:00",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def image_bytes(format_name, size=(64, 64)):
    stream = io.BytesIO()
    Image.new("RGB", size, (120, 40, 40)).save(stream, format=format_name)
    stream.seek(0)
    return stream


def photo_files(filename):
    return (
        os.path.exists(os.path.join(backend.PHOTOS_FOLDER, filename)),
        os.path.exists(os.path.join(backend.THUMBS_FOLDER, filename)),
    )


owner_id = make_user("owner", "Abcd1234!")
owner = app.test_client()
owner.post("/login", json={"username": "owner", "password": "Abcd1234!"})
oh = {"Authorization": f"Bearer {owner.post('/auth/refresh').get_json()['access_token']}"}

map_id = owner.post("/maps", headers=oh, json={"name": "Media"}).get_json()["id"]
spot_id = owner.post("/spots", headers=oh, json={
    "mapID": map_id, "name": "Spot", "lat": 1, "lng": 2,
}).get_json()["id"]

print("== Canonical JPEG naming and MIME (R-01) ==")
uploads = {}
for label, format_name, client_name in (
    ("png", "PNG", "shot.png"),
    ("gif", "GIF", "anim.gif"),
    ("uppercase", "PNG", "PHOTO.PNG"),
    ("extensionless", "JPEG", "noext"),
):
    r = owner.post(f"/spots/{spot_id}/photos", headers=oh,
                   data={"photo": (image_bytes(format_name), client_name)},
                   content_type="multipart/form-data")
    filename = r.get_json().get("filename", "") if r.status_code == 200 else ""
    uploads[label] = filename
    stored = photo_files(filename)
    check(
        r.status_code == 200 and filename.endswith(".jpg") and all(stored),
        f"a {label} upload stores canonical .jpg photo+thumb ({filename})",
    )
with Image.open(os.path.join(backend.PHOTOS_FOLDER, uploads["png"])) as stored_image:
    check(stored_image.format == "JPEG", "stored bytes are re-encoded JPEG")

photo_url = owner.get(f"/spots/{spot_id}/photos", headers=oh).get_json()[0]["photo_url"]
served = app.test_client().get(photo_url)
check(
    served.status_code == 200 and served.headers.get("Content-Type") == "image/jpeg",
    "signed serving sends the canonical image/jpeg type",
)

replaced = owner.put(f"/spots/{spot_id}/photos/{uploads['gif']}", headers=oh,
                     data={"photo": (image_bytes("PNG"), "newer.png")},
                     content_type="multipart/form-data")
new_name = replaced.get_json().get("filename", "")
check(
    replaced.status_code == 200 and new_name.endswith(".jpg")
    and all(photo_files(new_name)) and not any(photo_files(uploads["gif"])),
    "replacement stores canonical .jpg and removes the old files",
)
uploads["gif"] = new_name

print("\n== Decode-safety limits (S-10) ==")
r = owner.post(f"/spots/{spot_id}/photos", headers=oh,
               data={"photo": (image_bytes("PNG", (12000, 2)), "wide.png")},
               content_type="multipart/form-data")
check(
    r.status_code == 400 and r.get_json()["error"] == "Image dimensions are too large",
    "an over-dimension photo upload is rejected before decoding",
)
r = owner.post("/profile/avatar", headers=oh,
               data={"avatar": (image_bytes("PNG", (2, 12000)), "tall.png")},
               content_type="multipart/form-data")
check(
    r.status_code == 400 and r.get_json()["error"] == "Image dimensions are too large",
    "an over-dimension avatar is rejected by the same shared gate",
)
r = owner.post(f"/spots/{spot_id}/photos", headers=oh,
               data={"photo": (io.BytesIO(b"not an image"), "junk.png")},
               content_type="multipart/form-data")
check(r.status_code == 400, "non-image bytes stay a 400")

print("\n== Derived photo counts (R-05) ==")
conn = sqlite3.connect(backend.DB_FILE)
columns = [row[1] for row in conn.execute("PRAGMA table_info(spots)")]
conn.close()
check("photo_count" not in columns, "spots no longer stores a photo_count column")
detail = owner.get(f"/spots/{spot_id}", headers=oh).get_json()
check(detail["photo_count"] == 4, "spot detail derives photo_count from photo rows")
listing = owner.get(f"/maps/{map_id}/spots", headers=oh).get_json()
check(listing[0]["photo_count"] == 4, "spot listing derives photo_count from photo rows")
owner.delete(f"/spots/{spot_id}/photos/{uploads['png']}", headers=oh)
check(
    owner.get(f"/spots/{spot_id}", headers=oh).get_json()["photo_count"] == 3
    and not any(photo_files(uploads["png"])),
    "photo deletion updates the derived count and removes both files",
)

copied = owner.post(f"/spots/{spot_id}/copy/{map_id}", headers=oh).get_json()
check(
    copied["spot"]["photo_count"] == 3
    and owner.get(f"/spots/{copied['spot']['id']}", headers=oh).get_json()["photo_count"] == 3,
    "copying a marker copies its photos with a matching derived count",
)

print("\n== Atomicity and compensation (R-02/S-14) ==")
log_records = []
handler = logging.Handler()
handler.emit = lambda record: log_records.append(record.getMessage())
backend.LOGGER.addHandler(handler)
backend.LOGGER.setLevel(logging.INFO)

real_replace = os.replace


def failing_replace(src, dst):
    if dst.startswith(backend.PHOTOS_FOLDER) or dst.startswith(backend.THUMBS_FOLDER):
        raise OSError("induced disk failure")
    return real_replace(src, dst)


os.replace = failing_replace
try:
    conn = sqlite3.connect(backend.DB_FILE)
    rows_before = conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
    conn.close()
    r = owner.post(f"/spots/{spot_id}/photos", headers=oh,
                   data={"photo": (image_bytes("PNG"), "doomed.png")},
                   content_type="multipart/form-data")
finally:
    os.replace = real_replace
body = r.get_json()
conn = sqlite3.connect(backend.DB_FILE)
rows_after = conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
conn.close()
check(
    r.status_code == 500 and body["error"] == "Could not save photo"
    and "correlation_id" in body and "induced" not in str(body),
    "an induced disk failure returns a generic error with a correlation id",
)
check(rows_after == rows_before, "the failed upload leaves no database row")
staged_left = [name for name in os.listdir(backend.PHOTOS_FOLDER) if name.endswith(".tmp")]
check(not staged_left, "the failed upload leaves no staged files")
check(
    any(f"correlation_id={body['correlation_id']}" in message for message in log_records),
    "the server log carries the same correlation id",
)

real_copy = shutil.copy


def failing_copy(src, dst):
    raise OSError("induced copy failure")


shutil.copy = failing_copy
try:
    conn = sqlite3.connect(backend.DB_FILE)
    spots_before = conn.execute("SELECT COUNT(*) FROM spots").fetchone()[0]
    conn.close()
    r = owner.post(f"/spots/{spot_id}/copy/{map_id}", headers=oh)
finally:
    shutil.copy = real_copy
conn = sqlite3.connect(backend.DB_FILE)
spots_after = conn.execute("SELECT COUNT(*) FROM spots").fetchone()[0]
conn.close()
check(
    r.status_code == 500 and r.get_json()["error"] == "Could not copy the marker"
    and spots_after == spots_before,
    "a failed copy rolls back the new marker and reports generically",
)

published_destinations = []


def failing_copy_publish(src, dst):
    if dst.startswith(backend.THUMBS_FOLDER):
        raise OSError("induced thumbnail publish failure")
    result = real_replace(src, dst)
    if dst.startswith(backend.PHOTOS_FOLDER):
        published_destinations.append(dst)
    return result


conn = sqlite3.connect(backend.DB_FILE)
spots_before = conn.execute("SELECT COUNT(*) FROM spots").fetchone()[0]
photos_before = conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
conn.close()
photo_files_before = set(os.listdir(backend.PHOTOS_FOLDER))
thumb_files_before = set(os.listdir(backend.THUMBS_FOLDER))
os.replace = failing_copy_publish
try:
    r = owner.post(f"/spots/{spot_id}/copy/{map_id}", headers=oh)
finally:
    os.replace = real_replace
conn = sqlite3.connect(backend.DB_FILE)
spots_after = conn.execute("SELECT COUNT(*) FROM spots").fetchone()[0]
photos_after = conn.execute("SELECT COUNT(*) FROM photos").fetchone()[0]
conn.close()
photo_files_after = set(os.listdir(backend.PHOTOS_FOLDER))
thumb_files_after = set(os.listdir(backend.THUMBS_FOLDER))
check(
    r.status_code == 500 and r.get_json()["error"] == "Could not copy the marker",
    "a thumbnail publish failure aborts the whole marker copy",
)
check(
    spots_after == spots_before and photos_after == photos_before,
    "the publish failure rolls back every new spot and photo row",
)
check(
    published_destinations
    and photo_files_after == photo_files_before
    and thumb_files_after == thumb_files_before
    and not any(name.endswith(".tmp") for name in photo_files_after | thumb_files_after),
    "the publish failure removes already-visible destinations and every staged file",
)

remaining = [uploads["uppercase"], uploads["extensionless"], uploads["gif"]]
r = owner.delete(f"/maps/{map_id}", headers=oh)
check(
    r.status_code == 200
    and not any(any(photo_files(name)) for name in remaining),
    "map deletion now removes every photo and thumbnail file",
)

print("\n== Batch-upload burst headroom ==")
burst_map = owner.post("/maps", headers=oh, json={"name": "Burst"}).get_json()["id"]
burst_spot = owner.post("/spots", headers=oh, json={
    "mapID": burst_map, "name": "Burst", "lat": 1, "lng": 2,
}).get_json()["id"]
# Freeze the limiter's clock so the burst accounting is exact: no refill can
# leak in however slowly the loop runs.
real_time = backend.time.time
frozen_now = real_time()
backend.time.time = lambda: frozen_now
backend.rate_limit = real_rate_limit
backend.PRIVATE_BUCKET.clear()
statuses = []
try:
    for index in range(70):
        r = owner.post(f"/spots/{burst_spot}/photos", headers=oh,
                       data={"photo": (image_bytes("PNG", (8, 8)), f"batch{index}.png")},
                       content_type="multipart/form-data")
        statuses.append(r.status_code)
finally:
    backend.rate_limit = lambda *a, **k: None
    backend.time.time = real_time
check(
    statuses[:61] == [200] * 61,
    "a 61-photo batch upload passes the authenticated burst untouched",
)
check(
    set(statuses[61:]) == {429},
    "the private bucket still throttles a runaway burst at the exact boundary",
)

print("\n== Manual orphan checker ==")
env = os.environ.copy()
env["MARKERVAULT_DB_PATH"] = backend.DB_FILE
env["MARKERVAULT_PHOTOS_PATH"] = backend.PHOTOS_FOLDER
env["MARKERVAULT_THUMBS_PATH"] = backend.THUMBS_FOLDER
env["MARKERVAULT_AVATARS_PATH"] = backend.AVATARS_FOLDER
checker = ["/workspace/markervault/tests/venv/bin/python"
           if os.path.exists("/workspace/markervault/tests/venv/bin/python") else sys.executable,
           "/workspace/markervault/tools/check_media_orphans.py"]
clean = subprocess.run(checker, env=env, cwd=WORK, text=True, capture_output=True)
check(
    clean.returncode == 0 and "consistent" in clean.stdout,
    "the orphan checker reports a consistent state",
)
stray = os.path.join(backend.PHOTOS_FOLDER, "stray_orphan.jpg")
open(stray, "wb").write(b"x")
conn = sqlite3.connect(backend.DB_FILE)
conn.execute("INSERT INTO photos (spot_id, filename) VALUES (?, ?)", (spot_id, "ghost.jpg"))
conn.commit()
conn.close()
dirty = subprocess.run(checker, env=env, cwd=WORK, text=True, capture_output=True)
check(
    dirty.returncode == 1 and "ORPHAN" in dirty.stdout and "MISSING" in dirty.stdout,
    "the orphan checker reports both orphaned files and missing files",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
