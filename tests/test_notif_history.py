"""Notification-history foundation: schema, writer, retention, read isolation,
and race-safe high-water seen semantics."""
import importlib.util
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import uuid

import bcrypt


WORK = tempfile.mkdtemp(prefix="mv_notif_history_")
for source_name in (
    "backend.py",
    "markervault_schema.py",
    "request_validation.py",
    "markervault_config.py",
    "username_validation.py",
    "email_delivery.py",
):
    shutil.copy(
        os.path.join("/workspace/markervault", source_name),
        os.path.join(WORK, source_name),
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


@app.route("/_test/notif_internal_error")
@backend.require_auth
def notif_internal_error_route():
    try:
        raise OSError("private internal detail")
    except OSError:
        return backend.internal_error("test.internal", "Test operation failed")


@app.route("/_test/notif_unhandled_error")
@backend.require_auth
def notif_unhandled_error_route():
    raise RuntimeError("private unhandled detail")

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


def make_user(username):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email) "
        "VALUES (?, ?, ?, 'user', 'approved', ?, 'Notif', 'Tester', ?)",
        (
            user_id,
            username,
            bcrypt.hashpw(b"Abcd1234!", bcrypt.gensalt()),
            "2026-07-22T00:00:00Z",
            f"{username}@example.test",
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def login(username):
    client = app.test_client()
    response = client.post(
        "/login",
        json={"username": username, "password": "Abcd1234!"},
    )
    check(response.status_code == 200, f"{username} logs in")
    token = client.post("/auth/refresh").get_json()["access_token"]
    return client, {"Authorization": f"Bearer {token}"}


def history_rows(user_id):
    conn = backend.get_db()
    rows = conn.execute(
        "SELECT id, event, target_type, target_id, target_label, message, detail, "
        "correlation_id, seen FROM notif_history WHERE user_id=? ORDER BY id",
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def clear_history():
    conn = backend.get_db()
    conn.execute("DELETE FROM notif_history")
    conn.commit()
    conn.close()


def make_map(owner_id, name):
    conn = backend.get_db()
    cursor = conn.execute(
        "INSERT INTO maps (owner_id, name, is_base, created, description, notes) "
        "VALUES (?, ?, 0, '2026-07-22T00:00:00Z', '', '')",
        (owner_id, name),
    )
    map_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return map_id


def make_spot(map_id, name, photos=()):
    conn = backend.get_db()
    cursor = conn.execute(
        "INSERT INTO spots (map_id, name, lat, lng, created, notes, listing, subset) "
        "VALUES (?, ?, 38.7, -9.1, '2026-07-22T00:00:00Z', '', 'General', 'Main')",
        (map_id, name),
    )
    spot_id = cursor.lastrowid
    for filename, caption in photos:
        conn.execute(
            "INSERT INTO photos (spot_id, filename, caption) VALUES (?, ?, ?)",
            (spot_id, filename, caption),
        )
    conn.commit()
    conn.close()
    return spot_id


print("== Canonical notification-history schema ==")
conn = sqlite3.connect(backend.DB_FILE)
columns = conn.execute("PRAGMA table_info(notif_history)").fetchall()
column_names = [row[1] for row in columns]
table_sql = conn.execute(
    "SELECT sql FROM sqlite_master WHERE type='table' AND name='notif_history'"
).fetchone()[0]
foreign_keys = conn.execute("PRAGMA foreign_key_list(notif_history)").fetchall()
index_columns = conn.execute("PRAGMA index_info(idx_notif_history_user)").fetchall()
conn.close()
check(
    column_names == [
        "id",
        "user_id",
        "created",
        "event",
        "target_type",
        "target_id",
        "target_label",
        "message",
        "detail",
        "correlation_id",
        "seen",
    ],
    "canonical schema exposes the frozen diagnostic fields in contract order",
)
check(
    "CHECK (seen IN (0, 1))" in table_sql,
    "seen is constrained to the two SQLite boolean values",
)
check(
    any(row[2] == "users" and row[3] == "user_id" and row[6] == "CASCADE" for row in foreign_keys),
    "notification owners use an enforced ON DELETE CASCADE foreign key",
)
check(
    [row[2] for row in index_columns] == ["user_id", "id"],
    "the per-user chronological lookup index is canonical",
)
check(
    backend.NOTIF_HISTORY_CAP == 200 and len(backend.NOTIF_EVENTS) == 7,
    "the backend exports the configured cap and closed event taxonomy",
)

alice_id = make_user("alice")
bob_id = make_user("bob")
charlie_id = make_user("charlie")
alice, alice_headers = login("alice")
bob, bob_headers = login("bob")
charlie, charlie_headers = login("charlie")

print("\n== Fail-open bounded writer ==")
long_message = "Deleted\n" + "M" * backend.NOTIF_MESSAGE_MAX
long_id = "i" * (backend.NOTIF_TARGET_ID_MAX + 25)
long_label = "L" * (backend.NOTIF_TARGET_LABEL_MAX + 25)
long_correlation = "c" * (backend.NOTIF_CORRELATION_ID_MAX + 25)
written = backend.notify(
    alice_id,
    "map.deleted",
    long_message,
    target_type="map",
    target_id=long_id,
    target_label=long_label,
    detail={"markers": 3, "photos": 7},
    correlation_id=long_correlation,
)
rows = history_rows(alice_id)
check(written and len(rows) == 1, "a valid structured notification is persisted")
stored = rows[0]
check(
    "\n" not in stored[5]
    and len(stored[5]) == backend.NOTIF_MESSAGE_MAX
    and stored[5].endswith("…"),
    "messages lose control characters and truncate with an ellipsis",
)
check(
    len(stored[3]) == backend.NOTIF_TARGET_ID_MAX
    and len(stored[4]) == backend.NOTIF_TARGET_LABEL_MAX
    and len(stored[7]) == backend.NOTIF_CORRELATION_ID_MAX
    and stored[3].endswith("…")
    and stored[4].endswith("…")
    and stored[7].endswith("…"),
    "target ids, labels, and correlation ids use their fixed output caps",
)
check(
    json.loads(stored[6]) == {"markers": 3, "photos": 7} and stored[8] == 0,
    "bounded detail round-trips and new rows start unseen",
)
conn = backend.get_db()
try:
    conn.execute("UPDATE notif_history SET seen=2 WHERE user_id=?", (alice_id,))
    conn.commit()
except sqlite3.IntegrityError:
    invalid_seen_rejected = True
    conn.rollback()
else:
    invalid_seen_rejected = False
conn.close()
check(invalid_seen_rejected, "SQLite rejects invalid seen values at runtime")

log_stream = io.StringIO()
log_handler = logging.StreamHandler(log_stream)
backend.LOGGER.addHandler(log_handler)
backend.LOGGER.setLevel(logging.ERROR)
secret_message = "PRIVATE_MESSAGE_SENTINEL"
secret_detail = "PRIVATE_DETAIL_SENTINEL"
written = backend.notify(
    alice_id,
    "unknown.event",
    secret_message,
    target_type="map",
    target_id="map-7",
    detail={"secret": secret_detail},
    correlation_id="corr-7",
)
log_text = log_stream.getvalue()
check(not written, "an event outside the closed taxonomy fails open")
check(
    "area=notif_history.write_failed" in log_text
    and "event=unknown.event" in log_text
    and "target_id=map-7" in log_text
    and "correlation_id=corr-7" in log_text,
    "a failed write emits the required diagnostic identifiers",
)
check(
    secret_message not in log_text and secret_detail not in log_text,
    "write-failure logs exclude message and detail payloads",
)
written = backend.notify(
    alice_id,
    "map.deleted",
    "Oversized detail is rejected.",
    target_type="map",
    target_id="map-overlong",
    detail={"names": "x" * backend.NOTIF_DETAIL_MAX},
)
check(
    not written and len(history_rows(alice_id)) == 1,
    "detail beyond the fixed cap fails open without storing a partial row",
)
log_stream.seek(0)
log_stream.truncate(0)
original_get_db = backend.get_db


def failed_get_db():
    raise sqlite3.OperationalError("forced notification database failure")


backend.get_db = failed_get_db
written = backend.notify(
    alice_id,
    "map.deleted",
    secret_message,
    target_type="map",
    target_id="map-8",
    detail={"secret": secret_detail},
    correlation_id="corr-8",
)
backend.get_db = original_get_db
log_text = log_stream.getvalue()
backend.LOGGER.removeHandler(log_handler)
check(not written, "a database failure remains fail-open to the caller")
check(
    "target_id=map-8" in log_text
    and "correlation_id=corr-8" in log_text
    and secret_message not in log_text
    and secret_detail not in log_text,
    "database-failure logging remains useful without leaking notification content",
)

print("\n== Destructive operation producers ==")
clear_history()
trip_map_id = make_map(alice_id, "Weekend trip")
make_spot(
    trip_map_id,
    "Campground",
    (("camp-a.jpg", "Camp A"), ("camp-b.jpg", "Camp B")),
)
make_spot(trip_map_id, "Viewpoint", (("view.jpg", "View"),))
commit_observations = []
original_notify = backend.notify


def observe_committed_map_delete(*args, **kwargs):
    conn = backend.get_db()
    map_count = conn.execute(
        "SELECT COUNT(*) FROM maps WHERE id=?",
        (trip_map_id,),
    ).fetchone()[0]
    history_count = conn.execute(
        "SELECT COUNT(*) FROM notif_history WHERE user_id=?",
        (alice_id,),
    ).fetchone()[0]
    conn.close()
    commit_observations.append((map_count, history_count))
    return original_notify(*args, **kwargs)


backend.notify = observe_committed_map_delete
try:
    response = alice.delete(f"/maps/{trip_map_id}", headers=alice_headers)
finally:
    backend.notify = original_notify
rows = history_rows(alice_id)
check(
    response.status_code == 200 and commit_observations == [(0, 0)],
    "map notification runs after the committed cascade and before its history insert",
)
check(
    len(rows) == 1
    and rows[0][1:6] == (
        "map.deleted",
        "map",
        str(trip_map_id),
        "Weekend trip",
        "Map “Weekend trip” deleted.",
    )
    and json.loads(rows[0][6]) == {"markers": 2, "photos": 3},
    "map deletion stores one named row with accurate pre-delete child counts",
)
check(
    alice.delete(f"/maps/{trip_map_id}", headers=alice_headers).status_code == 404
    and len(history_rows(alice_id)) == 1,
    "a failed repeated map deletion creates no notification",
)

marker_map_id = make_map(alice_id, "Marker cleanup")
campground_id = make_spot(
    marker_map_id,
    "Campground",
    (("marker-a.jpg", "A"), ("marker-b.jpg", "B")),
)
viewpoint_id = make_spot(marker_map_id, "Viewpoint")
campground_response = alice.delete(
    f"/spots/{campground_id}",
    headers=alice_headers,
)
viewpoint_response = alice.delete(
    f"/spots/{viewpoint_id}",
    headers=alice_headers,
)
marker_rows = history_rows(alice_id)[-2:]
check(
    campground_response.status_code == 200
    and viewpoint_response.status_code == 200
    and [row[1] for row in marker_rows] == ["marker.deleted", "marker.deleted"]
    and [row[4] for row in marker_rows] == ["Campground", "Viewpoint"],
    "two explicit marker deletions create two clear per-object rows",
)
check(
    json.loads(marker_rows[0][6]) == {
        "map_id": marker_map_id,
        "map_label": "Marker cleanup",
        "photos": 2,
    }
    and marker_rows[0][5]
    == "Marker “Campground” deleted from “Marker cleanup”.",
    "marker deletion freezes parent-map context and cascaded photo count",
)

editor_map_id = make_map(alice_id, "Shared cleanup")
editor_spot_id = make_spot(editor_map_id, "Editor marker")
conn = backend.get_db()
conn.execute(
    "INSERT INTO map_shares (map_id, user_id, role, created) "
    "VALUES (?, ?, 'editor', '2026-07-22T00:00:00Z')",
    (editor_map_id, bob_id),
)
conn.commit()
conn.close()
alice_row_count = len(history_rows(alice_id))
response = bob.delete(f"/spots/{editor_spot_id}", headers=bob_headers)
bob_rows = history_rows(bob_id)
check(
    response.status_code == 200
    and len(bob_rows) == 1
    and bob_rows[0][1] == "marker.deleted"
    and bob_rows[0][4] == "Editor marker"
    and len(history_rows(alice_id)) == alice_row_count,
    "an editor deletion notifies the acting user without cross-user fan-out",
)

photo_map_id = make_map(alice_id, "Photo cleanup")
photo_spot_id = make_spot(
    photo_map_id,
    "Survey Start",
    (("overlook.jpg", "Survey overlook"),),
)
response = alice.delete(
    f"/spots/{photo_spot_id}/photos/overlook.jpg",
    headers=alice_headers,
)
photo_row = history_rows(alice_id)[-1]
check(
    response.status_code == 200
    and photo_row[1:6] == (
        "photo.deleted",
        "photo",
        "overlook.jpg",
        "Survey overlook",
        "Photo “Survey overlook” deleted from marker “Survey Start”.",
    ),
    "photo deletion stores its filename, caption label, and clear object message",
)
check(
    json.loads(photo_row[6]) == {
        "map_id": photo_map_id,
        "map_label": "Photo cleanup",
        "marker_id": photo_spot_id,
        "marker_label": "Survey Start",
    },
    "photo deletion freezes marker and map diagnostic context",
)
row_count = len(history_rows(alice_id))
check(
    alice.delete(
        f"/spots/{photo_spot_id}/photos/overlook.jpg",
        headers=alice_headers,
    ).status_code == 404
    and alice.delete("/spots/999999", headers=alice_headers).status_code == 404
    and len(history_rows(alice_id)) == row_count,
    "failed photo and marker deletions create no history rows",
)

fail_open_map_id = make_map(alice_id, "Fail-open deletion")
notify_attempts = []


def reject_notification(*args, **kwargs):
    notify_attempts.append((args, kwargs))
    return False


backend.notify = reject_notification
try:
    response = alice.delete(f"/maps/{fail_open_map_id}", headers=alice_headers)
finally:
    backend.notify = original_notify
conn = backend.get_db()
remaining_map = conn.execute(
    "SELECT COUNT(*) FROM maps WHERE id=?",
    (fail_open_map_id,),
).fetchone()[0]
conn.close()
check(
    response.status_code == 200
    and remaining_map == 0
    and len(notify_attempts) == 1
    and len(history_rows(alice_id)) == row_count,
    "notification failure cannot undo or misreport a committed map deletion",
)

print("\n== Authenticated internal-error producers ==")
clear_history()
records = []


class ListHandler(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())


handler = ListHandler()
backend.LOGGER.addHandler(handler)
response = alice.get("/_test/notif_internal_error", headers=alice_headers)
payload = response.get_json()
rows = history_rows(alice_id)
check(
    response.status_code == 500
    and payload["error"] == "Test operation failed"
    and payload["correlation_id"],
    "the shared internal-error path returns generic text with a correlation id",
)
check(
    len(rows) == 1
    and rows[0][1:5] == (
        "server.error",
        "request",
        "/_test/notif_internal_error",
        "test.internal",
    )
    and rows[0][7] == payload["correlation_id"]
    and json.loads(rows[0][6]) == {
        "area": "test.internal",
        "method": "GET",
        "route": "/_test/notif_internal_error",
    },
    "authenticated explicit 5xx history links sanitized request context to the log id",
)
check(
    any(payload["correlation_id"] in record for record in records)
    and "private internal detail" not in rows[0][5]
    and "private internal detail" not in rows[0][6],
    "exception detail stays in server logging and out of notification content",
)

app.config["PROPAGATE_EXCEPTIONS"] = False
response = alice.get("/_test/notif_unhandled_error", headers=alice_headers)
rows = history_rows(alice_id)
check(
    response.status_code == 500
    and len(rows) == 2
    and rows[-1][1] == "server.error"
    and rows[-1][4] == "request.unhandled"
    and rows[-1][7] == response.get_json()["correlation_id"],
    "an uncaught authenticated exception produces exactly one correlated row",
)
row_count = len(rows)
check(
    app.test_client().get("/_test/notif_unhandled_error").status_code == 401
    and len(history_rows(alice_id)) == row_count,
    "an unauthenticated failure path writes no notification",
)

avatar_bytes = open(
    "/workspace/markervault/public/assets/images/default-user-thumb.png",
    "rb",
).read()
original_replace = backend.os.replace


def fail_avatar_replace(*args, **kwargs):
    raise OSError("forced avatar publish failure")


backend.os.replace = fail_avatar_replace
try:
    response = alice.post(
        "/profile/avatar",
        headers=alice_headers,
        data={"avatar": (io.BytesIO(avatar_bytes), "avatar.png")},
        content_type="multipart/form-data",
    )
finally:
    backend.os.replace = original_replace
rows = history_rows(alice_id)
check(
    response.status_code == 500
    and len(rows) == row_count + 1
    and rows[-1][1] == "server.error"
    and rows[-1][4] == "avatar.save",
    "the former raw avatar 500 now uses the correlated notification path",
)

backend.LOGGER.removeHandler(handler)
source = open(os.path.join(WORK, "backend.py"), encoding="utf-8").read()
internal_areas = set(re.findall(r"internal_error\('([^']+)'", source))
raw_500_returns = [
    line.strip()
    for line in source.splitlines()
    if line.strip().startswith("return jsonify") and line.strip().endswith(", 500")
]
check(
    internal_areas == {
        "avatar.save",
        "import_kml",
        "map.delete",
        "photo.replace",
        "photo.upload",
        "request.unhandled",
        "spot.copy",
    }
    and raw_500_returns
    == ["return jsonify({'error': message, 'correlation_id': correlation_id}), 500"],
    "all explicit 5xx returns are statically centralized in internal_error",
)

print("\n== Per-user retention and ownership ==")
clear_history()
original_cap = backend.NOTIF_HISTORY_CAP
backend.NOTIF_HISTORY_CAP = 3
for item in range(5):
    backend.notify(
        alice_id,
        "marker.deleted",
        f"Alice marker {item} deleted.",
        target_type="marker",
        target_id=str(item),
        target_label=f"Alice {item}",
    )
backend.notify(
    bob_id,
    "marker.deleted",
    "Bob marker retained.",
    target_type="marker",
    target_id="bob-1",
    target_label="Bob marker",
)
backend.NOTIF_HISTORY_CAP = original_cap
alice_retained = history_rows(alice_id)
bob_retained = history_rows(bob_id)
check(
    [row[3] for row in alice_retained] == ["2", "3", "4"],
    "insert-time retention keeps only the user's newest capped rows",
)
check(
    len(bob_retained) == 1 and bob_retained[0][3] == "bob-1",
    "one user's retention sweep never removes another user's history",
)
backend.NOTIF_HISTORY_CAP = 2
shrunk_payload = alice.get("/notif_history", headers=alice_headers).get_json()
backend.NOTIF_HISTORY_CAP = original_cap
check(
    len(shrunk_payload["notifications"]) == 2
    and shrunk_payload["unseen"] == 2
    and len(history_rows(alice_id)) == 2,
    "a read reapplies a lowered cap before calculating the snapshot and badge",
)
conn = backend.get_db()
conn.execute("DELETE FROM users WHERE user_id=?", (bob_id,))
conn.commit()
bob_after_delete = conn.execute(
    "SELECT COUNT(*) FROM notif_history WHERE user_id=?",
    (bob_id,),
).fetchone()[0]
conn.close()
check(bob_after_delete == 0, "deleting a user cascades their private history")

print("\n== Authenticated read and high-water seen API ==")
clear_history()
backend.notify(
    alice_id,
    "map.deleted",
    "Map Alpha deleted.",
    target_type="map",
    target_id="map-alpha",
    target_label="Alpha",
    detail={"markers": 2, "photos": 4},
)
backend.notify(
    alice_id,
    "photo.deleted",
    "Photo Lake deleted.",
    target_type="photo",
    target_id="lake.jpg",
    target_label="Lake",
    detail={"map_id": "map-alpha", "marker_id": "marker-lake"},
)
backend.notify(
    charlie_id,
    "server.error",
    "The server could not complete the request.",
    target_type="request",
    target_id="POST /maps",
    correlation_id="charlie-corr",
)
unauthenticated = app.test_client()
check(
    unauthenticated.get("/notif_history").status_code == 401
    and unauthenticated.post("/notif_history/seen", json={"through_id": 1}).status_code == 401
    and unauthenticated.post("/notif_history/1/seen", json={"seen": True}).status_code == 401,
    "all notification-history routes require authentication",
)
response = alice.get("/notif_history", headers=alice_headers)
payload = response.get_json()
check(
    response.status_code == 200
    and [row["target_id"] for row in payload["notifications"]] == ["lake.jpg", "map-alpha"],
    "full history returns only the owner rows newest first",
)
check(
    payload["unseen"] == 2
    and payload["through_id"] == payload["notifications"][0]["id"]
    and payload["notifications"][1]["detail"] == {"markers": 2, "photos": 4},
    "full history returns its unseen count, snapshot high-water, and decoded detail",
)
check(
    alice.get("/notif_history?summary=1", headers=alice_headers).get_json() == {"unseen": 2},
    "summary mode omits row bodies",
)
check(
    alice.get("/notif_history?summary=yes", headers=alice_headers).status_code == 400,
    "unsupported summary values fail closed",
)
snapshot_through_id = payload["through_id"]
backend.notify(
    alice_id,
    "marker.deleted",
    "Marker Ridge deleted.",
    target_type="marker",
    target_id="marker-ridge",
    target_label="Ridge",
)
response = alice.post(
    "/notif_history/seen",
    headers=alice_headers,
    json={"through_id": snapshot_through_id},
)
check(
    response.status_code == 200 and response.get_json() == {"marked": 2, "unseen": 1},
    "mark-all-seen reports a newer concurrent row as still unseen",
)
alice_after_seen = history_rows(alice_id)
check(
    [row[8] for row in alice_after_seen] == [1, 1, 0],
    "the high-water update marks the rendered snapshot and not the newer row",
)
check(
    alice.post(
        "/notif_history/seen",
        headers=alice_headers,
        json={"through_id": None},
    ).get_json() == {"marked": 0, "unseen": 1}
    and alice.post(
        "/notif_history/seen",
        headers=alice_headers,
        json={"through_id": 0},
    ).get_json() == {"marked": 0, "unseen": 1},
    "null and zero high-water values are explicit no-ops",
)
invalid_seen_bodies = (
    {},
    {"through_id": True},
    {"through_id": "1"},
    {"through_id": -1},
    ["not", "an", "object"],
)
check(
    all(
        alice.post("/notif_history/seen", headers=alice_headers, json=body).status_code == 400
        for body in invalid_seen_bodies
    ),
    "missing and mistyped high-water values return 400",
)
charlie_payload = charlie.get("/notif_history", headers=charlie_headers).get_json()
check(
    len(charlie_payload["notifications"]) == 1
    and charlie_payload["notifications"][0]["correlation_id"] == "charlie-corr"
    and all(row["target_id"] != "marker-ridge" for row in charlie_payload["notifications"]),
    "authenticated reads cannot cross user boundaries",
)
marker_notification_id = next(
    row[0] for row in history_rows(alice_id) if row[3] == "marker-ridge"
)
response = alice.post(
    f"/notif_history/{marker_notification_id}/seen",
    headers=alice_headers,
    json={"seen": True},
)
check(
    response.status_code == 200
    and response.get_json() == {
        "id": marker_notification_id,
        "seen": True,
        "unseen": 0,
    },
    "one owned row can be marked seen and returns the exact unseen count",
)
response = alice.post(
    f"/notif_history/{marker_notification_id}/seen",
    headers=alice_headers,
    json={"seen": True},
)
check(
    response.status_code == 200
    and response.get_json()["unseen"] == 0,
    "setting one row's seen state is idempotent",
)
map_notification_id = next(
    row[0] for row in history_rows(alice_id) if row[3] == "map-alpha"
)
response = alice.post(
    f"/notif_history/{map_notification_id}/seen",
    headers=alice_headers,
    json={"seen": False},
)
check(
    response.status_code == 200
    and response.get_json() == {
        "id": map_notification_id,
        "seen": False,
        "unseen": 1,
    },
    "one owned row can be marked unseen and restores the badge count",
)
charlie_notification_id = charlie_payload["notifications"][0]["id"]
invalid_row_seen_bodies = (
    {},
    {"seen": 1},
    {"seen": "true"},
    ["not", "an", "object"],
)
check(
    all(
        alice.post(
            f"/notif_history/{marker_notification_id}/seen",
            headers=alice_headers,
            json=body,
        ).status_code == 400
        for body in invalid_row_seen_bodies
    )
    and alice.post(
        f"/notif_history/{charlie_notification_id}/seen",
        headers=alice_headers,
        json={"seen": True},
    ).status_code == 404
    and alice.post(
        "/notif_history/999999999/seen",
        headers=alice_headers,
        json={"seen": True},
    ).status_code == 404
    and history_rows(charlie_id)[0][8] == 0,
    "row updates require a boolean and cannot reveal or mutate another user's row",
)
conn = backend.get_db()
conn.execute("DELETE FROM notif_history WHERE user_id=?", (charlie_id,))
conn.commit()
conn.close()
empty_payload = charlie.get("/notif_history", headers=charlie_headers).get_json()
check(
    empty_payload == {"notifications": [], "through_id": None, "unseen": 0},
    "empty history has a null snapshot high-water and zero unseen rows",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
