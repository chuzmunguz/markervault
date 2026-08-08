import os, sys, shutil, tempfile, importlib.util, uuid
from io import BytesIO
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch

WORK = tempfile.mkdtemp(prefix="mv_avatar_")
shutil.copy("/workspace/markervault/backend.py", os.path.join(WORK, "backend.py"))
shutil.copy("/workspace/markervault/markervault_schema.py", os.path.join(WORK, "markervault_schema.py"))
shutil.copy("/workspace/markervault/request_validation.py", os.path.join(WORK, "request_validation.py"))
shutil.copy("/workspace/markervault/username_validation.py",
            os.path.join(WORK, "username_validation.py"))
shutil.copy("/workspace/markervault/markervault_config.py",
            os.path.join(WORK, "markervault_config.py"))
shutil.copy("/workspace/markervault/email_delivery.py",
            os.path.join(WORK, "email_delivery.py"))
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

import bcrypt
from datetime import datetime
from PIL import Image

PASS = FAIL = 0


def check(cond, label):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def make_user(username, password, role="user", status="approved",
              first_name="Alice", last_name="Smith", email="alice@example.com"):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, first_name, last_name, email) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (user_id, username, bcrypt.hashpw(password.encode(), bcrypt.gensalt()),
         role, status, datetime.now().isoformat(), first_name, last_name, email)
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def login(username, password):
    client = app.test_client()
    lr = client.post("/login", json={"username": username, "password": password})
    rr = client.post("/auth/refresh")
    return client, lr, rr


def H(token):
    return {"Authorization": f"Bearer {token}"}


def image_upload(fmt, color, size, filename):
    payload = BytesIO()
    Image.new("RGB", size, color).save(payload, format=fmt)
    payload.seek(0)
    return payload, filename


alice_id = make_user("alice", "Alice123!")
boss_id = make_user("boss", "Boss1234!", "super_admin", "approved",
                    "Boss", "Admin", "boss@example.com")
alice, login_response, refresh_response = login("alice", "Alice123!")
token = refresh_response.get_json()["access_token"]
boss, _, boss_refresh = login("boss", "Boss1234!")
boss_token = boss_refresh.get_json()["access_token"]
anon = app.test_client()

print("\n== 1. Schema, folder, and initial response contract ==")
conn = backend.get_db()
columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
audit_before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
conn.close()
check("avatar" in columns, "users.avatar column exists")
check(os.path.isdir(backend.AVATARS_FOLDER), "avatars folder is created at boot")
profile = alice.get("/profile", headers=H(token)).get_json()
check(profile.get("avatar_url") is None, "GET /profile initially returns avatar_url null")
check(refresh_response.get_json().get("avatar_url") is None,
      "auth refresh initially returns avatar_url null")

print("\n== 2. PNG upload is normalized and stored ==")
first_upload = image_upload("PNG", "red", (420, 180), "portrait.png")
r = alice.post("/profile/avatar", headers=H(token),
               data={"avatar": first_upload}, content_type="multipart/form-data")
uploaded = r.get_json()
avatar_url = uploaded.get("avatar_url", "")
filename = f"{alice_id}.jpg"
avatar_path = os.path.join(backend.AVATARS_FOLDER, filename)
check(r.status_code == 200 and uploaded.get("success") is True and avatar_url,
      f"PNG upload -> success + signed URL (got {r.status_code})")
conn = backend.get_db()
stored_avatar = conn.execute(
    "SELECT avatar FROM users WHERE user_id = ?", (alice_id,)
).fetchone()[0]
conn.close()
check(stored_avatar == filename, f"database stores stable filename ({stored_avatar})")
check(os.path.isfile(avatar_path), "avatar file exists")
with Image.open(avatar_path) as normalized:
    normalized_shape = (normalized.format, normalized.size, normalized.mode)
check(normalized_shape == ("JPEG", (256, 256), "RGB"),
      f"avatar is 256x256 RGB JPEG ({normalized_shape})")
first_bytes = open(avatar_path, "rb").read()

print("\n== 3. Signed avatar URL is public and appears in both response bodies ==")
r = anon.get(avatar_url)
check(r.status_code == 200, f"tokenless signed avatar GET -> 200 (got {r.status_code})")
check(r.headers.get("X-Accel-Redirect") == f"/internal_avatars/{filename}"
      and r.headers.get("Content-Type") == "image/jpeg",
      "avatar serving returns the nginx redirect and JPEG content type")
check(r.headers.get("Cache-Control") == "private, max-age=1800",
      "avatar responses are browser-cacheable for the URL-stability window")
profile_url = alice.get("/profile", headers=H(token)).get_json().get("avatar_url")
check(profile_url and urlparse(profile_url).path == f"/avatars/{filename}",
      "GET /profile returns a signed avatar URL")
refreshed = alice.post("/auth/refresh").get_json()
check(refreshed.get("avatar_url")
      and urlparse(refreshed["avatar_url"]).path == f"/avatars/{filename}",
      "auth refresh returns a signed avatar URL")

print("\n== 3b. Administration and sharing payloads carry avatar URLs ==")
admin_row = next(u for u in boss.get("/admin/users", headers=H(boss_token)).get_json()
                 if u["user_id"] == alice_id)
check(urlparse(admin_row["avatar_url"]).path == f"/avatars/{filename}",
      "active administration user payload carries the avatar URL")
pending_id = make_user("pending", "Pending1!", "user", "pending",
                       "Pending", "Person", "pending@example.com")
conn = backend.get_db()
conn.execute("UPDATE users SET avatar = ? WHERE user_id = ?", (filename, pending_id))
conn.commit()
conn.close()
pending_row = next(u for u in boss.get("/admin/users", headers=H(boss_token)).get_json()
                   if u["user_id"] == pending_id)
check(pending_row["avatar_url"] is None,
      "pending self-registration payload suppresses avatars")
share_user = next(u for u in boss.get("/users", headers=H(boss_token)).get_json()
                  if u["user_id"] == alice_id)
check(urlparse(share_user["avatar_url"]).path == f"/avatars/{filename}",
      "map share picker payload carries the avatar URL")
map_id = boss.post("/maps", headers=H(boss_token), json={"name": "Shared"}).get_json()["id"]
boss.put(f"/maps/{map_id}/collaborators", headers=H(boss_token),
         json={"username": "alice", "role": "viewer"})
collaborator = boss.get(
    f"/maps/{map_id}/collaborators", headers=H(boss_token)
).get_json()[0]
check(urlparse(collaborator["avatar_url"]).path == f"/avatars/{filename}",
      "current map collaborator payload carries the avatar URL")
group_id = boss.post(
    "/admin/groups", headers=H(boss_token), json={"name": "Avatar Team"}
).get_json()["id"]
boss.put(f"/admin/groups/{group_id}/members", headers=H(boss_token),
         json={"username": "alice"})
group = next(g for g in boss.get("/admin/groups", headers=H(boss_token)).get_json()
             if g["id"] == group_id)
check(urlparse(group["members"][0]["avatar_url"]).path == f"/avatars/{filename}",
      "share-group member payload carries the avatar URL")
# The setup above intentionally emits map/group governance audit rows. Reset the
# baseline so the final assertion remains specifically about avatar operations.
conn = backend.get_db()
audit_before = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
conn.close()

print("\n== 3c. URLs are stable within a bucket; v is the content version ==")
stable_a = alice.get("/profile", headers=H(token)).get_json()["avatar_url"]
stable_b = alice.get("/profile", headers=H(token)).get_json()["avatar_url"]
check(stable_a == stable_b,
      "consecutive issuances mint byte-identical URLs (browser cache serves re-renders)")
stable_q = parse_qs(urlparse(stable_a).query)
check(stable_q["v"][0] == str(os.stat(avatar_path).st_mtime_ns),
      "v equals the avatar file's mtime_ns (moves only on re-upload)")
_now = int(backend.time.time())
_exp = int(stable_q["exp"][0])
check(_exp % (backend.PHOTO_URL_TTL // 2) == 0 and _now < _exp <= _now + backend.PHOTO_URL_TTL,
      "exp sits on a half-TTL bucket boundary within (now, now+TTL]")

print("\n== 4. Signature failures are rejected ==")
query = parse_qs(urlparse(avatar_url).query)
exp = query["exp"][0]
uid = query["uid"][0]
check(anon.get(
    f"/avatars/{filename}?exp={exp}&uid={uid}&sig=TAMPERED"
).status_code == 403, "tampered signature -> 403")
with patch.object(backend.time, "time", return_value=1):
    expired_url = backend.sign_photo_url("avatars", filename, alice_id)
check(anon.get(expired_url).status_code == 403, "correct but expired signature -> 403")
check(anon.get(f"/avatars/{filename}").status_code == 403,
      "missing signature parameters -> 403")

print("\n== 5. Re-upload overwrites the one stable file ==")
second_upload = image_upload("GIF", "blue", (180, 420), "replacement.gif")
r = alice.post("/profile/avatar", headers=H(token),
               data={"avatar": second_upload}, content_type="multipart/form-data")
second_url = r.get_json().get("avatar_url", "")
check(r.status_code == 200 and urlparse(second_url).path == f"/avatars/{filename}"
      and second_url != avatar_url,
      "GIF re-upload keeps the stable filename but returns a fresh cache-busting URL")
check(parse_qs(urlparse(second_url).query)["v"][0] != stable_q["v"][0],
      "re-upload bumps the v content version, forcing an image reload")
second_bytes = open(avatar_path, "rb").read()
check(second_bytes != first_bytes, "re-upload replaces the file contents")

print("\n== 6. Invalid uploads fail without damaging the current avatar ==")
r = alice.post("/profile/avatar", headers=H(token),
               data={"avatar": (BytesIO(b"not an image"), "broken.png")},
               content_type="multipart/form-data")
check(r.status_code == 400, "garbage image body -> 400")
conn = backend.get_db()
after_bad = conn.execute(
    "SELECT avatar FROM users WHERE user_id = ?", (alice_id,)
).fetchone()[0]
conn.close()
check(open(avatar_path, "rb").read() == second_bytes and after_bad == filename,
      "garbage upload preserves the existing file and DB value")
wrong_extension = image_upload("PNG", "green", (32, 32), "avatar.webp")
check(alice.post("/profile/avatar", headers=H(token),
                 data={"avatar": wrong_extension},
                 content_type="multipart/form-data").status_code == 400,
      "unsupported filename extension -> 400")
check(alice.post("/profile/avatar", headers=H(token),
                 data={}, content_type="multipart/form-data").status_code == 400,
      "missing multipart avatar field -> 400")
oversized = BytesIO(b"x" * (app.config["MAX_CONTENT_LENGTH"] + 1))
check(alice.post("/profile/avatar", headers=H(token),
                 data={"avatar": (oversized, "huge.png")},
                 content_type="multipart/form-data").status_code == 413,
      "request above MAX_CONTENT_LENGTH -> 413")
check(anon.post("/profile/avatar",
                data={"avatar": image_upload("PNG", "black", (16, 16), "anon.png")},
                content_type="multipart/form-data").status_code == 401,
      "upload without a Bearer token -> 401")

print("\n== 7. Delete clears storage and invalidates old signed URLs ==")
r = alice.delete("/profile/avatar", headers=H(token))
check(r.status_code == 200 and r.get_json().get("success") is True,
      "DELETE /profile/avatar -> success")
conn = backend.get_db()
deleted_value = conn.execute(
    "SELECT avatar FROM users WHERE user_id = ?", (alice_id,)
).fetchone()[0]
audit_after = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
conn.close()
check(deleted_value is None and not os.path.exists(avatar_path),
      "delete NULLs the column and removes the file")
check(alice.get("/profile", headers=H(token)).get_json().get("avatar_url") is None,
      "GET /profile returns avatar_url null after delete")
check(anon.get(second_url).status_code == 404,
      "previously valid signed URL -> 404 after delete")
check(anon.delete("/profile/avatar").status_code == 401,
      "delete without a Bearer token -> 401")
check(audit_after == audit_before,
      "avatar upload/re-upload/delete emit no audit rows")

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
