import os, sys, shutil, tempfile, importlib.util, uuid
from io import BytesIO
from urllib.parse import urlparse, parse_qs

WORK = tempfile.mkdtemp(prefix="mv_p4_")
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
from PIL import Image

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

def parse_signed(url):
    q = parse_qs(urlparse(url).query)
    return q.get('exp',[None])[0], q.get('sig',[None])[0]

# Setup: alice owns a map+spot+photo; bob is outsider then shared viewer; admin; dave outsider
alice_id = make_user("alice","Alice123!","user","approved")
bob_id   = make_user("bob","Bob12345!","user","approved")
admin_id = make_user("admin","Admin123!","admin","approved")
for uid in (alice_id, bob_id, admin_id): backend.create_base_map(uid)

alice, alice_t = login("alice","Alice123!")
bob, bob_t     = login("bob","Bob12345!")
admin, admin_t = login("admin","Admin123!")

m = alice.post("/maps", headers=H(alice_t), json={"name":"PhotoMap"}).get_json()
map_id = m["id"]
s = alice.post("/spots", headers=H(alice_t), json={"mapID":map_id,"name":"s","lat":1,"lng":1}).get_json()
spot_id = s["id"]
# Insert a photo row directly (skip real image upload)
FN = "pic_" + uuid.uuid4().hex + ".jpg"
conn = backend.get_db(); conn.execute("INSERT INTO photos (spot_id, filename, caption) VALUES (?,?,?)", (spot_id, FN, "cap")); conn.commit(); conn.close()

# A tokenless client to simulate a browser <img src> (no Authorization header)
anon = app.test_client()

print("\n== 1. get_photos returns signed photo_url + thumb_url (with uid) ==")
photos = alice.get(f"/spots/{spot_id}/photos", headers=H(alice_t)).get_json()
p = photos[0]
check('sig=' in p['photo_url'] and 'exp=' in p['thumb_url'] and 'uid=' in p['photo_url'],
      f"signed urls present w/ uid ({p.get('photo_url','')[:50]}...)")
photos_again = alice.get(f"/spots/{spot_id}/photos", headers=H(alice_t)).get_json()
check(photos_again[0]['photo_url'] == p['photo_url']
      and photos_again[0]['thumb_url'] == p['thumb_url'],
      "photo and thumb URLs are stable within the signature bucket")

print("\n== 2. ★ Image loads with NO Bearer header (the actual bug) -> 200 + X-Accel ==")
r = anon.get(p['photo_url'])   # NO auth header, like a real <img src>
check(r.status_code == 200, f"tokenless GET photo_url -> 200 (got {r.status_code})")
check(r.headers.get('X-Accel-Redirect') == f"/internal_photos/{FN}", f"X-Accel-Redirect correct ({r.headers.get('X-Accel-Redirect')})")
check(r.headers.get('Content-Type') == 'image/jpeg', f"Content-Type is image/jpeg not text/html (got {r.headers.get('Content-Type')})")
check(r.headers.get('Cache-Control') == 'private, max-age=1800',
      "photo response is privately browser-cacheable for the URL-stability window")
rt = anon.get(p['thumb_url'])
check(rt.status_code == 200 and rt.headers.get('X-Accel-Redirect') == f"/internal_thumbs/{FN}", "tokenless thumb -> 200 + X-Accel")
check(rt.headers.get('Cache-Control') == 'private, max-age=1800',
      "thumb response is privately browser-cacheable for the URL-stability window")

print("\n== 3. Tampered / missing / expired / tampered-uid rejected ==")
exp, sig = parse_signed(p['photo_url'])
check(anon.get(f"/photos/{FN}?exp={exp}&uid={alice_id}&sig=TAMPERED").status_code == 403, "tampered sig -> 403")
check(anon.get(f"/photos/{FN}").status_code == 403, "no query at all -> 403")
check(anon.get(f"/photos/{FN}?exp=1&uid={alice_id}&sig={sig}").status_code == 403, "expired exp -> 403")
# swapping uid in the URL breaks the signature (sig was computed over alice's uid)
check(anon.get(f"/photos/{FN}?exp={exp}&uid={bob_id}&sig={sig}").status_code == 403, "swapped uid breaks sig -> 403")

print("\n== 4. A URL signed for bob (outsider, no access) -> 403 on map check ==")
with app.test_request_context():
    bob_url = backend.sign_photo_url('photos', FN, bob_id)  # valid sig for bob, but bob has no map access
check(anon.get(bob_url).status_code == 403, "valid-sig-for-outsider -> 403 (map access re-checked)")

print("\n== 5. Share with bob as viewer -> bob's signed URL now works tokenlessly ==")
alice.put(f"/maps/{map_id}/collaborators", headers=H(alice_t), json={"username":"bob","role":"viewer"})
bphotos = bob.get(f"/spots/{spot_id}/photos", headers=H(bob_t)).get_json()
check(isinstance(bphotos, list) and bphotos, "viewer bob can list photos")
if bphotos:
    r = anon.get(bphotos[0]['photo_url'])  # tokenless, like <img src>
    check(r.status_code == 200, f"viewer bob's signed photo loads tokenlessly -> 200 (got {r.status_code})")

print("\n== 6. Unshare revokes even within the URL's TTL ==")
alice.delete(f"/maps/{map_id}/collaborators/{bob_id}", headers=H(alice_t))
if bphotos:
    r = anon.get(bphotos[0]['photo_url'])  # same still-unexpired URL
    check(r.status_code == 403, f"bob's still-valid-sig URL -> 403 after unshare (got {r.status_code})")

print("\n== 7. Admin has no photo access to other users' maps (no bypass) ==")
r = admin.get(f"/spots/{spot_id}/photos", headers=H(admin_t))
check(r.status_code == 404, f"admin GET alice's spot photos -> 404 (got {r.status_code})")

print("\n== 8. Nonexistent file with a valid-shaped sig -> 404 ==")
with app.test_request_context():
    ghost = backend.sign_photo_url('photos', 'ghost.jpg', alice_id)
check(anon.get(ghost).status_code == 404, "signed URL for missing photo -> 404")

print("\n== 9. Replacement accepts the original stored name and assigns a fresh UUID name ==")
replacement = BytesIO()
Image.new("RGB", (12, 8), color="purple").save(replacement, format="JPEG")
replacement.seek(0)
r = alice.put(
    f"/spots/{spot_id}/photos/{FN}",
    headers=H(alice_t),
    data={"photo": (replacement, FN)},
    content_type="multipart/form-data",
)
replacement_data = r.get_json()
replacement_name = replacement_data.get("filename", "") if replacement_data else ""
check(
    r.status_code == 200 and replacement_name and replacement_name != FN,
    f"same-name replacement succeeds with a fresh stored name (got {r.status_code})",
)
conn = backend.get_db()
stored_name = conn.execute(
    "SELECT filename FROM photos WHERE spot_id = ?",
    (spot_id,),
).fetchone()[0]
conn.close()
check(
    stored_name == replacement_name
    and os.path.isfile(os.path.join(backend.PHOTOS_FOLDER, replacement_name))
    and os.path.isfile(os.path.join(backend.THUMBS_FOLDER, replacement_name)),
    "replacement database row, photo, and thumbnail use the fresh name",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
