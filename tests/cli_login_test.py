"""Create a real CLI user in an isolated DB, then verify backend login/profile."""
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile


WORK = tempfile.mkdtemp(prefix="mv_cli_login_")
env = os.environ.copy()
env["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64
env["MARKERVAULT_DB_PATH"] = os.path.join(WORK, "spots.db")

created = subprocess.run(
    [
        sys.executable,
        "/workspace/markervault/create_users.py",
        "--username", "boss",
        "--password", "Boss1234!",
        "--role", "admin",
        "--first-name", "Boss",
        "--last-name", "User",
        "--email", "boss@acme.com",
    ],
    cwd=WORK,
    env=env,
    text=True,
    capture_output=True,
)
assert created.returncode == 0, created.stderr or created.stdout

os.chdir(WORK)
module_dir = os.getcwd()
os.environ["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64
shutil.copy("/workspace/markervault/backend.py", "backend.py")
shutil.copy("/workspace/markervault/markervault_schema.py", "markervault_schema.py")
shutil.copy("/workspace/markervault/request_validation.py", "request_validation.py")
shutil.copy("/workspace/markervault/username_validation.py", "username_validation.py")
shutil.copy("/workspace/markervault/markervault_config.py", "markervault_config.py")
shutil.copy("/workspace/markervault/email_delivery.py", "email_delivery.py")
if module_dir not in sys.path:
    sys.path.insert(0, module_dir)

spec = importlib.util.spec_from_file_location("backend", os.path.join(module_dir, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)
backend.COOKIE_SECURE = False
backend.rate_limit = lambda *a, **k: None

app = backend.app
app.testing = True
cl = app.test_client()
r = cl.post("/login", json={"username": "boss", "password": "Boss1234!"})
print("login status:", r.status_code)
rr = cl.post("/auth/refresh")
j = rr.get_json()
print("refresh:", j.get("username"), j.get("role"), j.get("first_name"), j.get("last_name"))
tok = j["access_token"]
p = cl.get("/profile", headers={"Authorization": f"Bearer {tok}"}).get_json()
conn = backend.get_db()
verified_at = conn.execute(
    "SELECT email_verified_at FROM users WHERE username='boss'"
).fetchone()[0]
conn.close()
print("profile email:", p.get("email"))
assert (
    r.status_code == 200
    and j.get("role") == "admin"
    and p.get("email") == "boss@acme.com"
    and verified_at is not None
)
print("OK: CLI-created user logs in with a verified email+name")

# Stage 7 cutover: with the service environment loaded, the CLI provisions the
# configured external database directory and never touches a working-directory DB.
EXTERNAL_WORK = tempfile.mkdtemp(prefix="mv_cli_external_")
external_db = os.path.join(EXTERNAL_WORK, "runtime", "db", "spots.db")
external_env = env.copy()
external_env["MARKERVAULT_DB_PATH"] = external_db
external = subprocess.run(
    [
        sys.executable,
        "/workspace/markervault/create_users.py",
        "--username", "external",
        "--password", "Ext1234!x",
        "--role", "user",
        "--first-name", "External",
        "--last-name", "Path",
        "--email", "external@acme.com",
    ],
    cwd=EXTERNAL_WORK,
    env=external_env,
    text=True,
    capture_output=True,
)
assert external.returncode == 0, external.stderr or external.stdout
assert os.path.isfile(external_db), "CLI must provision the configured external DB path"
assert not os.path.exists(os.path.join(EXTERNAL_WORK, "spots.db")), \
    "CLI must not create a stray working-directory spots.db"
print("OK: CLI provisions the configured external DB without a stray working-directory DB")

# No env file and no MARKERVAULT_DB_PATH means nothing configures a database, so the
# CLI must refuse rather than silently create a stray working-directory spots.db.
NO_DB_WORK = tempfile.mkdtemp(prefix="mv_cli_nodb_")
no_db_env = os.environ.copy()
no_db_env["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64
no_db_env.pop("MARKERVAULT_DB_PATH", None)
refused = subprocess.run(
    [
        sys.executable,
        "/workspace/markervault/create_users.py",
        "--username", "nobody",
        "--password", "Nobody12!",
        "--role", "user",
        "--first-name", "No",
        "--last-name", "Body",
        "--email", "nobody@acme.com",
    ],
    cwd=NO_DB_WORK,
    env=no_db_env,
    text=True,
    capture_output=True,
)
assert refused.returncode != 0, "CLI must refuse when no database is configured"
assert not os.path.exists(os.path.join(NO_DB_WORK, "spots.db")), \
    "CLI must not create a database when it refuses"
print("OK: CLI refuses to run when no env file and no MARKERVAULT_DB_PATH configure a database")
