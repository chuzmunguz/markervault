import importlib.util
import subprocess
import sys

from pathlib import Path


ROOT = Path("/workspace/markervault")
GUARD_PATH = ROOT / "tools" / "check_repository_artifacts.py"
spec = importlib.util.spec_from_file_location("artifact_guard", GUARD_PATH)
artifact_guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact_guard)

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


for path in (
    ".env",
    "nested/.env.local",
    "avatars/example.jpg",
    "cache.sqlite3-journal",
    "logs/app.log",
    "photos/example.jpg",
    "secret.pem",
    "spots.db",
    "spots.db-wal",
    "temp/import.kml",
    "tests/ui_audit.png",
    "tests/pw-test/audit.png",
    "tests/venv/bin/python",
):
    check(artifact_guard.forbidden_artifact(path), f"guard rejects {path}")

for path in (
    ".env.example",
    "public/assets/images/default-user-thumb.png",
):
    check(not artifact_guard.forbidden_artifact(path), f"guard preserves {path}")

private_key = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key"
aws_key = "prefix AKIAABCDEFGHIJKLMNOP suffix"
literal_secret = 'secret = "this-is-a-long-secret-value"'
check(
    "private key" in artifact_guard.secret_matches(private_key),
    "guard detects private-key material",
)
check(
    "AWS access key" in artifact_guard.secret_matches(aws_key),
    "guard detects AWS access keys",
)
check(
    "literal credential assignment" in artifact_guard.secret_matches(literal_secret),
    "guard detects literal credential assignments",
)
check(
    not artifact_guard.secret_matches("secret = os.environ.get('SECRET')"),
    "guard permits environment-backed credentials",
)

result = subprocess.run(
    (sys.executable, str(GUARD_PATH), "--root", str(ROOT)),
    check=False,
    capture_output=True,
    text=True,
)
check(result.returncode == 0, "live repository passes artifact guard")
if result.stdout.strip():
    print(result.stdout.strip())
if result.stderr.strip():
    print(result.stderr.strip())

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
