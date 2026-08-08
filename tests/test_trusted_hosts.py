import importlib.util
import os
import shutil
import sys
import tempfile


WORK = tempfile.mkdtemp(prefix="mv_hosts_")
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
os.environ["MARKERVAULT_TEMPORARY_LAN_HOSTS"] = "markervault.lan,192.168.1.50"

spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)

backend.COOKIE_SECURE = False
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


def status(host, path="/maps"):
    client = app.test_client()
    response = client.get(path, headers={"Host": host})
    return response.status_code


print("== Development allowlist ==")
check(
    backend.ALLOWED_HOSTS
    == ("markervault.lan", "192.168.1.50", "localhost", "127.0.0.1", "::1"),
    "backend exposes the configured allowlist plus development loopback",
)
check(status("localhost") == 401, "loopback test-client host reaches the route gate")
check(status("localhost:5000") == 401, "host port is ignored for the allowlist match")
check(status("markervault.lan") == 401, "configured LAN hostname is accepted")
check(status("MarkerVault.LAN") == 401, "host matching is case-insensitive")
check(status("markervault.lan.") == 401, "a trailing FQDN dot is normalized")
check(status("192.168.1.50") == 401, "configured LAN IP address is accepted")
check(status("[::1]:5000") == 401, "bracketed IPv6 loopback is accepted in development")

print("\n== Unrecognized hosts ==")
rejected = app.test_client().get("/maps", headers={"Host": "evil.example"})
check(rejected.status_code == 421, "an unknown host is rejected with 421")
check(
    rejected.get_json() == {"error": "Unrecognized request host"},
    "the rejection is a stable JSON error",
)
check(
    status("markervault.lan.evil.example") == 421,
    "a suffix-spoofed hostname is rejected",
)
check(status("") == 421, "an empty host is rejected")
check(
    app.test_client().post(
        "/login",
        headers={"Host": "evil.example"},
        json={"username": "nobody", "password": "wrong"},
    ).status_code == 421,
    "the gate also covers public unauthenticated routes",
)
check(
    app.test_client().post(
        "/auth/refresh",
        headers={"Host": "evil.example"},
    ).status_code == 421,
    "the gate covers the refresh endpoint before cookie handling",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
