"""Stage 12 account lifecycle: disabled compatibility and enabled email flows."""
import importlib.util
import json
import os
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import uuid

import bcrypt


WORK = tempfile.mkdtemp(prefix="mv_account_lifecycle_")
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

for name in tuple(os.environ):
    if name.startswith("MARKERVAULT_"):
        del os.environ[name]
os.environ.update({
    "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
    "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
    "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION": "true",
    "MARKERVAULT_PUBLIC_ORIGIN": "http://localhost",
    "MARKERVAULT_SMTP_HOST": "127.0.0.1",
    "MARKERVAULT_SMTP_SECURITY": "plaintext",
    "MARKERVAULT_SMTP_FROM_ADDRESS": "markervault@example.test",
    "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL": "true",
})

spec = importlib.util.spec_from_file_location("backend", os.path.join(WORK, "backend.py"))
backend = importlib.util.module_from_spec(spec)
sys.modules["backend"] = backend
spec.loader.exec_module(backend)
backend.COOKIE_SECURE = False
backend.rate_limit = lambda *args, **kwargs: None
app = backend.app
app.testing = True


class CapturingSender:
    def __init__(self):
        self.messages = []
        self.fail = False

    def send(self, recipient, content):
        if self.fail:
            raise backend.EmailDeliveryError("generic delivery failure")
        self.messages.append((recipient, content))


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 localhost MarkerVault lifecycle SMTP\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("ascii", errors="replace").rstrip("\r\n")
            upper = command.upper()
            if upper.startswith("EHLO"):
                self.wfile.write(b"250-localhost\r\n250 SIZE 1048576\r\n")
            elif upper == "DATA":
                self.wfile.write(b"354 end with dot\r\n")
                message = bytearray()
                while True:
                    data_line = self.rfile.readline()
                    if data_line in (b".\n", b".\r\n", b""):
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    message.extend(data_line)
                self.server.messages.append(bytes(message))
                self.wfile.write(b"250 queued\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 goodbye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), SMTPHandler)
        self.messages = []


sender = CapturingSender()
backend.EMAIL_SENDER = sender

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS
    global FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


def registration(username, email):
    return {
        "username": username,
        "password": "Account1!",
        "first_name": username.capitalize(),
        "last_name": "Tester",
        "email": email,
    }


def token_from_last(fragment):
    match = re.search(rf"#{fragment}=([A-Za-z0-9_-]+)", sender.messages[-1][1].text_body)
    return match.group(1) if match else None


def user_row(username):
    conn = backend.get_db()
    row = conn.execute(
        "SELECT user_id, status, email, email_verified_at, password_hash "
        "FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()
    return row


def token_row(user_id, purpose):
    conn = backend.get_db()
    row = conn.execute(
        "SELECT token_hash, target_email, created, expires "
        "FROM account_tokens WHERE user_id=? AND purpose=?",
        (user_id, purpose),
    ).fetchone()
    conn.close()
    return row


def make_user(username, role="user", status="approved", verified=True):
    user_id = str(uuid.uuid4())
    conn = backend.get_db()
    conn.execute(
        "INSERT INTO users "
        "(user_id, username, password_hash, role, status, created, "
        "first_name, last_name, email, email_verified_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            user_id,
            username,
            bcrypt.hashpw(b"Account1!", bcrypt.gensalt()),
            role,
            status,
            "2026-07-24T00:00:00Z",
            username.capitalize(),
            "Tester",
            f"{username}@example.test",
            "2026-07-24T00:00:00Z" if verified else None,
        ),
    )
    conn.commit()
    conn.close()
    backend.create_base_map(user_id)
    return user_id


def login(username, password="Account1!"):
    client = app.test_client()
    login_response = client.post(
        "/login",
        json={"username": username, "password": password},
    )
    if login_response.status_code != 200:
        return client, login_response, None
    refresh = client.post("/auth/refresh")
    token = refresh.get_json().get("access_token") if refresh.status_code == 200 else None
    return client, login_response, token


def headers(token):
    return {"Authorization": f"Bearer {token}"}


print("\n== Schema and mode contract ==")
conn = backend.get_db()
tables = {
    row[0]
    for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
}
columns = {
    row[1]
    for row in conn.execute("PRAGMA table_info(users)").fetchall()
}
conn.close()
check("account_tokens" in tables and "email_verified_at" in columns,
      "canonical schema contains verification state and account tokens")
capabilities = app.test_client().get("/account-capabilities").get_json()
check(capabilities == {"email_account_flows": True},
      "public capability response reflects enabled mode")

print("\n== Registration, resend, verification, and approval ==")
client = app.test_client()
response = client.post("/register", json=registration("alice", "alice@example.test"))
alice = user_row("alice")
verification_one = token_from_last("verify-email")
stored = token_row(alice[0], "email_verification")
check(
    response.status_code == 200
    and response.get_json() == {
        "success": True,
        "email_sent": True,
        "message": "Registration received. Verify your email.",
    },
    "enabled registration reports delivery without a premature approval message",
)
check(alice[1] == "pending" and alice[3] is None,
      "enabled self-registration remains pending and unverified")
check(
    stored is not None
    and stored[0] == backend._account_token_hash(verification_one)
    and verification_one not in stored,
    "verification token is stored only as a hash",
)
login_response = app.test_client().post(
    "/login",
    json={"username": "alice", "password": "Account1!"},
)
check(login_response.status_code == 403 and "verification" in login_response.get_json()["error"].lower(),
      "unverified registration cannot log in")

message_count = len(sender.messages)
cooldown_response = client.post(
    "/email-verification/resend",
    json={"email": "alice@example.test"},
)
check(
    cooldown_response.status_code == 200 and len(sender.messages) == message_count,
    "verification resend cooldown returns generically without another delivery",
)

conn = backend.get_db()
conn.execute(
    "UPDATE account_tokens SET created=0 WHERE user_id=? AND purpose='email_verification'",
    (alice[0],),
)
conn.commit()
conn.close()
resend_response = client.post(
    "/email-verification/resend",
    json={"email": "alice@example.test"},
)
verification_two = token_from_last("verify-email")
check(resend_response.status_code == 200 and verification_two != verification_one,
      "resend issues a new verification token after cooldown")
check(
    client.post(
        "/email-verification/confirm",
        json={"token": verification_one},
    ).status_code == 400,
    "newest verification token invalidates the previous token",
)
verify_response = client.post(
    "/email-verification/confirm",
    json={"token": verification_two},
)
alice = user_row("alice")
check(
    verify_response.status_code == 200
    and verify_response.get_json()["message"] == (
        "Email verified. An administrator must approve your account before "
        "you can log in."
    )
    and alice[3] is not None
    and token_row(alice[0], "email_verification") is None,
    "verification marks the email and introduces the administrator approval step",
)
check(
    client.post(
        "/email-verification/confirm",
        json={"token": verification_two},
    ).status_code == 400,
    "verification token is single-use",
)
check(
    app.test_client().post(
        "/login",
        json={"username": "alice", "password": "Account1!"},
    ).status_code == 403,
    "verified registration still waits for administrator approval",
)

super_id = make_user("rootadmin", role="super_admin")
admin_client, _, admin_token = login("rootadmin")
admin_create = admin_client.post(
    "/admin/users/create",
    headers=headers(admin_token),
    json={
        "username": "adminmade",
        "password": "Account1!",
        "first_name": "Admin",
        "last_name": "Made",
        "email": "adminmade@example.test",
        "role": "user",
    },
)
adminmade = user_row("adminmade")
check(
    admin_create.status_code == 200
    and adminmade[1] == "approved"
    and adminmade[3] is not None,
    "admin-created account is approved and verified automatically",
)
approve = admin_client.post(
    f"/admin/users/{alice[0]}/approve",
    headers=headers(admin_token),
)
check(approve.status_code == 200, "verified registration can be approved normally")
alice_client, alice_login, alice_token = login("alice")
check(alice_login.status_code == 200 and alice_token,
      "verified and approved registration can log in")

print("\n== Explicit admin bypass ==")
response = client.post("/register", json=registration("bypass", "bypass@example.test"))
bypass = user_row("bypass")
blocked = admin_client.post(
    f"/admin/users/{bypass[0]}/approve",
    headers=headers(admin_token),
)
allowed = admin_client.post(
    f"/admin/users/{bypass[0]}/approve",
    headers=headers(admin_token),
    json={"bypass_verification": True},
)
bypass = user_row("bypass")
check(blocked.status_code == 409 and allowed.status_code == 200,
      "admin approval requires an explicit bypass for an unverified address")
check(bypass[1] == "approved" and bypass[3] is not None,
      "admin bypass marks the account verified and approved")
conn = backend.get_db()
bypass_detail = conn.execute(
    "SELECT detail FROM audit_log "
    "WHERE action='user.approve' AND target_id=? ORDER BY id DESC LIMIT 1",
    (bypass[0],),
).fetchone()
conn.close()
check(
    bypass_detail is not None
    and json.loads(bypass_detail[0]).get("verification_bypassed") is True,
    "admin approval bypass is explicit in the audit record",
)
admin_profile = {
    "username": "bypass",
    "first_name": "Bypass",
    "last_name": "Tester",
    "email": "bypass-admin@example.test",
}
blocked_edit = admin_client.put(
    f"/admin/users/{bypass[0]}/profile",
    headers=headers(admin_token),
    json=admin_profile,
)
allowed_edit = admin_client.put(
    f"/admin/users/{bypass[0]}/profile",
    headers=headers(admin_token),
    json={**admin_profile, "bypass_verification": True},
)
check(
    blocked_edit.status_code == 409
    and allowed_edit.status_code == 200
    and user_row("bypass")[2] == "bypass-admin@example.test",
    "admin email edits also require and honor an explicit verification bypass",
)

print("\n== Pending self-service email change ==")
profile_response = alice_client.put(
    "/profile",
    headers=headers(alice_token),
    json={
        "first_name": "Alice",
        "last_name": "Tester",
        "email": "alice-new@example.test",
    },
)
profile = profile_response.get_json()
alice_before_confirm = user_row("alice")
email_change_token = token_from_last("verify-email")
check(
    profile_response.status_code == 200
    and profile["email"] == "alice@example.test"
    and profile["pending_email"] == "alice-new@example.test",
    "self-service email change keeps the active address and exposes the pending address",
)
check(alice_before_confirm[2] == "alice@example.test" and alice_before_confirm[3] is not None,
      "current verified email remains active until confirmation")
pending_hash = token_row(alice[0], "email_verification")[0]
profile_refresh = alice_client.put(
    "/profile",
    headers=headers(alice_token),
    json={
        "first_name": "Alicia",
        "last_name": "Tester",
        "email": "alice@example.test",
    },
)
check(
    profile_refresh.status_code == 200
    and profile_refresh.get_json()["pending_email"] == "alice-new@example.test"
    and token_row(alice[0], "email_verification")[0] == pending_hash,
    "non-email profile edits preserve the pending address and verification token",
)
check(
    client.post(
        "/email-verification/confirm",
        json={"token": email_change_token},
    ).status_code == 200
    and user_row("alice")[2] == "alice-new@example.test",
    "confirming a pending profile address swaps it atomically",
)

print("\n== Password recovery, eligibility, expiry, and replay ==")
sender.messages.clear()
known = client.post(
    "/password-recovery/request",
    json={"email": "alice-new@example.test"},
)
unknown = client.post(
    "/password-recovery/request",
    json={"email": "nobody@example.test"},
)
reset_one = token_from_last("reset-password")
reset_stored = token_row(alice[0], "password_reset")
check(
    known.status_code == unknown.status_code == 200
    and known.get_json() == unknown.get_json(),
    "known and unknown recovery requests return the same response",
)
check(
    reset_stored is not None
    and reset_stored[0] == backend._account_token_hash(reset_one),
    "password-reset token is stored hashed",
)
conn = backend.get_db()
conn.execute(
    "UPDATE account_tokens SET created=0 "
    "WHERE user_id=? AND purpose='password_reset'",
    (alice[0],),
)
conn.commit()
conn.close()
client.post(
    "/password-recovery/request",
    json={"email": "alice-new@example.test"},
)
reset_two = token_from_last("reset-password")
reset_validation = client.post(
    "/password-recovery/validate",
    json={"token": reset_two},
)
check(
    reset_validation.status_code == 200
    and reset_validation.get_json() == {"valid": True}
    and token_row(alice[0], "password_reset") is not None,
    "validating a password-reset link does not consume it",
)
check(
    reset_two != reset_one
    and client.post(
        "/password-recovery/reset",
        json={"token": reset_one, "new_password": "Superseded1!"},
    ).status_code == 400,
    "newest password-reset token invalidates the previous token",
)
check(
    client.post(
        "/password-recovery/reset",
        json={"token": reset_two, "new_password": "weak"},
    ).status_code == 400,
    "password recovery enforces the shared password policy",
)
reset = client.post(
    "/password-recovery/reset",
    json={"token": reset_two, "new_password": "Recovered1!"},
)
check(reset.status_code == 200, "valid recovery token resets the password")
check(
    client.post(
        "/password-recovery/reset",
        json={"token": reset_two, "new_password": "Another1!"},
    ).status_code == 400,
    "password-reset token is single-use",
)
check(
    app.test_client().post(
        "/login",
        json={"username": "alice", "password": "Account1!"},
    ).status_code == 401
    and login("alice", "Recovered1!")[1].status_code == 200,
    "recovery rejects the old password and accepts the new password",
)
check(alice_client.post("/auth/refresh").status_code == 401,
      "password recovery revokes existing session families")
conn = backend.get_db()
account_audit_actions = {
    row[0]
    for row in conn.execute(
        "SELECT action FROM audit_log WHERE target_id=?",
        (alice[0],),
    ).fetchall()
}
conn.close()
check(
    {
        "account.email_verified",
        "account.password_reset_requested",
        "account.password_reset",
    }.issubset(account_audit_actions),
    "verification and recovery flows emit their lifecycle audit actions",
)

sender.messages.clear()
client.post(
    "/password-recovery/request",
    json={"email": "alice-new@example.test"},
)
expired_reset = token_from_last("reset-password")
conn = backend.get_db()
conn.execute(
    "UPDATE account_tokens SET expires=? WHERE user_id=? AND purpose='password_reset'",
    (int(time.time()) - 1, alice[0]),
)
conn.commit()
conn.close()
check(
    client.post(
        "/password-recovery/validate",
        json={"token": expired_reset},
    ).status_code == 400
    and client.post(
        "/password-recovery/reset",
        json={"token": expired_reset, "new_password": "Expired1!"},
    ).status_code == 400,
    "expired password-reset token is rejected before and during submission",
)

disabled_id = make_user("disabled", status="disabled")
pending_id = make_user("pending", status="pending", verified=False)
sender.messages.clear()
disabled_response = client.post(
    "/password-recovery/request",
    json={"email": "disabled@example.test"},
)
pending_response = client.post(
    "/password-recovery/request",
    json={"email": "pending@example.test"},
)
check(
    disabled_response.get_json() == pending_response.get_json() == unknown.get_json()
    and not sender.messages,
    "disabled and pending accounts receive generic recovery responses without delivery",
)

print("\n== Delivery failure remains retryable ==")
sender.fail = True
failed_registration = client.post(
    "/register",
    json=registration("mailfail", "mailfail@example.test"),
)
mailfail = user_row("mailfail")
failed_token = token_row(mailfail[0], "email_verification")
check(
    failed_registration.status_code == 200
    and failed_registration.get_json()["email_sent"] is False
    and mailfail is not None,
    "SMTP failure preserves the pending registration",
)
check(failed_token is not None and failed_token[2] == 0,
      "failed verification delivery can be retried immediately")
sender.fail = False
sender.messages.clear()
client.post(
    "/email-verification/resend",
    json={"email": "mailfail@example.test"},
)
check(len(sender.messages) == 1, "resend succeeds after a transient delivery failure")

print("\n== Disabled-mode compatibility ==")
backend.REQUIRE_EMAIL_VERIFICATION = False
disabled_capabilities = client.get("/account-capabilities")
disabled_profile_client, _, disabled_profile_token = login("bypass")
disabled_profile_payload = disabled_profile_client.get(
    "/profile",
    headers=headers(disabled_profile_token),
).get_json()
disabled_admin_payload = admin_client.get(
    "/admin/users",
    headers=headers(admin_token),
).get_json()
disabled_register = client.post(
    "/register",
    json=registration("legacy", "legacy@example.test"),
)
legacy = user_row("legacy")
check(
    disabled_capabilities.get_json() == {"email_account_flows": False}
    and client.post("/password-recovery/request", json={}).status_code == 404
    and client.post("/password-recovery/validate", json={}).status_code == 404
    and client.post("/email-verification/resend", json={}).status_code == 404,
    "disabled mode hides email flows at both capability and endpoint boundaries",
)
check(
    disabled_register.get_json()
    == {
        "success": True,
        "message": "Registration received.",
    }
    and legacy[3] is not None,
    "disabled registration confirms receipt without email-verification wording",
)
check(
    "email_verified" not in disabled_profile_payload
    and "pending_email" not in disabled_profile_payload
    and all("email_verified" not in user for user in disabled_admin_payload),
    "disabled mode preserves existing profile and admin-user payload keys",
)
backend.REQUIRE_EMAIL_VERIFICATION = True

print("\n== Real backend-to-SMTP boundary ==")
smtp_server = SMTPServer()
smtp_thread = threading.Thread(target=smtp_server.serve_forever, daemon=True)
smtp_thread.start()
backend.EMAIL_SENDER = backend.SMTPDelivery(
    enabled=True,
    host="127.0.0.1",
    port=smtp_server.server_address[1],
    timeout=2,
    security="plaintext",
    from_address="markervault@example.test",
    envelope_from="markervault@example.test",
    username=None,
    password=None,
)
live_smtp_registration = client.post(
    "/register",
    json=registration("livesmtp", "livesmtp@example.test"),
)
smtp_server.shutdown()
smtp_server.server_close()
smtp_thread.join(timeout=1)
check(
    live_smtp_registration.status_code == 200
    and live_smtp_registration.get_json()["email_sent"] is True
    and len(smtp_server.messages) == 1
    and b"http://localhost/#verify-email=" in smtp_server.messages[0],
    "real registration path delivers a verification link through loopback SMTP",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
shutil.rmtree(WORK, ignore_errors=True)
sys.exit(1 if FAIL else 0)
