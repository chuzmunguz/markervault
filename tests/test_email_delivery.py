import io
import logging
import smtplib
import socketserver
import sys
import threading
import time

from email import policy
from email.parser import BytesParser
from pathlib import Path


ROOT = Path("/workspace/markervault")
sys.path.insert(0, str(ROOT))

from email_delivery import EmailDeliveryError
from email_delivery import LOGGER
from email_delivery import SMTPDelivery
from email_delivery import password_reset_email_content
from email_delivery import test_email_content
from email_delivery import verification_email_content


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


class CapturingSMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        envelope_from = None
        recipients = []
        self.wfile.write(b"220 localhost MarkerVault test SMTP\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("ascii", errors="replace").rstrip("\r\n")
            upper = command.upper()
            if upper.startswith("EHLO"):
                self.wfile.write(b"250-localhost\r\n250 SIZE 1048576\r\n")
            elif upper.startswith("HELO"):
                self.wfile.write(b"250 localhost\r\n")
            elif upper.startswith("MAIL FROM:"):
                envelope_from = command.split(":", 1)[1].split(" ", 1)[0].strip("<>")
                self.wfile.write(b"250 sender accepted\r\n")
            elif upper.startswith("RCPT TO:"):
                recipient = command.split(":", 1)[1].split(" ", 1)[0].strip("<>")
                recipients.append(recipient)
                self.wfile.write(b"250 recipient accepted\r\n")
            elif upper == "DATA":
                self.wfile.write(b"354 end with dot\r\n")
                data = bytearray()
                while True:
                    data_line = self.rfile.readline()
                    if data_line in (b".\n", b".\r\n", b""):
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    data.extend(data_line)
                self.server.messages.append(
                    {
                        "envelope_from": envelope_from,
                        "recipients": tuple(recipients),
                        "data": bytes(data),
                    }
                )
                self.wfile.write(b"250 queued\r\n")
            elif upper == "RSET":
                envelope_from = None
                recipients = []
                self.wfile.write(b"250 reset\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 goodbye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class CapturingSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), CapturingSMTPHandler)
        self.messages = []


class StallingHandler(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(0.4)


class StallingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class RunningServer:
    def __init__(self, server):
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.server

    def __exit__(self, exc_type, exc, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


class LogCapture:
    def __init__(self):
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.previous_level = LOGGER.level
        self.previous_propagate = LOGGER.propagate

    def __enter__(self):
        LOGGER.addHandler(self.handler)
        LOGGER.setLevel(logging.INFO)
        LOGGER.propagate = False
        return self.stream

    def __exit__(self, exc_type, exc, traceback):
        LOGGER.removeHandler(self.handler)
        LOGGER.setLevel(self.previous_level)
        LOGGER.propagate = self.previous_propagate


class SMTPSpy:
    def __init__(self, calls, kind, *args, **kwargs):
        self.calls = calls
        self.calls.append((kind, args, kwargs))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def ehlo(self):
        self.calls.append(("ehlo",))

    def starttls(self, *, context):
        self.calls.append(("starttls", context))

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def send_message(self, message, *, from_addr, to_addrs):
        self.calls.append(
            (
                "send_message",
                message["From"],
                message["To"],
                from_addr,
                to_addrs,
            )
        )


def delivery(**overrides):
    values = {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 25,
        "timeout": 1,
        "security": "plaintext",
        "from_address": "from@example.test",
        "envelope_from": "bounce@example.test",
        "username": None,
        "password": None,
    }
    values.update(overrides)
    return SMTPDelivery(**values)


print("\n== Disabled boundary ==")
network_calls = []


def forbidden_factory(*args, **kwargs):
    network_calls.append((args, kwargs))
    raise AssertionError("disabled email attempted a connection")


disabled = delivery(
    enabled=False,
    host=None,
    from_address=None,
    envelope_from=None,
    smtp_factory=forbidden_factory,
    smtp_ssl_factory=forbidden_factory,
)
with LogCapture() as disabled_log:
    disabled_result = disabled.send(
        "not validated while disabled",
        test_email_content(),
    )
check(
    disabled_result.delivered is False
    and disabled_result.status == "disabled"
    and network_calls == [],
    "disabled delivery is a network-free no-op",
)
check(
    "status=disabled template=delivery_test" in disabled_log.getvalue(),
    "disabled delivery emits only redacted status metadata",
)


print("\n== Real loopback SMTP delivery ==")
server = CapturingSMTPServer()
with RunningServer(server):
    sender = delivery(port=server.server_address[1])
    content = verification_email_content(
        "João & <Team>",
        "https://markervault.example.test/verify?token=private-token",
    )
    with LogCapture() as success_log:
        result = sender.send("person@example.test", content)

message_record = server.messages[0] if server.messages else None
parsed = (
    BytesParser(policy=policy.default).parsebytes(message_record["data"])
    if message_record is not None
    else None
)
plain_body = parsed.get_body(preferencelist=("plain",)).get_content() if parsed else ""
html_body = parsed.get_body(preferencelist=("html",)).get_content() if parsed else ""
check(result.delivered and result.status == "sent", "loopback SMTP delivery succeeds")
check(
    message_record is not None
    and message_record["envelope_from"] == "bounce@example.test"
    and message_record["recipients"] == ("person@example.test",),
    "SMTP envelope sender and recipient use explicit addresses",
)
check(
    parsed is not None
    and parsed["From"] == "from@example.test"
    and parsed["To"] == "person@example.test",
    "message From and To headers are correct",
)
check(
    "João & <Team>" in plain_body
    and "João &amp; &lt;Team&gt;" in html_body,
    "Unicode survives delivery and HTML template values are escaped",
)
check(
    "private-token" not in success_log.getvalue()
    and "person@example.test" not in success_log.getvalue()
    and "status=sent template=account_verification" in success_log.getvalue(),
    "success logs omit recipient, content, and token-bearing URLs",
)


print("\n== STARTTLS and implicit TLS selection ==")
starttls_calls = []
starttls_context = object()
ordinary_password = "ordinary-password"
starttls_sender = delivery(
    host="smtp.example.test",
    port=587,
    security="starttls",
    username="mailer@example.test",
    password=ordinary_password,
    smtp_factory=lambda *args, **kwargs: SMTPSpy(
        starttls_calls,
        "smtp",
        *args,
        **kwargs,
    ),
    smtp_ssl_factory=forbidden_factory,
    ssl_context_factory=lambda: starttls_context,
)
starttls_sender.send("person@example.test", test_email_content())
check(
    [call[0] for call in starttls_calls]
    == ["smtp", "ehlo", "starttls", "ehlo", "login", "send_message"],
    "STARTTLS is negotiated before SMTP AUTH and delivery",
)
check(
    starttls_calls[3] == ("ehlo",)
    and starttls_calls[4]
    == ("login", "mailer@example.test", ordinary_password),
    "ordinary password is passed unchanged through standard SMTP AUTH",
)

implicit_calls = []
implicit_context = object()
app_password = "app password with spaces"
implicit_sender = delivery(
    host="smtp.example.test",
    port=465,
    security="implicit_tls",
    username="mailer@example.test",
    password=app_password,
    smtp_factory=forbidden_factory,
    smtp_ssl_factory=lambda *args, **kwargs: SMTPSpy(
        implicit_calls,
        "smtp_ssl",
        *args,
        **kwargs,
    ),
    ssl_context_factory=lambda: implicit_context,
)
implicit_sender.send("person@example.test", test_email_content())
check(
    [call[0] for call in implicit_calls]
    == ["smtp_ssl", "login", "send_message"]
    and implicit_calls[0][2]["context"] is implicit_context,
    "implicit TLS uses SMTP_SSL without a STARTTLS downgrade",
)
check(
    implicit_calls[1] == ("login", "mailer@example.test", app_password),
    "app password uses the same SMTP AUTH path without transformation",
)


print("\n== Timeout, failure, and redaction ==")
stalling_server = StallingServer(("127.0.0.1", 0), StallingHandler)
with RunningServer(stalling_server):
    timeout_sender = delivery(
        port=stalling_server.server_address[1],
        timeout=0.05,
    )
    started = time.monotonic()
    with LogCapture() as timeout_log:
        try:
            timeout_sender.send("person@example.test", test_email_content())
        except EmailDeliveryError as exc:
            timeout_error = str(exc)
        else:
            timeout_error = ""
    elapsed = time.monotonic() - started
check(
    timeout_error == "Email delivery failed"
    and elapsed < 1
    and "status=failed template=delivery_test" in timeout_log.getvalue(),
    "SMTP timeout fails synchronously with a bounded generic error",
)

secret_values = (
    "person@example.test",
    "credential-secret",
    "private-token",
)


def failing_factory(*args, **kwargs):
    raise smtplib.SMTPException(" ".join(secret_values))


failure_sender = delivery(
    host="smtp.example.test",
    username="mailer@example.test",
    password=secret_values[1],
    security="starttls",
    smtp_factory=failing_factory,
)
hostile_content = verification_email_content(
    "Person",
    f"https://example.test/verify?token={secret_values[2]}",
)
with LogCapture() as failure_log:
    try:
        failure_sender.send(secret_values[0], hostile_content)
    except EmailDeliveryError as exc:
        failure_message = str(exc)
        failure_cause = exc.__cause__
    else:
        failure_message = ""
        failure_cause = None
logged_failure = failure_log.getvalue()
check(
    failure_message == "Email delivery failed"
    and failure_cause is None
    and all(secret not in logged_failure for secret in secret_values),
    "SMTP failures expose no chained detail, credentials, recipients, URLs, or server",
)
check(
    "status=failed template=account_verification error_type=SMTPException"
    in logged_failure,
    "failure logs retain bounded operational status and exception class",
)


print("\n== Template and product-boundary invariants ==")
reset = password_reset_email_content(
    "Álvaro",
    "https://example.test/reset?token=reset-secret",
)
check(
    reset.template == "password_reset"
    and "Álvaro" in reset.text_body
    and "reset-secret" in reset.text_body,
    "password-reset template preserves Unicode and its caller-supplied link",
)
backend_text = (ROOT / "backend.py").read_text(encoding="utf-8")
check(
    backend_text.count("EMAIL_SENDER.send(") == 2
    and "verification_email_content(" in backend_text
    and "password_reset_email_content(" in backend_text,
    "Stage 12 exposes only the verification and password-reset delivery callers",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
