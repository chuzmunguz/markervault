import json
import os
import sqlite3
import subprocess
import sys
import tempfile

from dataclasses import FrozenInstanceError
from pathlib import Path


ROOT = Path("/workspace/markervault")
PYTHON = Path(sys.executable)
sys.path.insert(0, str(ROOT))

from markervault_config import ConfigurationError
from markervault_config import database_path
from markervault_config import load_backend_configuration


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


def expect_configuration_error(environ, expected):
    try:
        load_backend_configuration(environ, secret_factory=lambda _: "d" * 64)
    except ConfigurationError as exc:
        return expected in str(exc)
    return False


default_config = load_backend_configuration(
    {"MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64}
)
check(default_config.environment == "development", "environment defaults to development")
check(default_config.database_path == "spots.db", "database path defaults to CWD spots.db")
check(default_config.bind_token_to_ip is True, "token IP binding defaults to true")
check(default_config.cookie_secure is True, "secure cookies default to true")
check(default_config.photos_path == "photos", "photo path default is unchanged")
check(default_config.thumbs_path == "thumbs", "thumbnail path default is unchanged")
check(default_config.avatars_path == "avatars", "avatar path default is unchanged")
check(default_config.temp_path == "temp", "temporary path default is unchanged")
check(
    default_config.private_rate_burst == 60,
    "authenticated batch flows get the larger private burst by default",
)
check(default_config.max_image_dimension == 10000, "image dimension cap defaults to 10000")
check(default_config.max_image_pixels == 40 * 1000 * 1000, "image pixel cap defaults to 40 MP")
check(default_config.kml_max_workers == 2, "KML executor defaults to two workers")
check(default_config.kml_jobs_per_user == 1, "KML admission defaults to one job per user")
check(default_config.kml_jobs_global == 4, "KML admission defaults to four global jobs")
check(default_config.kml_max_bytes == 20 * 1024 * 1024, "KML byte budget matches the nginx body limit")
check(default_config.kml_max_elements == 100000, "KML element budget defaults to 100000")
check(default_config.kml_max_depth == 50, "KML depth budget defaults to 50")
check(default_config.kml_max_placemarks == 2000, "KML placemark budget defaults to 2000")
check(default_config.kml_max_photos_per_spot == 20, "KML per-spot photo budget defaults to 20")
check(
    default_config.kml_max_download_bytes == 2 * 1024 * 1024 * 1024,
    "KML aggregate download budget defaults to 2 GiB",
)
tuned_kml = load_backend_configuration({
    "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
    "MARKERVAULT_KML_MAX_PLACEMARKS": "5000",
    "MARKERVAULT_KML_MAX_FETCH_ATTEMPTS": "25",
    "MARKERVAULT_KML_MAX_JOB_SECONDS": "45",
})
check(default_config.kml_max_fetch_attempts == 500, "KML fetch-attempt budget defaults to 500")
check(default_config.kml_max_job_seconds == 900, "KML job deadline defaults to 900 seconds")
check(
    tuned_kml.kml_max_placemarks == 5000
    and tuned_kml.kml_max_fetch_attempts == 25
    and tuned_kml.kml_max_job_seconds == 45,
    "KML budgets are environment-tunable",
)
check(
    expect_configuration_error(
        {"MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64, "MARKERVAULT_KML_MAX_FETCH_ATTEMPTS": "0"},
        "MARKERVAULT_KML_MAX_FETCH_ATTEMPTS must be at least 1",
    )
    and expect_configuration_error(
        {"MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64, "MARKERVAULT_KML_MAX_JOB_SECONDS": "0"},
        "MARKERVAULT_KML_MAX_JOB_SECONDS must be at least 1",
    ),
    "zero attempt/time KML budgets fail precisely",
)
check(
    expect_configuration_error(
        {"MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64, "MARKERVAULT_KML_MAX_WORKERS": "0"},
        "MARKERVAULT_KML_MAX_WORKERS must be at least 1",
    ),
    "a zero-worker KML executor fails precisely",
)
check(default_config.notif_history_cap == 200, "notification history defaults to 200 rows per user")
check(
    load_backend_configuration({
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_NOTIF_HISTORY_CAP": "75",
    }).notif_history_cap == 75,
    "notification history retention is environment-tunable",
)
check(
    expect_configuration_error(
        {"MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64, "MARKERVAULT_NOTIF_HISTORY_CAP": "0"},
        "MARKERVAULT_NOTIF_HISTORY_CAP must be at least 1",
    ),
    "a zero notification-history cap fails precisely",
)
check(default_config.email_delivery_enabled is False, "email delivery defaults off")
check(
    default_config.require_email_verification is False,
    "email verification defaults off",
)
check(default_config.public_origin is None, "public origin is unset by default")
check(
    default_config.email_verification_token_duration == 24 * 60 * 60
    and default_config.password_reset_token_duration == 30 * 60
    and default_config.email_resend_cooldown == 60,
    "account token lifetimes and resend cooldown use the approved defaults",
)
check(default_config.smtp_host is None, "SMTP host is unset by default")
check(default_config.smtp_port == 587, "SMTP port defaults to submission")
check(default_config.smtp_timeout == 10, "SMTP timeout defaults to ten seconds")
check(default_config.smtp_security == "starttls", "SMTP security defaults to STARTTLS")
check(default_config.smtp_from_address is None, "SMTP From address is unset by default")
check(default_config.smtp_envelope_from is None, "SMTP envelope sender is unset by default")
check(default_config.smtp_username is None, "SMTP username is unset by default")
check(default_config.smtp_password is None, "SMTP password is unset by default")
check(
    default_config.smtp_allow_unauthenticated_local is False,
    "unauthenticated local SMTP defaults off",
)
check(database_path({}) == "spots.db", "side-effect-free DB primitive keeps default")
check(
    database_path({"MARKERVAULT_DB_PATH": "/tmp/markervault.sqlite3"})
    == "/tmp/markervault.sqlite3",
    "side-effect-free DB primitive accepts an explicit path",
)

try:
    default_config.database_path = "changed.db"
except FrozenInstanceError:
    frozen = True
else:
    frozen = False
check(frozen, "backend configuration is immutable after startup")

check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_BIND_TOKEN_TO_IP": "sometimes",
        },
        "MARKERVAULT_BIND_TOKEN_TO_IP must be a boolean",
    ),
    "invalid token-binding value fails precisely",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_DB_PATH": " ",
        },
        "MARKERVAULT_DB_PATH must not be empty",
    ),
    "empty database path fails precisely",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_PRIVATE_REFILL_INTERVAL": "nan",
        },
        "must be greater than 0",
    ),
    "non-finite rate value fails precisely",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_CANONICAL_HOSTS": "-invalid.example.test",
        },
        "contains an invalid hostname",
    ),
    "invalid canonical host fails precisely",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_ENVIRONMENT": "public",
        },
        "MARKERVAULT_ENVIRONMENT must be one of",
    ),
    "unknown environment mode fails precisely",
)
check(
    expect_configuration_error(
        {"MARKERVAULT_ENVIRONMENT": "production"},
        "MARKERVAULT_ACCESS_TOKEN_SECRET is required in production",
    ),
    "production mode rejects a missing signing secret",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ENVIRONMENT": "production",
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "short",
        },
        "must contain at least 32 characters",
    ),
    "production mode rejects a weak signing secret",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ENVIRONMENT": "production",
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        },
        "MARKERVAULT_CANONICAL_HOSTS is required",
    ),
    "production mode rejects a missing canonical host",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION": "true",
        },
        "requires MARKERVAULT_EMAIL_DELIVERY_ENABLED=true",
    ),
    "verification cannot be enabled without delivery",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
            "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION": "true",
            "MARKERVAULT_SMTP_HOST": "127.0.0.1",
            "MARKERVAULT_SMTP_SECURITY": "plaintext",
            "MARKERVAULT_SMTP_FROM_ADDRESS": "local@example.test",
            "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL": "true",
        },
        "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION requires "
        "MARKERVAULT_PUBLIC_ORIGIN",
    ),
    "verification requires an explicit public link origin",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
        },
        "email delivery requires: MARKERVAULT_SMTP_HOST, "
        "MARKERVAULT_SMTP_FROM_ADDRESS",
    ),
    "enabled delivery requires its server and From address",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_USERNAME": "mailer@example.test",
        },
        "MARKERVAULT_SMTP_USERNAME and MARKERVAULT_SMTP_PASSWORD must be set together",
    ),
    "SMTP credentials must be configured as a pair",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_USERNAME": "mailer@example.test",
            "MARKERVAULT_SMTP_PASSWORD": "secret",
            "MARKERVAULT_SMTP_SECURITY": "plaintext",
        },
        "authenticated SMTP requires starttls or implicit_tls",
    ),
    "authenticated SMTP cannot silently use plaintext",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_HOST": "smtp.example.test",
            "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL": "true",
        },
        "requires a loopback SMTP host",
    ),
    "unauthenticated SMTP is restricted to an explicit loopback server",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_SECURITY": "opportunistic",
        },
        "MARKERVAULT_SMTP_SECURITY must be one of",
    ),
    "unknown SMTP security modes fail precisely",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_PORT": "65536",
        },
        "MARKERVAULT_SMTP_PORT must be at most 65535",
    ),
    "SMTP port range is validated",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_TIMEOUT": "0",
        },
        "MARKERVAULT_SMTP_TIMEOUT must be greater than 0",
    ),
    "SMTP timeout must be positive",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_SMTP_FROM_ADDRESS": "not-an-address",
        },
        "MARKERVAULT_SMTP_FROM_ADDRESS must be a valid email address",
    ),
    "SMTP From address is validated",
)

smtp_password = "  ordinary or app password with spaces  "
smtp_config = load_backend_configuration(
    {
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
        "MARKERVAULT_SMTP_HOST": "smtp.example.test",
        "MARKERVAULT_SMTP_PORT": "465",
        "MARKERVAULT_SMTP_TIMEOUT": "4.5",
        "MARKERVAULT_SMTP_SECURITY": "implicit_tls",
        "MARKERVAULT_SMTP_FROM_ADDRESS": "from@example.test",
        "MARKERVAULT_SMTP_ENVELOPE_FROM": "bounce@example.test",
        "MARKERVAULT_SMTP_USERNAME": "mailer@example.test",
        "MARKERVAULT_SMTP_PASSWORD": smtp_password,
    }
)
check(
    smtp_config.email_delivery_enabled
    and smtp_config.smtp_host == "smtp.example.test"
    and smtp_config.smtp_port == 465
    and smtp_config.smtp_timeout == 4.5
    and smtp_config.smtp_security == "implicit_tls",
    "authenticated implicit-TLS SMTP configuration parses once",
)
check(
    smtp_config.smtp_from_address == "from@example.test"
    and smtp_config.smtp_envelope_from == "bounce@example.test",
    "header From and envelope sender remain distinct",
)
check(
    smtp_config.smtp_username == "mailer@example.test"
    and smtp_config.smtp_password == smtp_password,
    "ordinary and app-password values use the same opaque credential fields",
)
check(
    smtp_password not in repr(smtp_config)
    and "mailer@example.test" not in repr(smtp_config),
    "SMTP credentials are redacted from configuration repr",
)

local_smtp_config = load_backend_configuration(
    {
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
        "MARKERVAULT_SMTP_HOST": "127.0.0.1",
        "MARKERVAULT_SMTP_PORT": "2525",
        "MARKERVAULT_SMTP_SECURITY": "plaintext",
        "MARKERVAULT_SMTP_FROM_ADDRESS": "local@example.test",
        "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL": "true",
    }
)
check(
    local_smtp_config.smtp_allow_unauthenticated_local
    and local_smtp_config.smtp_username is None
    and local_smtp_config.smtp_envelope_from == "local@example.test",
    "explicit loopback configuration enables unauthenticated test SMTP",
)
email_account_config = load_backend_configuration(
    {
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_EMAIL_DELIVERY_ENABLED": "true",
        "MARKERVAULT_REQUIRE_EMAIL_VERIFICATION": "true",
        "MARKERVAULT_PUBLIC_ORIGIN": "http://localhost:8080/",
        "MARKERVAULT_SMTP_HOST": "127.0.0.1",
        "MARKERVAULT_SMTP_SECURITY": "plaintext",
        "MARKERVAULT_SMTP_FROM_ADDRESS": "local@example.test",
        "MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL": "true",
        "MARKERVAULT_EMAIL_VERIFICATION_TOKEN_DURATION": "120",
        "MARKERVAULT_PASSWORD_RESET_TOKEN_DURATION": "90",
        "MARKERVAULT_EMAIL_RESEND_COOLDOWN": "5",
    }
)
check(
    email_account_config.require_email_verification
    and email_account_config.public_origin == "http://localhost:8080"
    and email_account_config.email_verification_token_duration == 120
    and email_account_config.password_reset_token_duration == 90
    and email_account_config.email_resend_cooldown == 5,
    "email-assisted account mode and its timing controls parse together",
)
check(
    all(
        expect_configuration_error(
            {
                "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
                "MARKERVAULT_PUBLIC_ORIGIN": value,
            },
            "MARKERVAULT_PUBLIC_ORIGIN",
        )
        for value in (
            "https://user:secret@localhost",
            "https://localhost/path",
            "https://localhost:not-a-port",
            "https://untrusted.example.test",
        )
    ),
    "public origin rejects credentials, paths, and hosts outside the allowlist",
)
PRODUCTION_PATHS = {
    "MARKERVAULT_DB_PATH": "/var/lib/markervault/db/spots.db",
    "MARKERVAULT_PHOTOS_PATH": "/var/lib/markervault/photos",
    "MARKERVAULT_THUMBS_PATH": "/var/lib/markervault/thumbs",
    "MARKERVAULT_AVATARS_PATH": "/var/lib/markervault/avatars",
    "MARKERVAULT_TEMP_PATH": "/var/lib/markervault/temp",
}
production_config = load_backend_configuration(
    {
        "MARKERVAULT_ENVIRONMENT": "production",
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_CANONICAL_HOSTS": "maps.example.test",
        **PRODUCTION_PATHS,
    }
)
check(production_config.environment == "production", "valid production config parses")
check(
    production_config.canonical_hosts == ("maps.example.test",),
    "canonical hosts are normalized once",
)
check(
    production_config.database_path == "/var/lib/markervault/db/spots.db"
    and production_config.photos_path == "/var/lib/markervault/photos",
    "production runtime paths are taken from the environment",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ENVIRONMENT": "production",
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_CANONICAL_HOSTS": "maps.example.test",
            "MARKERVAULT_PUBLIC_ORIGIN": "http://maps.example.test",
            **PRODUCTION_PATHS,
        },
        "MARKERVAULT_PUBLIC_ORIGIN must use https in production",
    ),
    "production public origin requires HTTPS",
)
for path_name in PRODUCTION_PATHS:
    check(
        expect_configuration_error(
            {
                "MARKERVAULT_ENVIRONMENT": "production",
                "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
                "MARKERVAULT_CANONICAL_HOSTS": "maps.example.test",
                **{**PRODUCTION_PATHS, path_name: "relative/location"},
            },
            f"{path_name} must be an absolute path in production",
        ),
        f"production mode rejects a relative {path_name}",
    )
check(
    production_config.allowed_hosts == ("maps.example.test", "markervault.lan"),
    "production trusts exactly the canonical and temporary LAN hosts",
)
lan_config = load_backend_configuration(
    {
        "MARKERVAULT_ENVIRONMENT": "production",
        "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
        "MARKERVAULT_CANONICAL_HOSTS": "maps.example.test",
        "MARKERVAULT_TEMPORARY_LAN_HOSTS": "markervault.lan,192.168.1.50,maps.example.test",
        **PRODUCTION_PATHS,
    }
)
check(
    lan_config.allowed_hosts == ("maps.example.test", "markervault.lan", "192.168.1.50"),
    "allowed hosts merge canonical and LAN entries without duplicates",
)
check(
    default_config.allowed_hosts
    == ("markervault.lan", "localhost", "127.0.0.1", "::1"),
    "development additionally trusts loopback hosts for local runs and tests",
)
check(
    expect_configuration_error(
        {
            "MARKERVAULT_ACCESS_TOKEN_SECRET": "x" * 64,
            "MARKERVAULT_TEMPORARY_LAN_HOSTS": "*",
        },
        "contains an invalid hostname",
    ),
    "host allowlists reject wildcard entries",
)

with tempfile.TemporaryDirectory(prefix="mv_config_") as work:
    work_path = Path(work)
    db_path = work_path / "configured.sqlite3"
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("MARKERVAULT_"):
            del env[name]
    env["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64
    env["MARKERVAULT_DB_PATH"] = str(db_path)
    env["PYTHONPATH"] = str(ROOT)

    backend_script = """
import json
import backend
print(json.dumps({
    "db": backend.DB_FILE,
    "bind": backend.BIND_TOKEN_TO_IP,
    "photos": backend.PHOTOS_FOLDER,
    "email_sender_enabled": backend.EMAIL_SENDER.enabled,
    "requests": [],
}))
"""
    backend_result = subprocess.run(
        (str(PYTHON), "-c", backend_script),
        cwd=work,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    check(backend_result.returncode == 0, "backend boots with explicit shared DB path")
    backend_payload = None
    if backend_result.returncode == 0:
        backend_payload = json.loads(backend_result.stdout.strip().splitlines()[-1])
    check(
        backend_payload is not None and backend_payload["db"] == str(db_path),
        "backend exposes the configured DB path",
    )
    check(
        backend_payload is not None and backend_payload["bind"] is True,
        "explicit DB path does not alter token-binding policy",
    )
    check(
        backend_payload is not None and backend_payload["photos"] == "photos",
        "explicit DB path does not alter media paths",
    )
    check(
        backend_payload is not None
        and backend_payload["email_sender_enabled"] is False,
        "backend constructs the SMTP boundary disabled by default",
    )
    check(
        backend_payload is not None and backend_payload["requests"] == [],
        "configuration startup adds no client request contract",
    )
    check(db_path.exists(), "backend initializes the configured database")
    check(not (work_path / "spots.db").exists(), "backend does not open fallback spots.db")

    cli_result = subprocess.run(
        (
            str(PYTHON),
            str(ROOT / "create_users.py"),
            "--username",
            "stage2user",
            "--password",
            "Abcd1234!",
            "--email",
            "stage2@example.test",
            "--first-name",
            "Stage",
            "--last-name",
            "Two",
        ),
        cwd=work,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    check(cli_result.returncode == 0, "create_users CLI accepts the shared DB path")
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT username, status FROM users WHERE username = ?",
        ("stage2user",),
    ).fetchone()
    conn.close()
    check(row == ("stage2user", "approved"), "CLI provisions the configured backend DB")
    check(not (work_path / "spots.db").exists(), "CLI does not create fallback spots.db")

with tempfile.TemporaryDirectory(prefix="mv_config_default_") as work:
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("MARKERVAULT_"):
            del env[name]
    env["MARKERVAULT_ACCESS_TOKEN_SECRET"] = "x" * 64
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        (
            str(PYTHON),
            "-c",
            "import backend; print(backend.DB_FILE)",
        ),
        cwd=work,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    check(result.returncode == 0, "backend boots with the default configuration")
    check(
        result.stdout.strip().splitlines()[-1] == "spots.db",
        "default backend launch retains the CWD database path",
    )
    check(Path(work, "spots.db").exists(), "default launch creates CWD spots.db")
    check(Path(work, "photos").is_dir(), "default launch retains the photo directory")
    check(Path(work, "thumbs").is_dir(), "default launch retains the thumbnail directory")
    check(Path(work, "avatars").is_dir(), "default launch retains the avatar directory")

with tempfile.TemporaryDirectory(prefix="mv_config_public_") as work:
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("MARKERVAULT_"):
            del env[name]
    env["MARKERVAULT_ENVIRONMENT"] = "production"
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        (str(PYTHON), "-c", "import backend"),
        cwd=work,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    check(result.returncode != 0, "invalid production configuration stops startup")
    check(
        "MARKERVAULT_ACCESS_TOKEN_SECRET is required in production" in result.stderr,
        "production startup failure names the missing requirement",
    )

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
