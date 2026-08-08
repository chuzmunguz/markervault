#!/usr/bin/env bash
set -e

# MarkerVault install + deploy (Stage 7 layout). Run from the synced repository
# checkout for EVERY deploy: sudo ./install.sh --wipe-data | --keep-data
# Idempotent desired-state pass: bootstraps whatever is missing (service user,
# environment file, venv), refreshes the tracked unit and nginx sites so the host
# can never drift from the repository, then deploys. Seeding is a separate explicit
# step: ./seed.sh for the disposable test fixtures, or create_users.py for a real
# account.
# The environment file is created once with a generated signing secret and never
# overwritten; rotating the secret stays a deliberate manual act.
#
# Deployment layout (S-01): three separate boundaries.
#   /var/www/markervault          application tree + venv (gunicorn WorkingDirectory)
#   /var/www/markervault/public   nginx document root (static frontend only)
#   /var/lib/markervault          runtime state: database, media, KML temp files

# Destructive vs. non-destructive is the only thing a deploy needs to vary, and both
# are explicit: there is NO default. A destructive default is dangerous once real data
# exists, and a preserving default silently keeps stale state when a clean slate was
# wanted; with neither available, no deploy can surprise anyone. Bare invocation stops
# and asks, which is strictly better than guessing.
MODE=""
if [ "$#" -eq 1 ]; then
    case "$1" in
        --wipe-data) MODE=wipe ;;
        --keep-data) MODE=keep ;;
    esac
fi
if [ -z "$MODE" ]; then
    cat >&2 <<'USAGE'
Usage: sudo ./install.sh --wipe-data | --keep-data

  --wipe-data   Deploy, then WIPE the database and generated media. Clean slate.
  --keep-data   Deploy and leave the database and generated media in place.

The choice is always explicit; there is no default and no deploy happens
without one.
USAGE
    exit 2
fi

SOURCE="$(cd "$(dirname "$0")" && pwd)"
APP=/var/www/markervault
ENV_DIR=/etc/markervault
ENV_FILE=$ENV_DIR/markervault.env

load_environment() {
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    DB="${MARKERVAULT_DB_PATH:?MARKERVAULT_DB_PATH missing from $ENV_FILE}"
    PHOTOS="${MARKERVAULT_PHOTOS_PATH:?MARKERVAULT_PHOTOS_PATH missing from $ENV_FILE}"
    THUMBS="${MARKERVAULT_THUMBS_PATH:?MARKERVAULT_THUMBS_PATH missing from $ENV_FILE}"
    AVATARS="${MARKERVAULT_AVATARS_PATH:?MARKERVAULT_AVATARS_PATH missing from $ENV_FILE}"
    TEMP="${MARKERVAULT_TEMP_PATH:?MARKERVAULT_TEMP_PATH missing from $ENV_FILE}"
}

# ================= PREFLIGHT =================
# Every check that can refuse deterministically runs here, before the script
# touches the host at all. The first mutation is the service-account creation
# below; nothing above it changes anything, so a refusal in this section leaves
# the host exactly as it was.
#
# This is NOT a claim that every abort is atomic. Past this section a failure can
# still leave work half-done — pip can fail with the venv modified, the overlay
# copy can fail partway, the liveness poll can fail after the service has already
# been restarted. What this section guarantees is narrower and worth having: the
# refusals we can predict happen before any of that.

for binary in python3 sqlite3 nginx systemctl getent adduser; do
    command -v "$binary" >/dev/null || { echo "ERROR: $binary is not installed" >&2; exit 1; }
done
python3 -c "import venv" 2>/dev/null || { echo "ERROR: python3-venv is not installed" >&2; exit 1; }

# The deploy copies a named list, never a glob. `"$SOURCE"/*` sweeps whatever
# happens to be sitting in the checkout into the application tree — a developer's
# spots.db, a __pycache__ the cleanup just removed. Deriving the list from git was
# considered and rejected: install.sh stays self-contained and works from any copy
# of the source, checkout or not.
#
# ACCEPTED TRADE-OFF: a hand-maintained list can omit a file. An omission surfaces
# fast — a missing member of the six-file bootstrap stops the service from booting,
# which the liveness poll turns into a loud abort, and a missing frontend asset is
# visible on first page load. The quiet case is a file used only by tests or
# tooling, which is why stage4_reproducibility_test.py checks this list against the
# repository's own contents. Validated HERE rather than at the copy loop, because a
# missing entry discovered mid-overlay would abort with the service stopped and the
# data already wiped.
DEPLOY_PATHS=(
    # Backend bootstrap: the service does not start without all six.
    backend.py
    markervault_schema.py
    request_validation.py
    markervault_config.py
    username_validation.py
    email_delivery.py
    # CLI and the direct/locked dependency manifests the venv is built from.
    create_users.py
    requirements.in
    requirements.txt
    # Tracked host manifests, kept beside the code so the tree stays self-describing.
    install.sh
    uninstall.sh
    seed.sh
    markervault.service
    markervault.nginx
    markervault.env.example
    vendored-assets.json
    README.md
    LICENSE
    THIRD_PARTY_LICENSES
    # Frontend sources. The overlay copy below deposits this directly at
    # $APP/public, which is also nginx's document root (S-01) — one on-disk home
    # per served file, no separate rebuild step needed.
    public
)
for deploy_path in "${DEPLOY_PATHS[@]}"; do
    if [ ! -e "$SOURCE/$deploy_path" ]; then
        echo "ERROR: $deploy_path is listed for deployment but missing from $SOURCE" >&2
        exit 1
    fi
done

if [ -f "$ENV_FILE" ]; then
    load_environment
elif [ "$MODE" = keep ]; then
    # A missing environment file does NOT prove there is no data to keep. It can
    # equally mean a damaged or half-restored host, which is exactly when
    # continuing is worst. Only --wipe-data bootstraps the file.
    echo "ERROR: --keep-data was requested but $ENV_FILE does not exist." >&2
    echo "Without it the database path is unknown, so nothing can be preserved" >&2
    echo "and nothing here can tell an untouched host from a damaged one." >&2
    echo "Deploy with --wipe-data to bootstrap a new environment file." >&2
    exit 1
fi

# --keep-data against a database carrying an older schema is the one way this
# deploy can look successful and then fail at runtime: initialize_schema is
# entirely CREATE TABLE IF NOT EXISTS, so new columns are silently not added and
# the application dies with "no such column". The system python3 runs it:
# markervault_schema.py imports nothing, so this still works when the venv itself
# is broken.
if [ "$MODE" = keep ]; then
    if ! python3 "$SOURCE/tools/check_schema_drift.py" "$DB"; then
        echo >&2
        echo "ERROR: the live database's schema differs from markervault_schema.py." >&2
        echo "The host has not been touched; the service is still running." >&2
        echo "Deploy with --wipe-data to rebuild from the current schema." >&2
        echo >&2
        echo "Note: the comparison is against the stored DDL verbatim, whitespace" >&2
        echo "included, so a purely cosmetic reformat of the schema strings reports" >&2
        echo "drift too. Read the diff above before assuming data is at stake." >&2
        exit 1
    fi
    echo "schema check: the live database matches markervault_schema.py"
fi

# ================= HOST MUTATION BEGINS HERE =================

# Unprivileged service account (no shell, no password).
if ! getent passwd markervault >/dev/null; then
    sudo adduser markervault --disabled-password --gecos "" --shell /usr/sbin/nologin
    echo "created service user markervault"
fi

sudo install -d -m 750 -o root -g markervault "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
    sudo cp "$SOURCE/markervault.env.example" "$ENV_FILE"
    sudo chown root:markervault "$ENV_FILE"
    sudo chmod 640 "$ENV_FILE"
    SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    sudo sed -i "s|^MARKERVAULT_ACCESS_TOKEN_SECRET=.*|MARKERVAULT_ACCESS_TOKEN_SECRET=$SECRET|" "$ENV_FILE"
    unset SECRET
    echo "created $ENV_FILE with a generated signing secret"
    echo "  -> review it now if you browse by LAN IP (MARKERVAULT_TEMPORARY_LAN_HOSTS)"
    # Only reachable under --wipe-data: preflight refuses --keep-data without it.
    load_environment
fi

# App tree + venv. The venv is root-owned like everything the service executes;
# the service user only needs read/execute, which default modes provide.
# Creating the interpreter is guarded — installing the dependencies is NOT. A
# guarded install means a changed pin in requirements.txt never reaches a host
# that already has a venv, so every backend security patch silently stays behind
# while the frontend assets land through the overlay copy. Against satisfied pins
# pip is a no-op costing a fraction of a second, so this runs every deploy.
sudo install -d "$APP"
if [ ! -x "$APP/venv/bin/python" ]; then
    sudo python3 -m venv "$APP/venv"
    echo "created $APP/venv"
fi
sudo "$APP/venv/bin/python" -m pip install --require-hashes -r "$SOURCE/requirements.txt"
"$APP/venv/bin/python" --version
"$APP/venv/bin/python" -m pip --version
sha256sum "$SOURCE/requirements.txt"

# systemd unit: the tracked manifest is the source of truth; re-copying every
# deploy keeps the installed unit from drifting.
sudo cp "$SOURCE/markervault.service" /etc/systemd/system/markervault.service
sudo systemctl daemon-reload
sudo systemctl enable markervault.service

# nginx: the APPLICATION vhost only. The host-wide default_server catch-all that
# rejects unknown Hosts (S-12) is host policy, maintained by the operator outside
# MarkerVault and never installed here. documentation/INSTALL.md lists it as a
# host prerequisite.
#
# `nginx -t` validates what is on disk, so the candidate has to be installed before
# it can be tested. Keep a copy of the outgoing vhost and put it back if validation
# fails: otherwise a bad tracked config replaces a good live one and stays there,
# breaking the next unrelated `nginx -s reload` long after this script exited.
NGINX_SITE=/etc/nginx/sites-available/markervault
NGINX_BACKUP=""
if [ -f "$NGINX_SITE" ]; then
    NGINX_BACKUP=$(mktemp)
    sudo cp "$NGINX_SITE" "$NGINX_BACKUP"
fi
sudo cp "$SOURCE/markervault.nginx" "$NGINX_SITE"
sudo ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/markervault
if ! sudo nginx -t; then
    if [ -n "$NGINX_BACKUP" ]; then
        sudo cp "$NGINX_BACKUP" "$NGINX_SITE"
        rm -f "$NGINX_BACKUP"
        echo "restored the previous vhost; the running nginx configuration is unchanged" >&2
    else
        sudo rm -f "$NGINX_SITE" /etc/nginx/sites-enabled/markervault
        echo "removed the candidate vhost; no MarkerVault site was previously installed" >&2
    fi
    echo "ERROR: the tracked nginx configuration failed validation." >&2
    exit 1
fi
[ -n "$NGINX_BACKUP" ] && rm -f "$NGINX_BACKUP"
sudo systemctl reload-or-restart nginx

# ---------- deployment ----------

sudo systemctl stop markervault

# Runtime state, per the mode chosen on the command line.
if [ "$MODE" = wipe ]; then
    sudo rm -f "$DB" "$DB-wal" "$DB-shm"
    sudo rm -rf "$PHOTOS" "$THUMBS" "$AVATARS" "$TEMP"
    echo "wiping the database and generated media (--wipe-data)"
else
    echo "keeping the existing database and generated media (--keep-data)"
fi

# Provision runtime storage; missing parents are created root-owned with 755.
# nginx (www-data) serves media directly through the internal aliases. Setgid makes
# every new file inherit www-data while the service's 0027 umask removes world access;
# the database directory stays owner-only (keep it in its own subdirectory, as in the
# env template).
sudo install -d -o markervault -g www-data -m 2750 "$PHOTOS" "$THUMBS" "$AVATARS"
sudo install -d -o markervault -g markervault -m 700 "$(dirname "$DB")" "$TEMP"

# Converge existing media in the same deployment that enables UMask=0027. Without
# this atomic transition, nginx would read old world-readable files while every new
# upload became an unreadable markervault:markervault 0640 file. Later deploys skip
# entries that already carry the intended group and mode.
sudo find "$PHOTOS" "$THUMBS" "$AVATARS" -xdev \
    \( -type d -o -type f \) ! -group www-data -exec chgrp www-data {} +
sudo find "$PHOTOS" "$THUMBS" "$AVATARS" -xdev \
    -type d ! -perm 2750 -exec chmod 2750 {} +
sudo find "$PHOTOS" "$THUMBS" "$AVATARS" -xdev \
    -type f ! -perm 0640 -exec chmod 0640 {} +

# The overlay copy below cannot remove files retired from the repository, so
# wipe everything under the app tree except venv (guarded above so a normal
# deploy doesn't pay to recreate it) before repopulating from DEPLOY_PATHS.
# Nothing else under $APP is precious — real state lives under /var/lib/markervault
# — so this needs no hand-maintained retirement list that can fall out of sync.
sudo find "$APP" -mindepth 1 -maxdepth 1 ! -name venv -exec rm -rf {} +

# The list and its existence check live in PREFLIGHT above, so a missing entry
# refuses before the service is stopped and the data wiped rather than aborting
# mid-overlay. Only the copy itself belongs here.
for deploy_path in "${DEPLOY_PATHS[@]}"; do
    sudo cp -r "$SOURCE/$deploy_path" "$APP/"
done

# Least-privilege invariant: the service user owns NOTHING it executes. Every
# deploy re-asserts root ownership over the whole app tree (venv included) and
# strips group/other write, so a compromised service process cannot swap its own
# code or this script. Gunicorn logs to the journal; runtime writes go only to
# the /var/lib/markervault paths from the environment file.
sudo chown -R root:root "$APP"
sudo chmod -R go-w "$APP"

sudo systemctl start markervault

# Prove the backend actually answers. markervault.service has no Type= line, so it is
# Type=simple: systemctl start succeeds the moment the process forks, before Python
# has imported anything, and Restart=on-failure turns a boot crash into a quiet
# crash-loop this script would otherwise report as success. With the dependency
# install now running on every deploy, an import-breaking upgrade is exactly the
# failure to expect here.
#
# ANY HTTP response means the application is up: this connects to the same address the
# unit binds, so the Host gate answers 421 (S-12) — a status line, not a 200, is the
# signal. A bare TCP accept is not enough, because gunicorn's master binds the socket
# before its workers import the app; requiring the status line is what distinguishes
# "listening" from "loaded".
if ! python3 - <<'LIVENESS'
import socket, sys, time

deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", 5000), timeout=2) as sock:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            if sock.recv(16).startswith(b"HTTP/"):
                sys.exit(0)
    except OSError:
        pass
    time.sleep(0.5)
sys.exit(1)
LIVENESS
then
    echo "ERROR: the backend never answered on 127.0.0.1:5000." >&2
    echo "Inspect: systemctl status markervault && journalctl -u markervault -n 30" >&2
    echo "A dependency upgrade that breaks an import shows up here." >&2
    exit 1
fi
echo "backend is answering on 127.0.0.1:5000"

# With --keep-data the users table pre-exists, so the schema wait below proves nothing
# on its own — the liveness poll above is what covers that mode.
if [ "$MODE" = keep ]; then
    echo
    echo "Deployed: existing database at $DB left in place."
    exit 0
fi

# Wait for the backend to create the schema at the configured path; a service that
# crashed or booted without its environment must fail here, loudly.
for _ in $(seq 1 15); do
    if sudo -u markervault sqlite3 "$DB" "SELECT 1 FROM users LIMIT 1;" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! sudo -u markervault sqlite3 "$DB" "SELECT 1 FROM users LIMIT 1;" >/dev/null 2>&1; then
    echo "ERROR: the backend did not initialize the schema at $DB." >&2
    echo "Inspect: systemctl status markervault && journalctl -u markervault -n 30" >&2
    echo "Common causes: an empty MARKERVAULT_ACCESS_TOKEN_SECRET or a broken venv." >&2
    exit 1
fi

echo
echo "Deployed: clean empty database at $DB."
echo "Seed the test fixtures with ./seed.sh, or create a real account with create_users.py."
