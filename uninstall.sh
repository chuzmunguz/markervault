#!/usr/bin/env bash
set -euo pipefail

# Reverse of install.sh. Removes only the artifacts install.sh creates and never
# touches shared system state (nginx core config, other sites, the host-wide
# default_server catch-all vhost that install.sh never installs, letsencrypt
# certificates).
#
#   sudo ./uninstall.sh            # remove app + service + nginx wiring;
#                                  # KEEP data, secrets, and the markervault user
#   sudo ./uninstall.sh --purge    # additionally remove /var/lib/markervault data,
#                                  # /etc/markervault secrets, and the markervault account
#
# There is deliberately no data removal without --purge: dropped databases and
# uploaded media are not recoverable.

PURGE=0
for argument in "$@"; do
    case "$argument" in
        --purge) PURGE=1 ;;
        -h|--help)
            sed -n '4,14p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $argument" >&2
            echo "Usage: sudo ./uninstall.sh [--purge]" >&2
            exit 2
            ;;
    esac
done
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root." >&2
    exit 1
fi

APP="/var/www/markervault"
STATE="/var/lib/markervault"
ENV_DIR="/etc/markervault"
UNIT="/etc/systemd/system/markervault.service"
NGINX_SITE="/etc/nginx/sites-available/markervault"
NGINX_LINK="/etc/nginx/sites-enabled/markervault"

# --- systemd unit -----------------------------------------------------------
if [ -f "$UNIT" ] || systemctl list-unit-files markervault.service >/dev/null 2>&1; then
    systemctl disable --now markervault.service >/dev/null 2>&1 || true
    rm -f "$UNIT"
    systemctl daemon-reload
    systemctl reset-failed markervault.service >/dev/null 2>&1 || true
    echo "Removed markervault.service."
fi

# --- nginx --------------------------------------------------------------------
nginx_changed=0
for target in "$NGINX_LINK" "$NGINX_SITE"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
        rm -f "$target"
        nginx_changed=1
    fi
done
if [ "$nginx_changed" -eq 1 ]; then
    echo "Removed markervault nginx site."
    if command -v nginx >/dev/null; then
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx || true
            echo "Reloaded nginx."
        else
            echo "WARNING: nginx -t failed after removing markervault config; not reloading." >&2
            echo "         Inspect with: nginx -t" >&2
        fi
    fi
fi

# --- application code (no runtime state lives here) --------------------------
if [ -d "$APP" ]; then
    rm -rf "$APP"
    echo "Removed application directory $APP."
fi

# --- data, secrets, service account (destructive; --purge only) --------------
if [ "$PURGE" -eq 1 ]; then
    if [ -d "$STATE" ]; then
        rm -rf "$STATE"
        echo "Purged runtime state $STATE (database, photos, thumbs, avatars)."
    fi
    if [ -d "$ENV_DIR" ]; then
        rm -rf "$ENV_DIR"
        echo "Purged secrets $ENV_DIR."
    fi
    if getent passwd markervault >/dev/null; then
        deluser --remove-home markervault >/dev/null 2>&1 || userdel -r markervault >/dev/null 2>&1 || true
        echo "Removed the markervault service account."
    fi
else
    echo
    echo "Kept (remove with --purge):"
    [ -d "$STATE" ] && echo "  $STATE   (database, photos, thumbs, avatars)"
    [ -d "$ENV_DIR" ] && echo "  $ENV_DIR       (secrets: MARKERVAULT_ACCESS_TOKEN_SECRET)"
    getent passwd markervault >/dev/null && echo "  service account 'markervault'"
fi

# --- artifacts install.sh never created, so uninstall never removes ----------
echo
echo "Not touched (install.sh did not create these — remove by hand if unused):"
echo "  TLS certificates under /etc/ssl or /etc/letsencrypt"
echo "  nginx access/error logs /var/log/nginx/markervault-*.log"
echo
echo "MarkerVault uninstalled."
