#!/usr/bin/env python3
"""Manual media/DB consistency report (R-02). Run on demand — never on a timer.

Compares the photos table and users.avatar against the configured photo, thumbnail,
and avatar directories, then reports files without DB rows (orphans) and DB rows
without files (missing). Read-only; exits 1 when anything is inconsistent so the
operator sees it, and prints the paths to act on. On the deployment box, load the
service environment first:
    sudo -u markervault bash -c 'set -a; source /etc/markervault/markervault.env; set +a; \
        cd /var/www/markervault && venv/bin/python tools/check_media_orphans.py'
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markervault_config import load_backend_configuration


def listing(folder):
    if not os.path.isdir(folder):
        return set()
    return {
        name for name in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, name)) and not name.startswith('.')
    }


def main():
    config = load_backend_configuration()
    if not os.path.isfile(config.database_path):
        sys.exit(f"database not found: {config.database_path}")

    conn = sqlite3.connect(config.database_path)
    photo_rows = {r[0] for r in conn.execute("SELECT filename FROM photos")}
    avatar_rows = {r[0] for r in conn.execute("SELECT avatar FROM users WHERE avatar IS NOT NULL")}
    conn.close()

    problems = 0
    for label, folder, expected in (
        ("photo", config.photos_path, photo_rows),
        ("thumbnail", config.thumbs_path, photo_rows),
        ("avatar", config.avatars_path, avatar_rows),
    ):
        on_disk = listing(folder)
        for name in sorted(on_disk - expected):
            problems += 1
            print(f"ORPHAN   {label} file without a DB row: {os.path.join(folder, name)}")
        for name in sorted(expected - on_disk):
            problems += 1
            print(f"MISSING  {label} row without a file: {name}")

    if problems:
        print(f"\n{problems} inconsistencies found")
        return 1
    print("media and database are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
