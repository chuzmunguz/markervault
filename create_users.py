import sqlite3
import getpass
import bcrypt
import os
import uuid
import argparse
import sys
from datetime import datetime
from markervault_config import database_path
from markervault_schema import initialize_schema
from request_validation import valid_email_format, validate_password_policy
from username_validation import validate_username


def ensure_base_map(cursor, uid):
    """Give a user their undeletable Base Map if they don't already have one."""
    cursor.execute("SELECT id FROM maps WHERE owner_id = ? AND is_base = 1", (uid,))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO maps (owner_id, name, is_base, created, description) VALUES (?, 'Base Map', 1, ?, ?)",
            (uid, datetime.now().isoformat(), 'Your default map. This map cannot be deleted.')
        )


SERVICE_ENV_FILE = "/etc/markervault/markervault.env"


def load_service_env():
    """Creating accounts only makes sense on a deployed host, whose service env file
    names the live database. Load it (plain KEY=VALUE lines, systemd EnvironmentFile
    format) so the CLI writes to the same database and media paths as the service. An
    explicit MARKERVAULT_DB_PATH already in the environment is honored as-is (how the
    test suite points the CLI at a scratch database). If neither the env file nor
    MARKERVAULT_DB_PATH is present there is no database to write to, so the script
    stops rather than inventing a stray working-directory one."""
    try:
        with open(SERVICE_ENV_FILE) as f:
            lines = f.readlines()
    except OSError:
        lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)
    if "MARKERVAULT_DB_PATH" not in os.environ:
        sys.exit(f"Error: {SERVICE_ENV_FILE} not found and MARKERVAULT_DB_PATH is unset. "
                 "Deploy MarkerVault (run install.sh) before creating accounts.")


def main():
    # Load the service environment first so the CLI writes to the same database the
    # running service uses; this refuses to run if no database is configured.
    load_service_env()
    db_path = database_path()
    if os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    # Any argument passed switches on non-interactive mode; with no args the script stays
    # fully interactive (unchanged behaviour). Username/role/force can be flags; the password
    # defaults to a hidden prompt (safer than putting it in shell history / the process list).
    parser = argparse.ArgumentParser(description="Create or replace a MarkerVault user (CLI users are pre-approved).")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-r", "--role", choices=["super_admin", "admin", "user"],
                        help="Role (super_admin can only be created here, not in the UI)")
    parser.add_argument("-f", "--force", action="store_true", help="Replace an existing user without asking")
    parser.add_argument("-p", "--password",
                        help="Password (INSECURE: visible in shell history / process list; prefer the hidden prompt)")
    parser.add_argument("-e", "--email", help="Email (required; must be unique)")
    parser.add_argument("--first-name", dest="first_name", help="First name (required)")
    parser.add_argument("--last-name", dest="last_name", help="Last name (required)")
    args = parser.parse_args()

    non_interactive = any([args.username, args.role, args.force, args.password,
                           args.email, args.first_name, args.last_name])

    # --- Username ---
    raw_username = args.username if args.username is not None else input("Enter username: ")
    ok, username, reason = validate_username(raw_username)
    if not ok:
        sys.exit(f"Error: {reason}")

    # --- Password (shared policy: request_validation.validate_password_policy) ---
    if args.password is not None:
        password = args.password
        valid, reason = validate_password_policy(password)
        if not valid:
            sys.exit(f"Error: {reason}")
    else:
        # Always prompt for the password even in non-interactive mode, unless -p was given.
        while True:
            password = getpass.getpass("Enter password: ")
            valid, reason = validate_password_policy(password)
            if not valid:
                print(reason)
                continue
            repeat_password = getpass.getpass("Repeat password: ")
            if password != repeat_password:
                print("Passwords do not match. Please try again.")
                continue
            break

    # --- Role ---
    if args.role:
        role = args.role
    elif non_interactive:
        role = "user"   # sensible default when other flags are given but role wasn't
    else:
        while True:
            role_input = input("Select role - (s) super-admin, (a) admin, (u) user: ").strip().lower()
            if role_input == 's':
                role = 'super_admin'
                break
            elif role_input == 'a':
                role = 'admin'
                break
            elif role_input == 'u':
                role = 'user'
                break
            else:
                print("Invalid input. Please enter 's' for super-admin, 'a' for admin or 'u' for user.")

    # --- First / last name (required by the app) ---
    def _prompt_required(label, arg_value):
        if arg_value is not None:
            val = arg_value.strip()
            if not val:
                sys.exit(f"Error: {label} cannot be empty.")
            return val
        if non_interactive and not sys.stdin.isatty():
            sys.exit(f"Error: {label} is required (pass the matching flag).")
        while True:
            val = input(f"Enter {label}: ").strip()
            if val:
                return val
            print(f"{label} cannot be empty.")

    first_name = _prompt_required("first name", args.first_name)
    last_name = _prompt_required("last name", args.last_name)

    # --- Email (required + valid format; shared with backend profile validation) ---
    if args.email is not None:
        email = args.email.strip()
        if not valid_email_format(email):
            sys.exit("Error: invalid email address.")
    elif non_interactive and not sys.stdin.isatty():
        sys.exit("Error: email is required (pass -e/--email).")
    else:
        while True:
            email = input("Enter email: ").strip()
            if valid_email_format(email):
                break
            print("Invalid email address.")

    # Connect to DB and ensure the canonical schema exists — this is the same
    # initializer backend.init_db invokes, so the CLI can bootstrap a fresh database
    # that is byte-identical in structure to a backend-created one (D-10).
    conn = sqlite3.connect(db_path, timeout=10)
    initialize_schema(conn)
    c = conn.cursor()

    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verified_at = datetime.now().astimezone().isoformat()

    # Check if username exists
    c.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (username,))
    existing = c.fetchone()

    # Email must be unique (case-insensitive), excluding this same user when replacing.
    c.execute("SELECT username FROM users WHERE email = ? COLLATE NOCASE AND username <> ? COLLATE NOCASE",
              (email, username))
    clash = c.fetchone()
    if clash:
        sys.exit(f"Error: email '{email}' is already used by user '{clash[0]}'.")
    c.execute(
        "SELECT u.username FROM account_tokens t "
        "JOIN users u ON u.user_id=t.user_id "
        "WHERE t.purpose='email_verification' "
        "AND t.target_email = ? COLLATE NOCASE "
        "AND u.username <> ? COLLATE NOCASE "
        "AND t.expires >= ?",
        (email, username, int(datetime.now().timestamp())),
    )
    clash = c.fetchone()
    if clash:
        sys.exit(
            f"Error: email '{email}' is pending verification by user '{clash[0]}'."
        )

    if existing:
        if args.force:
            overwrite = 'y'
        elif non_interactive and not sys.stdin.isatty():
            # No TTY to prompt on and no --force: refuse rather than hang.
            sys.exit(f"User '{username}' already exists. Pass --force to replace it.")
        else:
            overwrite = input(f"User '{username}' already exists. Replace it? (y/n): ").strip().lower()
        if overwrite == 'y':
            # CLI-created users are pre-approved (they bootstrap the system, incl. the first admin).
            c.execute(
                "UPDATE users SET password_hash = ?, role = ?, status = 'approved', "
                "first_name = ?, last_name = ?, email = ?, email_verified_at = ? "
                "WHERE username = ? COLLATE NOCASE",
                (password_hash, role, first_name, last_name, email, verified_at, username)
            )
            c.execute("SELECT user_id FROM users WHERE username = ? COLLATE NOCASE", (username,))
            uid = c.fetchone()[0]
            c.execute("DELETE FROM account_tokens WHERE user_id = ?", (uid,))
            # Same delegation cleanup as the UI role routes: admin-level accounts are never
            # controlled — that includes management-group memberships, which would keep
            # producing controls() over the new admin through any manager grant; a replace
            # down to 'user' dissolves only the account's OWN grants — co-managed
            # users/groups keep their other controllers/owners/managers, and one with none
            # left is thereby in nobody-land / superadmin-owned.
            if role in ('admin', 'super_admin'):
                c.execute("DELETE FROM user_controllers WHERE user_id = ?", (uid,))
                c.execute("DELETE FROM mgmt_group_members WHERE user_id = ?", (uid,))
            else:
                c.execute("DELETE FROM user_controllers WHERE admin_id = ?", (uid,))
                c.execute("DELETE FROM share_group_owners WHERE admin_id = ?", (uid,))
                c.execute("DELETE FROM mgmt_group_managers WHERE admin_id = ?", (uid,))
            ensure_base_map(c, uid)
            conn.commit()
            print(f"User '{username}' replaced successfully.")
        else:
            print("No changes made.")
    else:
        user_uuid = str(uuid.uuid4())
        # CLI-created users are pre-approved (they bootstrap the system, incl. the first admin).
        c.execute(
            "INSERT INTO users (user_id, username, password_hash, role, status, created, "
            "first_name, last_name, email, email_verified_at) "
            "VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?)",
            (user_uuid, username, password_hash, role, created, first_name, last_name,
             email, verified_at)
        )
        ensure_base_map(c, user_uuid)
        conn.commit()
        print(f"User '{username}' with role '{role}' created successfully.")

    conn.close()


if __name__ == "__main__":
    main()
