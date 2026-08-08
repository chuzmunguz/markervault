"""Canonical database schema shared by the Flask backend and the CLI (D-10).

initialize_schema(conn) is the ONLY place tables are defined; both entry points
invoke it, so the schemas cannot drift. The database is disposable pre-public:
schema changes are baked into CREATE TABLE here, never expressed as migrations.

R-06: the relationship tables (map_shares, share_group_members, map_group_shares,
mgmt_group_members) use their natural pair as a composite PRIMARY KEY — the old
autoincrement surrogate ids added no capability and are gone. Audit history keeps
its own identity in audit_log; repeated grant/change/remove cycles remain distinct
audit rows without a relationship-incarnation id.
"""


def initialize_schema(conn):
    c = conn.cursor()
    # Maps are owned per user. is_base marks each user's undeletable starter map (their
    # personal "Base Map"). Name uniqueness is scoped per owner, and the old global
    # Base-Map protection triggers are replaced by ownership-aware checks in the handlers.
    c.execute('''
        CREATE TABLE IF NOT EXISTS maps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            name TEXT NOT NULL,
            is_base INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL,
            description TEXT,
            notes TEXT,
            FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_maps_owner_name ON maps(owner_id, name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_maps_owner ON maps(owner_id)")
    # Sharing: a map can be shared with other users as 'viewer' (read-only) or
    # 'editor' (edit the map entity and its markers/photos, but not delete or re-share it).
    # The composite key doubles as the map_id lookup index.
    c.execute('''
        CREATE TABLE IF NOT EXISTS map_shares (
            map_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('viewer', 'editor')),
            created TEXT NOT NULL,
            PRIMARY KEY (map_id, user_id),
            FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_map_shares_user ON map_shares(user_id)")
    # Share groups (admin-managed): a map shared with a share group grants every member
    # the group's role. Access is computed per-request, so adding/removing a member
    # propagates instantly. Base Maps stay outside sharing, group or direct.
    # Ownership (the owns_share_group() relation) lives in share_group_owners, defined
    # after users. created_by records the creating account permanently; the delete rule
    # is gated on it ("creator only"), ownership alone isn't enough.
    # The sibling table pair for delegation is management_groups below — share-group
    # membership stays administratively inert (map-sharing reach only, never authority).
    c.execute('''
        CREATE TABLE IF NOT EXISTS share_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created TEXT NOT NULL,
            created_by TEXT REFERENCES users(user_id) ON DELETE SET NULL
        )
    ''')
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_share_groups_name_nocase ON share_groups(name COLLATE NOCASE)")
    c.execute('''
        CREATE TABLE IF NOT EXISTS share_group_members (
            group_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES share_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_share_group_members_user ON share_group_members(user_id)")
    c.execute('''
        CREATE TABLE IF NOT EXISTS map_group_shares (
            map_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('viewer', 'editor')),
            created TEXT NOT NULL,
            PRIMARY KEY (map_id, group_id),
            FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES share_groups(id) ON DELETE CASCADE
        )
    ''')
    # photo_count is deliberately absent (R-05): the photos table is the authoritative
    # relationship, and API responses derive the count with an indexed subquery.
    c.execute('''
        CREATE TABLE IF NOT EXISTS spots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            created TEXT NOT NULL,
            notes TEXT,
            listing TEXT DEFAULT 'General',
            subset TEXT DEFAULT 'Main',
            FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            spot_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            caption TEXT DEFAULT '',
            FOREIGN KEY (spot_id) REFERENCES spots(id) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS import_progress (
            job_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            map_id INTEGER NOT NULL,
            imported INTEGER,
            total INTEGER,
            skipped INTEGER,
            photos_failed INTEGER,
            photos_budget_skipped INTEGER,
            progress INTEGER,
            status TEXT,
            error TEXT,
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            completed TEXT,
            last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (map_id) REFERENCES maps(id) ON DELETE CASCADE
        )
    ''')
    # Profile fields are nullable at the schema level; first_name/last_name/email are
    # required by the /register and /profile handlers, not by the DB.
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'pending',
            created TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            company TEXT,
            department TEXT,
            birth_date TEXT,
            sex TEXT,
            avatar TEXT,
            email_verified_at TEXT DEFAULT CURRENT_TIMESTAMP,
            auth_version INTEGER NOT NULL DEFAULT 0
        )
    ''')
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_username_nocase ON users(username COLLATE NOCASE)")
    c.execute('''
        CREATE TABLE IF NOT EXISTS account_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_reset')),
            token_hash TEXT UNIQUE NOT NULL,
            target_email TEXT,
            created INTEGER NOT NULL,
            expires INTEGER NOT NULL,
            UNIQUE (user_id, purpose),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_account_tokens_target_email
        ON account_tokens (target_email COLLATE NOCASE)
        WHERE target_email IS NOT NULL
    ''')
    # user_controllers is the controls() relation, many-to-many: each row is one regular
    # admin who manages this user (co-managed teams hold several rows). Zero rows =
    # nobody-land (approved but under no admin; superadmin-assignable only, there is no
    # admin self-claim). admin_id only ever points at a role='admin' account —
    # superadmins need no grant and admins can never be controlled. Deleting either
    # account cascades away just that account's rows; a user whose last controller
    # disappears is thereby back in nobody-land with no cleanup step.
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_controllers (
            user_id TEXT NOT NULL,
            admin_id TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (user_id, admin_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_controllers_admin ON user_controllers(admin_id)")
    # share_group_owners is the owns_share_group() relation, many-to-many, mirroring
    # user_controllers: each row is one admin who manages the group. Zero rows =
    # superadmin-owned (the true default — an admin's ownership is a delegation, and
    # revoking the last one reverts here, never to a claimable pool).
    c.execute('''
        CREATE TABLE IF NOT EXISTS share_group_owners (
            group_id INTEGER NOT NULL,
            admin_id TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (group_id, admin_id),
            FOREIGN KEY (group_id) REFERENCES share_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_share_group_owners_admin ON share_group_owners(admin_id)")
    # Management groups (Addendum 3): the bulk-delegation sibling of share groups.
    # Superadmin-only end to end — created, renamed, deleted and membership-managed by
    # superadmins alone, and always owned by the superadmin side (no owner rows exist;
    # created_by is a historical fact, not authority). No admin self-serve path of any
    # kind. Members are regular users only, never admin-level accounts.
    c.execute('''
        CREATE TABLE IF NOT EXISTS management_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created TEXT NOT NULL,
            created_by TEXT REFERENCES users(user_id) ON DELETE SET NULL
        )
    ''')
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_management_groups_name_nocase ON management_groups(name COLLATE NOCASE)")
    # mgmt_group_membership: administratively inert ON ITS OWN (same invariant as
    # share-group membership) — it only produces controls() when combined with a
    # manager grant below.
    c.execute('''
        CREATE TABLE IF NOT EXISTS mgmt_group_members (
            group_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES management_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_mgmt_group_members_user ON mgmt_group_members(user_id)")
    # mgmt_group_managers is the manage_mgmt_group() relation: each row delegates
    # MANAGEMENT of the group's members to one regular admin (never ownership — the
    # group stays superadmin-owned). Combined with membership it is the second source
    # of controls(): effective_controls = direct user_controllers OR (member AND
    # manager). Many-to-many, additive, targeted revocation — superadmin-written only.
    c.execute('''
        CREATE TABLE IF NOT EXISTS mgmt_group_managers (
            group_id INTEGER NOT NULL,
            admin_id TEXT NOT NULL,
            created TEXT NOT NULL,
            PRIMARY KEY (group_id, admin_id),
            FOREIGN KEY (group_id) REFERENCES management_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_mgmt_group_managers_admin ON mgmt_group_managers(admin_id)")
    # Email is unique, case-insensitive (Alice@x.com and alice@x.com collide).
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_email_nocase ON users(email COLLATE NOCASE)")
    # S-05 session families: every login starts a family; rotation retains the
    # consumed predecessor (consumed_at + predecessor_id lineage) so presenting a
    # consumed token is detectable replay, which revokes the whole family. The
    # require_auth identity gate checks the family still holds a live active head.
    c.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            family_id TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'consumed')),
            expires INTEGER NOT NULL,
            created INTEGER NOT NULL,
            consumed_at INTEGER,
            predecessor_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id)")

    # Per-user notification history is a convenience/diagnostic surface, not an
    # audit log. Frozen target fields survive deletion of their object, while the
    # owning user's deletion removes the private history itself.
    c.execute('''
        CREATE TABLE IF NOT EXISTS notif_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            created TEXT NOT NULL,
            event TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            target_label TEXT,
            message TEXT NOT NULL,
            detail TEXT,
            correlation_id TEXT,
            seen INTEGER NOT NULL DEFAULT 0 CHECK (seen IN (0, 1)),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_notif_history_user ON notif_history(user_id, id)")

    c.execute("CREATE INDEX IF NOT EXISTS idx_spots_mapid ON spots(map_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_spots_mapid_name ON spots(map_id, name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_spots_listing ON spots(listing)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_spots_subset ON spots(subset)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_photos_spot_id ON photos(spot_id)")
    # Audit rows deliberately carry frozen string snapshots and no foreign keys so
    # they survive deletion of the actor or target they describe.
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor_id TEXT,
            actor_username TEXT,
            actor_role TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            target_label TEXT,
            detail TEXT,
            client_ip TEXT
        )
    ''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")

    conn.commit()
