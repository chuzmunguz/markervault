#!/usr/bin/env bash
set -e

# Seed the disposable test fixtures into a freshly deployed EMPTY database.
# Run after ./install.sh --wipe-data: sudo ./seed.sh
# Deployment and seeding are deliberately separate: a --wipe-data deploy hands over
# a clean empty schema; this script populates the standard test accounts, maps,
# spots, and notification-history examples.
# For a real account instead, use create_users.py with the service environment.
ENV_FILE=/etc/markervault/markervault.env

set -a
source "$ENV_FILE"
set +a
DB="${MARKERVAULT_DB_PATH:?MARKERVAULT_DB_PATH missing from $ENV_FILE}"
PASSWORD='Abcd1234!'

if ! sudo -u markervault sqlite3 "$DB" "SELECT 1 FROM users LIMIT 1;" >/dev/null 2>&1; then
    echo "ERROR: no schema at $DB — deploy first with ./install.sh --wipe-data" >&2
    exit 1
fi
if [ "$(sudo -u markervault sqlite3 "$DB" 'SELECT COUNT(*) FROM users;')" != "0" ]; then
    echo "ERROR: the database already has users; seeding targets a clean deploy." >&2
    echo "Rerun ./install.sh --wipe-data for a fresh empty database, then seed." >&2
    exit 1
fi

sudo -u markervault sqlite3 "$DB" <<'SQL'
.bail on
PRAGMA foreign_keys = ON;
BEGIN;

-- Every test account uses the bcrypt hash for Abcd1234!.
WITH seed_users(user_id, username, role, first_name, last_name, email, department) AS (
    VALUES
        ('b93aa953-b5ef-5a7c-8f66-9377e69b3a86', 'superadmin',  'super_admin', 'Super', 'Admin',      'superadmin@markervault.test',  'Platform'),
        ('cfcde411-94af-557b-9052-6198db312556', 'admin1', 'admin', 'Admin', '1',          'admin1@markervault.test', 'North Operations'),
        ('4317793e-aba6-5559-b580-a925f677c566', 'admin2', 'admin', 'Admin', '2',          'admin2@markervault.test', 'South Operations'),
        ('64f9d275-f426-50d9-847f-81313303300a', 'user1',  'user',  'User',  'Direct',     'user1@markervault.test',  'Field'),
        ('7203262c-c13b-5a73-a70d-00520143bad5', 'user2',  'user',  'User',  'Comanaged',  'user2@markervault.test',  'Routing'),
        ('a60d8765-a5e9-57f2-b89d-3d7b236daacb', 'user3',  'user',  'User',  'Grouped',    'user3@markervault.test',  'Field'),
        ('b0787a64-03f6-5de1-9e2b-d874472ca93d', 'user4',  'user',  'User',  'Mixed',      'user4@markervault.test',  'Routing'),
        ('4eb3e962-2f11-500c-8588-bf3db7951bcb', 'user5',  'user',  'User',  'Unassigned', 'user5@markervault.test',  'Sandbox')
)
INSERT INTO users (
    user_id,
    username,
    password_hash,
    role,
    status,
    created,
    first_name,
    last_name,
    email,
    company,
    department,
    email_verified_at
)
SELECT
    user_id,
    username,
    X'24326224313224694b58527545723444626159344a762e342f68676a7579324c4e5061716c523551747531366249716f367461642e4b703966567657',
    role,
    'approved',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    first_name,
    last_name,
    email,
    'MarkerVault Test',
    department,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM seed_users;

INSERT INTO maps (owner_id, name, is_base, created, description, notes)
SELECT
    user_id,
    'Base Map',
    1,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'Your default map. This map cannot be deleted.',
    'Seeded test base map.'
FROM users;

-- Direct manager assignments.
INSERT INTO user_controllers (user_id, admin_id, created) VALUES
    ('64f9d275-f426-50d9-847f-81313303300a', 'cfcde411-94af-557b-9052-6198db312556', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('7203262c-c13b-5a73-a70d-00520143bad5', 'cfcde411-94af-557b-9052-6198db312556', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('7203262c-c13b-5a73-a70d-00520143bad5', '4317793e-aba6-5559-b580-a925f677c566', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ('b0787a64-03f6-5de1-9e2b-d874472ca93d', 'cfcde411-94af-557b-9052-6198db312556', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Management group: Admin 2 manages User 3 and User 4 through the group.
INSERT INTO management_groups (name, created, created_by)
VALUES (
    'Field Management',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'b93aa953-b5ef-5a7c-8f66-9377e69b3a86'
);

INSERT INTO mgmt_group_members (group_id, user_id, created) VALUES
    ((SELECT id FROM management_groups WHERE name = 'Field Management'), 'a60d8765-a5e9-57f2-b89d-3d7b236daacb', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM management_groups WHERE name = 'Field Management'), 'b0787a64-03f6-5de1-9e2b-d874472ca93d', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO mgmt_group_managers (group_id, admin_id, created)
VALUES (
    (SELECT id FROM management_groups WHERE name = 'Field Management'),
    '4317793e-aba6-5559-b580-a925f677c566',
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);

-- Sharing groups.
INSERT INTO share_groups (name, created, created_by) VALUES
    ('Field Viewers', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'cfcde411-94af-557b-9052-6198db312556'),
    ('Field Editors', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), '4317793e-aba6-5559-b580-a925f677c566');

INSERT INTO share_group_owners (group_id, admin_id, created) VALUES
    ((SELECT id FROM share_groups WHERE name = 'Field Viewers'), 'cfcde411-94af-557b-9052-6198db312556', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM share_groups WHERE name = 'Field Editors'), '4317793e-aba6-5559-b580-a925f677c566', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO share_group_members (group_id, user_id, created) VALUES
    ((SELECT id FROM share_groups WHERE name = 'Field Viewers'), '64f9d275-f426-50d9-847f-81313303300a', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM share_groups WHERE name = 'Field Viewers'), 'a60d8765-a5e9-57f2-b89d-3d7b236daacb', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM share_groups WHERE name = 'Field Editors'), '7203262c-c13b-5a73-a70d-00520143bad5', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM share_groups WHERE name = 'Field Editors'), 'b0787a64-03f6-5de1-9e2b-d874472ca93d', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Custom maps.
INSERT INTO maps (owner_id, name, is_base, created, description, notes) VALUES
    ('cfcde411-94af-557b-9052-6198db312556', 'Operations HQ', 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Direct and group access test map.', 'Viewer/editor precedence cases.'),
    ('64f9d275-f426-50d9-847f-81313303300a', 'User 1 Field Survey', 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'User-owned survey map.', 'User 5 has direct editor access.'),
    ('7203262c-c13b-5a73-a70d-00520143bad5', 'User 2 Route Plan', 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Group editor test map.', 'Field Viewers can edit.'),
    ('4eb3e962-2f11-500c-8588-bf3db7951bcb', 'Unassigned Sandbox', 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Nobody-land user map.', 'No admin manages this owner.');

-- Direct map access.
INSERT INTO map_shares (map_id, user_id, role, created) VALUES
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), '64f9d275-f426-50d9-847f-81313303300a', 'editor', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), '7203262c-c13b-5a73-a70d-00520143bad5', 'viewer', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM maps WHERE name = 'User 1 Field Survey'), '4eb3e962-2f11-500c-8588-bf3db7951bcb', 'editor', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Group map access.
INSERT INTO map_group_shares (map_id, group_id, role, created) VALUES
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), (SELECT id FROM share_groups WHERE name = 'Field Viewers'), 'viewer', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), (SELECT id FROM share_groups WHERE name = 'Field Editors'), 'editor', strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ((SELECT id FROM maps WHERE name = 'User 2 Route Plan'), (SELECT id FROM share_groups WHERE name = 'Field Viewers'), 'editor', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Spots.
INSERT INTO spots (map_id, name, lat, lng, created, notes, listing, subset) VALUES
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), 'North Depot', 38.7369, -9.1427, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Primary equipment depot.', 'Operations', 'North'),
    ((SELECT id FROM maps WHERE name = 'Operations HQ'), 'River Checkpoint', 38.7078, -9.1366, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Permission test point.', 'Operations', 'Central'),
    ((SELECT id FROM maps WHERE name = 'User 1 Field Survey'), 'Survey Start', 38.7223, -9.1393, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Starting point.', 'Survey', 'Day 1'),
    ((SELECT id FROM maps WHERE name = 'User 1 Field Survey'), 'Survey Finish', 38.7152, -9.1301, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Finishing point.', 'Survey', 'Day 2'),
    ((SELECT id FROM maps WHERE name = 'User 2 Route Plan'), 'Route Alpha', 38.7514, -9.1562, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'First route waypoint.', 'Routes', 'Alpha'),
    ((SELECT id FROM maps WHERE name = 'User 2 Route Plan'), 'Route Beta', 38.7635, -9.0952, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Second route waypoint.', 'Routes', 'Beta'),
    ((SELECT id FROM maps WHERE name = 'Unassigned Sandbox'), 'Sandbox Marker', 38.7167, -9.1333, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Unassigned-user marker.', 'General', 'Main');

-- Notification history: every account gets seen and unseen examples so the badge,
-- list, Mark all seen flow, and complete event taxonomy are testable under every role.
WITH notification_templates(
    age_modifier,
    event,
    target_type,
    target_id,
    target_label,
    message,
    detail,
    correlation_id,
    seen
) AS (
    VALUES
        ('-3 days', 'map.deleted', 'map', 'seed-deleted-map-{username}', 'Archived Field Map', 'Map "Archived Field Map" deleted.', '{"markers":4,"photos":6}', NULL, 1),
        ('-1 day', 'marker.deleted', 'marker', 'seed-marker-old-checkpoint-{username}', 'Old Checkpoint', 'Marker "Old Checkpoint" deleted from "Field Survey".', '{"map_id":"seed-map-{username}","map_label":"Field Survey"}', NULL, 1),
        ('-12 hours', 'photo.deleted', 'photo', 'seed-photo-overlook-{username}.jpg', 'Survey overlook', 'Photo "Survey overlook" deleted from marker "Survey Start".', '{"map_label":"Field Survey","marker_id":"seed-marker-survey-start-{username}","marker_label":"Survey Start"}', NULL, 0),
        ('-6 hours', 'kml.import_done', 'kml_job', 'seed-job-done-{username}', 'Base Map', 'Imported 12 markers into "Base Map".', '{"imported":12,"job_id":"seed-job-done-{username}","map_id":"seed-base-map-{username}","map_label":"Base Map","photos_budget_skipped":0,"photos_failed":0,"skipped":0}', NULL, 0),
        ('-3 hours', 'kml.import_degraded', 'kml_job', 'seed-job-degraded-{username}', 'Field Survey', 'Imported 9 markers; photos failed or were skipped at Survey Start and Survey Finish.', '{"affected_spots":["Survey Start","Survey Finish"],"affected_spots_omitted":0,"exhausted_budgets":["attempts"],"imported":9,"job_id":"seed-job-degraded-{username}","map_id":"seed-map-{username}","map_label":"Field Survey","photos_budget_skipped":3,"photos_failed":2,"skipped":1}', NULL, 0),
        ('-1 hour', 'kml.import_error', 'kml_job', 'seed-job-error-{username}', 'Field Survey', 'The KML import could not be completed.', '{"error":"kml_parse_failed","job_id":"seed-job-error-{username}","map_id":"seed-map-{username}","map_label":"Field Survey"}', NULL, 0),
        ('-15 minutes', 'server.error', 'request', 'POST /maps', NULL, 'The server could not complete the request.', '{"area":"map.create","method":"POST","route":"/maps"}', 'seedreq-{username}', 0)
)
INSERT INTO notif_history (
    user_id,
    created,
    event,
    target_type,
    target_id,
    target_label,
    message,
    detail,
    correlation_id,
    seen
)
SELECT
    users.user_id,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now', notification_templates.age_modifier),
    notification_templates.event,
    notification_templates.target_type,
    replace(notification_templates.target_id, '{username}', users.username),
    notification_templates.target_label,
    notification_templates.message,
    replace(notification_templates.detail, '{username}', users.username),
    replace(notification_templates.correlation_id, '{username}', users.username),
    notification_templates.seen
FROM users
CROSS JOIN notification_templates;

COMMIT;

SELECT 'users: ' || COUNT(*) FROM users;
SELECT 'management groups: ' || COUNT(*) FROM management_groups;
SELECT 'sharing groups: ' || COUNT(*) FROM share_groups;
SELECT 'custom maps: ' || COUNT(*) FROM maps WHERE is_base = 0;
SELECT 'spots: ' || COUNT(*) FROM spots;
SELECT 'notifications: ' || COUNT(*) FROM notif_history;
SQL

echo
echo "All test users have password: $PASSWORD"
