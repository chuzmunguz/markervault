# Notification History (notifHistory) — specification

**Status: IMPLEMENTED (2026-07-22).** The backend foundation, fixtures,
destructive/KML/5xx producers, account-menu UI, and real-boundary coverage are complete.

## Purpose

Toasts vanish after ~3 seconds and are the only channel for outcomes the user may
need after the moment has passed (a deletion, an async KML result, a degraded
completion). This feature adds a durable, per-user, server-authored history of
those outcomes. Toasts themselves are unchanged.

## Decisions already made (owner, 2026-07-22)

- **Server-authored only.** History rows are written by the backend at the moment it
  performs the action, mirroring the `audit()` pattern. The client never posts
  notification text (no spoofing/noise surface). There is **no client-side toast
  log** — of the 114 toast call sites, ~47 are client-local prompts about the form
  or selection currently on screen and have no after-the-fact value; the rest are
  server-witnessed and can be recorded server-side.
- **Curated event set** (criterion: *persist what cannot be reconstructed by looking
  at the app afterward*):
  1. Destructive successes — one named row for every explicitly deleted
     map/marker/photo object.
  2. Async job outcomes — every KML terminal outcome: clean, degraded, failed, or
     interrupted.
  3. Partial/degraded completions — KML jobs with failed or skipped photos, with
     affected spot names (truncated list) so partial states are attributable.
  4. Authenticated internal errors (5xx) — generic message plus a
     `correlation_id`, linking user-visible history to the detailed server log.
  Deliberately excluded from v1: routine success chatter (the visible map state is
  the confirmation), validation 400s, client-local messages, sharing/role changes
  (current state is always inspectable in the collab panel; audit log covers
  forensics).
- **Naming: `notifHistory`** for user-facing surfaces (owner's call). URL path uses
  `notif_history`. Never "share" in DOM ids/URL paths (adblocker rule); existing
  toast ids stay untouched.
- **Retention cap: 200 by default** (owner decision), backend-configurable through
  `MARKERVAULT_NOTIF_HISTORY_CAP`, and enforced without background timers.
- **Post-commit/fail-open writes.** The real operation commits first; notification
  history is a synchronous best-effort side effect on its own connection. A history
  failure is logged and never rolls back or changes the successful operation.
- **Bulk actions remain per-selected-object actions.** Marker bulk deletion already
  issues one authenticated DELETE per selected marker. The owner approved removing
  the maps-sidebar child-marker pre-pass: map bulk deletion must issue one DELETE per
  selected map and let the backend cascade its children. Each committed target writes
  its own named history row; there are no count-only aggregate rows or bulk event
  types. A partial bulk run therefore records exactly which selected objects
  succeeded.
- **Seen state is explicit.** Opening or closing the panel never marks anything
  seen. A dedicated **Mark all seen** button marks only the rows included in the
  rendered snapshot.
- **UI placement.** `notifHistoryBtn` is an account-menu row between Profile and
  Administration (or between Profile and Logout when Administration is hidden).
- **Badge and icon.** Use a bell icon. Its badge displays the exact current unseen
  count with no `99+` abbreviation, hides at zero, and expands for every value allowed
  by the configured retention cap.

## Schema (baked into `markervault_schema.py` — no migrations, DB is disposable)

```sql
CREATE TABLE notif_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        TEXT NOT NULL,
    created        TEXT NOT NULL,             -- ISO-8601, server clock
    event          TEXT NOT NULL,             -- taxonomy below
    target_type    TEXT,                      -- map/marker/photo/kml_job/request
    target_id      TEXT,                      -- frozen id/filename/job id
    target_label   TEXT,                      -- frozen human-readable name
    message        TEXT NOT NULL,             -- server-authored, capped
    detail         TEXT,                      -- bounded server-authored JSON
    correlation_id TEXT,                      -- server/unexpected KML errors
    seen           INTEGER NOT NULL DEFAULT 0 CHECK (seen IN (0, 1)),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX idx_notif_history_user ON notif_history (user_id, id);
```

Event taxonomy (dotted, following `audit_log` style): `map.deleted`,
`marker.deleted`, `photo.deleted`, `kml.import_done`, `kml.import_degraded`,
`kml.import_error`, `server.error`.

`target_*` and `detail` are frozen diagnostic context, not live foreign references.
Deletion rows retain the deleted object's id/name plus its parent map/marker context;
KML rows retain the job/map ids and all terminal counters; `server.error` retains the
sanitized route rule, method, and error area. Exception details, raw URLs, request
bodies, credentials, and tokens never enter this table.

Server-output caps live beside the backend helper rather than in the request-field
validation module: `NOTIF_MESSAGE_MAX = 500`, `NOTIF_TARGET_TYPE_MAX = 40`,
`NOTIF_TARGET_ID_MAX = 200`, `NOTIF_TARGET_LABEL_MAX = 200`,
`NOTIF_CORRELATION_ID_MAX = 64`, and `NOTIF_DETAIL_MAX = 2000`. The frontend renders
messages and labels via `textContent`.

## Write path

Owner-approved helper contract (2026-07-22):

`notify(user_id, event, message, target_type=None, target_id=None,
target_label=None, detail=None, correlation_id=None)` next to `audit()`:

- It owns its database connection, exactly like `audit()`.
- A successful mutation commits first, then calls `notify()` synchronously before
  returning its response. A notification failure is fail-open and cannot undo the
  real action.
- Error paths roll back/close the failed action's connection before `internal_error()`
  calls `notify()` on its independent connection.
- This deliberately accepts a narrow crash window between the real commit and the
  history insert. Putting both writes in one transaction would remove that window,
  but then a notification-table failure could roll back or fail the user's real
  operation; those two guarantees cannot both be absolute.
- Retention enforced at insert (read-triggered precedent): after insert, delete this
  user's rows beyond the cap, oldest first. Reads defensively reapply the cap so a
  lower configured value after restart cannot leave unseen rows outside the rendered
  high-water snapshot. No timers.
- It returns whether insertion succeeded so tests can prove fail-open behavior; the
  response contract does not claim a row exists when insertion failed.
- A failed history insert emits one structured `notif_history.write_failed` server
  log with user id, event, target type/id, and any existing correlation id. It never
  logs the message/detail payload or credentials. This makes the accepted fail-open
  gap diagnosable without exposing notification content.

Curated call sites (v1):

- `delete_map`: one `map.deleted` row with the map id/name and pre-delete
  marker/photo counts. Cascaded children are diagnostic detail on that map row, not
  synthetic user actions.
- `delete_spot`: one `marker.deleted` row with marker id/name and parent map id/name.
- Photo DELETE: one `photo.deleted` row with filename/caption and parent marker/map
  context.
- The current bulk UI keeps calling those single-object routes. It naturally creates
  one row per successful object and no row for a failed object. Do not add bulk event
  types or accept notification text/counts from the client.
- Each deletion row belongs to the authenticated actor. An editor deleting a marker
  from a shared map gets the row in their own history; v1 does not fan that event out
  to the map owner or other collaborators.
- Example: deleting selected markers "Campground" and "Viewpoint" creates two rows:
  `Marker “Campground” deleted from “Weekend trip”.` and
  `Marker “Viewpoint” deleted from “Weekend trip”.` Deleting selected maps creates
  one named `map.deleted` row per map. The frozen ids remain in `target_id`/`detail`;
  there is never an information-poor `N objects deleted` replacement row.
- Required owner-approved map-client correction before enabling deletion producers:
  remove the child-marker DELETE pre-pass from both the single-map `deleteMap()` path
  and the maps-sidebar bulk path. The bulk path must also stop fetching each map's
  child list. The backend `delete_map` route already performs the database cascade and
  media cleanup. The client sends one DELETE per explicitly selected map; then
  `map.deleted` sees accurate pre-delete child counts and a large map cannot evict the
  history cap with synthetic child actions. Marker-sidebar bulk deletion remains
  unchanged.
- KML completion in `process_kml_job`, after `import_kml_file` commits and returns
  its terminal counters, attempts exactly one row. Clean run →
  `kml.import_done` with imported/skipped counts. Degraded run (photos_failed > 0
  or budget/deadline skips > 0) → `kml.import_degraded`, message includes counts,
  the first **10** affected spot names (or all when fewer), and "and N more…" when
  names were omitted. This closes the
  "partial states must be attributable" requirement from the degrade-and-finish
  decision. `detail` includes every terminal counter, the map/job ids, exhausted
  budget names, and the bounded affected-spot list. If that list would push the JSON
  past `NOTIF_DETAIL_MAX`, trim names from its tail and retain every numeric counter,
  budget name, and the exact omitted-name count.
- `process_kml_job`: expected fatal import failures and unexpected worker exceptions
  write `kml.import_error`. Unexpected exceptions mint a correlation id shared with
  the detailed server log; expected bounded-input failures retain their stable error
  token without exposing parser/exception text.
- Startup recovery: every queued/running job changed to `error='interrupted'` gets a
  `kml.import_error` row for its owner before normal service begins. Recovery first
  SELECTs the queued/running rows (including owner/map/job context), UPDATEs that
  exact selected set to interrupted and commits, then emits their terminal rows.
  Repeated boots are idempotent because the committed terminal rows no longer match
  the recovery selection.
- Normal KML completion attempts its fail-open notification and releases the
  admission slot before publishing `done`/`error` status. Therefore a client that
  observes terminal status can immediately fetch the matching history row and start
  another import without racing notification storage or slot release.
- Every authenticated Flask 5xx attempts exactly one `server.error` row under the
  fail-open write contract. All explicit 5xx paths route through `internal_error()`
  (including the former avatar-save raw 500), while a global 500 handler covers
  uncaught exceptions. The history row stores only generic text, method, sanitized
  route rule, area, and correlation id; detailed exception data remains in the server
  log. Unauthenticated failures and all 4xx responses write nothing. KML worker
  failures use `kml.import_error`, never a second `server.error` row.

## Read path (no polling — background-activity policy)

- `GET /notif_history` — auth required; own rows only; newest first; up to the cap.
  The response object contains `notifications`, `unseen`, and `through_id`, the
  highest row id in that rendered snapshot. When the snapshot is empty,
  `notifications` is empty, `through_id` is `null`, and Mark all seen is disabled;
  the POST endpoint also treats a null/zero high-water as a no-op.
- `GET /notif_history?summary=1` — auth required; returns the unseen count without
  row bodies. Called once at authenticated boot and after the current tab observes a
  curated deletion, terminal KML result, or authenticated 5xx. These are bounded
  operation-driven refreshes, not ambient polling.
- `POST /notif_history/seen` — auth required; JSON body `{ "through_id": N }`.
  The dedicated button updates only this user's unseen rows with `id <= N`. A row
  inserted after the panel snapshot remains unseen. The response returns the current
  unseen count so a concurrent new event keeps the badge visible.
- `POST /notif_history/<id>/seen` — auth required; JSON body `{ "seen": true|false }`.
  Sets one owned row to the requested state and returns that state plus the current
  exact unseen count. A missing or other user's row is an indistinguishable 404.
  Set-state semantics make retries idempotent even though clicking the row toggles
  the state visible to the user.
- Other tabs can have a stale badge until they open the panel, perform a relevant
  action, or reload. Cross-tab notification broadcasting and background refresh are
  deliberately out of v1.

## UI

- Account-menu button `notifHistoryBtn` with a bell icon immediately after
  `accountProfileBtn` and before `openAdminPanelBtn`, visible to every authenticated
  role. Its visible label is **Notifications**. Its badge shows the exact unseen
  count, never abbreviates it, and is absent when the count is zero.
- Overlay `notifHistoryOverlay` following the existing overlay conventions:
  rows (`notifHistoryList`) show a friendly event label and relative/absolute
  timestamp in a compact header, with the server-authored message beneath it. Neutral,
  success, warning, and error outcomes use restrained semantic accents; raw dotted
  event keys are not exposed as user-facing prose. Unseen rows are highlighted;
  empty state "No notifications yet." Opening re-fetches. Clicking or
  keyboard-activating a row toggles that row between seen and unseen and updates the
  exact badge from the server response. A visible **Mark all seen** button posts the
  current `through_id`; closing does nothing. No auto-refresh while open.
- `clearAuthState()` clears the badge, cached rows, `through_id`, and any open history
  overlay, and invalidates in-flight history responses so a kicked session followed
  by another login cannot expose the previous account's state.

## nginx

`location /notif_history { proxy_pass http://127.0.0.1:5000/notif_history; }` —
JSON-sized (1 MB default body cap applies; POST bodies contain only one integer or
one boolean).

## Tests

Implemented coverage:

- Backend `test_notif_history.py` (six-file bootstrap rule): canonical schema and
  enforced user cascade; fixed output bounds; valid detail serialization; fail-open
  writer and redacted `notif_history.write_failed` log; per-user retention and read
  isolation; list/summary response shapes; null/zero high-water no-ops; and
  idempotent, owner-isolated per-row seen state.
- Seen tests reproduce the high-water race: insert a second row after GET, mark
  through the first response's `through_id`, and prove the second row remains unseen.
- `stage4_reproducibility_test.py` executes the real `seed.sh` SQL against the
  canonical schema and proves all eight fixture accounts get seven rows, mixed seen
  state, the complete event taxonomy, and valid JSON detail.
- Deletion tests prove each explicit successful map/marker/photo creates one
  named/structured row after its mutation commits, failed objects create none, map
  cascades create no synthetic child rows, and a history-write failure cannot undo or
  misreport the real deletion. The browser matrix proves both single and multi-map
  client paths send only map DELETEs, with one request per selected map and no child
  reads/deletes, and proves a later map creation cannot re-render deleted map rows.

- KML tests cover clean, degraded, expected fatal, unexpected-correlated, and
  boot-interrupted outcomes, including the 10-name limit and idempotent startup.
- 5xx tests cover every explicit `internal_error()` path, the avatar-save path, an
  uncaught authenticated exception, unauthenticated exclusion, generic client text,
  exact correlation-id linkage, and no duplicate rows. A static assertion rejects
  authenticated raw-500 returns outside the shared helper.
- Browser tests verify the bell row is exactly between Profile and Administration,
  the badge shows the exact boot count and hides at zero, the panel lists rows, Mark
  all seen uses the current `through_id`, a concurrently inserted row keeps the exact
  remaining count, clicking a row toggles read/unread with the server's exact badge
  count, two-user re-login clears prior state, and there are **zero requests to
  `/notif_history` while idle**.
- HTML/mobile structure coverage includes the new overlay body order and verifies the
  account-menu row remains usable at the supported narrow viewport.
- The standalone live KML check crosses the real worker, SQLite, authenticated API,
  badge/panel, high-water seen write, per-row read/unread writes, and clean/degraded
  terminal paths.
- Both complete rigs are green at handback; AGENTS.md counts stay exact.

## Config

- `MARKERVAULT_NOTIF_HISTORY_CAP` (int, owner-approved default **200**,
  administrator-configurable) in `markervault_config.py`, exported as
  `NOTIF_HISTORY_CAP`.

## Non-goals (v1)

Sharing/role-change events; cross-user notifications (e.g. telling collaborators a
shared map was deleted — future candidate, drags in addendum-4 visibility rules);
email delivery; pagination; audit-log replacement (audit stays the forensic record;
this is a per-user convenience surface with no tamper-resistance claims); aggregate
bulk-summary rows; client-authored notification content; live cross-tab badge sync.

