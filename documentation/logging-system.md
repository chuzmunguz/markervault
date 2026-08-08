# Audit Logging System (design + rationale)

> **STATUS: IMPLEMENTED — Jul 16 2026.** The schema, fail-open writer, governance/auth
> instrumentation, super-only keyset endpoint, Audit tab, and backend/browser coverage
> are built. Deliberate implementation amendment: `detail` remains JSON text in SQLite
> but `GET /admin/audit` deserializes it to an object (or `null`) for clients.
>
> **Map-access taxonomy amendment — Jul 18 2026.** Admin-side map access records use
> six explicit `map_share.direct|group.grant|change|remove` actions. The owner accepted
> a database reset instead of legacy aliases; actual sharing behavior is unchanged.
>
> The Motivation below intentionally preserves the pre-implementation problem
> statement. The implementation status above is the current state.

> **Scope in one line:** a plain, append-only record of every **governance mutation** (who did what administrative action, to whom, when) **plus authentication events** (login / logout / failed login), readable by super-admins only. Deliberately **not** a tamper-evidence system, **not** a data-route access log, **not** an audit of owner-side sharing, **not** a retention/rotation engine.

---

## Motivation

markervault has, today, **zero logging of any kind** — `grep -niE "audit|log_action|app.logger|record_|logging\."` over `backend.py` returns nothing. Every privileged action (disable a user, reset a password, reassign a controller, share a map on someone's behalf, delete an account) happens and leaves no trace. Once it's done, there is no way to answer "who did this, and when?"

This gap is named explicitly — three times — in **Addendum 4**. That addendum seals regular admins out of the map-sharing graph, but it is scrupulously honest that one path remains for super-admins: a super can add themselves to a share group, reach every map shared to it, then remove themselves again, **leaving no record**. The addendum's own words:

> "there is no audit log anywhere in the system, and a super-admin can remove their own membership again afterward, leaving no record."
>
> "If durable traceability of that exception is ever wanted, it requires adding audit logging (which does not exist today); this addendum does not add it."

So an audit log is not decoration. It is the thing that turns Addendum 4's honestly-acknowledged "loud path is a figure of speech" into an actual artifact — `resetpwd` becomes a logged event, and the super-admin's share-group self-add/self-remove becomes **two** logged events. Be precise about that number: with **no access logging**, the self-add and the later self-remove are recorded, but the map access *in between* is not — the two membership events bracket an unlogged window, they do not capture the access itself. "Loud" stops being purely aspirational, but it does not become a complete record of what was reached.

**Honest scope of what this buys against the Addendum-4 impersonation path** (added after review, Jul 15 2026). The sanctioned loud path is: an admin resets a controlled user's password, then logs in *as that user* and acts through the **owner-facing** routes. This system makes the **reset** accountable (`user.resetpwd`) and logs **authentication events** (`auth.login` / `auth.logout` / `auth.login_failed`, each with client IP + timestamp). It does **not** audit owner-side sharing (`/maps/.../collaborators`), so a share change made *inside* an impersonated session is **not** recorded as a share event — and even the login it produces is attributed to the **user's** account, never proven to be the admin. What an investigator actually gets is a correlation: "Admin A reset B at 14:30" + "B logged in from IP X at 14:31" — a *human* draws the inference; the log never claims cryptographic proof of who held B's credentials. **The honest promise is therefore: password resets and logins are accountable; ordinary user-side sharing in an impersonated session is not audited.** (Auditing the owner-side share routes was considered and rejected — it would stamp innocent legitimate-user activity with no way to attribute the guilty case, and would balloon the log from governance-only to every user's every share operation. See "What this is not" and the Rejected Alternatives.)

## What this is (and, firmly, what it is not)

We discussed three possible jobs for an audit log:

- **(A) Accountability against a privileged insider** — a record even a super-admin/operator cannot quietly erase.
- **(B) Forensics / support** — "who changed this, when?", no adversary, just troubleshooting.
- **(C) User-facing transparency** — showing owners who acted on their maps.

**This system targets (B), consciously and on the record.** We considered (A) seriously and rejected it *for this deployment*, because (A) has a hard truth baked in:

> markervault is a **self-hosted, single-operator LAN application** (`markervault.lan`, one host, one person who is simultaneously the super-admin and the box's root/operator). An audit table living in the same `spots.db` that the operator can `sqlite3` directly gives **zero** tamper-evidence against that operator — they can `DELETE FROM audit_log` at will. Genuine tamper-evidence against a DB-privileged insider requires the log to leave the machine into a trust domain the operator does not control (a hosted sink, or a second box with genuinely separate credentials). On a single-operator LAN box, the operator *is* the root-holder, so no purely-local mechanism can deliver that guarantee — it would be exactly the "theater" Addendum 4 warns against elsewhere.

The user's explicit decision (recorded here so it isn't relitigated): **"this is overkill for a map sharing application, let's just do the simple audit logs with no threat paranoia."** The realistic adversary for a trusted-operator LAN tool is the **rogue admin acting through the app** — and a plain append-only table **records their successful app-side mutations while audit writes succeed** (an admin has no shell; they cannot reach the table except through the API, which does not expose a delete). Stated precisely rather than as "covers completely": the fail-open helper means an action whose audit write throws still proceeds unlogged, so the guarantee is "recorded when the write succeeds," not absolute. The operator deleting their own log is likewise not in the threat model; they are the owner of the box.

Therefore this system makes **no tamper-resistance claim**, and this document states that plainly so no future reader mistakes it for one. It is durable against the application (nothing in the app rewrites or deletes audit rows) — not against a human with shell access. That is the correct and honest scope for what markervault is.

**Also out of scope, deliberately:**

- **Data-route logging.** The ~20 map/spot/photo CRUD routes are *not* logged. That is high-volume, machine-speed noise that serves forensics poorly and accountability not at all. Audit is for **governance** actions (administering accounts, delegation, sharing), not for editing markers.
- **Retention / rotation / pruning.** Governance actions happen at *human* speed — realistically kilobytes per day. Building rotation now would be exactly the kind of background machinery the project rejects on principle. If the table ever gets large, prune it with a `WHERE ts <` query at that time. No timers, no scheduled jobs, no auto-cleanup.
- **Tamper-evidence add-ons** (hash chaining, off-box shipping). Explicitly declined per the decision above. If the deployment model ever changes (multi-tenant, hosted, untrusted operator), revisit — the emit path is designed so the *sink* could be swapped without touching call sites (see "Design for a possible future" below), but no such machinery is built now.

## Design

### Storage: one append-only table, denormalized, no foreign keys

A single `audit_log` table in `spots.db`, baked into `CREATE TABLE` (in both `init_db` and `create_users.py`) per the project's **no-migrations** rule — it simply appears on the next DB wipe, which the pending P9+ deploy already requires. No `ALTER TABLE`, ever.

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,          -- UTC ISO8601 ending in Z
    actor_id       TEXT,                   -- g.user_id  (denormalized snapshot)
    actor_username TEXT,                   -- g.username snapshot; attempted name on login failure
    actor_role     TEXT,                   -- g.role or explicit override (NULL on @require_auth-only routes + unknown-user login)
    action         TEXT NOT NULL,          -- dot-namespaced verb, e.g. 'user.disable'
    target_type    TEXT,                   -- 'user' | 'map' | 'share_group' | 'mgmt_group' | NULL
    target_id      TEXT,                   -- TEXT: targets are heterogeneous (UUIDs and int ids)
    target_label   TEXT,                   -- human snapshot (username / map name / group name)
    detail         TEXT,                   -- JSON string, nullable (role granted, old/new value…)
    client_ip      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
```

**Why denormalized with no FKs — a deliberate departure from the rest of the schema.** Every other table uses `FK … ON DELETE CASCADE`. An audit log must do the *opposite*: a row must **survive** the deletion of the user, map, or group it refers to. If you delete a user, you still want the durable record that they were disabled last Tuesday and by whom. FKs-with-cascade would erase history exactly when it becomes most interesting. So `actor_*` and `target_label` are frozen string snapshots taken at write time, and there are no foreign keys at all. This is the one place the schema intentionally breaks the house pattern, and it is correct here.

**The snapshot rule applies to *both* parties of a relationship event, not just the primary target (added after review, Jul 15 2026).** A relationship mutation names **two** people or objects — the primary governed target (frozen in `target_label`) *and* a secondary counterparty: the controller being added, the group member, the share recipient. The frozen-snapshot guarantee only delivers a readable-after-deletion row if the *counterparty's* human string is frozen too. Storing only the counterparty's **ID** in `detail` silently re-opens the exact orphan this no-FK design exists to prevent: once that account is deleted, `user.controller.add detail={"admin_id":"8d91…"}` is a dangling UUID with no surviving row to resolve it against — precisely the "history erased when it becomes most interesting" failure, just relocated from the target column into `detail`. **So every counterparty ID carries a `*_label` snapshot alongside it** (`admin_label`, `user_label`, `recipient_label`, `group_label`), captured at write time — usually from a string already in the handler's scope; where only an ID is in scope (the admin share-DELETE routes carry a bare `user_id`/`group_id` in the URL path), a small lookup fetches the name (mechanics in the build plan). This is a labeling discipline on `detail`, not a change to which object is the `target`. For **named governance targets, `target_label` is likewise required, not optional** — and for delete/reject events (where the row is about to vanish) it is captured *before* the DELETE, since a delete event with a null label is the least reconstructable row of all. (The build plan carries the per-handler labels and the pre-delete-capture mechanics.)

`target_id` is `TEXT` because targets are heterogeneous — user routes carry UUID strings, map/group routes carry integers. Storing everything as text sidesteps a type split for a column that is only ever read back for display/filtering, never joined.

### Emit: one helper, actor pulled from `g`, fail-open

The codebase is unusually well-suited to a clean audit seam. **Every** privileged request already flows through two decorators that stash the actor's identity in Flask's `g` before any handler runs:

- `require_auth` (backend.py, wrapper) sets `g.user_id`, `g.username`, `g.client_ip` — but `g.username` comes from the **JWT**, so it can be stale after a self-rename until the token expires.
- `require_admin` (stacks on `require_auth`) additionally sets `g.role` from a **fresh DB read**, not the token — so the logged role is always current. To keep the *logged username* equally current, that same fresh read is widened to also fetch `username` and overwrite `g.username` (one extra column, no extra query — see the plan). Without it, admin audit rows would carry a fresh `actor_role` beside a stale `actor_username`. (Self-service `@require_auth`-only events keep the JWT username; acceptable for short-lived tokens.)

That means a single helper needs no handler-signature changes anywhere:

```python
def audit(action, target_type=None, target_id=None, target_label=None,
          actor_id=None, actor_username=None, actor_role=None, client_ip=None,
          **detail):
    # Actor defaults to g (set by the decorators); the explicit overrides exist for
    # the pre-auth /login route, where g.user_id/username are NOT set but the handler
    # has resolved the user locally from the DB row.
    conn = None
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (ts, actor_id, actor_username, actor_role, "
            "action, target_type, target_id, target_label, detail, client_ip) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
             actor_id if actor_id is not None else getattr(g, 'user_id', None),
             actor_username if actor_username is not None else getattr(g, 'username', None),
             actor_role if actor_role is not None else getattr(g, 'role', None),
             action,
             target_type, str(target_id) if target_id is not None else None,
             target_label, json.dumps(detail) if detail else None,
             client_ip if client_ip is not None else getattr(g, 'client_ip', None)))
        conn.commit()
    except Exception:
        pass  # fail-open: audit is a side effect and must NEVER break the action it records
    finally:
        # Close even when execute/json.dumps/commit threw — the fail-open except above
        # would otherwise leak the SQLite connection (and possibly hold a lock).
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
```

Five load-bearing choices:

1. **Actor defaults to `g`, with explicit overrides.** The ~30 governance handlers pass nothing — the actor rides in from `g` (set by the decorators), so they need no signature change. `/login` is unauthenticated and passes its resolved/attempted actor explicitly. `/auth/logout` also has no access-token gate; it snapshots the actor from the matching refresh-token/user row before deleting that session.
2. **`getattr(g, …, None)`** — safe on the remaining `@require_auth`-only routes where `g.role` is never set (`/changepwd` and `/account`; `/profile` is not audited — see Coverage). Those still log with `actor_role = NULL`.
3. **Fail-open, blanket `except` — with a `finally` that always closes.** This is the one place a bare `except` is the *right* call: an audit write is a side effect, never a gate. A logging hiccup must never turn a successful disable/reset/share into a 500. But the close must live in a `finally` (with `conn = None` set before the `try`), so that a throw in `execute`/`json.dumps`/`commit` still releases the SQLite connection — otherwise fail-open would leak a handle (and possibly hold a lock) on every failure. (`json` and `datetime` already exist; `timezone` is added to the existing `datetime` import.) The honest cost: an action whose audit write throws still proceeds **unlogged** — which is why this system "records successful mutations *while audit writes succeed*,” not "records everything."
4. **Own connection, called AFTER the action's own commit.** `audit()` opens its own `get_db()` and commits independently. It is invoked *after* the handler has committed its real mutation and *on the success path only* — so the log reflects committed reality. A handler that returns a 4xx guard before mutating logs nothing; a handler whose `UPDATE` matched zero rows (e.g. "already disabled") logs nothing. A `200` from an idempotent endpoint is not enough: `INSERT ... ON CONFLICT DO NOTHING` handlers capture `rowcount` and emit `.add` only when a row was actually inserted; same-value edits similarly emit nothing. (The one intentional exception: a *failed* login logs on its 401/403 path — there the event being recorded IS "an auth attempt failed.")

5. **UTC on disk, local time on screen.** Audit timestamps are stored as ISO-8601 UTC values ending in `Z`; `timezone` is added to the existing `datetime` import. The Audit tab parses that value and uses `toLocaleString()`, so display follows the viewer's browser timezone without making the database record ambiguous.

### Coverage: all governance mutations (~30 sites) + auth events, success-path only

Each logged handler gets exactly one `audit()` call on its success path. **Scope note:** this covers governance (admin) mutations, authentication events, and two explicitly-kept account-security/lifecycle actions (`account.changepwd`, `account.delete`) — it does **not** cover ordinary self-service profile edits (`PUT /profile`); see "Self-service scope" below. The enumerated surface (verified against the tree):

| Handler (grep anchor) | `action` | notable `detail` |
|---|---|---|
| `admin_approve_user` / `admin_reject_user` | `user.approve` / `user.reject` | — |
| `admin_set_role` | `user.role` | `old`, `new` |
| `admin_disable_user` / `admin_enable_user` | `user.disable` / `user.enable` | — |
| `admin_reset_password` | `user.resetpwd` | **never the password** |
| `admin_edit_user_profile` | `user.profile_edit` | per changed field: `{field:{old,new}}` (values) |
| `admin_delete_user` | `user.delete` | — |
| `admin_create_user` | `user.create` | `role` |
| `admin_add_user_controller` / `…remove…` | `user.controller.add` / `.remove` | `admin_id` + `admin_label` |
| `admin_create/rename/delete_share_group` | `share_group.create/rename/delete` | create/delete: name; rename: `old_name` + `new_name` |
| `admin_add/remove_share_group_member` | `share_group.member.add/remove` | `user_id` + `user_label` |
| `admin_add/remove_share_group_owner` | `share_group.owner.add/remove` | `admin_id` + `admin_label` |
| `admin_*_mgmt_group*` (7 handlers) | `mgmt_group.*` | parallel to share_group (counterparty `*_label`; rename `old_name`+`new_name`) |
| `admin_set_map_share` (PUT/upsert) | `map_share.direct.grant/change` / `map_share.group.grant/change` | `recipient`/`group` + `recipient_label`/`group_label`, `operation:'created'|'role_changed'`, `old_role`, `new_role` |
| `admin_delete_map_share` / `…group_share` | `map_share.direct.remove` / `map_share.group.remove` | `recipient` + `recipient_label` / `group` + `group_label` |
| `change_password` (route `/changepwd`) | `account.changepwd` | — |
| `delete_own_account` | `account.delete` | — |
| `login` (success) | `auth.login` | *(actor via explicit override — `/login` is pre-auth, `g` is empty)* |
| `login` (failed) | `auth.login_failed` | `{reason}`; `actor_username=<attempted, truncated>`; `actor_id`/role set only for a known account |
| `auth_logout` | `auth.logout` | — |

**Authentication events** (`auth.*`) are included so the Addendum-4 impersonation path leaves a trail (see "Honest scope…" in the Motivation). `/login` is unauthenticated, so it passes the actor explicitly (the helper takes `actor_id`/`actor_username`/`actor_role`/`client_ip` overrides that default to `g`). **One concrete source change this requires:** `/login` today selects only `user_id, password_hash, status` — it has neither the canonical `username` nor the role needed for successful-login snapshots and known-account failures. The query must be widened to `SELECT user_id, username, password_hash, status, role`. A successful login uses the canonical row values. For `auth.login_failed`, `actor_username` deliberately means the **username presented during the attempt**, not proof that the account holder was behind the screen; it is truncated (for example `[:128]`) before persistence, while `actor_id`/`actor_role` are filled only when that presented name resolves to a known account. The UI therefore says **“Failed login for alice”**, not “alice performed auth.login_failed.” This documented auth-failure exception keeps the schema simple and records the identifier operators care about without making an attribution claim. Failed logins are bounded by the existing rate-limit on `/login`. `/auth/logout` takes its explicit actor snapshot from the matching refresh row, revokes only that session, and clears the cookie even when the row is absent; an absent row emits no actor-attributed event. **Logout is best-effort:** a session can also end by token expiry or a closed browser, which hit no route, so `auth.logout` events are inherently incomplete; `auth.login` is the reliable half.

**Self-service scope (decided Jul 15 2026):** self-service is **not** broadly audited. The only self-service actions logged are `account.changepwd` and `account.delete`, kept deliberately because a user changing their own password or deleting their own account are **security / lifecycle** events worth a record even though the actor is the user acting on themselves. **Ordinary profile edits (`PUT /profile`, `update_profile`) are excluded** — changing one's company or department is low-value churn, not a security event. This is an explicit boundary, not a gap: there is no `account.profile_edit`. (The same boundary covers the queued avatar feature — `POST/DELETE /profile/avatar` is self-service profile content and is not audited; see the build plan's §3c.)

**Two routes deliberately excluded:** `/parse-maps-link` (a data/utility route) and — importantly — the **owner-side share routes** `/maps/<id>/collaborators` (PUT/DELETE/bulk). The latter is a considered choice, not an oversight: see "Honest scope…" above and the Rejected Alternatives. (Note: `/auth/logout` is **no longer excluded** — it is logged as `auth.logout`, reversing an earlier draft that treated it as a session no-op. And `PUT /profile` is excluded per "Self-service scope" just above.)

**`resetpwd` never logs the password** — the `detail` blob for that action carries no secret material, and a test asserts it. This is the single most important content rule in the emit path.

**Profile edits log old→new *values*, not just field names** (user's explicit choice — full reconstruction over a data-light log). `admin_edit_user_profile` records `detail = {"email": {"old": …, "new": …}, …}` for each changed field, capturing the prior row before the `UPDATE`. When username validation is present, this comparison uses the validated **cleaned** username rather than the raw request string: surrounding-whitespace normalization that returns the stored value is not a change, invalid input never reaches audit, and a genuine case-only rename remains a logged string change. **Accepted trade-off:** the audit log consequently stores copies of profile field values (names, company, department, email, etc.). This is a deliberate forensics-over-minimalism call. It does **not** extend to secrets — the password is never a value in any record; `resetpwd`/`changepwd` log only that the event happened.

**Idempotent success is not a mutation.** Controller/member/owner/manager additions use `ON CONFLICT DO NOTHING` and still return `200` when the relationship already exists; those handlers capture `rowcount` and log `.add` only for the first, state-changing request. The admin map-share PUT is an upsert, so it records one of four explicit direct/group `grant` or `change` actions, retaining `operation:'created'|'role_changed'` and old/new roles in detail; setting the already-current role records nothing. The two DELETE routes similarly emit explicit direct/group `remove` actions. Because `_apply_map_share` is reused by owner routes that remain outside audit scope, the helper exposes the operation to the admin handler without auditing ordinary owner sharing.

The three mutation routes on the `/admin/maps/<id>/collaborators` surface (PUT and the two DELETE variants) are governance mutations and are logged. The fourth route, GET, is read-only and is **not** audited. All four become **super-admin-only** under Addendum 4, but that changes only their authorization gates; it does not turn the GET into an audit event. (This is distinct from the **owner-side** `/maps/.../collaborators` routes, which are *not* audited — see above. See "Sequencing" below.)

### Read: `GET /admin/audit`, super-admin only, keyset-paginated

A single read endpoint, gated to super-admins with the same `if g.role != 'super_admin': 403` check the management-group routes already use:

- **Super-only, not all-admins.** The log names cross-scope actors and targets — actions on users and maps a regular admin has no authority over. Exposing it to regular admins would re-leak exactly the cross-scope picture Addendum 4 seals. So reading the audit trail is a super-admin capability, consistent with the "unscoped actor" role (Invariant 5).
- **Keyset pagination on `id`** (`WHERE id < :before ORDER BY id DESC LIMIT :n`, capped), newest-first — cheap, stable under concurrent inserts, no `OFFSET` drift. Returns `{entries: [...], next_before: <id|null>}`. **Inputs are validated:** `limit` and `before` are parsed as non-negative ints, `limit` clamped to **1..500** (both ends — a negative `LIMIT` is treated by SQLite as *unlimited*, so the cap must guard the low end too, and a bare `int('foo')` would 500), malformed values return **400**. See the plan for the exact parse.
- **No nginx change** — the existing `location /admin/` block already proxies every `/admin/*` path.

### Read UI: a super-only "Audit" tab (click-driven, no auto-refresh)

The Administration screen already has the exact pattern to clone: the **Management Groups** tab is super-only, hidden via `display:none` + an `activeAdminTab` fallback for non-supers, and refetches its data whenever the tab is activated. The Audit tab mirrors it precisely:

- `<button data-admintab="audit" id="adminAuditTabBtn" style="display:none;">Audit</button>` + a matching `#adminAuditPanel`.
- Hidden for non-supers at open time; `activeAdminTab` falls back to `active` if a non-super somehow lands on it.
- Loads a fresh first page on **every activation** — still click-driven and never on a timer. A **"Load more"** button pages via `?before=` on click. No polling, no automatic timer refresh, and no background churn (consistent with the project's standing rejection of timers/auto-refresh).
- Rows are **read-only**: the stored UTC `ts` localized with `toLocaleString()` · actor/attempted username · action · target label · expandable detail. For `auth.login_failed`, the row uses purpose-built wording such as **“Failed login for alice”** so the attempted username is not presented as a verified person. Persisted strings are rendered with `textContent`, never `innerHTML`. No actions on the rows — it is a ledger, not a control surface.

## Design for a possible future (without building it now)

The emit path routes *all* audit writes through the single `audit()` helper. If the deployment model ever changes and real tamper-evidence becomes warranted, the change is localized: swap the body of `audit()` to *also* (or instead) emit via Python's `logging` to a dedicated logger whose handler ships off-box (syslog/journald→remote, or a hosted sink) — the ~30 call sites do not change. **This is a note about extensibility, not a feature being built.** No logging framework, no handler, no off-box anything is part of this work. It is recorded only so a future maintainer knows the seam exists.

## Sequencing with Addendum 4

Audit and Addendum 4 are **adjacent, not entangled** — the genuinely shared surface is just the **three admin share-mutation handlers** (the PUT and the two DELETEs), and even there the edits are orthogonal: audit adds an emit line on the success path; Addendum 4 swaps the authorization gate above it. The rest of the nearby surface is single-owner: the collaborator **GET** and `admin_user_maps` belong to Addendum 4 alone (re-gate / payload split — the GET is read-only and deliberately unaudited), while `_apply_map_share`'s prior-role capture and the `require_admin` SELECT widening belong to audit alone (the widening *appends* a column, so the `row[0]` role read Addendum 4's gates rely on is unaffected in either build order). Either order works mechanically; **Addendum 4 first is the recommended order** (flipped Jul 16 2026 — the original audit-first recommendation predates Addendum 4 being fully synced and ready to build, and the mechanical argument for it cuts both ways: "Addendum 4 edits only the gate above an existing `audit()` line" is exactly as simple in reverse, "audit adds an emit line under an existing gate"):

- **Addendum 4 first (recommended):** audit then instruments the final, already-sealed handlers. Three concrete reasons. (a) `test_audit.py`'s `map_share.*` cases are written once against the final gates, with super-admin callers — post-seal the only permitted callers anyway. (b) Every document stays literally true at its own merge moment: Addendum 4 leans on "there is no audit log anywhere in the system" in three load-bearing honesty passages (Motivation's loud-≠-attributable paragraph, decision §5's traceability paragraph, "What does NOT change"); merging it after audit ships would land it carrying already-false claims. (c) Addendum 4 is the security fix (the live un-share bug) and audit is observability — if anything interrupts between the two builds, better to be holding the seal than the log.
- **Audit first (workable, with two guardrails):** write every `map_share.*` audit test with a **super-admin** caller from day one, or the suite breaks when the gates flip; and at the Addendum-4 merge, amend its three "no audit log anywhere" passages plus its blast-radius bullets ("no audit logging exists anywhere in `backend.py`"; the two-column `SELECT role, status` that audit widens to include `username`) as implementation-time amendments — the log will exist by then.

Either way, whichever ships **second** owes the first one's documents a dated annotation (the build plan's housekeeping section carries the Addendum-4-first version of this).

They share the same pending DB-wipe deploy (the new `audit_log` table rides it for free), so there is no extra deploy cost to doing both, in either order.

## What does NOT change

- **Storage of everything else** — no existing table, column, FK, or index is touched. One new table + one index, additive.
- **nginx** — `location /admin/` already covers `GET /admin/audit`. No config change.
- **Authorization model** — the audit system reads `g.role`/`g.user_id` that the existing decorators already set; it introduces no new permission, relation, or invariant. It observes the governance surface; it does not alter it.
- **Data routes, contents sealing, the sharing graph** — untouched. Audit records *that* a governance action occurred; it adds no new data to any map/user payload.

## Rejected alternatives

- **Tamper-evident log (hash chain / off-box sink).** Rejected for this deployment: markervault is a single-operator LAN box where the super-admin *is* root, so no local mechanism can make the log un-erasable by the operator, and shipping off-box is infrastructure this tool doesn't warrant. Would be theater against the only insider who has shell. (Revisit only if the deployment becomes multi-tenant/hosted/untrusted-operator.)
- **Same-DB table + hash chaining as a middle ground.** Considered (cheap, upgrades silent DELETE to a detectable gap). Rejected as still-misleading for a single-operator box — a shell operator can recompute the chain — and as more machinery than "no threat paranoia" calls for.
- **Logging the data routes too.** Rejected: machine-speed, high-volume noise that no one reads, serving neither forensics nor accountability. Audit is governance-only.
- **Auditing the owner-side share routes** (`/maps/.../collaborators` PUT/DELETE/bulk) to close the impersonation path end-to-end. Rejected: the actor on those routes is whoever's token is in `g` — the **impersonated user**, not the admin — so a record there could never distinguish an admin acting-as-a-user from the legitimate user doing their own sharing. In practice it would stamp overwhelmingly innocent activity (real users sharing their maps) and still fail to attribute the one guilty case, all while expanding the log from governance-only to every user's every share operation. The honest alternative — logging `user.resetpwd` + the login events and letting a human correlate by IP/timestamp — gives the impersonation path a real trail without the noise or the false precision. (Full reasoning in "Honest scope…" in the Motivation.)
- **Retention/rotation engine.** Rejected as premature background machinery; the table grows at human speed. Prune by hand if it ever matters.
- **CLI-only reading (no endpoint/UI).** Considered as the minimal surface. Rejected in favor of the super-only endpoint + tab so the log is usable without shell access — the whole point is accountability the super-admin can actually *look at*.
- **Making the read endpoint available to all admins.** Rejected: the log names cross-scope actors/targets; exposing it to regular admins re-leaks the cross-scope picture Addendum 4 seals. Super-only, per Invariant 5.
- **Auto-capture via a logging decorator** (log method+path+body automatically). Rejected: produces HTTP-shaped, semantically-poor records, and would capture the `resetpwd` request body (a password) unless carefully scrubbed. Explicit per-handler `audit()` calls log *meaningful* events and never touch secret material.
