# Permissions Model — Geolocation Markers App

## Roles

- **Superadmin** — unscoped, global reach over everyone and everything. Cannot be limited by any control relation.
- **Admin** — scoped. Can manage the users delegated to them (directly or via a management group) or created by them, and the share groups delegated to them or created by them. Cannot control, view, or act on other admins or superadmins — this is a flat wall, with no transitive or nested admin hierarchy.
- **User** — no management capabilities. Has owned maps and shared-with-them maps like everyone else.

### Superadmins are a self-policing peer group

Superadmins are unscoped over each other, not only over admins and users. A superadmin may edit, disable, reset the password of, and **delete** another superadmin through the admin console. There is no super-over-super wall of the kind that separates admins (Invariant 4) — the tier governs itself, and every `_guard_admin_target` check waves a superadmin caller through regardless of the target's role.

Only three restrictions apply, and all are structural safety rather than peer protection:

- **The role is CLI-only.** The web never promotes to, demotes from, or otherwise grants the `super_admin` role, so a superadmin's role is immutable from the UI. Creating a superadmin, or moving any account into or out of that role, is done solely with `create_users.py` (see the role discussion in `INSTALL.md`).
- **No self-delete from the console.** A superadmin cannot delete their own account through the admin console (a mid-session foot-gun). Self-service account deletion is a separate path and is allowed unless the account is the last admin-level one.
- **The last admin-level account is protected.** The last remaining approved `admin`-or-`super_admin` account can be neither deleted nor disabled, so management can never lock itself out.

A superadmin is deliberately **not** shielded from deletion, disabling, or password reset by *another* superadmin. That is a decision, not a gap — see "Guarding superadmins against a rogue peer" under Rejected Alternatives.

## The Two Group Types (Naming)

There are two structurally similar but functionally separate group concepts, named as sibling pairs so code reads unambiguously:

- **Share groups** (`share_groups` / `share_group_members` / `share_group_owners`) — map-sharing participation only. Membership is administratively inert (Invariant 1).
- **Management groups** (`management_groups` / `mgmt_group_members` / `mgmt_group_managers`) — bulk delegation of `controls()` only. Superadmin tooling end to end.

The tables, code identifiers, and UI labels follow this naming. **Deliberate exceptions, not to be "finished" later:** URL paths (`/admin/groups`, `/groups`, `/collaborators/group/…`) and frontend DOM ids/CSS classes keep the bare `group` naming — adblock filter lists match "share" substrings in URLs and element ids and quietly block or hide them (the same reason the share routes are named `/collaborators`). The `map_group_shares` table name is also kept: it lives entirely in the sharing graph, where "group" can only mean share group.

## Core Relations

### `controls(admin, user)`

The only relation that grants management authority over a user. It has **two sources**, checked everywhere as one union:

```
effective_controls(admin, user) =
    direct grant (a user_controllers row)
    OR (user ∈ management_group AND manage_mgmt_group(admin, management_group))
```

**Direct grants** (stored as the `user_controllers(user_id, admin_id)` join table) are populated two ways:
- Admin creates the user (auto-granted).
- A superadmin delegates an existing user to an admin.

**Group-derived grants** come from management-group membership combined with a manager delegation (both relations below).

All origins are the same fact once established — there is no distinction in how the relation is checked. This is a union, not an override: a group-derived grant and a direct grant are just two origins for the same fact, exactly as "admin created the user" and "superadmin delegated the user" are two origins for a direct grant. Every grant is revocable by a superadmin at any time — a direct grant by targeted revocation, a group-derived one by removing the member or the manager delegation.

Many-to-many: a user can have zero sources of control (nobody-land), one (the common case), or several (a co-managed team). Assignment is additive — delegating an already-controlled user to another admin adds a co-controller without disturbing the existing ones — and revocation is targeted, removing one named source only. Co-controllers act fully and independently regardless of how each grant arose, with no coordination or approval between them (co-managed teams coordinate outside the system; conflict-resolution logic would solve a problem this use case doesn't have). The relation only ever points at a regular `admin` account — superadmins need no grant, and admins can never be controlled.

**Every permission check reads the union.** In the implementation this is one shared SQL predicate (`controls_predicate()` in `backend.py`) used at every authorization and visibility site — never inline one half only.

**Composing the two sources:** direct assignment remains the tool for the case a group can't express — one user, one exception. A user in Management-Group-G (managed by Admin-A) can additionally be assigned directly to Admin-B; they are then co-controlled by A (via the group) and B (directly), acting independently, without touching the group or its other members. To fully remove A's reach on that one user, remove the user from the group — that revokes that source only, and the user falls back to nobody-land only if no other source remains. No per-user exception flag or override table exists; removal-from-group is the sole mechanism, kept deliberately simple.

### `owns_share_group(admin, share_group)`

The only relation that grants authority over a share group.

Populated the same two ways:
- Admin creates the share group (auto-granted).
- A superadmin delegates an existing share group to an admin.

Same fact, same check, regardless of origin. Revocable by a superadmin at any time.

Many-to-many (stored as the `share_group_owners(group_id, admin_id)` join table), mirroring `controls()`: zero owners = superadmin-owned (the true default), one owner is the common case, several = a co-owned team group. Delegation is additive, revocation targeted, co-owners act independently — exactly as for controllers. The creator is additionally recorded permanently (`share_groups.created_by`) — the delete rule is gated on the self-created distinction, and ownership alone doesn't carry it.

### `share_group_membership(person, share_group)`

Flat, single-purpose, **administratively inert**. Grants map-sharing participation only.

This relation never implies view, control, or any authority over co-members, regardless of the roles involved. This is a key invariant: share-group membership must never be read as an authority signal anywhere in the system. It exists purely to support map sharing.

### `management_group(id, name)`

A named bucket of users, separate from the sharing tables. **Created, renamed, and deleted only by superadmins, and always owned by the superadmin side** — there is no admin-facing "create a management group" action, unlike share groups where any admin can create and own one. Kept distinct from share groups so delegated management of one never implies authority via the other, and vice versa.

### `mgmt_group_membership(user, management_group)`

Flat, single-purpose, **administratively inert on its own** — the same invariant as share-group membership, applied to the new table. Being in a management group grants nothing by itself; only combined with a manager delegation (below) does it produce `controls()`.

**Members are end-users being managed, never admin-level accounts.** Unlike share-group membership — where membership alone is inert, so an admin being a member changed nothing — management-group membership combined with a manager grant directly produces `controls()`. Allowing an admin as a member would mean another admin's `manage_mgmt_group` grant confers `controls()` over *that* admin, which is a different relation entirely (admin-over-admin authority lives with superadmins per Invariant 4/5, never via `controls()`). The membership-add action rejects admin-level accounts. Pending users must be approved first (same rule as direct assignment); disabled users are eligible — control over a disabled user is exactly what enables re-enabling them.

### `manage_mgmt_group(admin, management_group)`

Grants one admin management authority over a group's members. The group itself stays owned by the superadmin side — this relation delegates *management*, not ownership; an admin never owns the group, only acts as its manager. **This relation can only be created, changed, or removed by a superadmin — never by an admin, and never by an admin acting on their own group.** An admin who ends up in this table got there because a superadmin put them there; they have no create/claim/self-assign path onto it, and no UI action that writes to it. This is stricter than `owns_share_group`, where an admin can create and own a share group themselves — management groups have no self-serve path at all, by design, since they're a bulk-delegation tool for the superadmin, not a workspace concept admins build for themselves.

Many-to-many, additive: a management group can have zero or more delegated managers, and revocation is targeted to one named admin without disturbing the others — same mechanics as `owns_share_group`'s co-ownership, just superadmin-only end to end and framed as delegated management rather than ownership. The recipient must be an approved regular admin — never a superadmin, who needs no grant.

## Lifecycle: Users vs. Groups

Users and groups follow genuinely different lifecycles — they are not symmetric, and should not be modeled as if they were.

**Users — three states: pending, nobody-land, controlled.**

- **Pending.** A self-registered user who has not yet been approved. Cannot log in. Not visible to anyone but superadmins. Only a superadmin can approve a pending user, which moves them to nobody-land. Approval doesn't "grant" anything new in terms of authority — superadmins already have standing, unscoped authority over every user regardless of state, pending included. What approval actually changes is the account's own status (from not-yet-real to active/loginable) and its visibility for the next step, which is assignment to an admin.
- **Nobody-land.** An approved-but-unassigned user: exists, can log in, has **no source of control** — neither a direct controller nor a management-group membership under a delegated manager — but remains, like every user, under the superadmin role's standing unscoped authority regardless of state. Critically, nobody-land is **not** an open claim pool — admins cannot self-claim out of it. Every path out of nobody-land is a superadmin act: direct assignment to a chosen admin, or placement in a management group that has (or later gets) a delegated manager. This applies to every user who didn't originate from an admin directly: self-registered users (once approved) and any other user without an admin-creator. This is a deliberate design choice: a superadmin who does not want a given user under any admin simply never assigns them — there is no separate "reserved" flag needed, since non-assignment is already the default, safe state. Nobody-land users are also **invisible to admins** — with no self-claim there is nothing an admin could do with them, so listing them would be pure leak; they appear only in superadmin views.
- **Controlled.** A user with at least one active source of `controls()`. Reached three ways: (1) an admin created the user directly — assignment to that admin is automatic and immediate, no nobody-land stopover at all; (2) a superadmin directly assigns a nobody-land user to a chosen admin; or (3) a superadmin places the user in a management group with a delegated manager.

Revocation is always targeted at one named source and never touches co-controllers; only when the last source is gone — direct grants and management-group memberships alike — does the user return to nobody-land (superadmin-assignable only, not admin-claimable), regardless of how that user originally became controlled.

**Share groups — always owned, no ownerless state.** A share group can never exist without an owner; there is no group equivalent of nobody-land. Superadmin ownership is the true default: when an admin creates a share group, that is superadmin ownership delegated to the admin at the moment of creation, not a fresh unowned entity being claimed. When a superadmin revokes an admin's `owns_share_group()` grant, any co-owners keep theirs; when the last grant is revoked, ownership reverts to the superadmin who retains it — never to an unclaimed pool visible to other admins. This matters because a share group's membership can be sensitive, and passively exposing an "unowned" group to browsing admins would be a quiet visibility leak — reverted groups are visible to superadmins alone, exactly like nobody-land users. Only a superadmin can re-delegate a reverted group from there.

**Management groups — always superadmin-owned, full stop.** Ownership is never delegated and never reverts, because it never leaves the superadmin side; there is no reverted or unclaimed state to reason about. What comes and goes is the `manage_mgmt_group` delegation on top — additive, targeted, superadmin-written. A group with zero delegated managers is simply dormant: its memberships produce no `controls()` for anyone until a manager is delegated.

## Visibility

The management lists ARE the scope — nothing out of scope is rendered, not even read-only:

- An admin's user list contains exactly the users they effectively control, as one flat set — **no annotation of whether each user arrived by direct grant or via a management group**. Pending users, nobody-land users, other admins' users and admin-level accounts (including the admin's own row) are all absent. The admin's own account and maps are managed through the app itself (profile, owner routes), never through the admin window.
- An admin's group list contains exactly the share groups they own. Superadmin-owned share groups and other admins' share groups are absent. **Management groups are invisible to admins entirely** — no tab, no list, no read-only view; an admin never learns a management group's existence or composition, including which group produced their own reach.
- Superadmins see everything, pending users and management groups included.
- With multi-control, scopes can overlap: a co-managed user (or co-owned share group) appears in every holding admin's list simultaneously — the lists union rather than partition.
- Co-managers see each other by name: when a user or share group has more than one controller/owner, each holding admin's detail view shows a read-only "Co-managers" line naming the others — **source-agnostic and deduplicated**: direct controllers and management-group managers merge into one list of admin names, never exposing the group behind a grant. The regular-admin `/admin/users` wire contract follows the same rule: it carries one generic `managers` list (username + real-name parts only) and omits the source-bearing `controllers` / `group_managers` keys entirely. Nothing is editable there and no authority is conveyed — delegation editing stays superadmin-only. Rationale: co-controllers act independently and coordinate outside the system, which presumes knowing who to coordinate with; admin usernames are already global in the share picker, so the line exposes nothing new.
- **Source matters only in superadmin tooling**, because that's where "reassign a whole group" and "adjust one direct grant" are different actions with different blast radii. In the superadmin's user detail, direct grants render as editable/revocable chips, while group-derived control shows as a separate read-only "via management group" line naming the managers; the group-level actions live on the Management Groups tab. That distinction belongs there and nowhere else.
- A regular admin's view of a controlled user's maps is **bare metadata** — name, date, marker/photo counts only (plus the row's `id` / `is_base` flags). It carries **no collaborator roster** (whom the user shares out to) and **no "shared with this user" list** (whom the user receives from): the map-sharing graph is a relationship between people and is sealed from regular admins, consistent with Invariant 2. There is no read-only version of it either — the category simply does not exist in the regular-admin console. **Superadmins are exempt** because they are the model's unscoped actor (Invariant 5), and retain the full rosters and shared-with view.
- The map-sharing pickers (`/users`, `/groups`) stay deliberately global for every authenticated user — usernames and share-group names are not secrets, while the sensitive fact is the connection between them. Management groups are never share targets and never appear in any picker.

## Admin Permissions

| Action | Scope |
|---|---|
| Enable/disable user | `controls(admin, user)` |
| Reset password | `controls(admin, user)` |
| Edit user's profile (incl. username) | `controls(admin, user)` for admins. Superadmins are unscoped here in full: they may edit other admins, other superadmins, and themselves (an explicit exception to the "own row is managed through the app" convention — profile facts only; password/role/status keep their dedicated actions). Username changes are admin-mediated only (no self-service rename in the profile overlay); renames are identity-safe because every relation keys on `user_id`. |
| Create user | Unrestricted; the created user is auto-assigned to the creating admin, no nobody-land stopover (revocable by superadmin; revoking the last source of control moves the user to nobody-land, superadmin-assignable only). A *superadmin's* creations start in nobody-land instead — supers need no grant, and recording one would only hide the user from delegation. |
| Approve/reject user (self-registered) | Superadmin only; approval moves a pending user to nobody-land (active, loginable, account provisioned, no source of control yet — always already under standing superadmin authority), rejection deletes the pending registration. Assignment to a specific admin is still a separate step. |
| Assign user (from nobody-land or additively) | Superadmin only; grants a direct `controls()` row to whichever admin the superadmin chooses. Additive, not exclusive: a second, third… co-manager can be granted without disturbing existing ones (a user can go from nobody-land to multi-controlled in successive assignments). Every path out of nobody-land is a superadmin act — this one, or management-group placement below; there is no admin self-claim. Target must be an approved regular user (approve first; admins are never controlled); the receiving controller must be an approved regular admin — never a superadmin, who needs no grant. |
| Delete user | Superadmin only, regardless of how `controls()` was acquired |
| Add user to share group | `controls(admin, user)` AND `owns_share_group(admin, group)` (created or delegated). Admins can never add *themselves* — nobody controls themselves. Superadmins may self-add (unscoped; settled Jul 12 2026). |
| Remove user from share group | `controls(admin, user)` AND `owns_share_group(admin, group)` — scoped like adding; members placed from outside the owner's scope stay until a superadmin removes them |
| Create share group | Unrestricted; grants `owns_share_group()` as a delegation from the superadmin (revocable by superadmin; revoking the last owner returns ownership to the superadmin, never to an unclaimed pool). A *superadmin's* creations stay superadmin-owned (no owner rows). |
| Edit share group | `owns_share_group(admin, group)` (created or delegated) |
| Delete share group | Delete authority belongs solely to the group's original creator, never to co-owners who did not create it. Allowed only if the creator is a currently active admin who **still owns the group** (their `owns_share_group()` grant not revoked) **and** every member is within **that creator's own** control list (no outside users, admins, or superadmins relying on it) — an individual check, never a collective one, evaluated against effective `controls()` (group-derived members count as in-scope). If the creator is a superadmin, or their ownership was revoked, or they were demoted or deleted (ownership having reverted per the Cascades rule), deletion always escalates to a superadmin — regardless of how many admins currently co-own the group. Owner count and delegation affect who can *edit* the group or *manage its membership*; they never affect who can *delete* it. |
| Create/rename/delete management group | Superadmin only — no admin-facing equivalent of any kind. Deletion is a superadmin bookkeeping action, not a creator-earned right (Invariant 3's creator-scoped delete rule doesn't apply — these groups are never admin-created); it cascades memberships and manager grants, ending every group-derived `controls()` fact at once. |
| Add/remove management-group member | Superadmin only. Members must be regular users — never admin-level accounts (membership × a manager grant produces `controls()`, and admins are never controlled). Pending users must be approved first; disabled users are eligible. Removal revokes that source of control only — direct grants and other groups' memberships are untouched. |
| Delegate/revoke management-group manager | Superadmin only, additive, targeted revocation — mirrors the direct-assignment route. The recipient must be an approved regular admin — never a superadmin, who needs no grant. Revoking one manager drops the whole group's members out of that admin's effective `controls()` in one action, leaving other managers and all direct grants untouched. |
| View user's maps | **Regular admin:** `controls(admin, user)` and the target must be a regular user — never an admin/superadmin and never the caller themselves. The view is bare metadata only: name, date, marker/photo counts, plus `id` / `is_base`; no collaborator rosters or shared-with list. **Superadmin:** unscoped — may view any existing account, including admin-level accounts and themselves, with the full owned-map rosters, shared-with list, and per-map collaborator detail. |
| Edit user's map shares | **Superadmin only.** A superadmin may edit any map's share list with global user/share-group targets, subject to the no-self-grant guard below. Regular admins have no map-share write path; an admin who genuinely must act as a user uses the loud, sanctioned password-reset path. |

### Editing map shares (superadmin only)

- **Who:** superadmins only, via the `/admin/maps/<id>/collaborators` routes. There is **no `controls()` requirement** — a superadmin may edit the share list of **any** map (Invariant 5, unscoped actor). Regular admins have no map-share write path at all.
- **Targets:** global and unscoped — a share may name any user or any share group. Management groups are never share targets.
- **The one guard (no-self-grant):** a superadmin may not grant themselves access, either as a direct recipient or through a share group they belong to. The accepted asymmetry remains: a superadmin may separately add themselves to a share group's membership, a broader but roster-visible path. That group-membership action is not a map-share edit and is not closed here.

Map sharing remains global and independent of the admin-control hierarchy: owners manage their own shares through the owner routes, and the superadmin is the explicit unscoped administrative exception. A `controls()` grant conveys no share visibility or mutation authority to a regular admin.

## Cascades & Cleanup

Delegation never dangles:

- Promoting a user to admin clears all their controllers **and all their management-group memberships** — admins are never controlled, and a membership left behind would keep producing `controls()` over the new admin through any manager grant. (The management-groups addendum's cascade list omitted the membership half; settled during implementation, Jul 13 2026.) A demoted-then-repromoted account does not get memberships back either — re-delegation is explicit.
- Demoting an admin to user removes that admin's *own* grants only — their `user_controllers`, `share_group_owners`, and `mgmt_group_managers` rows: co-managed users, co-owned share groups, and co-managed management groups keep their other controllers/owners/managers, and a user or group left with none is thereby in nobody-land / superadmin ownership — no separate fallback step needed. Management-group *membership* rows are untouched by a manager's demotion or deletion — membership has no admin-scoped foreign key to cascade. `created_by` persists (a historical fact), but a demoted-then-repromoted admin does not get their grants back automatically — re-delegation is explicit.
- Deleting an admin has the same effect (the join-table FKs `ON DELETE CASCADE` drop just that admin's rows).
- Reassigning a management group's manager updates every member's effective control in one action, without touching any direct `controls()` grants other admins hold on those same users.
- The CLI (`create_users.py`) applies the same rules when a replace changes an account's role.

## Invariants

These are the rules most likely to get silently violated by a well-intentioned shortcut during implementation. They should stay visible in the spec, not just in the reasoning behind it.

1. **Group membership never grants authority or view over other members — of either group type.** Share-group membership is administratively inert, full stop (map-sharing reach only). Management-group membership is inert *on its own*: it produces `controls()` only in combination with a `manage_mgmt_group` grant, and even then the authority runs admin→member, never member→member or member→admin. The only paths to authority are `controls()` (both sources), `owns_share_group()`, and `manage_mgmt_group()`. A future permission check must never take a shortcut through "same group" logic — this was the fix for a real privilege-escalation path found during design.
2. **Map sharing is independent of the control hierarchy.** Map *owners* manage their own shares through owner routes gated by `is_map_owner`. Superadmins may manage any map's shares as the explicit **unscoped** exception (Invariant 5), subject to the no-self-grant guard. `controls()` grants a **regular admin neither read nor write** access to any map-share connection — not the per-map roster, not the shared-with list, and not the write path. Share *targets* remain global (a share may name any user or share group), and management groups are never share targets.
3. **Create is always self-serve for workspace concepts; edit follows ownership/control however it was acquired; delete always escalates to superadmin when the blast radius could exit the acting admin's reach.** For users that reach is the admin's own effective control list; for share groups likewise — delete authority is scoped to the group's original creator alone (who must still be an active, owning admin), with every member inside that creator's own control list, independent of current co-ownership; co-ownership governs editing and membership only. This pattern is applied uniformly to users and share groups — the acting admin's own reach, same shape, same reasoning, no special-casing one or the other. Note that "self-serve create" only auto-grants control/ownership when the *creating actor* is the admin themselves (admin creates user, admin creates share group). It does not apply to users who originate without an admin-creator (self-registration): those require a superadmin to both approve and assign — admins have no role in either step, and cannot self-claim from nobody-land. **Management groups sit deliberately outside this pattern**: they are not a workspace concept admins build for themselves but superadmin bulk-delegation tooling, so they have no self-serve path at any layer, and their deletion is superadmin bookkeeping rather than a creator-earned right.
4. **Admins never control, view, or act on other admins or superadmins**, no matter how groups or delegation are structured. There is no nested or transitive admin tier. Multi-control does not bend this: it is only ever multiple admins pointing at the same user/group, never at each other — flat coexistence of independent grants, no cycles, no reachability computation anywhere. Management groups enforce it structurally: admin-level accounts can never be members, so no manager grant can ever produce `controls()` over an admin.
5. **Superadmins are the only actors who can perform destructive/irreversible or cross-scope *governance*.** "Cross-scope" means an administrative action whose *authority* reaches outside the acting admin's control scope — not every in-scope action with an indirect cross-scope *effect*. Superadmin-only governance covers hard delete (user, or any group beyond the creator-scoped share-group case in the Delete row), delegation/revocation of `controls()`, `owns_share_group()` and `manage_mgmt_group()` themselves, and every management-group operation of any kind (create, rename, delete, membership). A regular admin curating an owned share group's membership is not cross-scope governance: both the group and member are within the admin's delegated reach, while any outside effect rides on a map owner's prior decision to share to a curator-managed group. The invariant prohibits governing outside an admin's scope; it does not prohibit in-scope actions with delegated effects outside it.

## Rejected Alternatives (and why)

Kept here so these don't get re-litigated or accidentally reintroduced later.

- **Transitive/nested admin hierarchy** (admins controlling other admins, arbitrary depth). Explored as a way to solve delegation depth and "vacation coverage" scenarios, then dropped. It solved a real problem but reintroduced cycle-prevention, transitive-reachability computation, and subtree blast-radius risk on delete — complexity disproportionate to the benefit at this stage. If multi-tenant partitioning is ever needed later, prefer a coarse `organization_id` tenancy boundary over rebuilding this graph.
- **Capacity-based group membership** (`participant` vs. `manager` roles within a group). Explored as a fix for a privilege-escalation bug where group membership implicitly granted view access. Superseded by the simpler fix: remove all authority from group membership entirely, rather than tagging *which* memberships carry authority.
- **Reusing share groups for delegation** (making `owns_share_group` also grant `controls()` over members — considered before Addendum 3 introduced the second group type). Dropped: it reintroduces the exact privilege-escalation shape Invariant 1 was written to close, and would silently hand management authority to any admin who owns a group for sharing purposes, forcing an audit of every existing share group for who it accidentally hands control to. Hence the structurally identical but functionally separate `management_group` tables.
- **Admin self-claim from a nobody-land pool** (an earlier draft of this spec). Any admin could see and claim unassigned users. Dropped: non-assignment must be a safe default under superadmin control, and an open claim pool both invites quiet scope growth and leaks every unassigned account to every admin.
- **Wholesale `manages_all_users` flag + separate scope tables** (the first implementation attempt, Jul 12 2026 — built, then reverted). Delegation is now an explicit per-grant fact (`user_controllers` / `share_group_owners` / `mgmt_group_managers` rows); no flag shortcuts, no wholesale-scope tables, no "Management Scope" chips UI. Do not resurrect.
- **Co-owner delete for multi-owner share groups** (Addendum 1's original carve-out: any current owner may delete, gated by the owner set's *collective* control — built Jul 12 2026, replaced Jul 13 2026 by Addendum 2). It conflated co-running a group with being able to destroy one you didn't create: a later-delegated co-owner could delete a team they never made. Superseded by creator-only delete (creator ∧ still-owner ∧ own-scope membership). The still-owner condition was added during the Addendum 2 review — the addendum's literal "no longer tied to current ownership at all" would have made delete authority survive a superadmin's revocation of the creator's grant (irrevocable short of demotion, and invisible in the creator's group list). Do not resurrect either variant.
- **Admin-set co-managers for self-created share groups** (proposed and dropped Jul 13 2026). Would have let a group's creator additively grant `owns_share_group()` to other admins. Coherent only under tight constraints (grantor = creator ∧ still-owner, additive-only with revocation staying superadmin-only, recipients regular admins only), but it breaks Invariant 5's "delegation is superadmin-only", needs an Invariant 4 carve-out for additive peer-grants, and requires exposing the admin roster to admins. Dropped for simplicity: all `owns_share_group()` delegation stays superadmin-only. Do not resurrect without rewriting Invariants 4 and 5 together.
- **Guarding superadmins against a rogue peer** (blocking a superadmin from deleting, disabling, or password-resetting another superadmin from the web, so the tier could only be managed from the CLI). Explored after asking whether a compromised or malicious superadmin should be able to remove peers, then dropped. In-app permission guards cannot contain a genuinely rogue superadmin: they are the unscoped top tier, the destructive damage — deleting every admin and user along with their cascaded maps, spots, and photos, or resetting passwords to hijack accounts — lands faster than any operator can react, and the guard would only have preserved the other superadmins while everything else was already gone. The real control for that threat is operational rather than a permission rule: database and file backups with a tested restore, the audit log to scope the rollback, and keeping the number of superadmin accounts small. The guard also carried a disproportionate cost. Neither the web console nor `create_users.py` deletes users today, so a GUI-only block would leave **no** supported way to delete a superadmin at all — only hand-editing SQLite, which would orphan that user's photo files on disk — forcing a new CLI deletion command to be built purely to retain a capability that currently exists freely. And it would have closed only the irreversible actions while disable — recoverable by any other superadmin — stayed open, so the "neutralize a peer" scenario was never actually shut. Cost without commensurate protection. Do not resurrect without a concrete threat that in-app enforcement can actually address. (Settled Aug 5 2026.)
