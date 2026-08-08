# Addendum — Management Groups

> **STATUS: MERGED & IMPLEMENTED — Jul 13 2026.** Everything below is now folded into `permissions-model.md` and built in the code (`backend.py`, `create_users.py`, `frontend.js`, `index.html`; storage = `management_groups` / `mgmt_group_members` / `mgmt_group_managers`, resolution = the shared `controls_predicate()` union). Do not re-apply; kept for the design rationale. Amendments settled during implementation, now normative in the merged spec:
>
> 1. **Cascade gap closed:** promoting a member to admin also deletes their `mgmt_group_members` rows (this addendum's Cascades section only covered demoting/deleting a *manager*; a leftover membership would keep producing `controls()` over the new admin, violating Invariant 4). Demote-then-repromote does not restore memberships — re-delegation is explicit. Same rule in `create_users.py`'s role replace.
> 2. **Member eligibility made explicit:** regular users only (as written here), pending accounts must be approved first (mirrors direct assignment), disabled accounts are eligible — control is what enables re-enabling them.
> 3. **Manager eligibility made explicit:** approved regular admins only — never superadmins (who need no grant), mirroring the `/controllers` and `/owners` recipient rules.
> 4. **Rename scope exceptions:** the `group` → `share_group` rename covers tables, code identifiers, API payload fields (`groups` → `share_groups` in `/admin/users`) and UI labels, but **URL paths and DOM ids/CSS classes deliberately keep the bare "group" naming** (adblock filters match "share" substrings in URLs/element ids — same reason the share routes are `/collaborators`), and the `map_group_shares` table name is kept (sharing-graph context is unambiguous). Documented in the merged spec's Naming section — do not "finish" the rename.
> 5. **Role-split user payload:** superadmin `/admin/users` rows carry `controllers` (direct grants, editable chips) and `group_managers` (group-derived grants); the super's user detail shows the latter as a separate read-only line, and the nobody-land/"Unassigned" marker requires BOTH sources empty. Regular-admin rows instead carry only one deduplicated `managers` list (username + real-name parts, no IDs or group names) and omit both source-bearing keys, so source attribution exists only in superadmin tooling.

Extends the Permissions Model (`permissions-model.md`) to solve bulk delegation. Direct admin assignment (`controls(admin, user)`, the existing "Managed By" action) is unchanged and stays available — this addendum adds a second, parallel source for the same relation. It does not replace anything.

## Naming

**This is a rename in the actual codebase, not just in this document.** As part of implementing this addendum, rename the existing sharing-group identifiers everywhere they appear in code — table/collection names, model/entity classes, migration files, query and variable names, API fields, admin-panel labels — from `group` / `group_membership` / `owns_group` to `share_group` / `share_group_membership` / `owns_share_group`.

Reasoning: once `management_group` exists alongside a bare `group`, the two names no longer read as siblings — nothing in the code signals that they're two variants of the same pattern (bucket + membership + ownership) built for different purposes. Renaming the old one to `share_group` makes the pair `share_group*` / `management_group*` (or `mgmt_group*`) symmetric and self-explanatory to anyone reading the code later, with zero ambiguity about which table backs which feature.

This is a rename only — no change in behavior, cascades, or Invariants 1–5, which apply identically under the new name. Because `group` is likely referenced in many places (queries, serializers, admin UI strings, tests), it's worth tracking as its own well-defined step within the implementation, alongside the new `management_group` tables and UI.

## Problem

With hundreds of users, reassigning them one by one — e.g. after an admin is demoted or deleted, or during an ongoing reorg — is a chore. Direct assignment has no notion of a reusable cohort, so every reassignment touches one `controls()` row at a time.

## Why not reuse the existing sharing groups

Sharing groups (`share_group`, `share_group_membership`, `owns_share_group`) exist for map-sharing participation only, and `share_group_membership` is deliberately inert (Invariant 1) — it must never imply authority. Making `owns_share_group` also grant `controls()` over members would:

- Reintroduce the exact privilege-escalation shape Invariant 1 was written to close.
- Silently hand management authority to any admin who owns a group for sharing purposes, and force an audit of every existing sharing group to check who it accidentally hands control to.

So this needs a **second group type**, structurally identical to sharing groups, but functionally separate and dedicated to delegation.

## New Relations

Mirrors the existing group pattern exactly (see `owns_share_group` / `share_group_membership` in the base spec), applied to a distinct table pair:

### `management_group(id, name)`

A named bucket of users, separate from the sharing `share_group` table. **Created, renamed, and deleted only by superadmins, and always owned by the superadmin who created it** — there is no admin-facing "create a management group" action, unlike sharing groups where any admin can create and own one. Kept distinct from `share_group` so delegated management of one never implies `controls()` via the other, and vice versa.

### `mgmt_group_membership(user, management_group)`

Flat, single-purpose, **administratively inert on its own** — same invariant as sharing-group membership. Being in a management group grants nothing by itself; only combined with ownership (below) does it do anything. This is a deliberate mirror of Invariant 1, applied to the new table: membership is never itself an authority signal.

**Members are end-users being managed, never admins.** Unlike sharing-group membership — where membership alone is inert (Invariant 1), so an admin being a member changed nothing — management-group membership combined with a manager grant directly produces `controls()`. Allowing an admin to be added as a member would mean another admin's `manage_mgmt_group` grant confers `controls()` over *that* admin, which is a different relation entirely (admin-over-admin authority lives with superadmins per Invariant 5, never via `controls()`). The membership-add action must reject or simply not offer admin accounts as candidates.

### `manage_mgmt_group(admin, management_group)`

Grants one admin management authority over a group's members. The management group itself is always owned by the superadmin who created it — this relation delegates *management*, not ownership; an admin never owns the group, only acts as its manager. **This relation can only be created, changed, or removed by a superadmin — never by an admin, and never by an admin acting on their own group.** An admin who ends up in this table got there because a superadmin put them there; they have no create/claim/self-assign path onto it, and no UI action that writes to it. This is stricter than `owns_share_group`, where an admin can create and own a sharing group themselves — management groups have no self-serve path at all, by design, since they're a bulk-delegation tool for the superadmin, not a workspace concept admins build for themselves.

Many-to-many, additive: a management group can have zero or more admins delegated to manage it, and revocation is targeted to one named admin without disturbing the others — same mechanics as `owns_share_group`'s co-ownership, just superadmin-only end to end and framed as delegated management rather than ownership.

## Effective Control

`controls(admin, user)` — the single relation checked everywhere in the base spec — now has two sources instead of one:

```
effective_controls(admin, user) =
    direct controls(admin, user)
    OR (user ∈ management_group AND manage_mgmt_group(admin, management_group))
```

This is a **union**, not an override, consistent with the existing multi-control semantics (base spec, `controls()` section): co-controllers already act fully and independently with no coordination required, regardless of how each grant was acquired. A group-derived grant and a direct grant are just two origins for the same fact — exactly how "admin created the user" and "superadmin delegated the user" are already two origins for the same `controls()` fact today.

**Nothing downstream changes.** Every row in the Admin Permissions table, every Cascade rule, and Invariants 1–5 continue to check `controls()` exactly as written. Only how that fact gets populated in bulk is new.

## Composing Direct Assignment with Group Membership

Direct assignment is not deprecated — it's the mechanism for exactly the case a group can't express: one user, one exception, without touching the group.

**Example:** User is in Management-Group-G, owned by Admin-A. You want Admin-B to also manage that one user, without moving the whole group or affecting Admin-A.

1. Use the existing "Managed By" action to grant Admin-B direct `controls()` over that one user.
2. The user is now co-controlled by A (via the group) and B (via direct grant), acting independently — same as any other multi-controlled user today.
3. Group membership, Admin-A's grant, and every other member of the group are untouched.

**To fully remove Admin-A's reach on that one user** (not just add B alongside): remove the user from the management group. This revokes that source of control only, same shape as revoking one named admin's direct grant today — targeted, doesn't touch co-controllers, falls back to nobody-land only if no other source of control remains. No per-user exception flag or override table is introduced; removal-from-group is the sole mechanism, kept deliberately simple.

## Visibility

The admin never needs to know, and is never shown, whether a given `controls()` fact came from a direct assignment or a management group. The admin's user list is exactly what it is today (base spec, Visibility section): the flat, unioned set of users they effectively control, no source annotation, no badge.

The existing "Co-managers" line is unchanged in behavior: it names other controlling admins regardless of how each one's grant arose. An admin has never had a revoke action of their own (Invariant 5 — delegation/revocation is superadmin-only), so there is no action that needs to behave differently depending on source.

**Source only matters in superadmin tooling**, because that's where "reassign a whole group" and "adjust one direct grant" are different actions with different blast radii. That distinction belongs there and nowhere else.

*Jul 17 2026 note:* the superadmin user-details pane additionally names the selected user's management-group **memberships** (a "Management groups" row beside "Share groups", `None` when empty). This is superadmin-only, consistent with the paragraph above: the `/admin/users` payload omits the `management_groups` key for regular admins entirely, and a regular admin's detail view shows no management-group information. A briefly shipped variant that displayed memberships to regular admins was reverted the same day.

## Cascades

Same shape as existing group cascades (base spec, Cascades & Cleanup):

- Demoting or deleting an admin drops their `manage_mgmt_group` rows only (their own grant). Other delegated managers, if any, keep theirs.
- Reassigning a management group to a different admin updates every member's effective control in one action, without touching any direct `controls()` grants other admins hold on those same users.
- `mgmt_group_membership` rows are untouched by admin demotion/deletion — only the delegated manager of the group changes; membership itself has no admin-scoped foreign key to cascade.

## Admin Panel

**For superadmins:** create an exact clone of the existing Groups tab, named **"Management Groups"**, wired to the new `management_group` / `mgmt_group_membership` / `manage_mgmt_group` tables instead of the sharing-group ones. Same layout, same interactions — list / create / rename / delete groups, add/remove members, assign/reassign the delegated manager (i.e. write to `manage_mgmt_group`) — just pointed at the new tables. The existing Groups tab itself is renamed to **"Share Groups"** and otherwise untouched.

Within a management group's details view, the field that reads **"Owned By"** on the Share Groups tab is labeled **"Managed By"** on the new Management Groups tab, to reflect that admins listed there are delegated managers, not owners — the group itself is always owned by the superadmin who created it (see New Relations above).

**Every action on the Management Groups tab is superadmin-only — there is no admin-facing equivalent of any kind.** Admins have no path to create, own, rename, or manage membership of a management group.

**For admins:** the only visible change is that their existing Groups tab is renamed to **Share Groups**. Nothing else changes for them — no Management Groups tab, no "Managed By" field, no new action of any kind. They still see only the users in their effective `controls()` set, with no indication of whether that access came from a direct assignment or a management group (see Visibility above).

This mirrors and extends the base spec's Invariant 5 (all `controls()` delegation is superadmin-only): here, both the group itself and the management delegation on top of it are superadmin-only, with no admin self-serve path at any layer.

## What This Does Not Change

- Direct assignment (`controls()` via the existing "Managed By" action) stays exactly as-is and remains the right tool for one-off exceptions.
- No new group-delete puzzle: management groups aren't admin-created the way sharing groups are (Invariant 3's creator-scoped delete rule doesn't apply here — deletion of a management group is a superadmin bookkeeping action, not something an admin creator earns by making the group).
- Invariant 1 holds for the new table exactly as it holds for the old one: membership alone is inert; only ownership converts it into authority.
