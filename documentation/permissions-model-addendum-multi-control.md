# Addendum: Multi-Admin Control (Co-Managed Teams)

> **STATUS: MERGED & IMPLEMENTED — Jul 12 2026.** Everything below is now folded into `permissions-model.md` and built in the code (`backend.py`, `create_users.py`, `frontend.js`; storage = `user_controllers` / `group_owners` join tables). Do not re-apply; kept for the design rationale.
>
> **Point 4 (multi-owner delete carve-out) was SUPERSEDED on Jul 13 2026 by Addendum 2:** delete authority now belongs to the creator alone (creator ∧ still-owner ∧ every member in the creator's own control list). Do not resurrect the any-current-owner/collective-control rule.

This is a proposed extension to `permissions-model.md`. It does not replace or edit that document — treat this as a diff to review and merge in deliberately, since it changes storage shape, not just wording.

**Motivation:** support teams that are genuinely co-managed by more than one admin at once (steady-state, not temporary vacation coverage). A user or a group currently has at most one controlling/owning admin; this addendum makes both many-to-many.

## What changes structurally

### `controls(admin, user)` becomes many-to-many

Base spec: single-valued, stored as `users.controlled_by` (nullable FK; NULL = nobody-land).

Addendum: replace with a join table, e.g. `user_controllers(user_id, admin_id)`. A user can have zero controllers (nobody-land, unchanged), one controller (today's common case), or several (co-managed). Every permission check that reads "does `controls(admin, user)` hold" becomes "does a row exist for this admin/user pair" — same semantics, just existence-checked against a table instead of an FK equality.

### `owns_group(admin, group)` becomes many-to-many

Base spec: single-valued, stored as `groups.owner_id` (nullable FK; NULL = superadmin-owned).

Addendum: replace with a join table, e.g. `group_owners(group_id, admin_id)`. Same shift: zero owners (superadmin-owned, unchanged), one owner (common case), or several (co-owned team group).

`groups.created_by` is **unaffected** — it stays a single, permanent historical fact regardless of how many current owners exist. See the Delete Group change below for why this matters.

## Behavioral decisions (the parts that needed an actual answer, not just a schema change)

1. **Co-controllers/co-owners act independently, with no coordination or approval between them.** Any admin with a grant on a user or group can act on it fully, exactly as a sole controller could today. No conflict resolution, no "notify the other controller," no locking. This is deliberate: co-managed teams are expected to coordinate outside the system, and building conflict-resolution logic would solve a problem this use case doesn't actually have.

2. **Revocation is always targeted, never a wipe.** A superadmin revokes *one specific admin's* grant on a user or group. This never clears other existing controllers/owners. (This is the one place the old single-value model had no ambiguity — revoke meant "clear the one value" — and the new model must be explicit that revoke means "remove this one row," not "delete all rows for this user/group.")

3. **Assignment from nobody-land is additive.** A superadmin can assign a second, third, etc. co-manager to a user or group that already has one or more controllers/owners, without disturbing the existing ones. A user/group can go straight from nobody-land to multi-controlled in successive assignment actions, or in one step if the UI supports multi-select.

4. **Delete Group drops the single-creator requirement for multi-owner groups.** Base spec rule: delete is allowed only for self-created groups, gated additionally by a clean-membership check. That rule assumed one owner, for whom "self-created" was a meaningful and simple gate. For a group with multiple current owners, requiring the literal original creator specifically (`created_by`) would mean co-managers who joined after creation could never delete a team they equally run — an arbitrary and unhelpful restriction once co-ownership is the intended steady state.

   **New rule for multi-owner groups:** delete is allowed for *any current owner* in the owner set, provided the same clean-membership check still passes (every member is within the collective control of the group's current owners — no outside users, admins, or superadmins relying on it). `created_by` remains recorded for audit/history but is no longer part of the permission gate once a group has more than one owner.

   Single-owner groups are unaffected — the base spec's rule (self-created + clean membership) still applies unchanged when there's exactly one owner.

## What does NOT change

- No cycles are introduced. Control still only ever flows superadmin → admin → user (or superadmin → admin → group ownership); it never flows admin → admin. Invariant #4 from the base spec (admins never control other admins) holds exactly as before — multi-control is only ever multiple admins pointing at the same user/group, never at each other.
- No reachability/transitive computation is needed. This is flat coexistence of independent grants, not a hierarchy — unlike the rejected transitive-admin-hierarchy alternative in the base spec, this introduces no graph traversal anywhere.
- Cascades arguably get *simpler*, not harder: demoting or deleting one co-controlling admin now only removes that admin's own row from the join table. Other co-controllers are unaffected, and the user/group does not need to fall back to nobody-land/superadmin-ownership unless it had no other controller/owner left. (Base spec's "everything reverts to nobody-land" cascade still applies exactly as written for the single-controller case, and now also applies whenever the last remaining controller/owner is removed.)
- Map ownership/sharing, group-membership-is-inert, the no-self-dealing rule on share editing, and every other invariant in the base spec are untouched — this addendum only concerns the control/ownership relations themselves.

## Visibility impact

A user or group now appears in the Users/Groups tab of **every** admin who holds a grant on it, not just one. The "management lists ARE the scope" principle from the base spec is unchanged — it just now means the union of scopes can overlap between admins, rather than partitioning users/groups exclusively.
