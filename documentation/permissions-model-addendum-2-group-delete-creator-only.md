# Addendum 2: Group Deletion Belongs to the Creator Alone

> **STATUS: MERGED & IMPLEMENTED — Jul 13 2026, with one amendment.** Folded into `permissions-model.md` and built in `backend.py`. The merged rule additionally requires the creator to **still hold `owns_group()`** on the group — this addendum's literal "delete authority is no longer tied to current ownership at all" would have let a creator whose grant was revoked by a superadmin keep delete power (irrevocable short of demotion, with no UI surface, and silently restored on re-promotion contrary to the "re-delegation is explicit" cascade rule). Do not re-apply; kept for the design rationale.

This is a proposed patch to `permissions-model.md`, as extended by Addendum 1 (multi-admin control). It does not edit either document — treat this as a diff to review and merge deliberately. It **supersedes** an earlier draft of this addendum that only handled the superadmin-created case; this version replaces that draft with a broader, simpler rule.

## The problem

Addendum 1's Delete Group rule reads:

> Multi-owner groups: any current owner may delete (the creator requirement drops — co-managers equally run the team), provided every member is within the collective control of the current owners.

This conflates two different things: **running a group together** (shared editing, shared membership control — appropriate for co-owners) and **being able to destroy a group you didn't create** (not the same privilege, and not something co-ownership should confer). Under the rule as written, if Admin-A creates a group and Admin-B is later delegated as a co-owner, Admin-B can delete it — despite never having created it. That holds regardless of who originally made the group, so it isn't limited to the superadmin-origin case; it's a general gap in the multi-owner carve-out.

## The fix

Delete authority is no longer tied to current ownership at all — it belongs to exactly one person: **the group's original creator**, and only while that creator is a currently active admin.

- **Owner count stops mattering for delete.** Sole-owner vs. multi-owner is no longer the relevant split. Co-owners (however many) can still edit the group and manage its membership, per the existing `owns_group()` gate — but none of that grants delete authority unless they are also the creator.
- **`created_by` becomes the entire gate**, alongside the creator's current role and control scope:
  - If the group's creator is a **currently active admin** (not demoted, not deleted): only that admin may delete it, and only if every member is within **that creator's own** control list. This is now an individual check, not a collective one — deletion is no longer a joint decision among co-owners (superadmins retain unconditional delete authority regardless of this section, per the base spec's standing-authority invariant — this bullet only governs when an *admin* may delete).
  - If the creator is a **superadmin**, or an admin who has since been **demoted or deleted** (in which case ownership has already reverted to the superadmin per the Cascades rule): deletion always escalates to a superadmin. No current admin — co-owner or otherwise — can delete it.

## Updated rule text (drop-in replacement for the Delete Group row)

> **Delete group** — Delete authority belongs solely to the group's original creator, never to co-owners who did not create it. Allowed only if the creator is a currently active admin **and** every member of the group is within that creator's own control list (no outside users, admins, or superadmins relying on it). If the creator is a superadmin, or was an admin who has since been demoted or deleted (ownership having reverted to the superadmin), deletion always escalates to a superadmin — regardless of how many admins currently co-own or co-manage the group. Owner count and delegation affect who can *edit* the group or *manage its membership*; they never affect who can *delete* it.

## What does NOT change

- Editing the group's own properties remains governed by `owns_group()` exactly as before (Addendum 1, unchanged) — multiple delegated co-owners can fully and independently manage those settings. Adding/removing members is **not** loosened by co-ownership alone: it still requires the base spec's two-part gate, `controls(admin, user) AND owns_group(admin, group)` (invariant #7). A co-owner can only add or remove members they personally control — not members controlled by a different co-owner.
- The Cascades rule is unaffected: demoting or deleting the creator-admin still reverts ownership to the superadmin, which — combined with this patch — also means delete authority disappears entirely at that point, for anyone but a superadmin. This was already implied by the cascade rule; this addendum just makes explicit that no other co-owner inherits it.
- No changes to `controls()`, user lifecycle, map sharing, or any other invariant from the base spec or Addendum 1.
