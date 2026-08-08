# Username Validation (length cap + character policy) — design + rationale

> **STATUS: IMPLEMENTED — Jul 16 2026.** The shared `username_validation.py` policy is wired into registration, admin user creation, admin-mediated rename, and `create_users.py`; `/login` remains permissive and `PUT /profile` still cannot rename. No schema or normative contract amendments were needed. Test-harness amendment: every isolated backend suite now copies the shared module and adds its temporary directory to `sys.path`, and `cli_login_test.py` creates its own temporary CLI user/DB instead of relying on a pre-existing directory. Do not re-apply; kept for the rationale and audit-integration seams below.

> **Scope in one line:** one shared `validate_username()` helper in `username_validation.py`, imported by both `backend.py` and the standalone `create_users.py`, enforcing a length cap and an allowlist charset at the **four** username creation/rename entry points — **not** `PUT /profile`, which by design never renames. No schema change, no migration.

## Motivation

Today a username is only `.strip()`-ed and checked non-empty. Concretely, across every entry point:

- **No length bound anywhere.** `/register`, `/admin/users/create`, `PUT /admin/users/<id>/profile`, and the `create_users.py` CLI all accept a username of arbitrary length. (`PUT /profile` is not in this list — it never touches username.) `validate_profile_fields` caps `first_name`/`last_name`/company/etc. at `PROFILE_FIELD_MAX = 100`, but **username never passes through it.** The `users.username` column is unbounded `TEXT`. So a 1 MB username (bounded only by the 20 MB request cap) is accepted and stored.
- **No character policy.** Only leading/trailing whitespace is stripped. A username may contain control characters (newlines, tabs), unicode bidirectional/direction-override characters, zero-width/format characters, or internal whitespace.

Two honest framings of why this matters — and one thing it is explicitly **not**:

1. **Log and display integrity.** Usernames appear in the audit log (`actor_username`, and the attempted string on a failed login), in the admin user list, the sidebar account card, "shared with"/co-manager lines, and reset-password confirmations. An unbounded or control-character-laden username degrades all of these: a newline in a username can forge a second line in a rendered log or list; a huge string bloats storage and breaks layout.
2. **Lookalike / impersonation hygiene.** For an **unknown/wild deployment** (the same premise driving Addendum 4), usernames that differ only by an invisible zero-width joiner, a trailing combining mark, or a right-to-left override are a real confusion/impersonation vector — "admin" vs "admin​" read identically but are distinct rows. An allowlist charset removes the whole class.

**What this is NOT: an XSS fix.** The frontend renders usernames via `textContent` everywhere (verified — 247 `textContent` sinks vs no username reaching `innerHTML`), so the browser already treats a username as literal text, not markup. A `<script>`-laden username is inert in the DOM today. This change is justified by integrity and lookalike concerns, **not** by closing an active injection hole — and it should not be oversold as one. (SQL injection is likewise already fully prevented: every username query is parameterized.)

## The policy

One shared helper in a new sibling module, `username_validation.py`, mirroring the existing `validate_password_policy` / `validate_profile_fields` pattern:

```python
import re

USERNAME_MAX = 32   # generous for a username, comfortably bounded

def validate_username(raw):
    # Returns (ok, cleaned, error_message). cleaned is the trimmed username to store.
    if not isinstance(raw, str):          # numeric/list/None JSON must not reach .strip()
        return False, None, "Username is required"
    name = raw.strip()
    if not name:
        return False, None, "Username is required"
    if len(name) > USERNAME_MAX:
        return False, None, f"Username must be at most {USERNAME_MAX} characters"
    # Allowlist: letters, digits, and a small separator set. No whitespace, no
    # control/format/bidi characters — an allowlist is more robust than trying to
    # blocklist every dangerous unicode category.
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        return False, None, "Username may contain only letters, digits, and . _ -"
    return True, name, None
```

Design choices, each deliberate:

- **★ `isinstance(raw, str)` guard first** (review Jul 15 2026). Flask's `request.get_json()` can yield a non-string here — a JSON `{"username": 123}` or `{"username": ["a"]}` — and `123.strip()` raises `AttributeError → 500`. The type guard turns any non-string (incl. `None`) into a clean 400 "Username is required." **Additionally, `/register` must require the body be a JSON object** (`isinstance(data, dict)` / the existing `if not data …` must also reject a JSON array or scalar) before indexing `data['username']`, so a top-level non-object body doesn't 500 either.
- **Allowlist, not blocklist.** `[A-Za-z0-9._-]` is trivially safe and covers the realistic naming need for a small trusted group. Blocklisting control/bidi/zero-width categories is fragile (unicode is a moving target) and still leaves confusables. If a future deployment needs unicode usernames, that becomes its own considered change with NFC normalization + a confusables strategy — not this pass.
- **ASCII-only is an accepted limitation.** It rejects legitimately non-ASCII names (accented letters, non-Latin scripts). For the current trusted user base this is acceptable; recorded here so it's a known trade-off, not an accident.
- **`USERNAME_MAX = 32`** — a proposed default; easy to change. Long enough for any reasonable handle, short enough to bound storage/display.
- **Casing untouched.** Uniqueness is already `COLLATE NOCASE`; this helper does not change case, only validates. Case-only renames (already supported) still work.

## ★ Shared placement — a real module, not a backend-only helper (review Jul 15 2026)

`create_users.py` is a **standalone script** (it does not import `backend.py`), so a `validate_username` defined only in `backend.py` is **not** actually shared — the CLI would need its own copy, and the two would drift. **Put `validate_username` + `USERNAME_MAX` in a small shared module named `username_validation.py`** that **both** `backend.py` and `create_users.py` import:

```python
from username_validation import validate_username
```

`username_validation.py` is an imported module, **not** an executable script: no database access, no Flask dependency, no side effects, no `main`, and no background process. It imports only stdlib `re`. This keeps the policy defined once without coupling the standalone CLI to the Flask application.

## Where it applies (FOUR entry points — NOT `/profile`)

| Entry point | Handler (grep anchor) | Change |
|---|---|---|
| Public registration | `register` (backend.py:851) | require JSON object, then replace the bare `.strip()` + empty check with `validate_username()` |
| Admin create user | `admin_create_user` (backend.py:1238) | same (JSON-object guard already there / add if missing) |
| Admin profile edit | `admin_edit_user_profile` (backend.py:1149) | `validate_username()` — this IS a username-rename path (admin-mediated, per the model) |
| CLI bootstrap | `create_users.py` (arg + interactive, ~L51–57) | same rule via the shared module, CLI error (`sys.exit`) |

**★ `PUT /profile` (`update_profile`, backend.py:2278) is DELIBERATELY NOT an entry point** (review + `permissions-model.md:112`). It **does not touch username at all** — its `UPDATE` sets only `first_name…sex`, and `test_profile.py` §8 explicitly asserts that a `PUT /profile` carrying `"username":"hacker"` is *ignored* (username stays unchanged). The permissions model is explicit: *"Username changes are admin-mediated only (no self-service rename in the profile overlay)."* So self-service rename is **out of scope by design** — listing `/profile` here was an error. Adding it would be a **separate feature** (profile-overlay username field + uniqueness + session/token implications + reversing that test), not part of this validation pass. Removed.

The four real entry points currently do their own `.strip()` + non-empty check; each is replaced by the shared helper so the rule is defined once. For each HTTP handler the order is: JSON-object/key guard → `validate_username(raw)` → existing password/profile validation → existing uniqueness check → store the returned cleaned username. The uniqueness check (`WHERE username = ? COLLATE NOCASE`) stays exactly as-is and runs *after* validation.

**★ CLI empty-argument fix** (review): `create_users.py` currently does `if args.username:` (truthiness), so `--username ""` falls through to the interactive `input()` prompt instead of erroring. Change to `if args.username is not None:` so an explicitly-passed empty string goes through `validate_username()` and **errors** (`sys.exit`) rather than silently prompting. (backend.py:851 register JSON-object guard + create_users.py:51 branch.)

For both CLI modes, validate the raw value after choosing its source:

```python
raw_username = args.username if args.username is not None else input("Enter username: ")
ok, username, reason = validate_username(raw_username)
if not ok:
    sys.exit(f"Error: {reason}")
```

This intentionally gives invalid interactive input the same CLI error/exit behavior as invalid flag input; adding an interactive retry loop is not part of this focused change.

## Interaction with the audit-logging work (TWO seams)

### 1. Failed-login attempted-username truncation

The audit plan truncates the *attempted* username at `[:128]` before persisting an `auth.login_failed` row, because `/login` itself has no cap. **This change makes that truncation almost vestigial** for the *known-user* case — a stored username is now ≤ `USERNAME_MAX`, so `auth.login` / known-user `auth.login_failed` already carry a bounded value. The `[:128]` cap remains useful on the **unknown-user** login attempt (an arbitrary string typed at the login box that matches no row — that never goes through `validate_username`, so the audit boundary still defensively truncates it).

Note: **`/login` is deliberately NOT given `validate_username`.** Login must accept whatever the user types and simply fail to match if it's malformed — running creation-time validation at login would leak "that username couldn't exist" and change the auth error surface. Login stays permissive; the audit boundary truncates the attempt string; creation is where the policy is enforced.

### 2. Audited admin profile edits use the cleaned username

The audit plan instruments `admin_edit_user_profile` as `user.profile_edit`, logging only real old→new field changes. Username validation must run **before** its uniqueness query, UPDATE, diff construction, or audit emit, and the returned cleaned username is the only username value used downstream:

- Invalid username → `400`; no database mutation and no audit row.
- Raw `" alice "` with stored `"alice"` → cleaned `"alice"`; username is unchanged. If no other profile field changes, the request produces no `user.profile_edit` row; if another field changes, only that real field change is logged.
- A genuine case-only rename such as `"Alice"` → `"ALICE"` remains valid and is a real string change, so it is stored and logged.
- `user.create` / `user.profile_edit` labels and detail use the cleaned username that is actually stored, never the untrimmed request value.

This is why username validation should be implemented **before audit logging**: audit then instruments the final validated handler and writes its tests once against the final semantics.

## What does NOT change

- **Schema** — `username TEXT` stays; the cap is enforced in code (no `CHECK` constraint, no migration — consistent with the disposable-DB / no-migrations rule).
- **Uniqueness** — the `COLLATE NOCASE` unique index and all lookup queries are untouched.
- **`/login`** — stays permissive (see above).
- **Existing usernames** — the DB is wiped on the pending deploy, and CLI/registration will re-create users under the new rule, so there is no "grandfathered invalid username" problem to handle. (If this ever shipped against a live DB, a one-off audit of existing usernames would be needed — not applicable here.)

## Test-harness integration (required by the new module)

The backend suites currently copy only `/workspace/markervault/backend.py` into an isolated temporary directory and load that copy with `importlib`. Once `backend.py` imports `username_validation`, those suites will fail unless the new sibling module is also available on `sys.path`.

Update all **17** `tests/test_*.py` bootstraps and `tests/cli_login_test.py` before `spec.loader.exec_module(backend)`:

```python
shutil.copy(
    "/workspace/markervault/username_validation.py",
    os.path.join(WORK, "username_validation.py")
)
if WORK not in sys.path:
    sys.path.insert(0, WORK)
```

For `cli_login_test.py`, whose `WORK` is relative and which changes into that directory, use the resulting absolute current directory:

```python
module_dir = os.getcwd()
shutil.copy("/workspace/markervault/username_validation.py", "username_validation.py")
if module_dir not in sys.path:
    sys.path.insert(0, module_dir)
```

Changing the process working directory does not reliably rewrite the existing `sys.path[0]`, so the explicit insertion is required; copying the file alone is not sufficient. The future `tests/test_audit.py` must start with this corrected bootstrap too. Update `tests/README.md` so it no longer claims that copying only `backend.py` is sufficient.

## Rejected / deferred alternatives

- **Blocklist dangerous unicode instead of allowlisting.** Rejected: fragile and incomplete against confusables; the allowlist is simpler and strictly safer for the trusted user base.
- **Allow full unicode with NFC normalization + confusables mapping.** Deferred: real work, only justified if a deployment genuinely needs non-ASCII handles. Out of scope now; flagged as the future path if the need arises.
- **A `CHECK` constraint on the column.** Rejected: enforcement lives in the shared validator (one place, good error messages); a DB constraint would duplicate it and fights the no-migrations posture.
- **Validating username at `/login`.** Rejected: login must stay permissive (fail-to-match, not reject-as-invalid) to avoid an existence oracle and an altered auth-error surface.

## Tests

- Add a focused `tests/test_username_validation.py` using the same isolated-backend bootstrap described above.
- `validate_username` unit checks: non-string (`123`, `["a"]`, `None`) → error; empty/whitespace-only → error; exactly 32 valid characters → ok; 33 → error; control char / newline / tab → error; zero-width / bidi override → error; internal space → error; valid `a.b_c-1` → ok; leading/trailing whitespace is removed; casing preserved.
- Each of the **four** entry points rejects an over-long and a bad-charset username with the right status (400 on the HTTP routes; `sys.exit` on CLI) and accepts a valid one.
- **Boundary hardening:** `validate_username(123)` / `(["a"])` / `(None)` → error, no exception (the `isinstance` guard); `/register` with a non-object JSON body (array/scalar) → 400, not 500; `create_users.py --username ""` → errors (not the interactive prompt).
- **`PUT /profile` regression:** its existing `test_profile.py` §8 (username-in-body is ignored) stays **unchanged and green** — this pass does not add self-service rename.
- Regression: whitespace-normalized same username is not a rename; a case-only rename still succeeds (uniqueness NOCASE unaffected). When audit is subsequently built, its suite pins the corresponding no-op/real-diff behavior described above.
- Existing suites that register/create users with simple usernames stay green (their fixtures already use allowlist-clean names — verify).
- CLI coverage should invoke the real `create_users.py` with `MARKERVAULT_DB_PATH` pointed at an isolated scratch database; cover valid create, invalid charset, over-limit, and explicit empty `--username`.

No frontend, nginx, schema, or migration change.
