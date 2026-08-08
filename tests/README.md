# markervault tests

Durable home for the markervault test suite. Migrated here from ephemeral session
scratchpads on Jul 15 2026 so the tests survive independent of any scratchpad.

The Python venv (`venv/`) and Node dependencies (`pw-test/node_modules/`) are both
untracked and reproducible from the pinned manifests. Playwright browser binaries
live in the external browser cache described below.

Current coverage at commit `80ff5cc` (2026-07-26): **1216 backend checks**
(29 `test_*.py` suites) + **386 browser checks** (10 suites), plus the standalone
CLI-login integration, HTML-structure, nginx configuration, and live refresh/KML
checks. Counts are dated because they go stale on every commit that adds a check —
re-derive from a run rather than trusting the figure.

## Backend suites (Python)

Each isolated suite copies `/workspace/markervault/backend.py`,
`/workspace/markervault/markervault_schema.py`,
`/workspace/markervault/request_validation.py`,
`/workspace/markervault/markervault_config.py`,
`/workspace/markervault/username_validation.py`, and
`/workspace/markervault/email_delivery.py` into its temporary directory, then places
that directory on `sys.path` before importing the copied backend. This six-file
bootstrap is required for every future backend suite. Edit the live files and rerun —
no manual copy is needed.

```sh
# run one suite
/workspace/markervault/tests/venv/bin/python /workspace/markervault/tests/test_admin_maps.py

# run all of them
cd /workspace/markervault/tests
for s in test_*.py; do venv/bin/python "$s"; done

# CLI-created-user login/profile integration (outside the test_*.py loop)
/workspace/markervault/tests/venv/bin/python /workspace/markervault/tests/cli_login_test.py
```

`test_admin_maps.py` is the home suite for admin map/share work.
`test_username_validation.py` is the home suite for username-policy work.
`test_audit.py` is the home suite for audit storage, instrumentation, pagination, and
server-side event/time/text filtering.
`test_avatar.py` is the home suite for avatar schema, processing, signed serving,
and self-service upload/removal.
`test_localized_fixes.py` covers the Stage 3 failed-login operation invariant and
refresh-cookie logout semantics, including the final guarantee that logout kills the
family's copied access JWTs immediately.
`test_session_families.py` is the Stage 10.2 home suite: session-family lineage,
atomic rotation with barrier-based concurrency, consumed-token replay revoking the
family (`auth.refresh_replay`), family-scoped logout, `auth_version` bumps on
disable/reset/password change, the family-checked identity gate, and IP-change
self-healing.
`test_email_delivery.py` covers the inactive SMTP boundary, a real loopback fake SMTP
server, envelope/header separation, Unicode templates, TLS mode selection, opaque
ordinary/app-password handling, bounded failure, and log redaction. It binds only an
ephemeral `127.0.0.1` port and requires no external account or network access.
`test_trusted_hosts.py` covers the Stage 7 backend Host allowlist (S-12): configured
LAN hosts, development loopback, port/case/FQDN-dot normalization, and 421 rejection
of unrecognized hosts on authenticated and public routes.
`test_field_limits.py` is the Stage 8 home suite: backend/CLI schema equivalence
through the canonical initializer, composite relationship primary keys, typed
request-field limits, the bcrypt 72-byte password boundary, and the shared
password contract vectors (`password_contract_vectors.json`). The browser mirror
side of those vectors runs with `node tests/password_contract_test.mjs`.
`test_media_integrity.py` is the Stage 9 home suite: canonical .jpg naming and
image/jpeg serving, shared decode-safety dimension limits, staged-write atomicity
with induced-failure compensation, derived photo counts, generic correlated errors,
and the manual orphan checker (`tools/check_media_orphans.py`).
`test_kml_import.py` is the Stage 11 home suite: exclusive per-job temporary
files under concurrent identical filenames, owner-authorized job progress with
indistinguishable 404s, imported-coordinate validation with compact skip and
photo-failure counts, per-job cleanup on success and failure, the bounded
executor with per-user/global admission 429s, KML depth/element/placemark/byte,
photo, fetch-attempt, and wall-clock budgets, read-triggered retention with the boot
sweep, clean/degraded/error/interrupted notification producers, affected-marker and
budget attribution, redacted structured logging at the KML call sites (S-14), and
the vetted-IP pinned HTTPS transport with local-TLS SNI/verification evidence (S-15).
`test_notif_history.py` is the notification-history home suite: canonical schema and
enforced ownership cascade, fixed output bounds, fail-open writes with redacted
diagnostics, per-user insert-time retention, authenticated read isolation,
race-safe high-water seen semantics, idempotent per-row read/unread state, and the
post-commit map/marker/photo deletion producers with frozen object context. It also
covers correlated authenticated 5xx, the uncaught-exception handler, unauthenticated
exclusion, and static centralization of explicit 500 responses.
`test_account_lifecycle.py` is the Stage 12 home suite: the disabled-mode compatibility
contract, verified-then-approved registration, resend cooldown and newest-token
semantics, explicit admin bypass, pending self-service email changes, generic eligible
recovery, reset replay/expiry/session revocation, audit events, retryable SMTP failure,
non-consuming reset-link preflight validation, and a real loopback SMTP delivery
through the Flask registration route.
Each suite prints `==== N passed, M failed ====`.

## Configuration and repository-hygiene checks

The configuration check exercises typed parsing, immutable startup state, default and
production-mode validation, and the shared backend/CLI database path against real
SQLite files. The frontend contract check verifies that its public configuration is
frozen, non-secret, and retains the existing behavior values. The repository guard
rejects unignored runtime/secret artifacts while preserving the intentional fixtures.
The reproducibility check also executes `seed.sh`'s SQL against the canonical schema
and verifies notification ownership, seen-state coverage, taxonomy, and JSON detail.

```sh
tests/venv/bin/python tests/configuration_test.py
node tests/frontend_config_test.mjs
tests/venv/bin/python tests/repository_artifact_test.py
tests/venv/bin/python tools/check_repository_artifacts.py
tests/venv/bin/python tests/stage4_reproducibility_test.py
python3 tests/html_structure_test.py
python3 tests/nginx_structure_test.py
node tests/password_contract_test.mjs
```

## Manual KML fixture

`kml_empty_name_fixture.kml` is a hand-import fixture for the F3 fix, not used by any
automated suite — `test_kml_import.py` builds its own equivalents inline. Import it
through the UI after a deploy to confirm the fix landed on the host.

`kml_fixture_import_check.py` runs the same expectations non-interactively. **It does
not replace the UI hand-import**: it drives the HTTP API against its own throwaway
backend, so it proves the parser and storage behave, not that the deployed frontend
delivers the file correctly. Do both after a deploy that touches KML.

| | |
| --- | --- |
| Path | `tests/kml_fixture_import_check.py` |
| Invocation | `tests/venv/bin/python tests/kml_fixture_import_check.py` |
| Input | `tests/kml_empty_name_fixture.kml` (resolved relative to the repository, not the cwd) |
| Output | eight `PASS`/`FAIL` lines, then `==== N passed, M failed ====` |
| Exit codes | `0` all expectations hold · `1` any failure |
| Writes | a temp directory (`mv_kml_fixture_*`) holding its own copy of the six bootstrap modules and its own SQLite database, **removed on success** |
| Touches production? | **No.** It never reads `/etc/markervault/markervault.env`, never contacts a deployed host, and creates the throwaway user `fixture` and map `Fixture` only inside its own database |
| Credentials | sets a dummy signing secret in its own environment; the fixture account's password is a literal in the file and grants nothing outside the temp database |
| Consumer | run by hand after KML changes; not part of the `test_*.py` loop, since it is a fixture check rather than a suite |

On failure the temp directory is deliberately left behind for inspection.

- Before F3 (`0a9ace1`) it imports **0 of 4** markers. One empty `<name></name>`
  reached `spots.name` (NOT NULL) and failed the whole job, taking three valid
  placemarks with it; the journal shows `IntegrityError: NOT NULL constraint failed:
  spots.name` and the UI shows only `import_failed`.
- After, it imports **4 of 4** with 0 skipped, as `Unnamed` (the empty-named
  placemark, taking the same fallback an absent `<name>` gets), `Marco Valido`,
  `Sem Local`, and `Com Local`.

It also covers the quiet half of the same defect: every row must carry
`listing = General` (empty `<Document><name/>`) and the first two `subset = Main`
(empty `<Folder><name/>`) rather than NULL, while `Zona Sul` shows a real folder name
passing through untouched. Note that the marker fallback (`Unnamed`) and the listing
fallback (`General`) are unrelated constants — they shared the word `General` until
2026-07-26, which made an unnamed marker look like it had adopted its listing. `Com Local` must read `Local: Alfama` and `Sem Local` must
be empty — pre-fix it stored the literal string `Local: None` (`0db4c8c`).

## Vendored-asset security check

`swiper_prototype_pollution_check.mjs` answers whether the vendored Swiper bundle still
carries the CVE-2026-27212 gadget. **Run it at every Swiper upgrade:**

```sh
node tests/swiper_prototype_pollution_check.mjs
```

The advisory says 12.1.2 fixed it, and OSV scans 12.2.0 clean, but the fix is
incomplete: the guard's direct string comparisons are the callback to an overridable
`Array.prototype.filter`. Today the check reports `GADGET STILL PRESENT` and exits 0 —
that is the recorded state, with no fixed version to upgrade to. It exits non-zero if
the bypass ever stops working, which is the signal to update `vendored-assets.json`
and `documentation/DEPENDENCIES.md`. Full reasoning and reachability analysis are in
the DEPENDENCIES Stage 13.1 section.

## Deployed-pin check

`tools/check_deployed_pins.py` answers "did a deploy's pins actually land". This
existed as an ad-hoc snippet until F1 showed that a silently skipped dependency
install is invisible from the outside; a deploy that looks successful is not evidence
the pins moved. Operator-facing, so it is also documented in
`documentation/INSTALL.md`.

| | |
| --- | --- |
| Path | `tools/check_deployed_pins.py` |
| Invocation | `sudo /var/www/markervault/venv/bin/python tools/check_deployed_pins.py requirements.txt` |
| Interpreter | the **deployed** venv, not `tests/venv` — it reports what that environment holds |
| Input | one requirements-file path, resolved from the current directory; run from the synced checkout |
| Output | one line per pin (`ok` / `DRIFT`), then `ALL PINS DEPLOYED` or `N PIN(S) NOT DEPLOYED` |
| Exit codes | `0` all pins match · `1` at least one mismatch or missing package · `2` usage error or unreadable manifest |
| Writes | **nothing.** Read-only: reads the manifest and queries installed metadata |
| Credentials | none read or written; needs `sudo` only to read a root-owned venv |
| Dependencies | standard library only, so it runs inside the production venv |
| Consumer | the operator, after every deploy (`documentation/INSTALL.md`) |
| Coverage | no automated suite — its own output is the assertion; both branches exercised by hand |

Lines beginning `#` or `-` are skipped, pin continuations have their trailing `\`
removed, and hash continuation lines are ignored. Pointing it at
`tests/requirements-test.txt` follows nothing and reports only that file's own
explicit pins.

## Static analysis (on demand, tooling not vendored)

Neither scanner is a project dependency — the test venv enables
`--require-hashes` and includes exactly `-r ../requirements.txt`
(`stage4_reproducibility_test.py` asserts both lines), so both run from a throwaway
environment. Recorded here so the runs are repeatable without keeping ~91 MB of
binaries in the tree.

```sh
# Python, offline, no telemetry
python3 -m venv /tmp/auditvenv && /tmp/auditvenv/bin/pip install bandit
/tmp/auditvenv/bin/bandit -q -r backend.py create_users.py markervault_schema.py \
    request_validation.py markervault_config.py username_validation.py \
    email_delivery.py tools/

# Python + JavaScript, offline, no account or telemetry (opengrep, a Semgrep fork)
curl -sSL -o /tmp/opengrep https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_manylinux_x86
chmod +x /tmp/opengrep
curl -sSL https://github.com/opengrep/opengrep-rules/archive/refs/heads/main.tar.gz | tar xz -C /tmp
LC_ALL=C.UTF-8 /tmp/opengrep scan --config /tmp/opengrep-rules-main/javascript public/frontend.js
LC_ALL=C.UTF-8 /tmp/opengrep scan --config /tmp/opengrep-rules-main/python backend.py tools/
```

**`LC_ALL=C.UTF-8` is required** — opengrep reads its rule files with the locale
encoding and dies on an ASCII default. Results as of 2026-07-26: bandit 0 High /
15 Medium / 7 Low, opengrep 14 JavaScript + 22 Python findings, **all reviewed as false
positives** during the project's code-sweep remediation. Notable: opengrep's
`is-function-without-parentheses` fires on `ip.is_private` etc. in `_resolve_public_ip`
— those are `ipaddress` **properties**, not methods, so the SSRF guard is correct. Use
these to corroborate the sweep's "checked and found clean" list; neither reaches the
authorization-ordering class of defect that matters most here.

## nginx checks

The Stage 7 structure check verifies the tracked configuration's public document
root, rejecting default servers, per-endpoint body limits, deduplicated proxy
headers, rate-limit status/zones, and runtime media aliases:

```sh
python3 /workspace/markervault/tests/nginx_structure_test.py
```

After deploying and reloading the tracked nginx configuration, burst the real refresh
endpoint to verify that edge rejections are 429 rather than nginx's default 503. The
check distinguishes nginx's HTML 429 from Flask's own JSON rate limiter:

```sh
/workspace/markervault/tests/nginx_429_live_check.sh https://markervault.lan
```

The refresh zone drains its burst at roughly one request every two seconds, so a test
run self-heals in under a minute.

The finding was first Confirmed on 2026-07-22 from the owner's live burst through the
deployed proxy (audit doc, commit `730a8c9`); this sentence previously still asked for
that evidence and was stale. **Re-verified 2026-07-25** (`https://markervault.lan`),
this time capturing the full output:

```text
Observed 20 total 429s (14 from nginx) and 0 503s
PASS: deployed nginx rate-limit rejections use 429
```

The edge boundary is therefore Confirmed rather than Plausible: rejections come back as
429 from nginx itself, never its default 503. The split across two limiters is expected
and worth recognizing when reading a run — nginx's `burst=20 nodelay` passes about 21
requests before rejecting, while Flask's own bucket (`MARKERVAULT_RATE_BURST` 14, so
`1 + burst` = 15 allowed) rejects those that get past the edge. A run showing only
JSON 429s would mean the edge never engaged.

## Running the live checks against gunicorn

Both live checks spawn their own backend. `MV_LIVE_GUNICORN=1` swaps only that spawn
command for `tests/venv/bin/gunicorn` with the tracked unit's explicit
`--workers 1 --worker-class sync --timeout 30` flags, so the rigs exercise the
production server instead of the Flask development server. The duplicated arguments
are checked against the unit by `stage4_reproducibility_test.py`. Seeding, environment
injection, the proxy front, and exit cleanup are identical in both modes.

```sh
MV_LIVE_GUNICORN=1 node /workspace/markervault/tests/pw-test/refresh_live_check.mjs
MV_LIVE_GUNICORN=1 node /workspace/markervault/tests/pw-test/kml_live_check.mjs
```

Knob-on runs the production shape: one synchronous worker, so requests serialize
instead of running threaded. Slowness or flakiness that appears only in this mode is
evidence about production — report it rather than rerunning until it passes. Each
knob-on run also prints the worker model and the access/error line counts gunicorn
actually emitted.

The stopgap check verifies that the tracked nginx denial locations cover the sensitive
path matrix without matching intended frontend, API, or signed-media routes:

```sh
python3 /workspace/markervault/tests/nginx_stopgap_test.py
```

After deploying and reloading the tracked nginx configuration, run the same check
against the real HTTPS service. Pass one currently valid signed photo, thumbnail, or
avatar URL copied from the browser so the nginx-to-Flask-to-internal-alias path is
included:

```sh
python3 /workspace/markervault/tests/nginx_stopgap_test.py \
    --base-url https://markervault.lan \
    --signed-media-url '/avatars/example.jpg?exp=...&uid=...&sig=...'
```

The live check accepts the deployment's current self-signed certificate. It requires
403/404 for sensitive paths, 200 for intended static assets and signed media, and the
expected unauthenticated JSON 401 from Flask for `POST /auth/refresh`.

### Rebuilding the Python venv

The venv is not tracked. Create it before running the documented `venv/bin/python`
commands:

```sh
cd /workspace/markervault/tests
python3 -m venv venv
venv/bin/python -m pip install --requirement requirements-test.txt
```

`requirements-test.txt` enables hash mode and includes the hash-locked production
manifest at `../requirements.txt`; there are currently no additional Python-only
test packages.

## Browser suites (Playwright, Node, mock backend)

These drive the frontend against a **mock backend** (no live server needed) in headless
chromium. `node_modules/` is vendored; the chromium binary comes from the Playwright
browser cache at `~/.cache/ms-playwright` (outside the workspace, stable per-user cache).

```sh
cd /workspace/markervault/tests/pw-test
node matrix_test.mjs          # 37 — viewer/editor UI matrix + bulk share/delete + delete/create state
node admin_groups_test.mjs    # 125 — admin screen: tabs, groups, share mgmt
node admin_mgroups_test.mjs   # 30 — management-groups tab
node comanagers_test.mjs      # 25 — non-super co-managers + sealed maps persona
node audit_test.mjs           # 28 — readable light audit log/reasons, filters, super-only access, pagination
node avatar_test.mjs          # 16 — profile/sidebar avatar upload, removal, fallback
node localized_fixes_test.mjs # 41 — document/mobile, routing/auth/KML/gallery, bounded KML polling, popup/logout recovery
node refresh_coordination_test.mjs # 45 — Stage 10 single-flight, cross-tab Web-Lock serialization, required-capability gate, memory-only tokens, 429/401/offline handling, no-flash boot, clean-slate re-login, rate-limit landing page
node notification_history_test.mjs # 21 — readable event labels, exact badge, row toggles, high-water seen, account isolation, operation refresh, no idle polling
node account_lifecycle_test.mjs # 18 — quiet login modes, one uniform fixed feedback slot per pane, contextual resend, stationary cards in every reset state, admin bypass, stable profile feedback
```

Run the complete browser rig with `npm test`.

### Live refresh check (real backend, no mocks)

`refresh_live_check.mjs` is separate from `npm test`: it seeds a scratch database,
starts the real Flask backend with 3-second access tokens behind a local
static+proxy origin, and drives real browser tabs through login, cross-tab refresh
rotation, expiry recovery, simultaneous reload, and logout revocation. This is the
real-server evidence the mock rig cannot provide. It needs `tests/venv` and binds
only loopback ports:

```sh
node /workspace/markervault/tests/pw-test/refresh_live_check.mjs
```

`kml_live_check.mjs` is the Stage 11 counterpart: it seeds two users on a scratch
database, runs the real backend and drives genuine KML imports through the UI —
real bearer-carrying multipart upload, the bounded worker, compact
skip/photo-failure counts in the final progress text, owner-authorized status
404s across two authenticated contexts, read-triggered retention, marker arrival,
and clean/degraded notification rows through the real SQLite/API/badge/panel,
high-water-seen, and per-row read/unread boundary:

```sh
node /workspace/markervault/tests/pw-test/kml_live_check.mjs
```

### Rebuilding the Node deps / browsers (if ever needed)
```sh
cd /workspace/markervault/tests/pw-test
npm ci --ignore-scripts
node node_modules/playwright/cli.js install chromium
```

## Notes
- The suites assume the assets under `/workspace/markervault/public/assets/` are present
  (see the browser-testing memory for the CDN/host allowlist the frontend needs).
- Screenshots (`tests/ui_*.png`, `tests/pw-test/*.png`) are regenerated on every
  browser-rig run for owner inspection. They are gitignored — never commit them.
  Exploratory smoke images stay under `/tmp`.
- See `../documentation/DEPENDENCIES.md` for the production, Node lockfile,
  browser-cache, vendored asset, and update workflows.
