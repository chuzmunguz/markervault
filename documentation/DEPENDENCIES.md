# Dependency and launch reproducibility

## Python runtime

`requirements.in` is the direct production input: the imported distributions plus
the gunicorn launcher used by systemd and the live rigs. `requirements.txt` is the
generated production lock containing those packages, their resolved transitive
dependencies, and SHA-256 hashes for every accepted artifact. Rebuild a production
virtual environment with the interpreter-provided pip:

```sh
cd /var/www/markervault
python3 -m venv venv
venv/bin/python -m pip install --require-hashes --requirement requirements.txt
```

The lock was generated on 2026-07-27 with Python 3.13.5, pip 25.1.1 and
pip-tools 7.6.0:

```sh
python3 -m venv /tmp/markervault-lock-tools
/tmp/markervault-lock-tools/bin/pip install pip-tools==7.6.0
/tmp/markervault-lock-tools/bin/pip-compile \
    --generate-hashes --no-header --strip-extras \
    --output-file=requirements.txt requirements.in
sha256sum requirements.txt
```

`requirements.txt` SHA-256: `a4ed3343f22365c8e92bfb0ab5451f04659ac039fd2eecef58d22ebe3c49f577`.
Regeneration must preserve the complete 18-package pin set unless a separately
reviewed dependency update intentionally changes it. Review both the pin diff and
the digest before committing.

The deployment is defined by the tracked Stage 7 manifests: `markervault.service`
(systemd unit mirroring the live service — user `markervault`,
`WorkingDirectory=/var/www/markervault`, gunicorn from `venv/` with one explicit
sync worker and a 30-second request timeout, journal logging, environment loaded from
`/etc/markervault/markervault.env`) and `markervault.env.example` (environment
template — production mode, signing secret, external runtime paths under
`/var/lib/markervault`, host allowlists). `install.sh` and `seed.sh` source the same
environment file, so the service, the scripts, and the CLI share one path/secret
source of truth.
The app tree is root-owned end to end (re-asserted by every deploy): the service
user executes the code but can write none of it. `sudo ./install.sh --wipe-data`
(or `--keep-data`) is the single idempotent install+deploy pass, run for every
deploy: it bootstraps whatever is missing, installs the hash-locked dependencies,
refreshes the unit and nginx sites from the tracked files, and ships the code.
One of the two mode flags is required — bare `sudo ./install.sh` prints usage and
exits without deploying. `--wipe-data` ends on a clean EMPTY database.
Seeding the disposable test fixtures is the separate explicit `sudo ./seed.sh`
(real accounts: `create_users.py`).

`tests/requirements-test.txt` enables `--require-hashes`, includes the production
manifest, and is the entry point for rebuilding the untracked test environment.
`install.sh` deliberately does not upgrade pip from the network: it uses the venv's
ensurepip-provided `python -m pip`, enforces the hashes, then prints the deployed
interpreter, pip version, and lock digest.

**Confirming a pin actually deployed.** A version bump in `requirements.txt` is not
evidence that the running host has it — that gap is exactly what let the whole Stage 13
dependency programme sit undeployed. After any deploy that changes a pin:

```sh
sudo /var/www/markervault/venv/bin/python tools/check_deployed_pins.py requirements.txt
```

Read-only, standard library only (so it runs inside the production venv), one line per
pin, exit 0 on `ALL PINS DEPLOYED` and 1 listing every mismatch. Full contract in
`tests/README.md`.

## SMTP delivery and optional account lifecycle

Stage 5 added the standard-library SMTP boundary; Stage 12 gives it account-lifecycle
callers behind a separate flag. Construction does not connect. With the tracked
defaults (`MARKERVAULT_EMAIL_DELIVERY_ENABLED=false` and
`MARKERVAULT_REQUIRE_EMAIL_VERIFICATION=false`), MarkerVault remains entirely
admin-managed: self-registration still waits only for approval, administrators/CLI
create verified accounts and reset passwords, and the public email endpoints return
404. No SMTP connection is attempted.

When both flags are enabled, self-registration verifies email before administrator
approval, users can verify a pending profile-email change, and approved/enabled users
can request password recovery. Administrators can explicitly bypass verification;
admin- and CLI-created accounts are verified immediately. Token values are random,
stored only as SHA-256 hashes, single-use, and replaced by newer requests.

The service environment is the only supported place for SMTP configuration:

| Variable | Default | Contract |
| --- | --- | --- |
| `MARKERVAULT_EMAIL_DELIVERY_ENABLED` | `false` | Enables the delivery boundary; account behavior remains unchanged unless verification is also enabled. |
| `MARKERVAULT_REQUIRE_EMAIL_VERIFICATION` | `false` | Enables verification/recovery semantics and their capability-controlled UI. Requires delivery and a public origin. |
| `MARKERVAULT_PUBLIC_ORIGIN` | unset | Explicit http(s) origin used in emailed links. Must be allowlisted; production requires HTTPS. Never derived from request Host. |
| `MARKERVAULT_EMAIL_VERIFICATION_TOKEN_DURATION` | `86400` | Verification-token lifetime in seconds (24 hours). |
| `MARKERVAULT_PASSWORD_RESET_TOKEN_DURATION` | `1800` | Reset-token lifetime in seconds (30 minutes). |
| `MARKERVAULT_EMAIL_RESEND_COOLDOWN` | `60` | Per-account resend cooldown in seconds. |
| `MARKERVAULT_SMTP_HOST` | unset | Required when delivery is enabled. |
| `MARKERVAULT_SMTP_PORT` | `587` | Integer from 1 through 65535. |
| `MARKERVAULT_SMTP_TIMEOUT` | `10` | Positive finite synchronous connection/operation timeout in seconds. |
| `MARKERVAULT_SMTP_SECURITY` | `starttls` | Exactly `starttls`, `implicit_tls`, or `plaintext`. |
| `MARKERVAULT_SMTP_FROM_ADDRESS` | unset | Required message `From` address. |
| `MARKERVAULT_SMTP_ENVELOPE_FROM` | message From | Optional distinct SMTP envelope sender. |
| `MARKERVAULT_SMTP_USERNAME` | unset | Standard SMTP AUTH username; set together with the password. |
| `MARKERVAULT_SMTP_PASSWORD` | unset | Opaque ordinary or provider app password; set together with the username. |
| `MARKERVAULT_SMTP_ALLOW_UNAUTHENTICATED_LOCAL` | `false` | Explicit test-only opt-in, accepted only for `localhost` or a loopback IP. |

Authenticated plaintext is rejected; authenticated delivery must use explicit
STARTTLS or implicit TLS. An app password follows the same SMTP AUTH path as an
ordinary password. OAuth-only providers are outside this stage. Never put real
credentials in source, browser configuration, SQLite, audit details, commands saved
in documentation, or logs.

Delivery is synchronous and fails with a generic error after the configured timeout.
There is no worker or polling loop. Account-triggered delivery uses a separate
in-memory public-rate bucket and generic request responses. Registration/profile
state survives a delivery failure so the user can retry through Resend verification.
Recovery sends only for approved, enabled, verified accounts; unknown, pending, and
disabled addresses receive the same public response. Reset links are preflighted by
a non-consuming public validation call when the reset pane opens, so an invalid or
expired link is explained before password entry; the reset submission still performs
the authoritative transactional validation and consumes a valid token.

Exercise the boundary without external credentials:

```sh
tests/venv/bin/python tests/test_email_delivery.py
tests/venv/bin/python tests/test_account_lifecycle.py
tests/venv/bin/python tests/configuration_test.py
```

The delivery and lifecycle checks use ephemeral loopback fake SMTP servers for real
envelope/message delivery, including registration through the actual Flask caller
path. TLS negotiation selection is exercised with in-process protocol spies so no
certificate or external provider is required.

## Browser test runtime

`tests/pw-test/package.json` pins Playwright exactly and
`tests/pw-test/package-lock.json` records package integrity.

Rebuild the Node tree and the external Chromium cache with:

```sh
cd /workspace/markervault/tests/pw-test
npm ci --ignore-scripts
node node_modules/playwright/cli.js install chromium
npm test
```

Chromium is stored outside the repository under `~/.cache/ms-playwright`. Its required
revision is recorded in `node_modules/playwright-core/browsers.json`. After changing
Playwright, review both lockfiles, rebuild the browser cache, and run all browser
suites before committing.

Browser screenshots are written directly under `tests/` as `ui_*.png` on every rig run,
for owner inspection only. They are **not tracked**: `/tests/ui_*.png` is gitignored and
`repository_artifact_test.py` makes the artifact guard reject them, so an in-tree
Playwright run leaves nothing to commit. Never add one. Exploratory desktop/mobile smoke
images stay under `/tmp`.

## Vendored browser assets

`vendored-assets.json` records every third-party JavaScript/CSS bundle, its exact
version or commit, upstream source, license, SHA-256 hashes, the last advisory review
date, the method that review used, and the date the next one is due. Per-library
`advisory_status` is the authoritative note for that dependency; the runtime upgrades
themselves stay isolated in Stage 13 substeps.

Verify hashes, application references, the Playwright lock/tree agreement, and the
production/test manifest relationship with:

```sh
python3 tests/stage4_reproducibility_test.py
```

## Advisory review 2026-07-25 (Stage 13.0)

Every vendored front-end version and every `requirements.txt` pin was queried against
OSV (`POST https://api.osv.dev/v1/querybatch`, npm and PyPI ecosystems, the
Leaflet.PolylineMeasure pin by commit), and each package's newest published release
was read from `registry.npmjs.org` / `pypi.org`. The Stage 4 audit recorded the bulk
OSV lookup as proxy-blocked; OSV is reachable from the working container, so that
stated limitation is closed. A root-path probe of `api.osv.dev` returns 404 and does
not mean the API is unavailable.

| Dependency | Result |
| --- | --- |
| Leaflet 1.9.4 | Clean in the npm ecosystem. CVE-2025-69993 exists only as a GIT/CPE range ending in `last_affected`, with no fix event and no fixed version anywhere; 1.9.4 is still the newest non-prerelease. **Owner decision 2026-07-25: stay on 1.9.4** with the DOM-node popup mitigation, and re-check for a fixed 1.x release at the next review. |
| Leaflet.PolylineMeasure `9908e5a2` | Clean. The pin equals upstream HEAD (2023-11-07) and the npm release 3.0.0 (2021-06-21) is older, so no upgrade exists. |
| Leaflet Routing Machine 3.2.12 | Clean; newest published release. |
| Leaflet Control Geocoder 3.3.1 | Clean, as is 4.0.0. Upgraded in Stage 13.2, then **retired entirely** once it turned out nothing could consume it — no longer vendored. |
| Swiper 12.0.3 → 12.2.0 | **Partially mitigated; the gadget is retained, and no fixed upstream release is identified as of 2026-07-26.** GHSA-hmx5-qpq5-p643 / CVE-2026-27212 lists `>=6.5.1 <12.1.2` as affected and OSV scans 12.2.0 clean, but the advisory's "fixed" is incomplete — see the correction below. Upgraded in Stage 13.1; the deferred 14.x major is affected too, so it would not help. |
| GLightbox 3.3.1 | Clean; newest stable release. |
| All 18 `requirements.txt` pins | Clean. `certifi`, `gunicorn`, and `packaging` lag their newest releases without any advisory driving it. **`certifi` was bumped in Stage 13.3 (see below);** `gunicorn`/`packaging` are Stage 13.4. |

Leaflet 2.x is ESM-only, exposes no global `L`, and breaks this plugin set, so it can
only ever be a separately planned migration stage rather than a dependency bump.

### Stage 13.1 — Swiper 12.0.3 → 12.2.0

`swiper-bundle.min.js` and `swiper-bundle.min.css` come from the published
`swiper-12.2.0.tgz`, whose download was checked against the registry's own `integrity`
(SHA-512) and `shasum` values before extraction. Only those two files are vendored; the
package's source maps and ESM bundle are not.

The advisory's mechanism is worth recording because the fix is invisible in a version
number: `extend()` filtered `__proto__`, `constructor`, and `prototype` out of its key
list with `Array.prototype.indexOf`, so an attacker who had already polluted that one
method defeated the guard and could reach `Object.prototype` through Swiper options.
12.1.2 replaced the array lookup with three direct string comparisons. The vendored
bundle was diffed across the fix boundary to confirm the patched form is actually
present rather than assumed from the version.

**Correction (2026-07-26): the claim that direct comparisons "no prototype can
intercept" was wrong, and the upstream fix is incomplete.** The comparisons are the
*callback* to an equally overridable `Array.prototype.filter`:

```js
Object.keys(Object(a)).filter(e => "__proto__" !== e && "constructor" !== e && "prototype" !== e)
```

Replace `filter` and the callback never runs. Executed against this exact bundle:
with an untouched prototype the guard holds, and with `Array.prototype.filter`
neutralized the pollution succeeds. Upstream issue
[8189](https://github.com/nolimits4web/swiper/issues/8189) is open and current upstream
master still carries the pattern, so **no fixed upstream release is identified as of
2026-07-26** — the same posture already recorded for Leaflet 1.9.4 / CVE-2025-69993.

**The deferred 14.x major would not resolve this.** npm's current latest, 14.0.6, was
downloaded and reproduced independently on 2026-07-26: same `.filter` guard, same
`polluted=yes`. Deferring that upgrade costs nothing here, and taking it would buy
nothing on this advisory.

The reproduction is tracked at `tests/swiper_prototype_pollution_check.mjs`; re-run it
at every Swiper upgrade. It exits 0 while the gadget is present (the recorded state)
and non-zero if the bypass ever stops working, which is the signal to update this
section and `vendored-assets.json`.

**Prerequisites, stated precisely.** The demonstrated bypass needs two things: prior
tampering with `Array.prototype.filter`, *and* a crafted object reaching Swiper's merge
path. MarkerVault passes only fixed literal option objects (see below) and nothing
routes remote input into `extendDefaults`, so there is **no identified
attacker-controlled path** to the second prerequisite — which makes application
exploitability *unconfirmed*, not proven absent. Note the earlier draft of this section
said exploitation "requires already having XSS": that is wrong as stated. Script
execution is one sufficient route to prototype tampering, not a necessary one, and
writing it that way understates the finding.

This is why the gadget is recorded rather than remediated: it is a library-level
weakness with no reachable path here and nothing to upgrade to.

The original error is worth recording as method: the mechanism was verified one level
too shallow. Confirming that `indexOf` had become direct comparisons answered the
question that was asked, and the surrounding call was never examined.

MarkerVault's own usage is unaffected by the change: the gallery passes a fixed option
object (`slidesPerView`, `centeredSlides`, `spaceBetween`, `grabCursor`, `rewind`,
`scrollbar`, `keyboard`, `navigation`) and calls only `slideTo()` and `destroy()`, none
of which changed within the 12.x line. Every Swiper class the markup and stylesheet
depend on — `swiper-wrapper`, `swiper-slide`, `swiper-button-next`/`-prev`,
`swiper-scrollbar`, `swiper-scrollbar-drag`, `swiper-lazy-preloader` — is still styled
by the new bundle.

### Stage 13.2 — Leaflet Control Geocoder 3.3.1 → 4.0.0

Maintenance, not advisory-driven. `dist/Control.Geocoder.js` and
`dist/Control.Geocoder.css` come from `leaflet-control-geocoder-4.0.0.tgz`, verified
against the registry's `integrity` before extraction; the CSS class set is identical to
3.3.1's, and the `IGeocoder` promise contract is unchanged. The only interface addition
is the exported `SuggestUnsupportedError`, which MarkerVault does not use. The declared
peer dependency narrowed from `leaflet ^1.6.0 || ^2.0.0` to `leaflet ^1.6.0` — 4.0.0
dropped Leaflet 2 support, which is consistent with staying on 1.9.4.

MarkerVault constructs the geocoder at exactly one place, as Routing Machine's
`geocoder` option; `geocodeAddress()` elsewhere in `frontend.js` is an independent
direct `fetch` to Nominatim and does not involve this library.

**A real defect, currently masked by CSS — pre-existing and unchanged by this
upgrade.** Routing Machine 3.2.12 calls the geocoder with the callback convention of a
much older API, and Control.Geocoder has been promise-based since 3.x, so it drops the
callback on every one of the three methods Routing Machine uses:

| Routing Machine calls | Purpose | Result |
| --- | --- | --- |
| `reverse(latLng, scale, callback, context)` | fill a waypoint's label | callback never fires, so the input stays empty |
| `geocode(query, callback, context)` | resolve typed text on Enter | callback never fires, so typing never resolves |
| `suggest(query, callback, context)` | per-keystroke autocomplete | Nominatim throws `SuggestUnsupportedError` by policy; Routing Machine predates that error |

A probe driving the real vendored bundles against a stubbed Nominatim confirms the
callback never fires on **either** 3.3.1 or 4.0.0, while the returned promise resolves
correctly in both.

Nothing was visibly wrong because MarkerVault hid those inputs with a stylesheet rule
and drives routing from its own `#startAddress`/`#endAddress` fields, which
`generate-route-btn` resolves through `geocodeAddress()` — an independent direct fetch
— before calling `setWaypoints()`. Un-hiding the inputs exposed all three failures at
once, confirmed on the live server. **The dependency was retired as a result; see
below.**

### Retiring Leaflet Control Geocoder

The library was removed outright rather than repaired. Nothing consumed it: Routing
Machine could not read its promises, and MarkerVault already reverse-geocodes through
its own centralized `nominatim.openstreetmap.org/reverse?` fetch. Keeping it meant
carrying two vendored files, an inventory entry, advisory tracking, and an upgrade
every cycle — and, on every route calculation, **two Nominatim reverse requests whose
answers were discarded**, against a service with a strict usage policy.

Measured before and after, driving real waypoints through the app:

| | With the geocoder | Retired |
| --- | --- | --- |
| Route line and alternatives | drawn | drawn, unchanged |
| Waypoint labels | empty | element no longer exists |
| Waypoint input boxes / add-waypoint button | 2 / 1 | 0 / 0 |
| Nominatim requests per route | 2 | 0 |
| Page errors | none | none |

Note what removal does **not** do. Routing Machine's coordinate fallback
(`wp.name = wpCoords`) lives inside the geocoder element it only builds when a geocoder
is supplied, so dropping the option does not make labels show coordinates — it removes
the waypoint-input row and the add-waypoint button entirely. That UI was already hidden,
so nothing visible changed, but restoring it later would require both the library and a
working callback adapter, which was never demonstrated.

Removed: the `geocoder` option in `frontend.js`, both `<script>`/`<link>` tags,
`assets/Control.Geocoder.{js,css}`, the `vendored-assets.json` entry, and the stylesheet
rule that hid the row. `localized_fixes_test.mjs` gained a "Routing without the retired
geocoder" section asserting the library is absent from the runtime and the routing
options, that no waypoint-geocoder UI is built, and that routing still draws its line
and alternatives; `stage4_reproducibility_test.py` asserts no reference or asset
survives.

### Stage 13.3 — certifi 2026.6.17 → 2026.7.22

Not advisory-driven; both releases scan clean. certifi carries no API surface — it is
the Mozilla CA bundle that `requests` uses, reached in MarkerVault only through the KML
importer's photo downloads over the vetted-IP pinned HTTPS transport (S-15).

The bundle goes from 118 to 121 certificates. Four roots are added — `SECOM TLS ECC
Root CA 2024`, `SECOM TLS RSA Root CA 2024`, `Telia EC TLS Root CA v3`, and `Telia RSA
TLS Root CA v3` — and **one is removed: `Atos TrustedRoot 2011`**. (Grepping for `Atos`
in the new bundle still hits, but only the two surviving 2021 TLS roots; the 2011 root
itself is gone. Match on the `# Label:` line, not the vendor name.) The removal
originates upstream: certifi is generated from Mozilla's CA store, so a root leaves the
bundle because Mozilla dropped it, not because certifi chose to.

The bump is therefore **not purely additive**, and both an earlier revision of this
section and the message of commit `69863ab` claimed it was. That commit message stands
as written — published history is not rewritten here — so this section is the
correction of record. The correct statement of the risk: an HTTPS endpoint whose chain
anchors at `Atos TrustedRoot 2011` verified before this bump and fails verification
after it. In MarkerVault that reaches exactly one path — the KML importer's photo
downloads — so the practical exposure is a KML import whose photo host still chains to
that root failing with a certificate error. Following Mozilla's distrust is still the
right call; the exposure is recorded here so a future import failure is diagnosable
rather than mysterious.

Method, for re-checking after any future certifi bump: unpack both wheels and diff the
`# Label: "…"` lines of `certifi/cacert.pem`. A certificate count alone hides a
simultaneous add and removal, and the arithmetic is the tell — 118 + 4 additions would
be 122, so the 121 total was already evidence that something had left.

`tests/venv/` was rebuilt from `tests/requirements-test.txt` for this change. The
rebuild also corrected drift: the previous environment predated `gunicorn` and
`packaging` entering the production manifest and therefore lacked both. The rebuilt
environment matches `requirements.txt` pin for pin, and `tests/venv/bin/gunicorn` now
exists — which Stage 13.4 depends on.

**Deployment.** This is a backend dependency change, so it carries the standing deploy
semantics: it reaches the server only at the next `sudo ./install.sh --wipe-data`,
which installs `requirements.txt` into the production virtual environment on every
run, followed by `sudo ./seed.sh` if the disposable fixtures are wanted. Committing it changes nothing
on the running host.

### Stage 13.4 — gunicorn 23.0.0 → 26.0.0, packaging 25.0 → 26.2

Three majors, not advisory-driven. Across all of them the release notes list exactly
one breaking change — removal of the eventlet worker, which is unused here. The
substantive risk was gunicorn 26's stricter HTTP/1.1 parsing (authority-form and
asterisk-form targets, control characters in header values, `Content-Length` list form,
general smuggling hardening), all of which nginx normalizes before MarkerVault sees it.
`packaging` moves only because gunicorn requires it.

**The live rigs can now run the production server.** `refresh_live_check.mjs` and
`kml_live_check.mjs` both spawn their own backend, so verifying gunicorn meant teaching
them to spawn it. Setting `MV_LIVE_GUNICORN=1` swaps **only** the spawn command for
`tests/venv/bin/gunicorn` with the tracked unit's explicit
`--workers 1 --worker-class sync --timeout 30` flags; seeding, environment injection,
the static/proxy front, and exit cleanup are identical, and the rig still owns the
process. With the knob off the rigs behave exactly as before. The repository
reproducibility test asserts that both duplicated argument lists stay aligned with the
unit.

```sh
MV_LIVE_GUNICORN=1 node tests/pw-test/refresh_live_check.mjs
MV_LIVE_GUNICORN=1 node tests/pw-test/kml_live_check.mjs
```

Knob-on runs the real production shape — a single synchronous worker, so requests
serialize rather than running threaded as under the Flask development server. Slowness
or flakiness in that mode is information about production and should be reported, not
retried until green. Both rigs pass in both modes, with the same 32 and 36 access-log
lines under gunicorn 23 and 26, so the stricter parser rejected nothing the app relies
on. The error channel was verified separately by inducing a 500 through the S-14
`internal_error` path: the correlation-id line, the traceback, and the 500 access-log
entry all arrive on gunicorn 26's log streams.

**New in 26 and switched off deliberately: the control socket.** gunicorn 26 opens a
Unix control socket at `$HOME/.gunicorn/gunicorn.ctl` *by default*, which lets anyone
able to act as the service user drive the master process. Mode `0600` limits that to
the service user and root, and MarkerVault uses no `gunicornc` tooling, so the surface
is pure cost — the tracked unit and the rig knob both pass `--no-control-socket`. Where
`$HOME` is unwritable the socket is non-fatal: the application serves normally and the
journal simply collects a repeating
`Control server error: [Errno 13] Permission denied` line.

**Deployment.** Same backend-dependency semantics as 13.3 — `requirements.txt` is
installed into the production virtual environment during `sudo ./install.sh
--wipe-data`. Because
`ExecStart` changed, the live unit must be refreshed from the tracked manifest, which
`install.sh` does. Confirm afterwards that `journalctl -u markervault` shows one
`Booting worker` line and no control-socket error.
