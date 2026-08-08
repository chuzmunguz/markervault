# MarkerVault public-launch gates

Everything that must be true before MarkerVault accepts public users. This is the
successor plan to the project's earlier code-audit remediation work, whose stages are
all implemented, deployed, and verified — nothing here re-opens that work.

**Status: not started.** No gate below has been begun. Each needs its own plan and
rollback before implementation, and each is sized to be a separate piece of work rather
than one release.

## What declaring launch actually changes

These gates are not only new features to add. Declaring public launch **revokes**
standing permissions the project has relied on since the beginning, so the operating
rules change on the same day:

| Today | After launch |
| --- | --- |
| Database, media and runtime state are disposable | User data must be preserved |
| New columns are baked into `CREATE TABLE`; no migrations | Schema changes need reviewed migrations |
| `install.sh --wipe-data` wipes the database and generated media; `--keep-data` already preserves them | `--keep-data` becomes the only mode used, and the drift guard's abort becomes a migration |
| Structural work may take the service offline | Downtime becomes a planned, announced event |
| Verified backups are not required | Restore-tested backups are required before destructive work |

`AGENTS.md` states the pre-public permission expires at launch. Gate 6 is where that
actually gets implemented, which is why it must be last: until it closes, the deploy
path still deletes the database.

## Order and why

Each gate depends on the ones above it:

1. **Real origin** — nothing else can be finished against a `.lan` name and a
   self-signed certificate. Emailed links in particular need a real HTTPS origin.
2. **Third-party providers** — the licensing blocker, and it determines what data
   leaves the browser.
3. **Privacy notice** — cannot be written until 2 settles where data actually goes.
4. **Email verification** — needs the HTTPS origin from 1.
5. **Remove LAN allowances** — only safe once 1 is proven; doing it early locks you out.
6. **Backups, migrations, retire disposable state** — the point of no return, and the
   gate that makes accepting real users defensible.

---

## Gate 1 — Real domain, public CA certificate, reviewed HSTS

**Current state.** `markervault.nginx` serves `server_name markervault.lan` on ports 80
and 443, with Debian's snakeoil certificate
(`/etc/ssl/certs/ssl-cert-snakeoil.pem`). `MARKERVAULT_ENVIRONMENT=production` and the
secure-cookie settings are already correct. HSTS is **already being sent**:
`Strict-Transport-Security "max-age=31536000; includeSubDomains" always`.

**Work.** Acquire the domain; set up automatically renewed ACME certificates; point
`ssl_certificate`/`ssl_certificate_key` at them; update `server_name` on both listeners;
re-review the HSTS policy for a public name.

**Decide deliberately.** HSTS is one of the few genuinely hard-to-reverse settings here.
`includeSubDomains` at a one-year max-age commits every subdomain of the new domain to
HTTPS for a year, on clients that have already seen the header — you cannot recall it by
changing the config. Preload submission is harder still to undo on browser timelines.
Choose the max-age and the preload question on purpose rather than inheriting the
current value because it is already there.

**Verify.** Full chain validates from an external client; a renewal dry-run succeeds and
reloads nginx; port 80 redirects; the HSTS header is present with the intended value;
`nginx_structure_test.py` and `nginx_stopgap_test.py` stay green.

**Rollback.** Keep the LAN name serving until the new origin is proven end to end —
that is why removing it is Gate 5 and not part of this one.

---

## Gate 2 — Third-party provider cutover

**Current state.** Three community services are called directly from the browser:

| Purpose | Endpoint | Where |
| --- | --- | --- |
| Map tiles | `https://{s}.tile.openstreetmap.org/...` | `frontend.js` tile layer |
| Geocoding (forward, search, reverse) | `https://nominatim.openstreetmap.org/...` | three `fetch` call sites in `frontend.js` |
| Routing | `https://router.project-osrm.org/route/v1` | `L.Routing.osrmv1()` default |

All three are demo/community endpoints whose usage policies do not permit production
traffic. This is a licensing blocker, not a performance one.

**Note what changed.** The Leaflet Control Geocoder dependency was retired, so geocoding
is now three direct `fetch` calls in `frontend.js` rather than a plugin — a cutover edits
those call sites. The commented `serviceUrl` line in the routing block is retained on
purpose as the escape hatch for a self-hosted OSRM; find it with
`grep -n serviceUrl public/frontend.js`, since line numbers drift.

**Work.** Decide per service between self-hosting and a commercial provider, then cut
over. Any API keys belong in `/etc/markervault/markervault.env` and must never reach
`frontend.js`, which is public.

**Verify.** Routing, search, and reverse geocoding all work against the new providers;
no requests to the retired hosts remain (check the browser network panel and the
`localized_fixes` browser suite); tiles render at several zoom levels.

---

## Gate 3 — Privacy notice

**Depends on Gate 2.** The notice cannot be accurate until the providers are settled.

**Must cover.** What leaves the browser and to whom — the user's IP address, their
search text, and the map areas they view all reach the tile, geocoding and routing
providers. What the server stores: accounts, maps, markers, photos, the audit log, and
notification history. Retention, and who can see what under the permissions model.

**One detail that is easy to miss.** Photo, thumbnail and avatar responses are sent with
`Cache-Control: private, max-age=1800`, so media can remain visible in a user's own
browser for up to thirty minutes after access is revoked or the item is deleted. That is
a documented, accepted behavior and it belongs in the notice rather than in a surprise.

---

## Gate 4 — Email verification and a production sender

**Depends on Gate 1** for an HTTPS `MARKERVAULT_PUBLIC_ORIGIN`; production configuration
rejects a non-HTTPS origin.

**Current state.** Fully built and reviewed in Stage 12, deliberately switched off:
`MARKERVAULT_EMAIL_DELIVERY_ENABLED=false`,
`MARKERVAULT_REQUIRE_EMAIL_VERIFICATION=false`, `MARKERVAULT_PUBLIC_ORIGIN` unset, SMTP
settings commented out. With the flags off the application stays entirely
admin-managed and the public email endpoints return 404. **No code is needed here** —
this gate is a configuration cutover and a sender decision.

**Work.** Choose a production-capable SMTP or transactional sender; set the SMTP
variables and `MARKERVAULT_PUBLIC_ORIGIN`; enable both flags. The configuration couples
them: requiring verification demands both delivery and a public origin.

**Known cost, already accepted.** Delivery is synchronous with no worker, so a slow
sender slows the request that triggered it, and the timing difference on recovery and
resend is an inherent side-channel of that design. Both were accepted knowingly; revisit
only if the chosen sender turns out to be slow.

**Verify.** Register, verify, approve; request recovery and complete a reset; confirm
emailed links use `PUBLIC_ORIGIN` and never the request `Host`.

**Rollback.** Set both flags back to false.

---

## Gate 5 — Remove the temporary LAN allowances

**Depends on Gate 1 being proven**, not merely deployed.

**Current state.** `MARKERVAULT_TEMPORARY_LAN_HOSTS=markervault.lan`, with the backend
Host gate returning 421 for unrecognized hosts and nginx gating on `server_name`.

**Work.** Drop the LAN entries from the environment file and from `server_name` once the
real origin is confirmed working from outside.

**Watch.** Doing this before Gate 1 is genuinely proven locks you out of your own
service. Keep console or SSH access available while making the change.

---

## Gate 6 — Backups, migrations, and retiring the disposable-state rule

The point of no return. Everything above can be undone; this one changes what the
project is allowed to do to its own data.

**Current state.** There is no backup procedure. `install.sh` deletes the database, WAL
and SHM files and the entire generated-media tree on **every** deploy, by design.
`AGENTS.md` forbids migrations and requires new columns to be baked into `CREATE TABLE`.

**Work.**

- A backup procedure covering the SQLite database (including its WAL) and the media
  tree under `/var/lib/markervault`, with a **restore actually tested** into a scratch
  instance that then boots — an untested backup is not a backup.
- A migration approach to replace the bake-into-`CREATE TABLE` rule.
- **Change `install.sh` so deploying no longer wipes state.** This is real code, not a
  policy note, and it is the concrete thing standing between the current deploy path and
  real user data.
- Amend `AGENTS.md` to retire the pre-public permission and record the date.

**Verify.** Restore a backup into a scratch instance and boot it; run a deploy and
confirm the database and media survive it.

---

## Definition of done

Public launch may be declared when all six gates are closed, the deploy path is
non-destructive, and a restore has been tested. At that point `AGENTS.md` is amended in
the same change, and from then on user data is preserved, schema changes go through
reviewed migrations, and destructive operational work requires a verified backup first.
