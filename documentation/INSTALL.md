# Installing and deploying MarkerVault

Everything runs through two scripts, `install.sh` and `seed.sh`. Both live in this
repository, so run them from the folder you cloned it into.

- **`sudo ./install.sh --wipe-data`** brings the app up on a clean, empty database.
  Run it for every deploy, including the first install.
- **`sudo ./install.sh --keep-data`** brings the app up with the database and uploaded
  files left untouched. Use it for a deploy where you need to keep what is already
  there.
- **`sudo ./seed.sh`** creates 8 test accounts, each with maps, spots, and 7
  notification-history entries, all using the password `Abcd1234!`. Run it only when
  you want sample data to work with.

`install.sh` has no default mode, so you must pass one of the two flags above. Run
it with no flag and it simply prints a short usage message and exits without changing
anything. That is deliberate, because a default of `--wipe-data` would destroy real
data by accident, while a default of `--keep-data` would silently leave old data
behind when you wanted a clean database. This way you choose the mode every time.

## Scope: a test environment

This guide assumes a **test or pre-production setup, where the database holds nothing
you cannot afford to lose.** Several steps in it run `sudo ./install.sh --wipe-data`:
the routine deploy, the rollback step, and the email-mode switch. Every one of them
deletes the SQLite database **and all uploaded media** (photos, thumbnails, and
avatars), then rebuilds an empty database. That is fine for a disposable test database,
and it is why the guide reaches for `--wipe-data` so freely.

A production deployment differs in two important ways:

- **You deploy with `--keep-data`.** It leaves the database and media in place, so it
  is the only mode that preserves real data. `--wipe-data` in production would destroy
  every account, map, marker, and photo.
- **A schema change needs a migration, and this project has none yet.** The installer
  only ever creates *missing* tables and never alters an existing one, so a backend
  change that adds, renames, or drops a column or table cannot be applied to a live
  database by this tooling. `--keep-data` compares the live schema against
  `markervault_schema.py`, and on any difference it **refuses to deploy** rather than
  let the app fail at runtime with a missing column. The only path this guide offers
  from there is `--wipe-data`, which adopts the new schema by throwing the data away.
  Evolving a production database instead requires a real migration written for that
  change. Writing one is a prerequisite for any schema-changing release, and it is out
  of scope here.

Runtime settings are not part of the schema and never need a wipe. Turning the email
options on or off, editing the LAN hosts, or rotating the signing secret is an
env-file change plus `sudo systemctl restart markervault`. The `--wipe-data` in the
email-mode steps below is only there to reset the sample data for a clean test. The
switch itself does not require it.

## What install.sh does

`install.sh` always brings the server to the same known state, and it is safe to run
as many times as you like. On each run it:

- Creates anything that is missing: the dedicated user account the app runs under,
  the configuration file (with a freshly generated secret key), and the Python
  virtual environment.
- Installs the exact package versions the app needs.
- Rebuilds the systemd service definition and both nginx site configs from the files
  in the repository. It checks the new nginx config with `nginx -t` and reloads only
  if that check passes, so a broken config never goes live.
- Deploys: applies the data mode you chose, copies the app's files into place (the
  repository's `public/` folder becomes the folder nginx serves to browsers), makes
  `root` the owner of all of those files, starts the app, and waits for the database
  tables to be created.

The one file it never overwrites once it exists is the configuration file,
`/etc/markervault/markervault.env`.

The Python packages are reinstalled on every deploy, so a changed version in
`requirements.txt` always reaches the server. The installer uses `pip` from inside
the virtual environment, checks every downloaded file against the checksums recorded
in the repository, and never quietly upgrades `pip` itself. If the right versions are
already installed, this step finishes in under a second and changes nothing. It also
prints the installed Python version, `pip` version, and a checksum of the locked
versions, so you can compare them against `documentation/DEPENDENCIES.md`.

## Pre-requisites

Set these up once, since the scripts do not manage them:

- A Debian-based Linux system with systemd.
- These packages installed: `nginx`, `python3`, `python3-venv`, `sqlite3`, and
  `ssl-cert` (which provides the self-signed certificate used until you have a real
  one).
- A copy of this repository on the machine.
- A way for your client machines to turn the name `markervault.lan` into the
  server's address, either through an entry in their hosts file or a record in your
  local DNS.

## First install

```sh
cd /path/to/markervault-clone
sudo ./install.sh --wipe-data
```

If your clients reach the server by its local IP address instead of the name
`markervault.lan`, do three more things:

1. Add the IP address to `MARKERVAULT_TEMPORARY_LAN_HOSTS` (comma-separated) in
   `/etc/markervault/markervault.env`.
2. Add the same IP address to both `server_name` lines in the repository's
   `markervault.nginx` file, and commit the change. Always edit the copy in the
   repository, not the deployed one, because every deploy overwrites the deployed
   copy.
3. Run `sudo ./install.sh --wipe-data` again.

The secret key is generated for you on the first run. To change it later, edit the
configuration file and run `sudo systemctl restart markervault`. Changing it logs
everyone out and breaks every existing photo link, so those all have to be reissued.

## Deploying updates

Every later deploy is the same as the first install: sync your clone, then run the
installer again. Add `seed.sh` only when you want fresh test data.

```sh
# sync the repository clone, then:
cd /path/to/markervault-clone
sudo ./install.sh --wipe-data   # → app running, EMPTY database
sudo ./seed.sh                  # only for test cycles
```

## Creating accounts

Real accounts are created with `create_users.py`. It adds a single account straight to
the live database, already approved so it can log in right away. You need it to
bootstrap the very first account on a fresh install, when no admin exists yet to create
one through the web interface. You also use it any time you want a real account rather
than the sample test data. It reads `/etc/markervault/markervault.env` on its own, so
it writes to the live
database without you loading the configuration into your shell first.

Run it as the `markervault` service user:

```sh
sudo -u markervault /var/www/markervault/venv/bin/python3 /var/www/markervault/create_users.py
```

With no arguments it prompts you for the username, role, password, and name. You can
also supply those as flags (`--username`, `--role`, `--password`, and so on) to create
an account without prompts.

MarkerVault has three roles: `user`, `admin`, and `super_admin`. Where each one can be
created depends on which tool you use:

- In the web interface, a super-admin can create `user` and `admin` accounts, while a
  regular admin can create `user` accounts only.
- With `create_users.py`, you can create any of the three, including `super_admin`.

A `super_admin` can only ever be created by this script, because the web interface
never offers that role. Changing an account's role is also a super-admin-only action,
and a super-admin's own role can never be changed through the web interface. Promoting
someone to super-admin or demoting one back down is therefore always a
`create_users.py` job.

## Email delivery modes

MarkerVault runs in one of two modes, chosen by two flags in
`/etc/markervault/markervault.env`. It ships in **admin-managed mode**, and switching
to **email-assisted mode** turns on the outbound-email features.

### Admin-managed mode (default)

MarkerVault sends no email in this mode. There is no email verification and no public
"forgot your password" recovery. Admins create ready-to-use accounts and reset passwords,
and anyone who self-registers stays pending until a super-admin approves them. This is 
the shipped default, with both flags off:

```sh
MARKERVAULT_EMAIL_DELIVERY_ENABLED=false
MARKERVAULT_REQUIRE_EMAIL_VERIFICATION=false
```

### Email-assisted mode

Here MarkerVault sends mail, so users verify their own email address at sign-up and can
recover a forgotten password without an admin. It needs a working mail server and a
public address in place before the flags go on, and the backend refuses to start if you
enable email without them. Configure it in this order:

1. Set `MARKERVAULT_PUBLIC_ORIGIN` to the HTTPS address your users open in their
   browser. The app builds every emailed link from this value, never from the incoming
   request.
2. Configure the outgoing mail server. `MARKERVAULT_SMTP_HOST` and
   `MARKERVAULT_SMTP_FROM_ADDRESS` are required. The security setting, envelope-from
   address, and login credentials are optional, though a username and password must be
   set together if you use them. The full list is in `markervault.env.example`.
3. Turn both flags on:

   ```sh
   MARKERVAULT_EMAIL_DELIVERY_ENABLED=true
   MARKERVAULT_REQUIRE_EMAIL_VERIFICATION=true
   ```

4. Apply the change by restarting the service with `sudo systemctl restart markervault`.
   On a test system you can instead run `sudo ./install.sh --wipe-data` for a clean
   database, then recreate accounts with `sudo ./seed.sh` or `create_users.py`.
5. Run the configuration, email-delivery, and account-lifecycle test suites.
6. Verify the full flow end to end: registration email, verification before approval,
   normal approval, admin bypass, resend, pending email change, password reset, and
   login with the new password. Requests for unknown, pending, or disabled accounts
   must all return the same generic message and send no mail.

To go back to admin-managed mode, set both flags to `false` and restart the service,
or rerun `sudo ./install.sh --wipe-data` on a test system.

## Checking a deploy went well

Run each command and confirm you get the result noted in the comment:

```sh
sudo systemctl status markervault                              # active (running)
sudo journalctl -u markervault -n 20                      # startup logs, no errors
sudo -u markervault find /var/www/markervault -writable   # prints NOTHING
curl -k -o /dev/null -w "%{http_code}\n" https://markervault.lan/backend.py   # 404
curl -si http://127.0.0.1:5000/maps | head -1             # 421 (direct backend, bad host)
```

Confirm the systemd security settings are applied:

```sh
sudo systemctl show markervault.service \
    -p UMask -p ReadWritePaths -p PrivateTmp -p PrivateDevices \
    -p ProtectSystem -p ProtectHome -p ProtectKernelTunables \
    -p ProtectKernelModules -p ProtectControlGroups -p RestrictSUIDSGID
```

Confirm the correct package versions are installed. A result of `ALL PINS DEPLOYED`
means they are, whereas a `DRIFT` line means a version did not install. The checksum
must match `documentation/DEPENDENCIES.md`:

```sh
sudo /var/www/markervault/venv/bin/python tools/check_deployed_pins.py requirements.txt
sha256sum requirements.txt
```

In a browser, log in, upload a photo to a marker, and open it. For a more thorough
live check:

```sh
python3 tests/nginx_stopgap_test.py --base-url https://markervault.lan \
    --signed-media-url '<current signed photo URL from browser devtools>'
```

Check that the uploaded files and the database still agree:

```sh
sudo -u markervault bash -c 'set -a; source /etc/markervault/markervault.env; set +a; \
    cd /var/www/markervault && venv/bin/python tools/check_media_orphans.py'
```

## When something goes wrong

- **`install.sh` stops at the `nginx -t` check.** The installer checks the nginx
  config before it reloads, so nothing on the server has changed and the running app
  is untouched. Fix the config and rerun.
- **"the backend did not initialize the schema"** or **"the backend never answered
  on 127.0.0.1:5000".** These are messages `install.sh` prints when the app fails to
  start. Run `sudo journalctl -u markervault -n 30`, which names the cause. The usual
  ones are an empty secret key, a package update the app can no longer load, or a
  damaged virtual environment (delete `/var/www/markervault/venv` and rerun
  `sudo ./install.sh --wipe-data`).
- **`install.sh` exits early, before it deploys anything.** At the start of every run
  it checks that everything it needs is in place and stops if something is missing,
  so nothing on the server has changed and the running app is untouched. The usual
  causes are a required package not installed, a required file missing from your copy
  of the repository, `--keep-data` when there is no existing configuration file to
  keep, or a database whose structure no longer matches `markervault_schema.py`. In
  each case the error message names what failed, so fix that and rerun.
- **`seed.sh` refuses to run.** It only adds sample data to a database that has been
  set up but has no users yet, so deploy first and seed second.
- **Rolling back.** Return your copy of the repository to the previous commit and
  rerun `sudo ./install.sh --wipe-data`. While the app is not public yet, there is no
  real data to preserve.
  
Logs go to the systemd journal (`sudo journalctl -u markervault`), including the
reference IDs that appear in the generic error messages shown to users.

## Layout reference

| Path | What it holds | Owner and permissions |
| --- | --- | --- |
| `/var/www/markervault` | App files and virtual environment (the app server, gunicorn, runs from here) | `root:root`, no group/other write |
| `/var/www/markervault/public` | The files nginx serves to browsers (static frontend only) | `root:root` |
| `/var/lib/markervault/db` | SQLite database | `markervault` 700 |
| `/var/lib/markervault/{photos,thumbs,avatars}` | Uploaded photos, thumbnails, and avatars (nginx serves these through internal-only routes) | `markervault:www-data` 2750; files 0640 |
| `/var/lib/markervault/temp` | Temporary files for KML import/export | `markervault` 700 |
| `/etc/markervault/markervault.env` | Secret key and runtime configuration | `root:markervault` 640 |

