<p align="center">
  <img src="public/logo.png" alt="MarkerVault" width="360">
</p>

MarkerVault is a self-hosted app for keeping track of places. You add a marker,
give it a name, notes, and a few photos, and it's saved to your own server. You
can sort your markers into separate maps, plan routes between them, import places
you already have, and share any map with the people you choose. Your data stays
on your server unless you decide to share it.

## What you can do

**Markers with photos and notes:** add a marker anywhere on the map and give it a
name, notes, and its own set of photos.

**Separate maps for separate things:** keep your markers in different maps, for
example, one for a road trip and another for hiking spots.

**Place search:** look up an address or a place name and add a marker where you
need it.

**Routing:** plan a route between your markers, add stops along the way, and see
the distance and travel time.

**Import:** bring markers in from a KML file, or paste a Google Maps link and
MarkerVault imports the pins for you.

**Sharing:** share a map with specific people, or with a group so a whole team
gets access at once.

**Works as an app:** install MarkerVault on your phone, tablet, or desktop as a
Progressive Web App, with its own home-screen icon and a full-screen layout
designed for phones.

**Self-hosted and private:** everything runs on your own machine or LAN, so your
places, photos, and notes never leave your server. Several people can share one
installation, each with their own account.

## Accounts and roles

MarkerVault is multi-user, with three roles:

- **Users** manage their own maps and markers, and decide who to share them with.
- **Admins** manage user accounts and the shared groups people can share into.
- **Superadmins** manage everyone, including other admins.

Accounts can be created from the web admin panel, or by users signing up on their own.
The *Sign up* form on the login page sends a join request for a superadmin to review, so
people can ask for access, but no one gets in until you approve them.

## Getting started

MarkerVault is self-hosted and one script handles the setup: the app, its dependencies,
the web server config, and the background service.

1. Clone this repo somewhere other than the install target (`/var/www/markervault`).
2. Run `sudo ./install.sh --wipe-data` for a fresh install, or `--keep-data` to
   redeploy over data you already have. On the first run it generates its own
   signing secret and config file. Run it again after you change any config so
   the service picks up the new values.
3. Optional: `sudo ./seed.sh` creates a few sample accounts and maps for local
   testing.

Then create your first operator account:

```sh
sudo -u markervault /var/www/markervault/venv/bin/python3 /var/www/markervault/create_users.py
```

Host prerequisites, configuration, verification steps, and troubleshooting are in
[`documentation/INSTALL.md`](documentation/INSTALL.md), and every setting is
documented with its default in `markervault.env.example`.

To remove it, `sudo ./uninstall.sh` unwires the service but keeps your data, and
`sudo ./uninstall.sh --purge` clears everything, including stored maps, photos,
and secrets.

## Under the hood

- Python backend with SQLite storage, so there is no separate database to run.
- Photos and avatars are served through signed URLs that expire.
- Rate limiting at both the application and the nginx layer.
- Built for private LAN use. The design specs in
  [`documentation/`](documentation/) cover the permissions model, logging, media
  serving, and what needs to be true before any public launch.

## Tests

A regression suite covers the backend, plus a Playwright browser rig that
exercises the admin panel, sharing, KML import, and notifications. See
[`tests/README.md`](tests/README.md).

## License

GPLv3. See [LICENSE](LICENSE).
