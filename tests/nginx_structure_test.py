#!/usr/bin/env python3
"""Stage 7 static assertions for the tracked nginx configuration: public document
root, rejecting default servers, per-endpoint body limits, deduplicated proxy
headers, rate-limit status/zones, and runtime media aliases outside the public tree."""
import re
import sys

from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
CONFIG = (PROJECT_DIR / "markervault.nginx").read_text(encoding="utf-8")

PASS = 0
FAIL = 0


def check(condition, label):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


def server_blocks(text):
    blocks = []
    for match in re.finditer(r"^server\s*\{", text, re.MULTILINE):
        depth = 0
        for position in range(match.start(), len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[match.start():position + 1])
                    break
    return blocks


app_blocks = server_blocks(CONFIG)

print("== Host handling (S-12) ==")
check(
    len(app_blocks) == 2
    and not re.search(r"^\s*listen\b.*default_server", CONFIG, re.MULTILINE),
    "the application file holds only redirect+app servers and never default_server",
)
check(
    all(
        re.search(r"server_name\s+[^_;]+;", block)
        for block in app_blocks
    ),
    "application servers declare explicit non-wildcard server names",
)
redirect_block = next(block for block in app_blocks if "return 301" in block)
check(
    "https://$host$request_uri" in redirect_block,
    "the allowlisted HTTP server redirects to HTTPS on the same recognized host",
)

app_block = next(block for block in app_blocks if "listen 443 ssl;" in block)

print("\n== Public document root (S-01) ==")
check(
    "root /var/www/markervault/public;" in app_block,
    "the document root is the dedicated public tree",
)
check(
    CONFIG.count("alias /var/lib/markervault/") == 3
    and "alias /var/www/markervault/" not in CONFIG,
    "all three internal media aliases point at runtime storage outside the web root",
)
check(
    len(re.findall(r"location\s+~\*?\s+\S+\s*\{\s*return\s+404;", CONFIG)) == 5,
    "the five defense-in-depth denial locations remain",
)
check(
    "access_log /var/log/nginx/markervault-access.log;" in app_block
    and "error_log  /var/log/nginx/markervault-error.log;" in app_block,
    "the application server logs to its own access/error files, not the shared default",
)

# F7: a location-level add_header REPLACES the inherited server-level set rather than
# adding to it, so every block declaring its own headers must restate the full set.
# Reproduced against nginx 1.26.3: photos, thumbnails and avatars were served without
# Strict-Transport-Security while every other response carried it.
required_media_headers = (
    "X-Content-Type-Options nosniff",
    "X-Frame-Options DENY",
    "Referrer-Policy strict-origin-when-cross-origin",
    'Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    "Content-Security-Policy \"default-src 'none'\"",
)
for media in ("photos", "thumbs", "avatars"):
    section = app_block[app_block.find(f"location /internal_{media}/"):]
    section = section[:section.find("}")]
    missing = [header for header in required_media_headers if header not in section]
    check(
        not missing,
        f"/internal_{media}/ restates the full security header set ({missing} missing)",
    )

print("\n== Body limits (S-02) ==")
check(
    "client_max_body_size 1m;" in app_block,
    "the server-level default body limit is small",
)
upload_limits = re.findall(r"client_max_body_size 20m;", app_block)
check(
    len(upload_limits) == 3,
    "exactly the three upload locations raise the limit to 20 MB",
)
for route in ("location ~ ^/spots/[0-9]+/photos", "location = /profile/avatar",
              "location /import_kml {"):
    section = app_block[app_block.find(route):]
    section = section[:section.find("}")]
    check("client_max_body_size 20m;" in section, f"20 MB limit is scoped to {route}")

print("\n== Proxy header dedup (D-11) ==")
check(
    len(re.findall(r"^\s*proxy_set_header\b", app_block, re.MULTILINE)) == 4,
    "the four stable proxy headers appear once at server level",
)
check(
    all(
        header in app_block
        for header in (
            "proxy_set_header Host $host;",
            "proxy_set_header X-Real-IP $remote_addr;",
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "proxy_set_header X-Forwarded-Proto $scheme;",
        )
    ),
    "all four forwarding headers are present",
)

print("\n== Notification history boundary ==")
notif_section = app_block[app_block.find("location /notif_history {"):]
notif_section = notif_section[:notif_section.find("}")]
check(
    "proxy_pass http://127.0.0.1:5000/notif_history;" in notif_section,
    "notification list, summary, and seen routes reach Flask",
)
check(
    "client_max_body_size" not in notif_section and "limit_req" not in notif_section,
    "notification history keeps the normal JSON body and private API rate boundaries",
)

print("\n== Optional account lifecycle boundary ==")
for route, upstream, label in (
    ("location = /account-capabilities", "/account-capabilities", "account capabilities"),
    ("location /email-verification/", "/email-verification/", "email verification"),
    ("location /password-recovery/", "/password-recovery/", "password recovery"),
):
    section = app_block[app_block.find(route):]
    section = section[:section.find("}")]
    check(
        route in app_block
        and f"proxy_pass http://127.0.0.1:5000{upstream};" in section
        and "client_max_body_size" not in section,
        f"{label} reaches the bounded Flask JSON endpoint",
    )

print("\n== Rate-limit boundary ==")
check(
    CONFIG.count("limit_req_status 429;") == 1
    and all("limit_req_status" not in block for block in app_blocks),
    "rate-limit rejection status is 429 once at shared http scope",
)
for zone in ("mv_login_zone", "mv_refresh_zone", "mv_link_zone", "mv_kml_zone"):
    check(
        re.search(rf"limit_req_zone \$binary_remote_addr zone={zone}:10m", CONFIG),
        f"shared zone {zone} is defined",
    )
check(
    len(re.findall(r"limit_req_dry_run on;", app_block)) == 0,
    "no zone remains in dry-run mode after Stage 10.1",
)
for route, zone in (("location /login", "mv_login_zone"),
                    ("location /import_kml {", "mv_kml_zone"),
                    ("location /parse-maps-link", "mv_link_zone")):
    section = app_block[app_block.find(route):]
    section = section[:section.find("}")]
    check(
        f"limit_req zone={zone}" in section and "limit_req_dry_run" not in section,
        f"{zone} is enforced on {route.split()[1]}",
    )
status_section = app_block[app_block.find("location /import_kml_status/"):]
status_section = status_section[:status_section.find("}")]
check(
    "limit_req" not in status_section,
    "KML progress polling is scoped outside the upload rate zone",
)
refresh_section = app_block[app_block.find("location = /auth/refresh"):]
refresh_section = refresh_section[:refresh_section.find("}")]
check(
    "limit_req zone=mv_refresh_zone burst=20 nodelay;" in refresh_section
    and "limit_req_dry_run" not in refresh_section,
    "the refresh zone is enforced at the pause-B measured burst since Stage 10.1",
)

print("\n== Accurate KML directives (R-11/C-09) ==")
kml_section = app_block[app_block.find("location /import_kml {"):]
kml_section = kml_section[:kml_section.find("}")]
check("proxy_cache_bypass" not in CONFIG, "the inert proxy_cache_bypass is gone")
check(
    "keepalive_timeout" not in CONFIG,
    "the mislabeled keepalive_timeout is gone",
)
check(
    "proxy_buffering off" not in CONFIG,
    "the response-buffering directive is no longer misdescribed as upload control",
)
check(
    "proxy_request_buffering off;" in kml_section,
    "KML uploads stream to Flask via request-buffering control",
)

print("\n== Static serving: exact files only, branded 404 ==")
check(
    "try_files $uri $uri/ =404;" in CONFIG,
    "unknown paths 404 instead of falling back to the app shell",
)
check(
    "try_files $uri /index.html" not in CONFIG,
    "the SPA-style /index.html fallback is gone (no client-side routes exist)",
)
check(
    "index index.html;" in app_block,
    "the bare / still resolves to the app shell via $uri/ + index",
)
check(
    "error_page 404 /404.html;" in CONFIG,
    "404 responses use the branded error page",
)
check(
    "error_page 403 =404 /404.html;" in CONFIG,
    "index-less directory URLs fold into the branded 404 (no plain nginx 403)",
)
error_section = CONFIG[CONFIG.find("location = /404.html"):]
error_section = error_section[:error_section.find("}")]
check(
    "internal;" in error_section,
    "the 404 body is internal-only, never a directly served 200",
)
error_page = PROJECT_DIR / "public/404.html"
error_text = error_page.read_text(encoding="utf-8") if error_page.exists() else ""
check(
    error_page.exists()
    and not re.search(r'src="(?!data:)', error_text)
    and error_text.count("href=") == 1
    and 'href="/"' in error_text,
    "404.html exists and is self-contained (no follow-up asset requests)",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
