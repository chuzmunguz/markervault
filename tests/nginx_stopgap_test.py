#!/usr/bin/env python3
import argparse
import re
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


PROJECT_DIR = Path(__file__).resolve().parents[1]
NGINX_CONFIG = PROJECT_DIR / "markervault.nginx"

DENIED_PATHS = (
    "/spots.db",
    "/spots.db-wal",
    "/spots.db-shm",
    "/cache.sqlite3-journal",
    "/backend.py",
    "/email_delivery.py",
    "/create_users.pyc",
    "/install.sh",
    "/seed.sh",
    "/markervault.nginx",
    "/AGENTS.md",
    "/requirements-test.txt",
    "/config.json",
    "/secret.pem",
    "/.git/config",
    "/nested/.env",
    "/temp/",
    "/temp/import.kml",
    "/tests/",
    "/tools/check_repository_artifacts.py",
    "/venv/bin/python",
    "/__pycache__/backend.cpython-313.pyc",
    "/node_modules/module/index.js",
    "/backend.py~",
    "/settings.bak",
)

ALLOWED_PATHS = (
    "/",
    "/index.html",
    "/frontend.js",
    "/style.css",
    "/assets/leaflet.js",
    "/maps",
    "/auth/refresh",
    "/photos/example.jpg",
    "/thumbs/example.jpg",
    "/avatars/example.jpg",
    "/internal_photos/example.jpg",
    "/internal_thumbs/example.jpg",
    "/internal_avatars/example.jpg",
)

LIVE_STATIC_PATHS = (
    "/",
    "/index.html",
    "/frontend.js",
    "/style.css",
    "/assets/leaflet.js",
)

# Nonexistent paths must be plain 404s: no SPA fallback serving the app shell at
# arbitrary depths, and the branded 404 body itself is internal-only. /assets/
# exists but has no index file — the 403=404 fold must make it indistinguishable.
LIVE_MISSING_PATHS = (
    "/sdsdfsdf",
    "/sdkljfslkjfsd/stuff/djsfhskdf",
    "/sdkljfslkjfsd/stuff/djsfhskdf/index.html",
    "/sdkljfslkjfsd/stuff/assets/leaflet.css",
    "/404.html",
    "/assets/",
)


def check(condition, label, failures):
    if condition:
        print(f"PASS  {label}")
        return

    print(f"FAIL  {label}")
    failures.append(label)


def denial_patterns(config):
    locations = re.findall(
        r"location\s+(~\*?)\s+(\S+)\s*\{\s*return\s+404;\s*\}",
        config,
        re.MULTILINE,
    )
    patterns = []

    for modifier, pattern in locations:
        flags = re.IGNORECASE if modifier == "~*" else 0
        patterns.append(re.compile(pattern, flags))

    return patterns


def path_is_denied(path, patterns):
    return any(pattern.search(path) for pattern in patterns)


def run_static_checks():
    failures = []
    config = NGINX_CONFIG.read_text(encoding="utf-8")
    patterns = denial_patterns(config)

    check(len(patterns) == 5, "five explicit 404 denial locations are present", failures)

    for path in DENIED_PATHS:
        check(path_is_denied(path, patterns), f"denial rules cover {path}", failures)

    for path in ALLOWED_PATHS:
        check(not path_is_denied(path, patterns), f"denial rules preserve {path}", failures)

    return failures


def request(url, method="GET"):
    context = ssl._create_unverified_context()
    data = b"" if method == "POST" else None
    req = Request(url, data=data, method=method)

    try:
        with urlopen(req, context=context, timeout=10) as response:
            return response.status, response.headers, response.read()
    except HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def run_live_checks(base_url, signed_media_url):
    failures = []
    base_url = base_url.rstrip("/") + "/"

    for path in DENIED_PATHS:
        try:
            status, _, _ = request(urljoin(base_url, path.lstrip("/")))
            check(status in (403, 404), f"live {path} returns 403/404, got {status}", failures)
        except URLError as exc:
            check(False, f"live {path} is reachable: {exc}", failures)

    for path in LIVE_STATIC_PATHS:
        try:
            status, _, _ = request(urljoin(base_url, path.lstrip("/")))
            check(status == 200, f"live {path} returns 200, got {status}", failures)
        except URLError as exc:
            check(False, f"live {path} is reachable: {exc}", failures)

    for path in LIVE_MISSING_PATHS:
        try:
            status, _, body = request(urljoin(base_url, path.lstrip("/")))
            check(status == 404, f"live {path} returns 404, got {status}", failures)
            check(
                b"There's nothing here" in body,
                f"live {path} serves the branded 404 body",
                failures,
            )
        except URLError as exc:
            check(False, f"live {path} is reachable: {exc}", failures)

    try:
        status, headers, _ = request(urljoin(base_url, "auth/refresh"), method="POST")
        content_type = headers.get_content_type()
        check(status == 401, f"live /auth/refresh reaches Flask and returns 401, got {status}", failures)
        check(content_type == "application/json", f"live /auth/refresh returns JSON, got {content_type}", failures)
    except URLError as exc:
        check(False, f"live /auth/refresh is reachable: {exc}", failures)

    try:
        status, headers, _ = request(urljoin(base_url, signed_media_url))
        content_type = headers.get_content_type()
        check(status == 200, f"live signed media returns 200, got {status}", failures)
        check(content_type.startswith("image/"), f"live signed media returns an image, got {content_type}", failures)
    except URLError as exc:
        check(False, f"live signed media is reachable: {exc}", failures)

    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument("--signed-media-url")
    args = parser.parse_args()

    if bool(args.base_url) != bool(args.signed_media_url):
        parser.error("--base-url and --signed-media-url must be supplied together")

    failures = run_static_checks()

    if args.base_url:
        failures.extend(run_live_checks(args.base_url, args.signed_media_url))

    if failures:
        print(f"\n==== {len(failures)} failed ====")
        return 1

    print("\n==== all nginx stopgap checks passed ====")
    return 0


if __name__ == "__main__":
    sys.exit(main())
