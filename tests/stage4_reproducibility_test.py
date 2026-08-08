import ast
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
sys.path.insert(0, str(ROOT))

from markervault_schema import initialize_schema


PASS = 0
FAIL = 0


def check(condition, label):
    global PASS
    global FAIL
    if condition:
        PASS += 1
        print(f"PASS  {label}")
    else:
        FAIL += 1
        print(f"FAIL  {label}")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


inventory_path = ROOT / "vendored-assets.json"
inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
check(inventory["schema_version"] == 2, "vendored inventory schema is recognized")
check(
    inventory["advisory_review_date"] == "2026-07-25",
    "vendored inventory records the Stage 13 advisory review date",
)
check(
    bool(inventory.get("advisory_review_method")),
    "vendored inventory records how the advisory review was performed",
)
check(
    inventory.get("next_advisory_review_date", "") > inventory["advisory_review_date"],
    "vendored inventory schedules the next advisory review",
)

recorded_files = {}
recorded_entry_count = 0
complete_metadata = True
for library in inventory["libraries"]:
    complete_metadata = complete_metadata and all(
        library.get(key)
        for key in ("name", "version", "upstream", "source", "license", "advisory_status")
    )
    for relative_path, expected_hash in library["files"].items():
        recorded_entry_count += 1
        recorded_files[relative_path] = expected_hash

check(complete_metadata, "every vendored library has version/source/license/advisory metadata")
check(
    recorded_entry_count == len(recorded_files),
    "vendored inventory contains no duplicate file entries",
)

# CVE-2025-69993 has no fixed release in Leaflet's 1.x line; the owner reserved the
# version target, so a bump may only arrive with its own planned migration stage.
leaflet = next(library for library in inventory["libraries"] if library["name"] == "Leaflet")
check(
    leaflet["version"] == "1.9.4" and "CVE-2025-69993" in leaflet["advisory_status"],
    "Leaflet stays on the owner-decided 1.9.4 pin with its advisory recorded",
)

for relative_path, expected_hash in sorted(recorded_files.items()):
    path = PUBLIC / relative_path
    check(path.is_file(), f"inventory file exists: {relative_path}")
    if path.is_file():
        check(sha256(path) == expected_hash, f"inventory hash matches: {relative_path}")

top_level_bundles = {
    str(path.relative_to(PUBLIC))
    for path in (PUBLIC / "assets").iterdir()
    if path.is_file() and path.suffix in (".js", ".css")
}
recorded_bundles = {
    path
    for path in recorded_files
    if Path(path).parent == Path("assets") and Path(path).suffix in (".js", ".css")
}
check(
    top_level_bundles == recorded_bundles,
    "every top-level vendored JavaScript/CSS bundle is inventoried",
)

index_text = (PUBLIC / "index.html").read_text(encoding="utf-8")
asset_references = set(re.findall(r'(?:src|href)="(assets/[^"]+)"', index_text))
check(
    all((PUBLIC / reference).is_file() for reference in asset_references),
    "every HTML asset reference resolves to a tracked file",
)
check(
    top_level_bundles <= asset_references,
    "every top-level JavaScript/CSS bundle is referenced by the application",
)
check(
    "assets/swiper-bundle.min.js" in asset_references
    and "assets/swiper-bundle.min.css" in asset_references,
    "application uses the single minified Swiper bundle pair",
)
check(
    not (PUBLIC / "assets/swiper-bundle.js").exists()
    and not (PUBLIC / "assets/swiper-bundle.css").exists(),
    "duplicate non-minified Swiper bundles are absent",
)

package_path = ROOT / "tests/pw-test/package.json"
lock_path = ROOT / "tests/pw-test/package-lock.json"
package = json.loads(package_path.read_text(encoding="utf-8"))
lock = json.loads(lock_path.read_text(encoding="utf-8"))
playwright_version = package["dependencies"]["playwright"]
check(
    re.fullmatch(r"\d+\.\d+\.\d+", playwright_version) is not None,
    "Playwright dependency is an exact version",
)
check(
    lock["packages"][""]["dependencies"]["playwright"] == playwright_version,
    "project lock root matches package.json",
)
check(
    lock["packages"]["node_modules/playwright"]["version"] == playwright_version,
    "project lock resolves the pinned Playwright version",
)
check(
    all(
        lock["packages"][name].get("integrity")
        for name in (
            "node_modules/fsevents",
            "node_modules/playwright",
            "node_modules/playwright-core",
        )
    ),
    "project lock records package integrity",
)
check(
    lock["packages"]["node_modules/fsevents"].get("optional") is True
    and lock["packages"]["node_modules/fsevents"].get("os") == ["darwin"],
    "project lock includes Playwright's platform-specific optional dependency",
)

requirements_text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
requirement_pins = []
requirement_hashes = {}
current_requirement = None
requirements_format_valid = True
for requirement_line in requirements_text.splitlines():
    stripped = requirement_line.strip()
    if not stripped or stripped.startswith("#"):
        continue
    logical_line = stripped.removesuffix("\\").rstrip()
    pin_match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^=\s]+)", logical_line)
    hash_match = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})", logical_line)
    if pin_match and stripped.endswith("\\"):
        if current_requirement is not None:
            requirements_format_valid = False
        current_requirement = re.sub(r"[-_.]+", "-", pin_match.group(1)).lower()
        requirement_pins.append((current_requirement, pin_match.group(2)))
        requirement_hashes.setdefault(current_requirement, [])
    elif hash_match and current_requirement is not None:
        requirement_hashes[current_requirement].append(hash_match.group(1))
        if not stripped.endswith("\\"):
            current_requirement = None
    else:
        requirements_format_valid = False
check(
    requirements_format_valid and current_requirement is None and bool(requirement_pins),
    "production Python requirements use valid pinned hash blocks",
)
check(
    all(requirement_hashes.get(name) for name, _ in requirement_pins),
    "every production Python pin has at least one SHA-256 artifact hash",
)
check(
    len(requirement_pins) == len({name for name, _ in requirement_pins}),
    "production requirements contain no duplicate packages",
)
check(
    any(name == "gunicorn" for name, _ in requirement_pins),
    "production manifest includes gunicorn",
)
requirements_in = [
    line.strip()
    for line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
runtime_import_roots = set()
for runtime_path in (
    "backend.py",
    "email_delivery.py",
    "create_users.py",
    "markervault_schema.py",
    "request_validation.py",
    "markervault_config.py",
    "username_validation.py",
):
    runtime_tree = ast.parse((ROOT / runtime_path).read_text(encoding="utf-8"))
    for node in ast.walk(runtime_tree):
        if isinstance(node, ast.Import):
            runtime_import_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            runtime_import_roots.add(node.module.split(".")[0])
import_distribution_map = {
    "bcrypt": "bcrypt",
    "defusedxml": "defusedxml",
    "flask": "flask",
    "jwt": "pyjwt",
    "PIL": "pillow",
    "requests": "requests",
}
check(
    set(import_distribution_map).issubset(runtime_import_roots),
    "every direct imported distribution is observed in the runtime entry points",
)
check(
    {re.sub(r"[-_.]+", "-", name).lower() for name in requirements_in}
    == set(import_distribution_map.values()) | {"gunicorn"}
    and len(requirements_in) == len(set(requirements_in)),
    "direct requirements contain imported distributions plus the gunicorn launcher",
)
dependencies_text = (ROOT / "documentation/DEPENDENCIES.md").read_text(encoding="utf-8")
recorded_lock_digest = re.search(
    r"`requirements\.txt` SHA-256: `([0-9a-f]{64})`",
    dependencies_text,
)
check(
    bool(recorded_lock_digest)
    and recorded_lock_digest.group(1) == sha256(ROOT / "requirements.txt"),
    "the documented production lock digest matches requirements.txt",
)
test_requirements = [
    line.strip()
    for line in (ROOT / "tests/requirements-test.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]
check(
    test_requirements == ["--require-hashes", "-r ../requirements.txt"],
    "test manifest enforces hash mode while extending the production manifest",
)

backend_text = (ROOT / "backend.py").read_text(encoding="utf-8")
backend_tree = ast.parse(backend_text)
imported_names = set()
for node in ast.walk(backend_tree):
    if isinstance(node, ast.Import):
        imported_names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        imported_names.update(alias.asname or alias.name for alias in node.names)
check(
    imported_names.isdisjoint(
        {"traceback", "queue", "send_from_directory", "Response", "stream_with_context"}
    ),
    "confirmed unused backend imports stay removed",
)
replace_photo_source = backend_text.split("def replace_photo", 1)[1].split(
    "\n@app.route",
    1,
)[0]
check(
    "Cannot replace with the same filename" not in replace_photo_source,
    "photo replacement has no ineffective filename-equality guard",
)
check(
    replace_photo_source.count("sanitize_filename(file.filename)") == 1,
    "photo replacement sanitizes the uploaded name exactly once",
)

frontend_text = (PUBLIC / "frontend.js").read_text(encoding="utf-8")
index_html_text = (PUBLIC / "index.html").read_text(encoding="utf-8")
# Control.Geocoder was retired: Routing Machine's callback API could never consume its
# promises, and the app reverse-geocodes through its own centralized fetch.
check(
    "Control.Geocoder" not in frontend_text
    and "Control.Geocoder" not in index_html_text
    and not (PUBLIC / "assets/Control.Geocoder.js").exists()
    and not (PUBLIC / "assets/Control.Geocoder.css").exists(),
    "retired Control.Geocoder dependency leaves no reference or asset behind",
)
check(
    "collapse-route-btn" not in frontend_text
    and "_collapseObserver" not in frontend_text,
    "unreachable routing-collapse implementation stays removed",
)
check(
    "//serviceUrl: 'http://192.168.193.50:5001/route/v1'" in frontend_text,
    "intentional local-routing fallback remains available",
)
check(
    frontend_text.count("nominatim.openstreetmap.org/reverse?") == 1,
    "reverse-geocoding request construction is centralized",
)
check(
    frontend_text.count("nominatimPlaceLabel(") == 3,
    "Nominatim label helper has all three intended consumers",
)

style_text = (PUBLIC / "style.css").read_text(encoding="utf-8")
stale_selectors = (
    ".clear-maps-name-text-btn",
    "#mapsNameInputWrapper",
    "#mapsNameInput",
    ".map-details-notes-text",
    "#profileCloseBtn",
    "#changePwdCloseBtn",
    "#collabCloseBtn",
    ".collapse-route-btn",
    ".leaflet-routing-alt-minimized",
    # Routing Machine builds no geocoder container without a geocoder option, so the
    # rule that used to hide it would style nothing.
    ".leaflet-routing-geocoders",
)
check(
    all(selector not in style_text for selector in stale_selectors),
    "confirmed stale/collapse CSS selectors stay removed",
)
check(
    not (ROOT / "tests/reconstruct_unscoped.py").exists(),
    "obsolete reconstruction scratch script is absent",
)
update_text = (ROOT / "install.sh").read_text(encoding="utf-8")
seed_text = (ROOT / "seed.sh").read_text(encoding="utf-8")
service_text = (ROOT / "markervault.service").read_text(encoding="utf-8")
service_directive_lines = [
    line.strip()
    for line in service_text.splitlines()
    if line.strip() and not line.lstrip().startswith(("#", "["))
]

b1a_directives = {
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectControlGroups": "true",
    "RestrictSUIDSGID": "true",
}
check(
    all(
        service_directive_lines.count(f"{name}={value}") == 1
        for name, value in b1a_directives.items()
    ),
    "the service enables the complete B1a non-storage sandbox",
)
check(
    all(
        service_directive_lines.count(f"{name}={value}") == 1
        for name, value in {
            "UMask": "0027",
            "PrivateTmp": "true",
            "ProtectSystem": "strict",
            "ProtectHome": "true",
            "ReadWritePaths": "/var/lib/markervault",
        }.items()
    ),
    "the service enables the complete B1b runtime-filesystem sandbox",
)
gunicorn_process_flags = "--workers 1 --worker-class sync --timeout 30"
service_exec_start = next(
    line for line in service_directive_lines if line.startswith("ExecStart=")
)
live_rig_process_flags = (
    "'--workers', '1', '--worker-class', 'sync', '--timeout', '30'"
)
live_rig_texts = [
    (ROOT / path).read_text(encoding="utf-8")
    for path in (
        "tests/pw-test/refresh_live_check.mjs",
        "tests/pw-test/kml_live_check.mjs",
    )
]
check(
    service_exec_start.count(gunicorn_process_flags) == 1
    and all(text.count(live_rig_process_flags) == 1 for text in live_rig_texts),
    "the unit and both real-backend rigs pin one sync worker with timeout 30",
)
root_markdown = {path.name for path in ROOT.glob("*.md")}
check(
    root_markdown == {"AGENTS.md", "README.md"}
    and (ROOT / "AGENTS.md").is_file()
    and not (ROOT / "AGENTS.md").is_symlink()
    and not (ROOT / "documentation/AGENTS.md").exists(),
    "project documentation is centralized while AGENTS (control) and README "
    "(portfolio) are the only root-level Markdown files",
)
check(
    'sudo find "$APP" -mindepth 1 -maxdepth 1 ! -name venv -exec rm -rf {} +' in update_text,
    "deployment wipes the app tree except venv before overlaying, so nothing "
    "retired from deployment can linger from an earlier deploy",
)
check(
    all(path.parent == ROOT / "tests" for path in ROOT.glob("**/ui_*.png")),
    "generated browser screenshots stay under tests/ (untracked, gitignored)",
)

# F1: the dependency install must not sit inside any conditional. Guarded, it is
# skipped on every host that already has a venv, so changed pins never deploy.
conditional_depth = 0
dependency_install_depths = []
for install_line in update_text.splitlines():
    stripped = install_line.strip()
    if stripped.startswith("if "):
        conditional_depth += 1
    elif stripped == "fi":
        conditional_depth -= 1
    elif " -m pip install --require-hashes -r " in stripped and "requirements.txt" in stripped:
        dependency_install_depths.append(conditional_depth)
check(
    dependency_install_depths == [0],
    "deployment installs hash-locked dependencies unconditionally, not behind the venv guard",
)
check(
    "install --upgrade pip" not in update_text,
    "deployment does not download a mutable latest pip bootstrap",
)
check(
    '"$APP/venv/bin/python" --version' in update_text
    and '"$APP/venv/bin/python" -m pip --version' in update_text
    and 'sha256sum "$SOURCE/requirements.txt"' in update_text,
    "deployment reports the interpreter, bundled pip, and production lock digest",
)

# F1 Phase 2: destructive vs. non-destructive is always explicit. Both refusals are
# executed rather than pattern-matched; each exits at the usage gate, which sits ahead
# of every sudo in the script, so nothing is touched on the way out.
for arguments, label in (
    ([], "no mode flag"),
    (["--nuke"], "an unrecognized flag"),
    (["--wipe-data", "--keep-data"], "both mode flags at once"),
):
    refused = subprocess.run(
        ["bash", str(ROOT / "install.sh"), *arguments],
        capture_output=True, text=True,
    )
    check(
        refused.returncode == 2 and "Usage:" in refused.stderr and not refused.stdout,
        f"install.sh refuses to deploy with {label} (exit {refused.returncode})",
    )

install_lines = update_text.splitlines()
usage_line = next(i for i, line in enumerate(install_lines) if "Usage:" in line)
first_sudo = next(i for i, line in enumerate(install_lines) if line.strip().startswith("sudo "))
check(
    usage_line < first_sudo,
    "the mode gate precedes every privileged action in the script",
)
media_provision_line = next(
    i for i, line in enumerate(install_lines)
    if '-g www-data -m 2750 "$PHOTOS" "$THUMBS" "$AVATARS"' in line
)
media_group_line = next(
    i for i, line in enumerate(install_lines)
    if "! -group www-data -exec chgrp www-data {} +" in line
)
media_directory_mode_line = next(
    i for i, line in enumerate(install_lines)
    if "-type d ! -perm 2750 -exec chmod 2750 {} +" in line
)
media_file_mode_line = next(
    i for i, line in enumerate(install_lines)
    if "-type f ! -perm 0640 -exec chmod 0640 {} +" in line
)
application_overlay_line = next(
    i for i, line in enumerate(install_lines)
    if line.strip().startswith("sudo cp -r")
)
check(
    media_provision_line
    < media_group_line
    < media_directory_mode_line
    < media_file_mode_line
    < application_overlay_line,
    "setgid provisioning and idempotent media migration precede the application start",
)
check(
    all(
        update_text.count(fragment) == 1
        for fragment in (
            '! -group www-data -exec chgrp www-data {} +',
            '-type d ! -perm 2750 -exec chmod 2750 {} +',
            '-type f ! -perm 0640 -exec chmod 0640 {} +',
        )
    ),
    "the media migration converges group, directory mode, and file mode once",
)

conditional_depth = 0
wipe_depths = []
wipe_line_numbers = []
for line_number, install_line in enumerate(install_lines):
    stripped = install_line.strip()
    if stripped.startswith("if "):
        conditional_depth += 1
    elif stripped == "fi":
        conditional_depth -= 1
    elif '"$DB-wal"' in stripped or '"$PHOTOS" "$THUMBS"' in stripped:
        if stripped.startswith("sudo rm"):
            wipe_depths.append(conditional_depth)
            wipe_line_numbers.append(line_number)
check(
    len(wipe_depths) == 2 and all(depth > 0 for depth in wipe_depths),
    f"the database and media wipe is guarded by the chosen mode ({wipe_depths})",
)

# The --keep-data schema-drift guard. It is the load-bearing safety property of that
# mode, so every branch is executed against real SQLite files.
# Deliberately the system python3, exactly as install.sh invokes it — the guard must
# not need the venv, since a broken venv is one of the states it exists to catch.
drift_checker = ["python3", str(ROOT / "tools/check_schema_drift.py")]
drift_dir = tempfile.mkdtemp(prefix="mv_drift_")


def drift_run(db_path):
    return subprocess.run(drift_checker + [db_path], capture_output=True, text=True)


def build_db(name, mutate=None):
    # Foreign keys stay off: these probes only need the stored DDL plus, for the
    # internal-objects case, a row that makes SQLite materialize sqlite_sequence.
    path = os.path.join(drift_dir, name)
    conn = sqlite3.connect(path)
    initialize_schema(conn)
    if mutate is not None:
        mutate(conn)
    conn.commit()
    conn.close()
    return path


matching = build_db("matching.db")
check(drift_run(matching).returncode == 0, "a matching schema reports no drift")
check(
    drift_run(os.path.join(drift_dir, "absent.db")).returncode == 0,
    "an absent database is not drift — the backend creates it on boot",
)

# sqlite_sequence exists the moment an AUTOINCREMENT table is written to, and
# sqlite_stat1 appears the first time ANALYZE is ever run. Both would read as drift
# without the sqlite_% filter, which is why the filter is not cosmetic.
def exercise(conn):
    conn.execute(
        "INSERT INTO maps (owner_id, name, is_base, created) "
        "VALUES ('someone', 'Base', 1, '2026-07-25T00:00:00')"
    )
    conn.execute("ANALYZE")


exercised = build_db("exercised.db", exercise)
internal = sqlite3.connect(exercised)
internal_names = {
    row[0] for row in internal.execute("SELECT name FROM sqlite_master")
    if row[0].startswith("sqlite_")
}
internal.close()
check(
    {"sqlite_sequence", "sqlite_stat1"} <= internal_names,
    f"the probe database really does carry SQLite's internal objects ({sorted(internal_names)})",
)
check(
    drift_run(exercised).returncode == 0,
    "SQLite's own internal objects are filtered out, not reported as drift",
)

renamed = build_db("renamed.db", lambda conn: conn.execute("ALTER TABLE maps RENAME TO maps_old"))
renamed_result = drift_run(renamed)
check(
    renamed_result.returncode == 1
    and "MISSING from the live database: table maps" in renamed_result.stdout,
    "a table missing from the live database is reported as drift",
)

dropped = build_db(
    "dropped.db",
    lambda conn: conn.execute("ALTER TABLE maps DROP COLUMN notes"),
)
dropped_result = drift_run(dropped)
check(
    dropped_result.returncode == 1
    and "DIFFERS: table maps" in dropped_result.stdout
    and "notes" in dropped_result.stdout,
    "a dropped column is reported as drift with the differing definition shown",
)

extra = build_db("extra.db", lambda conn: conn.execute("CREATE TABLE leftover (id INTEGER)"))
extra_result = drift_run(extra)
check(
    extra_result.returncode == 1
    and "ONLY in the live database:      table leftover" in extra_result.stdout,
    "a table the schema no longer defines is reported as drift",
)

shutil.rmtree(drift_dir, ignore_errors=True)

# Placement is the guarantee: every deterministic refusal must precede the FIRST host
# mutation, not merely the stop and the wipe. The earliest mutator is the service
# account creation — checking only against `systemctl stop` would let pip, the unit
# replacement and the nginx reload run before an abort that claims nothing changed.
#
# This is deliberately not a claim that all aborts are atomic: past preflight, pip can
# fail with the venv modified and the overlay copy can fail partway. What is asserted
# is that the predictable refusals happen first.
drift_call = next(i for i, line in enumerate(install_lines) if "check_schema_drift.py" in line)
path_validation = next(
    i for i, line in enumerate(install_lines)
    if "is listed for deployment but missing" in line
)
first_mutation = next(
    i for i, line in enumerate(install_lines)
    if line.strip().startswith("sudo adduser") or line.strip().startswith("sudo install -d")
)
pip_line = next(
    i for i, line in enumerate(install_lines)
    if " -m pip install --require-hashes -r " in line
)
unit_line = next(
    i for i, line in enumerate(install_lines)
    if "/etc/systemd/system/markervault.service" in line
)
nginx_line = next(i for i, line in enumerate(install_lines) if line.strip() == "sudo systemctl reload-or-restart nginx")
stop_line = next(i for i, line in enumerate(install_lines) if "systemctl stop" in line)
overlay_line = next(i for i, line in enumerate(install_lines) if line.strip().startswith("sudo cp -r"))

for label, mutator in (
    ("the first host mutation", first_mutation),
    ("the dependency install", pip_line),
    ("the unit replacement", unit_line),
    ("the nginx reload", nginx_line),
    ("the service stop", stop_line),
    ("the overlay copy", overlay_line),
):
    check(
        drift_call < mutator and path_validation < mutator,
        f"the drift check and deploy-path validation both precede {label}",
    )
check(
    all(path_validation < wipe_line for wipe_line in wipe_line_numbers)
    and all(drift_call < wipe_line for wipe_line in wipe_line_numbers),
    "both preflight refusals precede the data wipe",
)
check(
    "--keep-data was requested but" in update_text,
    "a missing environment file refuses --keep-data instead of assuming there is no data",
)
check(
    "restored the previous vhost" in update_text,
    "a failing nginx validation restores the outgoing vhost rather than leaving a bad one",
)
check(
    install_lines[drift_call].strip().startswith("if ! python3 "),
    f"the drift check runs under the system python3, not the venv "
    f"({install_lines[drift_call].strip()})",
)

# The liveness poll. markervault.service has no Type= line, so systemctl start
# succeeds the moment the process forks; without this the script reports a quiet
# crash-loop as a successful deploy. The snippet is lifted out of install.sh itself so
# the real logic is exercised — only the port and the deadline are substituted.
liveness_source = update_text.split("<<'LIVENESS'\n", 1)[1].split("\nLIVENESS\n", 1)[0]


def liveness_verdict(port, deadline_seconds=3):
    snippet = liveness_source.replace("5000", str(port)).replace("+ 15", f"+ {deadline_seconds}")
    return subprocess.run(
        ["python3", "-c", snippet], capture_output=True, text=True
    ).returncode


def serve_once(reply):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)

    def run():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            if reply is not None:
                try:
                    connection.sendall(reply)
                except OSError:
                    pass
                connection.close()
            # reply None: hold the connection open without answering.

    threading.Thread(target=run, daemon=True).start()
    return listener, listener.getsockname()[1]


# A non-200 must count as alive: the poll hits the same address the unit binds, so the
# backend's Host gate answers 421. Requiring a 200 would fail every healthy deploy.
answering, answering_port = serve_once(b"HTTP/1.1 421 Misdirected Request\r\n\r\n")
check(
    liveness_verdict(answering_port) == 0,
    "a 421 from the Host gate counts as alive, not a failure",
)
answering.close()

# A bare TCP accept must NOT count: gunicorn's master binds the listening socket
# before its workers import the application, so an import-breaking dependency upgrade
# would otherwise pass this check.
silent, silent_port = serve_once(None)
check(
    liveness_verdict(silent_port) == 1,
    "a socket that accepts but never answers is not treated as alive",
)
silent.close()

closed = socket.socket()
closed.bind(("127.0.0.1", 0))
closed_port = closed.getsockname()[1]
closed.close()
check(
    liveness_verdict(closed_port) == 1,
    "a refused connection times out and fails the deploy",
)

liveness_call = next(i for i, line in enumerate(install_lines) if "LIVENESS" in line)
start_line = next(i for i, line in enumerate(install_lines) if "systemctl start" in line)
check(
    start_line < liveness_call,
    "the liveness poll runs after the service is started",
)
check(
    "$MODE" not in install_lines[liveness_call - 1],
    "the liveness poll runs in both deploy modes, not only one",
)

# F9: the deploy copies a named list rather than a glob, so a stray file in the
# checkout is no longer swept into the app tree. The owner accepted the omit-a-file
# risk in exchange for keeping install.sh free of a git dependency; install.sh does
# not consult git, but this check does, which is where that risk gets caught.
deploy_block = update_text.split("DEPLOY_PATHS=(", 1)[1].split("\n)", 1)[0]
deploy_paths = {
    line.strip() for line in deploy_block.splitlines()
    if line.strip() and not line.strip().startswith("#")
}
tracked_top_level = {
    entry.split("/", 1)[0]
    for entry in subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
    ).stdout.split()
}
# .gitignore is repository metadata, not part of the deployed application.
tracked_top_level.discard(".gitignore")
# logo/ holds source art (GIMP .xcf, master PNGs, the Poppins archive) that the
# deployed icons in public/ are generated from; it is intentionally not deployed.
tracked_top_level.discard("logo")
# AGENTS.md is a repo-only agent control file; nothing at runtime reads it, so it
# is intentionally not deployed.
tracked_top_level.discard("AGENTS.md")
# tests/, tools/, and documentation/ are dev/ops-only — the test rig, deploy-time
# helpers (e.g. check_schema_drift.py, run from $SOURCE, never $APP), and project
# docs. Nothing at runtime reads them, so they stay tracked but are intentionally
# not deployed; install.sh also sweeps any copy an earlier deploy left behind.
tracked_top_level.discard("tests")
tracked_top_level.discard("tools")
tracked_top_level.discard("documentation")
check(
    'sudo cp -r "$SOURCE"/*' not in update_text,
    "the deploy no longer overlays the checkout with a glob",
)
check(
    deploy_paths == tracked_top_level,
    f"the deploy list matches the repository exactly "
    f"(missing {sorted(tracked_top_level - deploy_paths)}, "
    f"extra {sorted(deploy_paths - tracked_top_level)})",
)
check(
    all((ROOT / path).exists() for path in deploy_paths),
    "every listed deploy path exists in the working tree",
)

seed_match = re.search(r"<<'SQL'\n(.*?)\nSQL\n", seed_text, re.DOTALL)
seed_sql = "\n".join(
    line
    for line in seed_match.group(1).splitlines()
    if not line.startswith(".")
)
seed_db = sqlite3.connect(":memory:")
seed_db.execute("PRAGMA foreign_keys=ON")
initialize_schema(seed_db)
seed_db.executescript(seed_sql)
seed_counts = seed_db.execute(
    "SELECT user_id, SUM(seen=0), SUM(seen=1), COUNT(*) "
    "FROM notif_history GROUP BY user_id"
).fetchall()
seed_events = {
    row[0]
    for row in seed_db.execute("SELECT DISTINCT event FROM notif_history")
}
seed_details = [
    row[0]
    for row in seed_db.execute(
        "SELECT detail FROM notif_history WHERE detail IS NOT NULL"
    )
]
seed_user_state = seed_db.execute(
    "SELECT COUNT(*), SUM(email_verified_at IS NOT NULL) FROM users"
).fetchone()
account_token_count = seed_db.execute(
    "SELECT COUNT(*) FROM account_tokens"
).fetchone()[0]
seed_db.close()
check(
    len(seed_counts) == 8
    and all(row[3] == 7 for row in seed_counts)
    and sum(row[3] for row in seed_counts) == 56,
    "seed SQL gives all eight fixture accounts notification history",
)
check(
    all(row[1] > 0 and row[2] > 0 for row in seed_counts),
    "every seeded account has both seen and unseen notification examples",
)
check(
    seed_events == {
        "map.deleted",
        "marker.deleted",
        "photo.deleted",
        "kml.import_done",
        "kml.import_degraded",
        "kml.import_error",
        "server.error",
    },
    "seed history covers the complete closed notification event taxonomy",
)
check(
    all(isinstance(json.loads(detail), dict) for detail in seed_details),
    "every seeded notification detail value is valid JSON object text",
)
check(
    seed_user_state == (8, 8) and account_token_count == 0,
    "disposable fixtures recreate eight verified accounts with no stale lifecycle tokens",
)

print(f"\n==== {PASS} passed, {FAIL} failed ====")
sys.exit(1 if FAIL else 0)
