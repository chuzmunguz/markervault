#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys

from pathlib import Path, PurePosixPath


FORBIDDEN_DIRECTORIES = {
    "__pycache__",
    "avatars",
    "logs",
    "photos",
    "temp",
    "thumbs",
    "venv",
}
FORBIDDEN_SUFFIXES = (
    ".key",
    ".log",
    ".pem",
    ".pyc",
    ".sqlite",
    ".sqlite3",
)
SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "literal credential assignment",
        re.compile(
            r"""(?ix)
            \b(?:password|passwd|secret|api[_-]?key|token)\b
            \s*[:=]\s*
            ["'][^"'$\s][^"'\r\n]{14,}["']
            """
        ),
    ),
)
SECRET_SCAN_EXCLUSIONS = (
    "tests/",
    "tools/check_repository_artifacts.py",
)
SECRET_SCAN_SUFFIX_EXCLUSIONS = (
    ".png",
)
REQUIRED_IGNORES = (
    ".env",
    "avatars/example.jpg",
    "cache.sqlite3-journal",
    "logs/markervault.log",
    "photos/example.jpg",
    "secret.pem",
    "spots.db",
    "spots.db-shm",
    "spots.db-wal",
    "temp/import.kml",
    "tests/ui_audit.png",
    "tests/pw-test/audit.png",
    "tests/venv/bin/python",
    "thumbs/example.jpg",
)
REQUIRED_VISIBLE_FIXTURES = (
    "public/assets/images/default-user-thumb.png",
)


def forbidden_artifact(path):
    pure = PurePosixPath(path)
    parts = pure.parts
    name = pure.name.lower()
    if any(part.lower() in FORBIDDEN_DIRECTORIES for part in parts):
        return True
    # Browser-rig screenshots are regenerated on every run; they live locally for
    # owner inspection and are never committed.
    if parts[:1] == ("tests",) and name.startswith("ui_") and name.endswith(".png"):
        return True
    if parts[:2] == ("tests", "pw-test") and name.endswith(".png"):
        return True
    if name == ".env" or name.startswith(".env."):
        return name not in (".env.example", ".env.template")
    if name == "spots.db" or name.startswith("spots.db-"):
        return True
    if any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        return True
    if ".sqlite-" in name or ".sqlite3-" in name:
        return True
    return False


def secret_matches(text):
    return tuple(label for label, pattern in SECRET_PATTERNS if pattern.search(text))


def _git(root, *args):
    result = subprocess.run(
        ("git", *args),
        cwd=root,
        check=False,
        capture_output=True,
    )
    return result


def _candidate_paths(root):
    result = _git(
        root,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    return tuple(
        path.decode("utf-8")
        for path in result.stdout.split(b"\0")
        if path
    )


def _scan_secrets(root, paths):
    findings = []
    for path in paths:
        if path.startswith(SECRET_SCAN_EXCLUSIONS):
            continue
        if path.endswith(SECRET_SCAN_SUFFIX_EXCLUSIONS):
            continue
        target = root / path
        try:
            content = target.read_bytes()
        except OSError as exc:
            findings.append(f"{path}: cannot read ({exc})")
            continue
        if b"\0" in content:
            continue
        text = content.decode("utf-8", errors="replace")
        for label in secret_matches(text):
            findings.append(f"{path}: possible {label}")
    return findings


def check_repository(root):
    findings = []
    paths = _candidate_paths(root)
    for path in paths:
        if forbidden_artifact(path):
            findings.append(f"{path}: runtime or secret artifact is not ignored")

    for path in REQUIRED_IGNORES:
        result = _git(root, "check-ignore", "--no-index", "--quiet", "--", path)
        if result.returncode != 0:
            findings.append(f"{path}: representative runtime artifact is not ignored")

    for path in REQUIRED_VISIBLE_FIXTURES:
        result = _git(root, "check-ignore", "--no-index", "--quiet", "--", path)
        if result.returncode == 0:
            findings.append(f"{path}: intentional fixture is ignored")

    findings.extend(_scan_secrets(root, paths))
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Reject unignored runtime artifacts and high-confidence secrets."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    findings = check_repository(root)
    if findings:
        for finding in findings:
            print(f"FAIL  {finding}")
        return 1
    print("PASS  runtime and secret artifact guard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
