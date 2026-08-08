#!/usr/bin/env python3
"""Report whether a deployed virtual environment actually carries the pinned versions.

Run with the DEPLOYED interpreter, not the repository's:

    sudo /var/www/markervault/venv/bin/python tools/check_deployed_pins.py requirements.txt

The manifest path is resolved from the current directory, so run it from the synced
checkout. Exit 0 when every pin matches, 1 when any does not.

This exists because a deployed pin used to be unverifiable without reading pip's
output by eye. install.sh guarded the dependency install on the venv not existing
(F1), so no backend upgrade reached a host that already had one — silently, because
frontend assets landed through the overlay copy and looked like a successful deploy.
The guard is gone, but a check that answers "did the pins actually land" is still the
fastest way to confirm a deploy did what it claimed.

Deliberately imports nothing outside the standard library: it has to run inside the
deployed venv, which holds the application's dependencies and nothing else.
"""
import sys
from importlib.metadata import PackageNotFoundError, version


def main(argv):
    if len(argv) != 2:
        print("usage: check_deployed_pins.py <requirements file>", file=sys.stderr)
        return 2

    drift = 0
    try:
        manifest = open(argv[1], encoding="utf-8")
    except OSError as error:
        print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
        return 2

    with manifest:
        for line in manifest:
            line = line.strip()
            # Skip blanks, comments, hash continuations, and the "-r other.txt"
            # include used by the test manifest; only explicit == pins are
            # checkable here.
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = line.removesuffix("\\").rstrip()
            name, separator, pin = line.partition("==")
            if not separator:
                continue
            try:
                have = version(name)
            except PackageNotFoundError:
                have = "MISSING"
            if have != pin:
                drift += 1
            print(f"{'ok   ' if have == pin else 'DRIFT'} {name:22} want {pin:14} have {have}")

    print("\nALL PINS DEPLOYED" if not drift else f"\n{drift} PIN(S) NOT DEPLOYED")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
