#!/usr/bin/env python3
"""Compare a live database's schema against what initialize_schema would build.

Run by install.sh before a --keep-data deploy. markervault_schema.py is entirely
CREATE TABLE IF NOT EXISTS, so against a database carrying an older schema the new
columns are silently not added and the application fails at runtime with "no such
column" — after a deploy that looked successful. This makes that question announce
itself loudly at deploy time instead.

It detects; it does not resolve. This is not a migration framework and presumes no
future one: if the schemas match it is silent, and if they diverge a full
--wipe-data deploy clears it. If migrations are ever built, this simply starts
passing.

Deliberately imports nothing beyond the standard library and markervault_schema,
which itself imports nothing — so the check still works when the venv is broken,
which is one of the states it exists to catch.

Exit 0 = schemas identical, or there is no live schema yet.
Exit 1 = drift, with the differing objects printed.
Exit 2 = usage error or an unreadable database.
"""
import difflib
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from markervault_schema import initialize_schema


# A bare dump produces false positives, so the comparison is pinned exactly:
#   - the sqlite_% filter is required, not cosmetic. It excludes sqlite_sequence
#     (created by the AUTOINCREMENT tables), the sqlite_autoindex_* entries, and
#     sqlite_stat1, which appears the moment ANALYZE is ever run against the live
#     database and would otherwise read as drift.
#   - ORDER BY is required because raw row order follows creation order.
# IF NOT EXISTS is stripped from the stored DDL, but identically on both sides, so
# it cancels out. Stored DDL is otherwise verbatim, whitespace included.
SCHEMA_QUERY = (
    "SELECT type, name, sql FROM sqlite_master "
    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
)


def schema_of(conn):
    return {(row[0], row[1]): row[2] or "" for row in conn.execute(SCHEMA_QUERY)}


def expected_schema():
    conn = sqlite3.connect(":memory:")
    try:
        initialize_schema(conn)
        return schema_of(conn)
    finally:
        conn.close()


def report(expected, live):
    for key in sorted(set(expected) | set(live)):
        kind, name = key
        if key not in live:
            print(f"  MISSING from the live database: {kind} {name}")
        elif key not in expected:
            print(f"  ONLY in the live database:      {kind} {name}")
        elif expected[key] != live[key]:
            print(f"  DIFFERS: {kind} {name}")
            diff = difflib.unified_diff(
                live[key].splitlines(),
                expected[key].splitlines(),
                fromfile="live", tofile="expected", lineterm="",
            )
            for line in diff:
                print(f"    {line}")


def main(argv):
    if len(argv) != 2:
        print("usage: check_schema_drift.py <database path>", file=sys.stderr)
        return 2

    db_path = argv[1]
    expected = expected_schema()

    if not os.path.exists(db_path):
        return 0

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            live = schema_of(conn)
        finally:
            conn.close()
    except sqlite3.Error as error:
        print(f"cannot read {db_path}: {error}", file=sys.stderr)
        return 2

    if not live or live == expected:
        return 0

    print(f"Schema drift between {db_path} and markervault_schema.py:")
    report(expected, live)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
