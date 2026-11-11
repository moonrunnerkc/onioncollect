"""Log audit, guest only: log_audit.py --data DATA_DIR [--credentials DIR] LOG...

Run after every crawl by onioncollect-log-audit.service as the analyst, over the crawl log and the search UI's
log. Every line must be one of the known shapes, and no path or query string the crawl visited, and no extracted
record text, may appear in any log, each line's own timestamp aside. Section 15's credential values, read from
the *.env files in DIR (default /etc/onioncollect; the unit passes the copy systemd hands it), may appear neither
in a log nor in any file under DATA_DIR. A log that does not exist yet is skipped. Prints counts and line shapes
only, never log content and never a credential.
"""
import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

SOURCE = r"[a-z0-9][a-z0-9-]{1,62}"
KIND = r"(listing|detail)"
ERRORS = (r"timeout|tor_unreachable|redirect|redirect_offsite|not_text|gated|not_approved|not_source_host|excluded"
          r"|bad_path|parse_refused|excluded_body|auth_refused|auth_rejected|credential_unreadable|other:\w+")
HEALTH_KINDS = r"(redaction|unreachable|required-field-lost|below-expectation|parse-refused)"
PREFIX = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} (\w+) (\S+): (.*)$")
# A line's own timestamp is the logger's, never page content, and a record field can equal one to the minute
# (a mirror listing's "last modified"). Only the stamp at the start of a line is set aside.
STAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} ", re.MULTILINE)
SHAPES = {
    "fetched": re.compile(rf"{SOURCE} {KIND} status=\d{{3}} bytes=\d+ items=\d+ fields=\d+/\d+ new=\d+ redactions=\d+"
                          rf" discovered=\d+ elapsed=\d+\.\ds"),
    "failed": re.compile(rf"{SOURCE} {KIND} error=({ERRORS}) elapsed=\d+\.\ds"),
    "redirect": re.compile(rf"{SOURCE} redirect off the source, discovered=\d+"),
    "run": re.compile(rf"{SOURCE} run \d+ (started|done pages=\d+ failures=\d+ items=\d+ hit_rate=\d\.\d\d"
                      rf" below_expectation=\d+ new=\d+ redactions=\d+)"),
    "health": re.compile(rf"{SOURCE} health item {HEALTH_KINDS} priority=\d+"),
    "probe": re.compile(rf"{SOURCE} sibling probe (status=(\d{{3}}|None) error=(None|{ERRORS}) elapsed=\d+\.\ds"
                        r"|refused: (not_approved|not_source_host|excluded|bad_path))"),
    "session": re.compile(rf"{SOURCE} session (started|not started: ({ERRORS}))"),
    "disabled": re.compile(rf"{SOURCE} disabled: body tripped child_exploitation"),
    "refused": re.compile(rf"{SOURCE} write refused: a secret survived redaction"),
    "config": re.compile(rf"{SOURCE} not scheduled: .+"),
    "lifecycle": re.compile(r"crawler: (\d+ workers on \d+ tor instances|stopping, letting in-flight fetches finish|stopped"
                            rf"|no page left to fetch|form-session sources: (none|{SOURCE}(, {SOURCE})*))"),
    "worker": re.compile(r"worker \d+: stopped by \w+, shutting down"),
    "ui": re.compile(r"ui ((search|record|source|snapshot|not_found|wrong_host|method) status=\d{3} results=\d+"
                     r" elapsed=\d+\.\d{3}s|listening on port \d+|(search|record|source|snapshot) store unreadable: \w+)"),
    "tor": re.compile(r"tor \d+: (rotated circuits|success \d\.\d\d over \d+ fetches, last rotation (never|\d+s ago)"
                      r"|no circuit after \d+ s, (dropped from pool|kept in the pool for a fetch to wake)"
                      r"|circuit request refused \(\w+\), left to the ready wait"
                      r"|control connection lost, reconnected|control port unreachable \(\w+\), not rotated)"),
}
MIN_FIELD_CHARS = 8


def visited(db_path: Path) -> set[str]:
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    found = set()
    for (path,) in db.execute("SELECT path FROM visited_paths"):
        parts = urlsplit(path)
        if parts.path not in ("", "/"):
            found.add(parts.path)
        if parts.query:
            found.add(parts.query)
    return found


def record_text(db_path: Path) -> set[str]:
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    return {value for (fields,) in db.execute("SELECT fields FROM records")
            for value in json.loads(fields).values() if len(value) >= MIN_FIELD_CHARS}


def credentials(directory: Path) -> set[str]:
    values = set()
    for path in sorted(directory.glob("*.env")) if directory.is_dir() else ():
        for line in path.read_text().splitlines():
            value = line.partition("=")[2]
            if value:
                values.add(value)
    return values


def main(logs: list[Path], data_dir: Path, credentials_dir: Path) -> int:
    texts = [path.read_text() for path in logs if path.exists()]
    lines = [line for text in texts for line in text.splitlines()]
    shapes, unknown = Counter(), Counter()
    for line in lines:
        match = PREFIX.match(line)
        own = match and match.group(2).startswith("onioncollect.")
        shape = next((name for name, pattern in SHAPES.items() if own and pattern.fullmatch(match.group(3))), None)
        if shape:
            shapes[shape] += 1
        else:
            unknown[match.group(2) if match else "unprefixed"] += 1

    secrets = visited(data_dir / "collect.db") | record_text(data_dir / "records.db")
    text = "\n".join(texts)
    said = STAMP.sub("", text)
    leaked = sum(1 for secret in secrets if secret in said)
    held = credentials(credentials_dir)
    stored = [path.read_bytes() for path in data_dir.rglob("*") if path.is_file()]
    exposed = sum(1 for value in held if value in text or any(value.encode() in blob for blob in stored))

    print(f"logs read: {len(texts)} of {len(logs)}; log lines: {len(lines)}, by shape: {dict(shapes.most_common())}")
    print(f"lines of unknown shape: {sum(unknown.values())} {dict(unknown) if unknown else ''}")
    print(f"visited paths, queries and record text checked against the logs: {len(secrets)}, found: {leaked}")
    print(f"credential values checked against the logs and every file under the data dir: {len(held)},"
          f" found: {exposed}")
    return 1 if unknown or leaked or exposed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, default=Path("/etc/onioncollect"))
    args = parser.parse_args()
    sys.exit(main(args.logs, args.data, args.credentials))
