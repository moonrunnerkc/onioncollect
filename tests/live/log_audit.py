"""Step 8 log audit, guest only, as crawler: log_audit.py CRAWL_LOG CRAWL_DB

Every line must be one of the crawler's known shapes, and no path, query string or title the crawl
stored may appear anywhere in the log. Prints counts and line shapes only, never log content.
"""
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

HOST = r"[a-z2-7]{56}\.onion"
PREFIX = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} (\w+) (\S+): (.*)$")
SHAPES = {
    "fetched": re.compile(rf"{HOST} status=\d{{3}} bytes=\d+ links=\d+ onions=\d+ changed=(yes|no)( gated)? elapsed=\d+\.\ds"),
    "failed": re.compile(rf"{HOST} error=(timeout|tor_unreachable|redirect_offsite|redirect_excluded|not_text|not_onion|other:\w+) elapsed=\d+\.\ds"),
    "excluded": re.compile(rf"{HOST} excluded: (listed|child_exploitation|credential_dump|card_number)"),
    "dead": re.compile(rf"{HOST} marked dead"),
    "lifecycle": re.compile(r"crawler: (\d+ workers on \d+ tor instances|stopping, letting in-flight fetches finish|stopped)"),
    "worker": re.compile(r"worker \d+: stopped by \w+, shutting down"),
    "tor": re.compile(r"tor \d+: (rotated circuits|success \d\.\d\d over \d+ fetches, last rotation (never|\d+s ago)|no circuit after \d+ s, dropped from pool)"),
}


def main(log_path: Path, db_path: Path) -> int:
    lines = log_path.read_text().splitlines()
    shapes, unknown = Counter(), Counter()
    for line in lines:
        match = PREFIX.match(line)
        own = match and match.group(2).startswith("onioncrawl.")
        shape = next((name for name, pattern in SHAPES.items() if own and pattern.fullmatch(match.group(3))), None)
        if shape:
            shapes[shape] += 1
        else:
            unknown[match.group(2) if match else "unprefixed"] += 1

    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    secrets = set()
    for (url,) in db.execute("SELECT url FROM urls"):
        parts = urlsplit(url)
        if parts.path not in ("", "/"):
            secrets.add(parts.path)
        if parts.query:
            secrets.add(parts.query)
    for (title,) in db.execute("SELECT title FROM pages UNION SELECT title FROM hosts"):
        if title and len(title) >= 4:
            secrets.add(title)
    text = log_path.read_text()
    leaked = sum(1 for secret in secrets if secret in text)

    print(f"log lines: {len(lines)}, by shape: {dict(shapes.most_common())}")
    print(f"lines of unknown shape: {sum(unknown.values())} {dict(unknown) if unknown else ''}")
    print(f"stored paths, queries and titles checked against the log: {len(secrets)}, found in the log: {leaked}")
    return 1 if unknown or leaked else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
