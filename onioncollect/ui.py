"""Section 12's search UI: a small local web page over the three stores, run as the analyst and reached through
an SSH forward to 127.0.0.1. Standard library only. It reads through read-only SQLite connections and the
snapshot files; it never writes and never fetches. Its one socket is its own listener. ui_main.py starts it."""
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from onioncollect import lifecycle, search, views

ADDRESS = "127.0.0.1"
LOCAL_NAMES = {ADDRESS, "localhost"}
PORT = 8470
CRAWLER = "crawler"
STORES = ("collect.db", "records.db")
RECORD_ID = re.compile(r"[1-9][0-9]{0,11}")
SNAPSHOT_ID = re.compile(r"[0-9a-f]{64}")
HISTORY_RUNS = 30
LATEST_SNAPSHOTS = 10
HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_BYTES, LOG_FILES = 5 * 1024 * 1024, 3

log = logging.getLogger(__name__)


class Answer(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def refusal(data_dir: Path, uid: int, user: str) -> str | None:
    """Why this user may not run the UI: root, the crawler, or anyone who could write the stores it shows."""
    if uid == 0:
        return "refusing to run as root"
    if user == CRAWLER:
        return "the UI runs as the analyst, never as the crawler"
    stores = [data_dir, *(data_dir / name for name in (*STORES, "snapshots"))]
    writable = [str(path) for path in stores if path.exists() and os.access(path, os.W_OK)]
    if writable:
        return f"this user can write {', '.join(writable)}; the UI runs only as a user that cannot"
    return None


def configure_logging(path: Path) -> None:
    formatter = logging.Formatter(LOG_FORMAT)
    handlers = [logging.StreamHandler(sys.stderr), RotatingFileHandler(path, maxBytes=LOG_BYTES, backupCount=LOG_FILES)]
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(lambda record: record.name.startswith("onioncollect."))
    logging.basicConfig(level=logging.INFO, handlers=handlers)


class Stores:
    """A read-only connection per request, so a crawl's writes show as they land and nothing here can write."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def open(self, name: str) -> sqlite3.Connection:
        db = sqlite3.connect(f"{(self.data_dir / name).resolve().as_uri()}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only = ON")
        return db

    def rows(self, name: str, sql: str, params=()) -> list[dict]:
        db = self.open(name)
        try:
            return [dict(row) for row in db.execute(sql, params)]
        finally:
            db.close()


class App:
    """Route to page. Returns (route name, status, html, rows shown); the route name and the counts are what
    gets logged, never the query or anything a page shows."""

    def __init__(self, data_dir: Path, configs_dir: Path):
        self.data_dir, self.configs_dir = data_dir, configs_dir
        self.stores = Stores(data_dir)

    def answer(self, target: str) -> tuple[str, int, str, int]:
        parts = urlsplit(target)
        route, _, key = parts.path[1:].partition("/")
        pages = {"record": self.record, "source": self.source, "snapshot": self.snapshot}
        if parts.path == "/":
            name, page, argument = "search", self.search, parts.query
        elif route in pages and key and "/" not in key:
            name, page, argument = route, pages[route], key
        else:
            return "not_found", 404, views.page("Not found", views.message("No such page.")), 0
        try:
            title, body, count = page(argument)
        except Answer as exc:
            return name, exc.status, views.page("Not found" if exc.status == 404 else "Bad request",
                                                views.message(exc.detail)), 0
        except sqlite3.Error as exc:
            log.warning("ui %s store unreadable: %s", name, type(exc).__name__)
            return name, 503, views.page("Stores unavailable", views.message("Try again in a moment.")), 0
        return name, 200, views.page(title, body), count

    def search(self, query: str) -> tuple[str, str, int]:
        values = {name: given[-1] for name, given in parse_qs(query, max_num_fields=8).items()}
        form = views.search_form(values, lifecycle.CATEGORIES)
        if not values.get("q", "").strip():
            return "Search", form, 0
        source, category = values.get("source") or None, values.get("category") or None
        if source is not None and not lifecycle.SOURCE_ID.fullmatch(source):
            raise Answer(400, "A source id is lower-case letters, digits and hyphens.")
        if category is not None and category not in lifecycle.CATEGORIES:
            raise Answer(400, "Not a category.")
        since, until = day(values.get("since"), "00:00:00.000"), day(values.get("until"), "23:59:59.999")
        try:
            bound = search.parameters(values["q"], source, category, since, until)
        except ValueError as exc:
            raise Answer(400, str(exc)) from None
        rows = self.stores.rows("records.db", search.SQL, bound)
        for row in rows:
            row["fields"] = json.loads(row["fields"])
            row["sources"] = sorted((row["sources"] or row["source_id"]).split(","))
        snapshots = {row["id"]: found[0]["digest"] for row in rows if (found := self.page_snapshots(row, 1))}
        return "Search", form + views.results(rows, snapshots), len(rows)

    def record(self, key: str) -> tuple[str, str, int]:
        if not RECORD_ID.fullmatch(key):
            raise Answer(404, "No such record.")
        found = self.stores.rows("records.db", "SELECT * FROM records WHERE id = ?", (int(key),))
        if not found:
            raise Answer(404, "No such record.")
        record = found[0]
        hosts = self.stores.rows("records.db", "SELECT host, source_id, first_seen, last_seen FROM record_hosts"
                                               " WHERE record_id = ? ORDER BY first_seen", (record["id"],))
        record["sources"] = sorted({row["source_id"] for row in hosts} | {record["source_id"]})
        fields = json.loads(record["fields"])
        snapshots = self.page_snapshots(record, LATEST_SNAPSHOTS)
        return f"Record {record['id']}", views.record_page(record, fields, hosts, snapshots), 1

    def source(self, key: str) -> tuple[str, str, int]:
        found = self.stores.rows("collect.db", "SELECT * FROM sources WHERE id = ?", (key,)) \
            if lifecycle.SOURCE_ID.fullmatch(key) else []
        if not found:
            raise Answer(404, "No such source.")
        runs = self.stores.rows("collect.db", "SELECT * FROM runs WHERE source_id = ? ORDER BY id DESC LIMIT ?",
                                (key, HISTORY_RUNS))
        items = self.stores.rows("collect.db", "SELECT id, kind, priority, opened_at, detail FROM health_items"
                                               " WHERE source_id = ? AND status = 'open' ORDER BY priority DESC", (key,))
        snapshots = self.stores.rows("records.db", "SELECT digest, path, kind, taken_at, baseline FROM snapshots"
                                                   " WHERE source_id = ? ORDER BY taken_at DESC LIMIT ?",
                                     (key, LATEST_SNAPSHOTS))
        path = str(self.configs_dir / f"{key}.toml")
        return key, views.source_page(found[0], path, runs, items, snapshots), len(runs)

    def snapshot(self, key: str) -> tuple[str, str, int]:
        # The id is checked against the content-address format before it touches a query or a path.
        if not SNAPSHOT_ID.fullmatch(key):
            raise Answer(404, "No such snapshot.")
        meta = self.stores.rows("records.db", "SELECT source_id, path, kind, taken_at, baseline FROM snapshots"
                                              " WHERE digest = ? ORDER BY taken_at DESC", (key,))
        if not meta:
            raise Answer(404, "No such snapshot.")
        try:
            body = (self.data_dir / "snapshots" / key[:2] / f"{key}.html").read_text(errors="replace")
        except FileNotFoundError:
            raise Answer(404, "That snapshot has passed its retention clock.") from None
        return f"Snapshot {key[:12]}", views.snapshot_page(meta, body), 1

    def page_snapshots(self, record: dict, limit: int) -> list[dict]:
        if not record["follow_path"]:
            return []
        sources = record["sources"]
        marks = ", ".join("?" for _ in sources)
        return self.stores.rows("records.db", f"SELECT digest, path, kind, taken_at, baseline FROM snapshots"
                                              f" WHERE path = ? AND source_id IN ({marks})"
                                              f" ORDER BY taken_at DESC LIMIT ?",
                                (record["follow_path"], *sources, limit))


def day(given: str | None, clock: str) -> str | None:
    if not given:
        return None
    try:
        return f"{date.fromisoformat(given).isoformat()} {clock}"
    except ValueError:
        raise Answer(400, "Dates are YYYY-MM-DD.") from None


def local(host: str | None) -> bool:
    """The Host header names this machine. Any port, since the SSH forward's local port is the analyst's choice."""
    name = (host or "").rpartition(":")[0] if (host or "").count(":") == 1 else host
    return name in LOCAL_NAMES


class Handler(BaseHTTPRequestHandler):
    server_version = "onioncollect"
    sys_version = ""

    def do_GET(self):
        started = time.monotonic()
        if not local(self.headers.get("Host")):
            # A page another site rebinds to 127.0.0.1 arrives under its own name; only ours is served.
            route, status, html, count = "wrong_host", 400, views.page("Bad request", ""), 0
        else:
            route, status, html, count = self.server.app.answer(self.path)
        self.reply(status, html.encode())
        log.info("ui %s status=%d results=%d elapsed=%.3fs", route, status, count, time.monotonic() - started)

    def do_HEAD(self):
        self.refuse()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD

    def refuse(self):
        self.reply(405, views.page("Read only", views.message("This UI only reads.")).encode(), Allow="GET")
        log.info("ui method status=405 results=0 elapsed=0.000s")

    def reply(self, status: int, body: bytes, **extra: str) -> None:
        self.send_response(status)
        for name, value in (HEADERS | {"Content-Length": str(len(body))} | extra).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, format, *args):
        # http.server would log the request line, query string included. The route and counts are logged instead.
        pass


class UIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, data_dir: Path, configs_dir: Path, port: int):
        super().__init__((ADDRESS, port), Handler)
        self.app = App(data_dir, configs_dir)
