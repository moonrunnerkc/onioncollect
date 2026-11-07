import asyncio
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

import aiosqlite

from onioncrawl import onion, schema
from onioncrawl.config import Settings

LEASE = timedelta(minutes=10)
FRESH, RECRAWL = 0, 1

# One statement, so no other claim can interleave. `due` keeps only rows whose host still has a free
# lease slot; the window numbers each host's candidates so a batch never takes more of one host than
# its free slots (a correlated count alone would read the pre-update table and let a batch overfill).
# `done` rows are pages waiting for a recrawl; they come back at RECRAWL priority, behind discovery.
CLAIM = """
WITH busy AS (
    SELECT host, COUNT(*) AS leased FROM urls WHERE status = 'leased' GROUP BY host
), due AS (
    SELECT u.url, u.host, u.priority, u.depth, u.discovered_at, COALESCE(b.leased, 0) AS leased
    FROM urls u LEFT JOIN busy b ON b.host = u.host
    WHERE u.status IN ('queued', 'done') AND u.next_due <= :now AND COALESCE(b.leased, 0) < :per_host
    ORDER BY u.priority, u.depth, u.discovered_at
    LIMIT :pool
), picked AS (
    SELECT url FROM (
        SELECT url, priority, depth, discovered_at, leased,
               ROW_NUMBER() OVER (PARTITION BY host ORDER BY priority, depth, discovered_at) AS nth
        FROM due
    )
    WHERE leased + nth <= :per_host
    ORDER BY priority, depth, discovered_at
    LIMIT :n
)
UPDATE urls SET status = 'leased', lease_until = :lease
WHERE url IN picked
RETURNING url, host, depth, retries, last_hash,
          (SELECT unchanged_streak FROM hosts WHERE hosts.host = urls.host)
"""

# A host that answered keeps a gated or excluded verdict; anything else it was is now up.
ANSWERED_STATE = "CASE WHEN state IN ('gated', 'excluded') THEN state ELSE 'up' END"


@dataclass
class Task:
    url: str
    host: str
    depth: int
    retries: int
    last_hash: str | None
    unchanged_streak: int = 0


@dataclass
class PageInfo:
    title: str
    headings: list[str]
    links: set[str]
    text_onions: set[str]
    sha256: str
    simhash: int
    server: str | None
    gated: bool
    word_count: int
    http_code: int
    size: int


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(tzinfo=None).isoformat(" ", "milliseconds")


def unstamp(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def discovered(info: PageInfo) -> set[str]:
    return info.links | {f"http://{host}/" for host in info.text_onions}


def signed64(value: int) -> int:
    # SQLite integers are signed 64-bit; a simhash with the top bit set would overflow on insert.
    return value - (1 << 64) if value >= 1 << 63 else value


class Frontier:
    def __init__(self, settings: Settings, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.settings = settings
        self.clock = clock
        self.db: aiosqlite.Connection | None = None
        self.write_lock = asyncio.Lock()

    async def open(self, path: Path) -> None:
        self.db = await aiosqlite.connect(path)
        await self.db.execute("PRAGMA journal_mode=WAL")
        await self.db.execute("PRAGMA busy_timeout=5000")
        await self.db.executescript(schema.TABLES + schema.INDEXES)
        await self.db.commit()
        await self.release_stale_leases()

    async def close(self) -> None:
        await self.db.close()

    @contextlib.asynccontextmanager
    async def _write(self):
        async with self.write_lock:
            try:
                yield self.db
            except BaseException:
                await self.db.rollback()
                raise
            await self.db.commit()

    async def seed(self, urls: list[str]) -> tuple[int, int]:
        valid = [url for url in map(onion.normalize, urls) if url]
        async with self._write():
            await self._queue(valid, 0)
        return len(valid), len(urls) - len(valid)

    async def claim(self, n: int) -> list[Task]:
        now = self.clock()
        params = {
            "now": stamp(now), "lease": stamp(now + LEASE), "n": n,
            "per_host": self.settings.per_host_concurrency, "pool": n * 50,
        }
        async with self._write() as db:
            rows = await db.execute_fetchall(CLAIM, params)
        return [Task(*row) for row in rows]

    async def complete(self, task: Task, info: PageInfo, next_due: datetime, page_path: str | None) -> None:
        now = stamp(self.clock())
        parts = urlsplit(task.url)
        is_root = parts.path == "/" and not parts.query
        async with self._write() as db:
            await db.execute(
                "UPDATE urls SET status = 'done', priority = ?, retries = 0, lease_until = NULL, last_fetched = ?,"
                " last_hash = ?, last_code = ?, next_due = ? WHERE url = ?",
                (RECRAWL, now, info.sha256, info.http_code, stamp(next_due), task.url),
            )
            await db.execute(
                "UPDATE hosts SET state = CASE WHEN state = 'excluded' THEN state ELSE ? END,"
                " last_up = ?, consecutive_failures = 0,"
                " unchanged_streak = CASE WHEN ? THEN 0 ELSE unchanged_streak + 1 END,"
                " title = CASE WHEN ? THEN ? ELSE title END, simhash = CASE WHEN ? THEN ? ELSE simhash END"
                " WHERE host = ?",
                ("gated" if info.gated else "up", now, info.sha256 != task.last_hash,
                 is_root, info.title, is_root, signed64(info.simhash), task.host),
            )
            if page_path is not None:
                await db.execute(
                    "INSERT OR IGNORE INTO pages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (info.sha256, task.url, task.host, now, info.http_code, info.size, info.title,
                     signed64(info.simhash), page_path),
                )
            await db.execute("INSERT INTO uptime VALUES (?, ?, 1)", (task.host, now))
            if not info.gated:
                await self._queue(discovered(info), task.depth + 1)

    async def exclude(self, task: Task, info: PageInfo) -> None:
        now = stamp(self.clock())
        async with self._write() as db:
            await db.execute(
                "UPDATE hosts SET state = 'excluded', last_up = ?, consecutive_failures = 0, title = NULL,"
                " simhash = NULL WHERE host = ?",
                (now, task.host),
            )
            await db.execute(
                "UPDATE urls SET status = 'parked', lease_until = NULL, last_fetched = ? WHERE url = ?",
                (now, task.url),
            )
            await db.execute(
                "UPDATE urls SET status = 'parked' WHERE host = ? AND status IN ('queued', 'done')", (task.host,)
            )
            await db.execute("INSERT INTO uptime VALUES (?, ?, 1)", (task.host, now))
            await self._queue(discovered(info), task.depth + 1)

    async def fail(self, task: Task, retries: int, next_due: datetime | None, host_answered: bool) -> None:
        now = stamp(self.clock())
        async with self._write() as db:
            await db.execute(
                "UPDATE urls SET status = ?, retries = ?, next_due = COALESCE(?, next_due), lease_until = NULL,"
                " last_fetched = ? WHERE url = ?",
                ("parked" if next_due is None else "queued", retries,
                 None if next_due is None else stamp(next_due), now, task.url),
            )
            if host_answered:
                await db.execute(
                    f"UPDATE hosts SET state = {ANSWERED_STATE}, last_up = ?, consecutive_failures = 0 WHERE host = ?",
                    (now, task.host),
                )
            else:
                await db.execute(
                    "UPDATE hosts SET last_down = ?, consecutive_failures = consecutive_failures + 1 WHERE host = ?",
                    (now, task.host),
                )
            await db.execute("INSERT INTO uptime VALUES (?, ?, ?)", (task.host, now, int(host_answered)))

    async def recent_failures(self, host: str) -> list[datetime]:
        rows = await self.db.execute_fetchall(
            "SELECT checked_at FROM uptime WHERE host = ? AND up = 0 AND checked_at >"
            " COALESCE((SELECT MAX(checked_at) FROM uptime WHERE host = ? AND up = 1), '') ORDER BY checked_at",
            (host, host),
        )
        return [unstamp(row[0]) for row in rows]

    async def mark_dead(self, host: str) -> None:
        async with self._write() as db:
            await db.execute("UPDATE hosts SET state = 'dead' WHERE host = ? AND state != 'excluded'", (host,))
            await db.execute("UPDATE urls SET status = 'parked' WHERE host = ? AND status IN ('queued', 'done')", (host,))

    async def release_stale_leases(self) -> int:
        async with self._write() as db:
            cursor = await db.execute(
                "UPDATE urls SET status = 'queued', lease_until = NULL WHERE status = 'leased' AND lease_until < ?",
                (stamp(self.clock()),),
            )
            return cursor.rowcount

    async def excluded_hosts(self) -> set[str]:
        rows = await self.db.execute_fetchall("SELECT host FROM hosts WHERE state = 'excluded'")
        return {row[0] for row in rows}

    async def stats(self) -> dict:
        since = stamp(self.clock() - timedelta(hours=1))
        urls = await self.db.execute_fetchall("SELECT status, COUNT(*) FROM urls GROUP BY status")
        hosts = await self.db.execute_fetchall("SELECT state, COUNT(*) FROM hosts GROUP BY state")
        (pages,), = await self.db.execute_fetchall("SELECT COUNT(*) FROM pages")
        (fetches, ups), = await self.db.execute_fetchall(
            "SELECT COUNT(*), COALESCE(SUM(up), 0) FROM uptime WHERE checked_at >= ?", (since,)
        )
        return {
            "urls": dict(urls), "hosts": dict(hosts), "pages": pages,
            "fetches_last_hour": fetches, "up_last_hour": ups,
        }

    async def _queue(self, urls, depth: int) -> None:
        if depth > self.settings.max_depth:
            return
        now = stamp(self.clock())
        rows = [(url, onion.host_of(url)) for url in map(onion.normalize, urls) if url]
        await self.db.executemany(
            "INSERT OR IGNORE INTO hosts (host, first_seen) VALUES (?, ?)", [(host, now) for _, host in rows]
        )
        await self.db.executemany(
            "INSERT OR IGNORE INTO urls (url, host, depth, priority, next_due, discovered_at)"
            " SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS"
            " (SELECT 1 FROM hosts WHERE host = ? AND state IN ('dead', 'gated', 'excluded'))",
            [(url, host, depth, FRESH, now, now, host) for url, host in rows],
        )
