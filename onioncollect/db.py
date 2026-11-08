import asyncio
import contextlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

import aiosqlite

from onioncollect import lifecycle, schema

LEASE = timedelta(minutes=10)
RATE_WINDOW = timedelta(minutes=5)
LISTING, DETAIL = "listing", "detail"
COLLECTING = tuple(sorted(lifecycle.COLLECTING))

# One statement, so no other claim can interleave. `due` keeps only rows whose source still has a free
# lease slot; the window numbers each source's candidates so a batch never takes more of one source than
# its free slots (a correlated count alone would read the pre-update table and let a batch overfill).
# :collecting, the writer's list of live and degraded sources as JSON, is the approval gate at the queue: a row
# whose source is not collecting waits. The fetcher checks the state again before any request.
CLAIM = """
WITH busy AS (
    SELECT source_id, COUNT(*) AS leased FROM urls WHERE status = 'leased' GROUP BY source_id
), due AS (
    SELECT u.source_id, u.path, u.kind, u.page, u.discovered_at, COALESCE(b.leased, 0) AS leased
    FROM urls u LEFT JOIN busy b ON b.source_id = u.source_id
    WHERE u.status = 'queued' AND u.next_due <= :now AND COALESCE(b.leased, 0) < :per_source
      AND u.source_id IN (SELECT value FROM json_each(:collecting))
    ORDER BY u.page, u.discovered_at
    LIMIT :pool
), picked AS (
    SELECT source_id, path FROM (
        SELECT source_id, path, page, discovered_at, leased,
               ROW_NUMBER() OVER (PARTITION BY source_id ORDER BY page, discovered_at) AS nth
        FROM due
    )
    WHERE leased + nth <= :per_source
    ORDER BY page, discovered_at
    LIMIT :n
)
UPDATE urls SET status = 'leased', lease_until = :lease
WHERE (source_id, path) IN picked
RETURNING source_id, path, kind, page, run_id, retries
"""

# A listing page is fetched again on each run; a detail page only the first time it is seen.
QUEUE_LISTING = """
INSERT INTO urls (source_id, path, kind, page, run_id, next_due, discovered_at) VALUES (?, ?, 'listing', ?, ?, ?, ?)
ON CONFLICT (source_id, path) DO UPDATE SET kind = 'listing', page = excluded.page, run_id = excluded.run_id,
    status = 'queued', retries = 0, next_due = excluded.next_due
WHERE urls.status != 'leased' AND urls.run_id != excluded.run_id
"""
QUEUE_DETAIL = """
INSERT OR IGNORE INTO urls (source_id, path, kind, page, run_id, next_due, discovered_at)
VALUES (?, ?, 'detail', ?, ?, ?, ?)
"""


@dataclass
class Task:
    source_id: str
    path: str
    kind: str
    page: int
    run_id: int
    retries: int


@dataclass
class PageMetric:
    host: str
    elapsed: float
    status: int | None = None
    error: str | None = None
    bytes: int = 0
    items: int = 0
    incomplete: int = 0
    fields_resolved: int = 0
    fields_declared: int = 0
    below_expectation: bool = False
    redactions: int = 0
    records_new: int = 0
    # Each declared field's resolved count, over `field_items` items: a listing's items, or the one detail page.
    field_hits: dict[str, int] = field(default_factory=dict)
    field_items: int = 0


def stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(tzinfo=None).isoformat(" ", "milliseconds")


def unstamp(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


class Database:
    def __init__(self):
        self.conn: aiosqlite.Connection | None = None
        self.lock = asyncio.Lock()

    async def open(self, path: Path, *scripts: str, read_only: bool = False) -> None:
        self.path, self.read_only = path, read_only
        if read_only:
            # A reader never creates a store. Checked first: a failed connect would leave aiosqlite's thread behind.
            if not path.is_file():
                raise FileNotFoundError(path)
            self.conn = await aiosqlite.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            self.conn.row_factory = aiosqlite.Row
            await self.conn.execute("PRAGMA busy_timeout=5000")
            return
        self.conn = await aiosqlite.connect(path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA busy_timeout=5000")
        for script in scripts:
            await self.conn.executescript(script)
        await self.conn.commit()

    async def close(self) -> None:
        await self.conn.close()
        if self.read_only:
            return
        # SQLite deletes -wal and -shm when the last connection closes, and a reader that may not create files
        # in the directory (the analyst, read-only) then cannot open a WAL database at all. Empty ones are valid.
        for suffix in ("-wal", "-shm"):
            Path(f"{self.path}{suffix}").touch()

    @contextlib.asynccontextmanager
    async def write(self):
        async with self.lock:
            try:
                yield self.conn
            except BaseException:
                await self.conn.rollback()
                raise
            await self.conn.commit()

    async def rows(self, sql: str, params=()) -> list[aiosqlite.Row]:
        return list(await self.conn.execute_fetchall(sql, params))


async def open_collect(path: Path, read_only: bool = False) -> Database:
    database = Database()
    await database.open(path, schema.SOURCES, schema.RUNS, read_only=read_only)
    return database


async def open_frontier(path: Path) -> Database:
    database = Database()
    await database.open(path, schema.FRONTIER)
    return database


class Frontier:
    """The crawler's queue of paths, in its own state dir. Run totals and metrics are the writer's (runs.RunLog)."""

    def __init__(self, database: Database, per_source: int, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.db = database
        self.per_source = per_source
        self.clock = clock

    async def queue_seeds(self, source_id: str, run_id: int, seeds: tuple[str, ...]) -> None:
        now = stamp(self.clock())
        async with self.db.write() as db:
            await db.executemany(QUEUE_LISTING, [(source_id, path, 1, run_id, now, now) for path in seeds])

    async def claim(self, n: int, collecting: list[str]) -> list[Task]:
        now = self.clock()
        params = {"now": stamp(now), "lease": stamp(now + LEASE), "n": n, "per_source": self.per_source, "pool": n * 50,
                  "collecting": json.dumps(collecting)}
        async with self.db.write() as db:
            rows = await db.execute_fetchall(CLAIM, params)
        return [Task(*row) for row in rows]

    async def complete(self, task: Task, status: int | None, listing: list[tuple[str, int]], details: list[str]) -> None:
        now = stamp(self.clock())
        async with self.db.write() as db:
            await db.execute(
                "UPDATE urls SET status = 'done', retries = 0, lease_until = NULL, last_fetched = ?, last_code = ?"
                " WHERE source_id = ? AND path = ?",
                (now, status, task.source_id, task.path),
            )
            await db.executemany(QUEUE_LISTING, [(task.source_id, path, page, task.run_id, now, now) for path, page in listing])
            await db.executemany(QUEUE_DETAIL, [(task.source_id, path, 0, task.run_id, now, now) for path in details])

    async def fail(self, task: Task, status: int | None, retries: int, next_due: datetime | None) -> None:
        now = stamp(self.clock())
        due = None if next_due is None else stamp(next_due)
        async with self.db.write() as db:
            await db.execute(
                "UPDATE urls SET status = CASE WHEN ? IS NULL THEN 'failed' ELSE 'queued' END, retries = ?,"
                " next_due = COALESCE(?, next_due), lease_until = NULL, last_fetched = ?, last_code = ?"
                " WHERE source_id = ? AND path = ?",
                (due, retries, due, now, status, task.source_id, task.path),
            )

    async def open_in_run(self, run_id: int) -> int:
        (count,), = await self.db.rows(
            "SELECT COUNT(*) FROM urls WHERE run_id = ? AND status IN ('queued', 'leased')", (run_id,))
        return count

    async def pending(self, collecting: list[str]) -> int:
        """Pages of collecting sources still to fetch: queued (a retry included) or leased."""
        (count,), = await self.db.rows(
            "SELECT COUNT(*) FROM urls WHERE status IN ('queued', 'leased')"
            " AND source_id IN (SELECT value FROM json_each(?))", (json.dumps(collecting),)
        )
        return count

    async def release_stale_leases(self) -> int:
        async with self.db.write() as db:
            cursor = await db.execute(
                "UPDATE urls SET status = 'queued', lease_until = NULL WHERE status = 'leased' AND lease_until < ?",
                (stamp(self.clock()),),
            )
            return cursor.rowcount

    async def counts(self) -> dict[str, int]:
        return {row[0]: row[1] for row in await self.db.rows("SELECT status, COUNT(*) FROM urls GROUP BY status")}
