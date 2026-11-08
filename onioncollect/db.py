import asyncio
import contextlib
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
# The join on sources is the approval gate at the queue: a row whose source is not collecting waits.
CLAIM = f"""
WITH busy AS (
    SELECT source_id, COUNT(*) AS leased FROM urls WHERE status = 'leased' GROUP BY source_id
), due AS (
    SELECT u.source_id, u.path, u.kind, u.page, u.discovered_at, COALESCE(b.leased, 0) AS leased
    FROM urls u JOIN sources s ON s.id = u.source_id LEFT JOIN busy b ON b.source_id = u.source_id
    WHERE u.status = 'queued' AND u.next_due <= :now AND COALESCE(b.leased, 0) < :per_source
      AND s.state IN {COLLECTING}
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
    await database.open(path, schema.SOURCES, schema.FRONTIER, read_only=read_only)
    return database


class Frontier:
    def __init__(self, database: Database, per_source: int, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.db = database
        self.per_source = per_source
        self.clock = clock

    async def due_sources(self) -> list[str]:
        rows = await self.db.rows(
            f"SELECT id FROM sources s WHERE state IN {COLLECTING} AND (next_run IS NULL OR next_run <= ?)"
            " AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.source_id = s.id AND r.finished_at IS NULL) ORDER BY id",
            (stamp(self.clock()),),
        )
        return [row["id"] for row in rows]

    async def start_run(self, source_id: str, seeds: tuple[str, ...]) -> int:
        now = stamp(self.clock())
        async with self.db.write() as db:
            cursor = await db.execute("INSERT INTO runs (source_id, started_at) VALUES (?, ?)", (source_id, now))
            run_id = cursor.lastrowid
            await db.executemany(QUEUE_LISTING, [(source_id, path, 1, run_id, now, now) for path in seeds])
        return run_id

    async def claim(self, n: int) -> list[Task]:
        now = self.clock()
        params = {"now": stamp(now), "lease": stamp(now + LEASE), "n": n, "per_source": self.per_source, "pool": n * 50}
        async with self.db.write() as db:
            rows = await db.execute_fetchall(CLAIM, params)
        return [Task(*row) for row in rows]

    async def complete(self, task: Task, metric: PageMetric, listing: list[tuple[str, int]], details: list[str]) -> None:
        now = stamp(self.clock())
        async with self.db.write() as db:
            await db.execute(
                "UPDATE urls SET status = 'done', retries = 0, lease_until = NULL, last_fetched = ?, last_code = ?"
                " WHERE source_id = ? AND path = ?",
                (now, metric.status, task.source_id, task.path),
            )
            await db.executemany(QUEUE_LISTING, [(task.source_id, path, page, task.run_id, now, now) for path, page in listing])
            await db.executemany(QUEUE_DETAIL, [(task.source_id, path, 0, task.run_id, now, now) for path in details])
            await self._record(db, task, metric, now, up=True)

    async def fail(self, task: Task, metric: PageMetric, retries: int, next_due: datetime | None) -> None:
        now = stamp(self.clock())
        due = None if next_due is None else stamp(next_due)
        async with self.db.write() as db:
            await db.execute(
                "UPDATE urls SET status = CASE WHEN ? IS NULL THEN 'failed' ELSE 'queued' END, retries = ?,"
                " next_due = COALESCE(?, next_due), lease_until = NULL, last_fetched = ?, last_code = ?"
                " WHERE source_id = ? AND path = ?",
                (due, retries, due, now, metric.status, task.source_id, task.path),
            )
            await self._record(db, task, metric, now, up=metric.status is not None)

    async def _record(self, db: aiosqlite.Connection, task: Task, metric: PageMetric, now: str, up: bool) -> None:
        await db.execute(
            "INSERT INTO page_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task.run_id, task.source_id, metric.host, task.kind, now, metric.status, metric.error, metric.elapsed,
             metric.bytes, metric.items, metric.fields_resolved, metric.fields_declared, metric.redactions),
        )
        await db.execute(
            "UPDATE runs SET pages = pages + ?, failures = failures + ?, items = items + ?, incomplete = incomplete + ?,"
            " fields_resolved = fields_resolved + ?, fields_declared = fields_declared + ?,"
            " below_expectation = below_expectation + ?, redactions = redactions + ?, records_new = records_new + ?"
            " WHERE id = ?",
            (int(metric.error is None), int(metric.error is not None), metric.items, metric.incomplete,
             metric.fields_resolved, metric.fields_declared, int(metric.below_expectation), metric.redactions,
             metric.records_new, task.run_id),
        )
        await db.executemany(
            "INSERT INTO run_fields VALUES (?, ?, ?, ?, ?) ON CONFLICT (run_id, kind, field) DO UPDATE SET"
            " resolved = resolved + excluded.resolved, declared = declared + excluded.declared",
            [(task.run_id, task.kind, name, hits, metric.field_items) for name, hits in metric.field_hits.items()],
        )
        await self._sighted(db, metric.host, now, up)

    async def _sighted(self, db: aiosqlite.Connection, host: str, now: str, up: bool) -> None:
        column = "last_up" if up else "last_down"
        await db.execute(f"UPDATE hosts SET {column} = ? WHERE host = ?", (now, host))
        await db.execute("INSERT INTO uptime VALUES (?, ?, ?)", (host, now, int(up)))

    async def due_probes(self, interval: timedelta) -> list[tuple[str, str]]:
        """(source id, host) for each collecting source's hosts other than its active one that nothing has
        reached or tried within `interval`."""
        rows = await self.db.rows(
            f"SELECT s.id, h.host FROM hosts h JOIN sources s ON s.id = h.source_id WHERE h.state = ?"
            f" AND s.state IN {COLLECTING} AND h.host != s.active_host"
            " AND NOT EXISTS (SELECT 1 FROM uptime u WHERE u.host = h.host AND u.checked_at >= ?) ORDER BY s.id, h.host",
            (lifecycle.MEMBER, stamp(self.clock() - interval)),
        )
        return [(row["id"], row["host"]) for row in rows]

    async def record_probe(self, host: str, up: bool) -> None:
        async with self.db.write() as db:
            await self._sighted(db, host, stamp(self.clock()), up)

    async def finish_if_done(self, run_id: int, schedule: Callable[[aiosqlite.Row], datetime]) -> aiosqlite.Row | None:
        """Closes a run once nothing of it is queued or leased. Returns the run the first time only."""
        async with self.db.write() as db:
            (open_rows,), = await db.execute_fetchall(
                "SELECT COUNT(*) FROM urls WHERE run_id = ? AND status IN ('queued', 'leased')", (run_id,)
            )
            rows = await db.execute_fetchall(
                "SELECT r.*, s.failed_runs FROM runs r JOIN sources s ON s.id = r.source_id"
                " WHERE r.id = ? AND r.finished_at IS NULL", (run_id,)
            )
            if open_rows or not rows:
                return None
            run = rows[0]
            await db.execute("UPDATE runs SET finished_at = ? WHERE id = ?", (stamp(self.clock()), run_id))
            await db.execute(
                "UPDATE sources SET next_run = ?, failed_runs = CASE WHEN ? THEN failed_runs + 1 ELSE 0 END WHERE id = ?",
                (stamp(schedule(run)), run["pages"] == 0, run["source_id"]),
            )
            return run

    async def pending(self) -> int:
        """Pages of collecting sources still to fetch: queued (a retry included) or leased."""
        (count,), = await self.db.rows(
            f"SELECT COUNT(*) FROM urls u JOIN sources s ON s.id = u.source_id"
            f" WHERE u.status IN ('queued', 'leased') AND s.state IN {COLLECTING}"
        )
        return count

    async def release_stale_leases(self) -> int:
        async with self.db.write() as db:
            cursor = await db.execute(
                "UPDATE urls SET status = 'queued', lease_until = NULL WHERE status = 'leased' AND lease_until < ?",
                (stamp(self.clock()),),
            )
            return cursor.rowcount

    async def stats(self) -> dict:
        now = self.clock()
        (recent,), = await self.db.rows(
            "SELECT COUNT(*) FROM uptime WHERE checked_at >= ?", (stamp(now - RATE_WINDOW),)
        )
        (fetches, ups), = await self.db.rows(
            "SELECT COUNT(*), COALESCE(SUM(up), 0) FROM uptime WHERE checked_at >= ?", (stamp(now - timedelta(hours=1)),)
        )
        urls = await self.db.rows("SELECT status, COUNT(*) FROM urls GROUP BY status")
        sources = await self.db.rows("SELECT state, COUNT(*) FROM sources GROUP BY state")
        hosts = await self.db.rows("SELECT state, COUNT(*) FROM hosts GROUP BY state")
        (open_runs,), = await self.db.rows("SELECT COUNT(*) FROM runs WHERE finished_at IS NULL")
        return {
            "urls": {row[0]: row[1] for row in urls}, "sources": {row[0]: row[1] for row in sources},
            "hosts": {row[0]: row[1] for row in hosts}, "open_runs": open_runs,
            "fetches_last_hour": fetches, "up_last_hour": ups, "fetches_recent": recent,
        }
