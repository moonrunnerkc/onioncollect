"""Run bookkeeping in collect.db, the writer's side of a crawl: which sources are due, each run's totals, per-page
metrics, per-field hits, host sightings and the paths a run fetched. The crawler's queue of paths is db.Frontier,
in its own state dir; this never sees it."""
from datetime import UTC, datetime, timedelta
from typing import Callable

import aiosqlite

from onioncollect import detect, lifecycle
from onioncollect.db import COLLECTING, RATE_WINDOW, Database, PageMetric, stamp
from onioncollect.sources import RefusedChange


class RunLog:
    def __init__(self, database: Database, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.db = database
        self.clock = clock

    async def due_sources(self) -> list[str]:
        rows = await self.db.rows(
            f"SELECT id FROM sources s WHERE state IN {COLLECTING} AND (next_run IS NULL OR next_run <= ?)"
            " AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.source_id = s.id AND r.finished_at IS NULL) ORDER BY id",
            (stamp(self.clock()),),
        )
        return [row["id"] for row in rows]

    async def collecting(self) -> list[str]:
        rows = await self.db.rows(f"SELECT id FROM sources WHERE state IN {COLLECTING} ORDER BY id")
        return [row["id"] for row in rows]

    async def start(self, source_id: str) -> int:
        async with self.db.write() as db:
            if not await db.execute_fetchall(f"SELECT 1 FROM sources WHERE id = ? AND state IN {COLLECTING}",
                                             (source_id,)):
                raise RefusedChange(f"{source_id} is not collecting")
            cursor = await db.execute("INSERT INTO runs (source_id, started_at) VALUES (?, ?)",
                                      (source_id, stamp(self.clock())))
            return cursor.lastrowid

    async def record_page(self, run_id: int, source_id: str, kind: str, path: str, metric: PageMetric) -> None:
        now = stamp(self.clock())
        async with self.db.write() as db:
            await db.execute(
                "INSERT INTO page_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, source_id, metric.host, kind, now, metric.status, metric.error, metric.elapsed,
                 metric.bytes, metric.items, metric.fields_resolved, metric.fields_declared, metric.redactions),
            )
            await db.execute(
                "UPDATE runs SET pages = pages + ?, failures = failures + ?, items = items + ?,"
                " incomplete = incomplete + ?, fields_resolved = fields_resolved + ?,"
                " fields_declared = fields_declared + ?, below_expectation = below_expectation + ?,"
                " redactions = redactions + ?, records_new = records_new + ? WHERE id = ? AND source_id = ?",
                (int(metric.error is None), int(metric.error is not None), metric.items, metric.incomplete,
                 metric.fields_resolved, metric.fields_declared, int(metric.below_expectation), metric.redactions,
                 metric.records_new, run_id, source_id),
            )
            await db.executemany(
                "INSERT INTO run_fields VALUES (?, ?, ?, ?, ?) ON CONFLICT (run_id, kind, field) DO UPDATE SET"
                " resolved = resolved + excluded.resolved, declared = declared + excluded.declared",
                [(run_id, kind, name, hits, metric.field_items) for name, hits in metric.field_hits.items()],
            )
            # A path is a link a page named, so it could carry secret-shaped text in its query; such a path is
            # left out rather than stored.
            if not detect.contains_secret(path):
                await db.execute(
                    "INSERT INTO visited_paths VALUES (?, ?, ?, ?) ON CONFLICT (source_id, path)"
                    " DO UPDATE SET last_seen = excluded.last_seen", (source_id, path, now, now))
            await self._sighted(db, metric.host, now, up=metric.status is not None)

    async def record_probe(self, host: str, up: bool) -> None:
        async with self.db.write() as db:
            await self._sighted(db, host, stamp(self.clock()), up)

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

    async def finish(self, run_id: int, schedule: Callable[[aiosqlite.Row], datetime]) -> aiosqlite.Row | None:
        """Closes a run the crawler has nothing left of. Returns the run the first time only."""
        async with self.db.write() as db:
            rows = await db.execute_fetchall(
                "SELECT r.*, s.failed_runs FROM runs r JOIN sources s ON s.id = r.source_id"
                " WHERE r.id = ? AND r.finished_at IS NULL", (run_id,)
            )
            if not rows:
                return None
            run = rows[0]
            await db.execute("UPDATE runs SET finished_at = ? WHERE id = ?", (stamp(self.clock()), run_id))
            await db.execute(
                "UPDATE sources SET next_run = ?, failed_runs = CASE WHEN ? THEN failed_runs + 1 ELSE 0 END WHERE id = ?",
                (stamp(schedule(run)), run["pages"] == 0, run["source_id"]),
            )
            return run

    async def stats(self) -> dict:
        now = self.clock()
        (recent,), = await self.db.rows(
            "SELECT COUNT(*) FROM uptime WHERE checked_at >= ?", (stamp(now - RATE_WINDOW),)
        )
        (fetches, ups), = await self.db.rows(
            "SELECT COUNT(*), COALESCE(SUM(up), 0) FROM uptime WHERE checked_at >= ?", (stamp(now - timedelta(hours=1)),)
        )
        sources = await self.db.rows("SELECT state, COUNT(*) FROM sources GROUP BY state")
        hosts = await self.db.rows("SELECT state, COUNT(*) FROM hosts GROUP BY state")
        (open_runs,), = await self.db.rows("SELECT COUNT(*) FROM runs WHERE finished_at IS NULL")
        return {
            "sources": {row[0]: row[1] for row in sources}, "hosts": {row[0]: row[1] for row in hosts},
            "open_runs": open_runs, "fetches_last_hour": fetches, "up_last_hour": ups, "fetches_recent": recent,
        }
