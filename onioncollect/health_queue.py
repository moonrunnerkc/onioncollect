"""Section 13's queue: open items per source and kind, and the dispositions that close them.

An open item makes a live source degraded; closing a source's last open item makes it live again. Every
disposition, applied or refused, is a row in the audit trail.
"""
from datetime import UTC, datetime
from typing import Callable

import aiosqlite

from onioncollect import health, lifecycle
from onioncollect.db import Database, stamp
from onioncollect.health import Finding, RunSummary
from onioncollect.sources import RefusedChange, SourceTable

AUTOMATIC = "health"
OPEN = "open"
RUN_METRICS = """
SELECT r.id, r.started_at, r.finished_at, r.pages, r.failures, r.items, r.incomplete, r.fields_resolved,
       r.fields_declared, r.redactions, r.records_new,
       COUNT(p.run_id) AS attempts, COUNT(p.status) AS answered, AVG(p.elapsed) AS mean_elapsed,
       MAX(p.elapsed) AS max_elapsed, SUM(p.error IS 'parse_refused') AS parse_refused,
       (SELECT status FROM page_metrics q WHERE q.run_id = r.id AND q.status IS NOT NULL
        GROUP BY status ORDER BY COUNT(*) DESC, status LIMIT 1) AS status
FROM runs r LEFT JOIN page_metrics p ON p.run_id = r.id
WHERE r.source_id = ? GROUP BY r.id ORDER BY r.id DESC LIMIT ?
"""


class HealthQueue:
    def __init__(self, database: Database, sources: SourceTable,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.db = database
        self.sources = sources
        self.clock = clock

    async def raise_item(self, source_id: str, finding: Finding, run_id: int | None) -> int:
        """Opens an item, or refreshes the open one of the same kind with this run's numbers."""
        now = stamp(self.clock())
        async with self.db.write() as db:
            rows = await db.execute_fetchall(
                "UPDATE health_items SET priority = ?, detail = ?, last_seen = ?, last_run_id = ?,"
                " occurrences = occurrences + 1 WHERE source_id = ? AND kind = ? AND status = ? RETURNING id",
                (finding.priority, finding.detail, now, run_id, source_id, finding.kind, OPEN),
            )
            if rows:
                item = rows[0]["id"]
            else:
                cursor = await db.execute(
                    "INSERT INTO health_items (source_id, kind, priority, detail, opened_at, last_seen, last_run_id)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)", (source_id, finding.kind, finding.priority, finding.detail, now,
                                                      now, run_id),
                )
                item = cursor.lastrowid
        source = await self.sources.get(source_id)
        if source is not None and source["state"] == lifecycle.LIVE:
            await self.sources.change_state(source_id, lifecycle.DEGRADED)
        return item

    async def after_run(self, run: aiosqlite.Row, min_items: int, required: tuple[str, ...],
                        category: str) -> list[Finding]:
        """Raises what a finished run calls for, judged by its config's expectations, then ends any snooze this
        run has run out."""
        source = await self.sources.get(run["source_id"])
        if source is None or source["state"] not in lifecycle.COLLECTING:
            return []
        found = health.assess(await self.summary(run), min_items, required, category)
        for finding in found:
            await self.raise_item(run["source_id"], finding, run["id"])
        await self._end_snoozes(run["source_id"])
        return found

    async def summary(self, run: aiosqlite.Row) -> RunSummary:
        pages = await self.db.rows("SELECT kind, error FROM page_metrics WHERE run_id = ? ORDER BY rowid", (run["id"],))
        hits = await self.db.rows("SELECT field, resolved FROM run_fields WHERE run_id = ? AND kind = 'listing'",
                                  (run["id"],))
        errors = [row["error"] for row in pages if row["error"]]
        return RunSummary(
            pages=run["pages"], failed_runs=run["failed_runs"] + 1 if run["pages"] == 0 else 0,
            listing_pages=sum(row["kind"] == "listing" and row["error"] is None for row in pages),
            items=run["items"], incomplete=run["incomplete"], parse_refused=errors.count("parse_refused"),
            last_error=errors[-1] if errors else None, field_hits={row["field"]: row["resolved"] for row in hits},
        )

    async def _end_snoozes(self, source_id: str) -> None:
        # A watched item that did not recur while snoozed closes itself; one that did comes back to the queue.
        (finished,), = await self.db.rows(
            "SELECT COUNT(*) FROM runs WHERE source_id = ? AND finished_at IS NOT NULL", (source_id,))
        due = await self.db.rows(
            "SELECT * FROM health_items WHERE source_id = ? AND status = ? AND snoozed_until_run <= ?",
            (source_id, OPEN, finished),
        )
        for item in due:
            if item["last_seen"] <= item["watched_at"]:
                await self._close(item, health.WATCHING, "no recurrence while watched", AUTOMATIC, "")
            else:
                async with self.db.write() as db:
                    await db.execute("UPDATE health_items SET snoozed_until_run = NULL WHERE id = ?", (item["id"],))
        await self._restore(source_id)

    async def item(self, item_id: int) -> dict:
        rows = await self.db.rows("SELECT * FROM health_items WHERE id = ?", (item_id,))
        if not rows:
            raise RefusedChange(f"no health item {item_id}")
        return dict(rows[0])

    async def open_item(self, item_id: int) -> dict:
        item = await self.item(item_id)
        if item["status"] != OPEN:
            raise RefusedChange(f"health item {item_id} is already resolved")
        return item

    async def queue(self) -> list[dict]:
        """Open items, priority then age. Snoozed ones come last, marked by snoozed_until_run."""
        rows = await self.db.rows(
            "SELECT * FROM health_items WHERE status = ?"
            " ORDER BY snoozed_until_run IS NOT NULL, priority DESC, opened_at, id", (OPEN,))
        return [dict(row) for row in rows]

    async def resolve(self, item_id: int, disposition: str, note: str, by: str, detail: str = "") -> None:
        item = await self.open_item(item_id)
        await self._close(item, disposition, note, by, detail)
        await self._restore(item["source_id"])

    async def refused(self, item_id: int, disposition: str, note: str, by: str, detail: str) -> None:
        """A disposition whose checks failed: on the record, and the item stays open."""
        item = await self.open_item(item_id)
        async with self.db.write() as db:
            await self._log(db, item, disposition, False, note, by, detail)

    async def watch(self, item_id: int, runs: int, note: str, by: str) -> None:
        if runs < 1:
            raise RefusedChange("watching needs at least one run")
        item = await self.open_item(item_id)
        (finished,), = await self.db.rows(
            "SELECT COUNT(*) FROM runs WHERE source_id = ? AND finished_at IS NOT NULL", (item["source_id"],))
        async with self.db.write() as db:
            await db.execute("UPDATE health_items SET snoozed_until_run = ?, watched_at = ? WHERE id = ?",
                             (finished + runs, stamp(self.clock()), item_id))
            await self._log(db, item, health.WATCHING, True, note, by, f"snoozed for {runs} runs")

    async def close_source(self, source_id: str, disposition: str, note: str, by: str) -> int:
        """Closes every open item of a source, for a disable, a merge or a passed golive."""
        items = await self.db.rows("SELECT * FROM health_items WHERE source_id = ? AND status = ?", (source_id, OPEN))
        for item in items:
            await self._close(item, disposition, note, by, "")
        await self._restore(source_id)
        return len(items)

    async def _close(self, item, disposition: str, note: str, by: str, detail: str) -> None:
        if not note.strip():
            raise RefusedChange("a disposition needs a note")
        async with self.db.write() as db:
            await db.execute("UPDATE health_items SET status = ?, resolved_at = ?, snoozed_until_run = NULL"
                             " WHERE id = ?", (disposition, stamp(self.clock()), item["id"]))
            await self._log(db, item, disposition, True, note, by, detail)

    async def _log(self, db, item, disposition: str, applied: bool, note: str, by: str, detail: str) -> None:
        if disposition not in health.DISPOSITIONS:
            raise RefusedChange(f"disposition must be one of {', '.join(health.DISPOSITIONS)}")
        await db.execute(
            "INSERT INTO dispositions (item_id, source_id, disposition, applied, note, detail, decided_by, decided_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (item["id"], item["source_id"], disposition, int(applied), note, detail, by, stamp(self.clock())),
        )

    async def _restore(self, source_id: str) -> None:
        source = await self.sources.get(source_id)
        if source is None or source["state"] != lifecycle.DEGRADED:
            return
        if not await self.db.rows("SELECT 1 FROM health_items WHERE source_id = ? AND status = ?", (source_id, OPEN)):
            await self.sources.change_state(source_id, lifecycle.LIVE)

    async def log(self, source_id: str | None = None) -> list[dict]:
        rows = await self.db.rows(
            "SELECT d.*, i.kind, i.detail AS item_detail, i.opened_at FROM dispositions d"
            " JOIN health_items i ON i.id = d.item_id WHERE ? IS NULL OR d.source_id = ? ORDER BY d.decided_at, d.id",
            (source_id, source_id),
        )
        return [dict(row) for row in rows]

    async def run_metrics(self, source_id: str, limit: int) -> list[dict]:
        return [dict(row) for row in await self.db.rows(RUN_METRICS, (source_id, limit))]
