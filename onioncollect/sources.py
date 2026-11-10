import dataclasses
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable

from onioncollect import lifecycle, onion
from onioncollect.db import Database, stamp
from onioncollect.lifecycle import APPROVED, CANDIDATE, DECLINED, DISABLED, LIVE, MEMBER

SAFETY_REASON = "safety: "

SOURCE_COLUMNS = ("id", "state", "category", "active_host", "reviewer", "note", "approved_at", "state_changed_at",
                  "reason", "live_at", "next_run", "failed_runs", "cluster_id")


class RefusedChange(Exception):
    pass


def approvable(host: str, note: str, excluded: frozenset[str]) -> str:
    host = host.lower()
    if not onion.is_v3_onion(host):
        raise RefusedChange(f"{host} is not a v3 onion host")
    if host in excluded:
        raise RefusedChange(f"{host} is on the exclusion list")
    if not note.strip():
        raise RefusedChange("an approval needs a reviewer note")
    return host


@dataclass(frozen=True)
class Source:
    id: str
    state: str
    category: str
    active_host: str
    hosts: frozenset[str]


class SourceTable:
    def __init__(self, database: Database, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.db = database
        self.clock = clock

    async def resolve(self, source_id: str) -> Source | None:
        rows = await self.db.rows("SELECT id, state, category, active_host FROM sources WHERE id = ?", (source_id,))
        if not rows:
            return None
        hosts = await self.db.rows("SELECT host FROM hosts WHERE source_id = ? AND state = ?", (source_id, MEMBER))
        return Source(*rows[0], hosts=frozenset(row["host"] for row in hosts))

    async def add_candidates(self, hosts, found_on: str | None) -> int:
        # Every host the system sees lands here once and nowhere else. A host already present, declined
        # ones included, is left exactly as it was: re-discovery never resurrects anything.
        named = {host.lower() for host in hosts if onion.is_v3_onion(host)}
        rows = [(host, CANDIDATE, found_on, stamp(self.clock())) for host in sorted(named)]
        async with self.db.write() as db:
            before = db.total_changes
            await db.executemany(
                "INSERT OR IGNORE INTO hosts (host, state, found_on, first_seen) VALUES (?, ?, ?, ?)", rows
            )
            return db.total_changes - before

    async def add_redirect_target(self, source_id: str, target: str) -> int:
        """An off-source onion a source redirected to: a candidate like any other, plus the evidence triage
        shows next to it. Only host names are kept."""
        added = await self.add_candidates({target}, source_id)
        if onion.is_v3_onion(target):
            now = stamp(self.clock())
            async with self.db.write() as db:
                await db.execute(
                    "INSERT INTO redirects VALUES (?, ?, ?, ?) ON CONFLICT (target, source_id)"
                    " DO UPDATE SET last_seen = excluded.last_seen", (source_id, target.lower(), now, now),
                )
        return added

    async def redirected_from(self, hosts: list[str]) -> dict[str, list[str]]:
        rows = await self.db.rows("SELECT target, source_id FROM redirects ORDER BY source_id")
        wanted = set(hosts)
        found = {}
        for row in rows:
            if row["target"] in wanted:
                found.setdefault(row["target"], []).append(row["source_id"])
        return found

    async def approve(self, host: str, source_id: str, category: str, note: str, reviewer: str,
                      excluded: frozenset[str]) -> None:
        lifecycle.check_approval(source_id, category, note)
        host = approvable(host, note, excluded)
        now = stamp(self.clock())
        async with self.db.write() as db:
            await self._check_undecided(db, host)
            if await db.execute_fetchall("SELECT 1 FROM sources WHERE id = ?", (source_id,)):
                raise RefusedChange(f"source {source_id} already exists")
            await db.execute(
                "INSERT INTO sources (id, state, category, active_host, reviewer, note, approved_at, state_changed_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (source_id, APPROVED, category, host, reviewer, note, now, now),
            )
            await self._decide(db, host, MEMBER, source_id, reviewer, note, now)

    async def add_mirror(self, host: str, source_id: str, note: str, reviewer: str, excluded: frozenset[str]) -> None:
        """Approves a host into an existing source's host set. The source keeps its state and active host."""
        host = approvable(host, note, excluded)
        async with self.db.write() as db:
            await self._check_undecided(db, host)
            if not await db.execute_fetchall("SELECT 1 FROM sources WHERE id = ?", (source_id,)):
                raise RefusedChange(f"no source {source_id}")
            await self._decide(db, host, MEMBER, source_id, reviewer, note, stamp(self.clock()))

    async def merge(self, source_id: str, into: str, from_states: frozenset[str], reason: str,
                    into_states: frozenset[str] | None = None) -> list[str]:
        """Moves every host of one source into another's host set and disables the first with `reason`: an
        approved source folded as a mirror, or a live source merged into its twin. Returns the hosts moved."""
        now = stamp(self.clock())
        async with self.db.write() as db:
            rows = await db.execute_fetchall("SELECT id, state FROM sources WHERE id IN (?, ?)", (source_id, into))
            states = {row["id"]: row["state"] for row in rows}
            if source_id == into or into not in states:
                raise RefusedChange(f"no other source {into}")
            if states.get(source_id) not in from_states:
                raise RefusedChange(f"{source_id} is {states.get(source_id, 'not a source')}, and only"
                                    f" {' or '.join(sorted(from_states))} can be merged into another source")
            if into_states is not None and states[into] not in into_states:
                raise RefusedChange(f"{into} is {states[into]}, not {' or '.join(sorted(into_states))}")
            moved = await db.execute_fetchall(
                "UPDATE hosts SET source_id = ? WHERE source_id = ? AND state = ? RETURNING host",
                (into, source_id, MEMBER),
            )
            await db.execute(
                "UPDATE sources SET state = ?, state_changed_at = ?, reason = ? WHERE id = ?",
                (DISABLED, now, reason, source_id),
            )
            await db.execute("UPDATE runs SET finished_at = ? WHERE source_id = ? AND finished_at IS NULL",
                             (now, source_id))
        return sorted(row["host"] for row in moved)

    async def set_active_host(self, source_id: str, host: str) -> str:
        """Points a source at another host of its own set. Returns the host it was on."""
        async with self.db.write() as db:
            rows = await db.execute_fetchall(
                "SELECT s.active_host FROM sources s JOIN hosts h ON h.source_id = s.id"
                " WHERE s.id = ? AND h.host = ? AND h.state = ?", (source_id, host, MEMBER),
            )
            if not rows:
                raise RefusedChange(f"{host} is not in {source_id}'s host set")
            await db.execute("UPDATE sources SET active_host = ? WHERE id = ?", (host, source_id))
        return rows[0]["active_host"]

    async def reapprove(self, source_id: str, note: str, reviewer: str) -> None:
        """Disabled back to approved, so the source can go through golive again. A source the safety check
        disabled stays disabled, and one folded or merged away has no hosts left to approve."""
        if not note.strip():
            raise RefusedChange("reapproving needs a reviewer note")
        source = await self.get(source_id)
        if source is None:
            raise RefusedChange(f"no source {source_id}")
        if (source["reason"] or "").startswith(SAFETY_REASON):
            raise RefusedChange(f"{source_id} was disabled by the safety check ({source['reason']})")
        if source["state"] == DISABLED and not await self.db.rows(
                "SELECT 1 FROM hosts WHERE source_id = ? AND state = ?", (source_id, MEMBER)):
            raise RefusedChange(f"{source_id} has no hosts left ({source['reason']})")
        await self.change_state(source_id, APPROVED, f"reapproved: {note}")
        async with self.db.write() as db:
            await db.execute("UPDATE sources SET reviewer = ? WHERE id = ?", (reviewer, source_id))

    async def append_note(self, source_id: str, text: str, reviewer: str) -> str:
        """Adds a dated correction under a source's note and returns it. The note is extended inside the UPDATE
        and never passes through this process, so what the reviewer wrote at approval cannot be rewritten."""
        if not text.strip():
            raise RefusedChange("a correction needs its text")
        line = f"correction {self.clock():%Y-%m-%d} by {reviewer}: {' '.join(text.split())}"
        async with self.db.write() as db:
            if not await db.execute_fetchall(
                    "UPDATE sources SET note = note || char(10) || ? WHERE id = ? RETURNING id", (line, source_id)):
                raise RefusedChange(f"no source {source_id}")
        return line

    async def members(self) -> dict[str, str]:
        rows = await self.db.rows("SELECT host, source_id FROM hosts WHERE state = ?", (MEMBER,))
        return {row["host"]: row["source_id"] for row in rows}

    async def set_clusters(self, clusters: dict[str, str]) -> set[str]:
        """Writes the cluster ids. Returns the clusters that gained a source: those are the only places a
        record can now sit twice, once under each of two sources."""
        async with self.db.write() as db:
            before = {row["id"]: row["cluster_id"] for row in await db.execute_fetchall("SELECT id, cluster_id FROM sources")}
            await db.execute("UPDATE sources SET cluster_id = NULL WHERE cluster_id IS NOT NULL")
            await db.executemany("UPDATE sources SET cluster_id = ? WHERE id = ?",
                                 [(cluster, source_id) for source_id, cluster in clusters.items()])
        earlier = {}
        for source_id, cluster in clusters.items():
            earlier.setdefault(cluster, set()).add(before.get(source_id))
        return {cluster for cluster, was in earlier.items() if len(was) > 1 or None in was}

    async def in_cluster(self, cluster: str) -> tuple[str, ...]:
        rows = await self.db.rows("SELECT id FROM sources WHERE cluster_id = ? ORDER BY id", (cluster,))
        return tuple(row["id"] for row in rows)

    async def cluster_of(self, source_id: str) -> tuple[str, ...]:
        """The source ids whose records dedupe together: the source's cluster, or the source alone."""
        rows = await self.db.rows(
            "SELECT id FROM sources WHERE cluster_id = (SELECT cluster_id FROM sources WHERE id = ?) ORDER BY id",
            (source_id,),
        )
        return tuple(row["id"] for row in rows) or (source_id,)

    async def decline(self, host: str, reason: str, reviewer: str) -> None:
        host = host.lower()
        if not onion.is_v3_onion(host):
            raise RefusedChange(f"{host} is not a v3 onion host")
        if not reason.strip():
            raise RefusedChange("a decline needs a policy reason")
        async with self.db.write() as db:
            await self._check_undecided(db, host)
            await self._decide(db, host, DECLINED, None, reviewer, reason, stamp(self.clock()))

    async def _check_undecided(self, db, host: str) -> None:
        rows = await db.execute_fetchall("SELECT state FROM hosts WHERE host = ?", (host,))
        if rows and rows[0]["state"] != CANDIDATE:
            raise RefusedChange(f"{host} was already reviewed ({rows[0]['state']})")

    async def _decide(self, db, host: str, state: str, source_id: str | None, reviewer: str, reason: str,
                      now: str) -> None:
        # A requested host that was never discovered is reviewed all the same, from a fresh row.
        await db.execute(
            "INSERT INTO hosts (host, state, first_seen) VALUES (?, ?, ?) ON CONFLICT (host) DO NOTHING",
            (host, CANDIDATE, now),
        )
        await db.execute(
            "UPDATE hosts SET state = ?, source_id = ?, decided_at = ?, decided_by = ?, reason = ? WHERE host = ?",
            (state, source_id, now, reviewer, reason, host),
        )

    async def change_state(self, source_id: str, target: str, reason: str | None = None) -> None:
        now = stamp(self.clock())
        async with self.db.write() as db:
            rows = await db.execute_fetchall("SELECT state FROM sources WHERE id = ?", (source_id,))
            if not rows:
                raise RefusedChange(f"no source {source_id}")
            try:
                lifecycle.check_transition(rows[0]["state"], target)
            except ValueError as exc:
                raise RefusedChange(str(exc)) from None
            if target == DISABLED and not (reason or "").strip():
                raise RefusedChange("disabling a source needs a reason")
            live = target == LIVE and rows[0]["state"] == APPROVED
            await db.execute(
                "UPDATE sources SET state = ?, state_changed_at = ?, reason = ?,"
                " live_at = CASE WHEN ? THEN ? ELSE live_at END, next_run = CASE WHEN ? THEN ? ELSE next_run END"
                " WHERE id = ?",
                (target, now, reason, live, now, live, now, source_id),
            )
            if target in (DISABLED, APPROVED):
                # Its queued rows wait out of reach of claim; an open run would keep it off the schedule forever.
                await db.execute("UPDATE runs SET finished_at = ? WHERE source_id = ? AND finished_at IS NULL",
                                 (now, source_id))

    async def add_golive_report(self, source_id: str, passed: bool, lines: list[tuple[bool, str]]) -> None:
        """Every golive's output, pass or fail, kept for the write-up's fail-then-pass example."""
        async with self.db.write() as db:
            await db.execute("INSERT INTO golive_reports (source_id, run_at, passed, lines) VALUES (?, ?, ?, ?)",
                             (source_id, stamp(self.clock()), int(passed), json.dumps(lines)))

    async def get(self, source_id: str) -> dict | None:
        rows = await self.db.rows(f"SELECT {', '.join(SOURCE_COLUMNS)} FROM sources WHERE id = ?", (source_id,))
        if not rows:
            return None
        hosts = await self.db.rows("SELECT host FROM hosts WHERE source_id = ? ORDER BY host", (source_id,))
        return dict(rows[0]) | {"hosts": [row["host"] for row in hosts]}

    async def sources(self, state: str | None = None) -> list[dict]:
        rows = await self.db.rows(
            f"SELECT {', '.join(SOURCE_COLUMNS)} FROM sources WHERE ? IS NULL OR state = ? ORDER BY id", (state, state)
        )
        return [dict(row) for row in rows]

    async def hosts(self, state: str | None = None) -> list[dict]:
        rows = await self.db.rows(
            "SELECT host, state, source_id, found_on, first_seen, decided_at, decided_by, reason, last_up, last_down"
            " FROM hosts WHERE ? IS NULL OR state = ? ORDER BY first_seen, host", (state, state)
        )
        return [dict(row) for row in rows]


class PinnedHost:
    """The source table as the fetcher sees it, with one source resolved to a chosen host of its own set.
    Only the active host changes: the fetcher still refuses a host outside the source's approved set, its
    config or the exclusion list, and a source in a state it was not built for. Sibling probes and the
    mirror-swap and fixed checks fetch through this, so a non-active host never needs a URL."""

    def __init__(self, table: SourceTable, host: str):
        self.table = table
        self.host = host

    async def resolve(self, source_id: str) -> Source | None:
        source = await self.table.resolve(source_id)
        return source and dataclasses.replace(source, active_host=self.host)
