import asyncio
import hashlib
import itertools
import json
import os
import re
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from onioncollect import detect, schema, search
from onioncollect.db import Database, stamp
from onioncollect.fingerprint import Fingerprint, to_hex
from onioncollect.redact import Redacted

KEYED_HASH = re.compile(r"[0-9a-f]{64}")


class RefusedWrite(Exception):
    pass


async def refuse_secrets(*texts: str) -> None:
    # The second detector. The redaction gate should have left nothing; if it did, nothing is written.
    # A snapshot is up to 2 MB of hostile text, so the scan runs off the event loop.
    if await asyncio.to_thread(lambda: any(detect.contains_secret(text) for text in texts)):
        raise RefusedWrite("a secret survived redaction")


def check_summary(summary: Redacted) -> None:
    if not all(KEYED_HASH.fullmatch(value) for value in summary.hashes):
        raise RefusedWrite("hashes must be keyed SHA-256 hex digests")


def fts_text(fields: dict[str, str]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in fields.items())


class RecordStore:
    """Redacted records and snapshots only. Every write is checked again before it lands."""

    def __init__(self, root: Path, record_retention: timedelta, snapshot_retention: timedelta,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.root = root
        self.snapshot_dir = root / "snapshots"
        self.record_retention = record_retention
        self.snapshot_retention = snapshot_retention
        self.clock = clock
        self.db = Database()

    async def open(self, read_only: bool = False) -> None:
        if not read_only:
            # Group-readable: in the guest the group is the analyst's, which reads and never writes.
            for directory in (self.root, self.snapshot_dir):
                directory.mkdir(mode=0o750, parents=True, exist_ok=True)
                # Only when wrong: a chmod would also clear the setgid bit that keeps new files in that group.
                if stat.S_IMODE(directory.stat().st_mode) & 0o777 != 0o750:
                    directory.chmod(0o750)
        await self.db.open(self.root / "records.db", schema.RECORDS, read_only=read_only)

    async def close(self) -> None:
        await self.db.close()

    async def add(self, source_id: str, category: str, content_hash: str, follow_path: str | None,
                  fields: dict[str, str], summary: Redacted, *, host: str, cluster: tuple[str, ...]) -> bool:
        """Stores a record unless one with its content hash exists anywhere in the source's mirror cluster;
        either way the host it was read from is sighted on the row. True for a new row."""
        await refuse_secrets(*fields.values(), *fields.keys())
        check_summary(summary)
        sources = tuple(dict.fromkeys((source_id, *cluster)))
        now, expires = stamp(self.clock()), stamp(self.clock() + self.record_retention)
        async with self.db.write() as db:
            seen = await db.execute_fetchall(
                "UPDATE records SET last_seen = ?, expires_at = ? WHERE content_hash = ?"
                f" AND source_id IN ({', '.join('?' * len(sources))}) RETURNING id",
                (now, expires, content_hash, *sources),
            )
            ids = [row["id"] for row in seen]
            if not ids:
                cursor = await db.execute(
                    "INSERT INTO records (source_id, category, content_hash, follow_path, fields, redactions, hashes,"
                    " first_seen, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (source_id, category, content_hash, follow_path, json.dumps(fields), json.dumps(summary.counts),
                     json.dumps(summary.hashes), now, now, expires),
                )
                ids = [cursor.lastrowid]
                await db.execute("INSERT INTO records_fts (rowid, text) VALUES (?, ?)", (ids[0], fts_text(fields)))
            await db.executemany(
                "INSERT INTO record_hosts VALUES (?, ?, ?, ?, ?) ON CONFLICT (record_id, host)"
                " DO UPDATE SET source_id = excluded.source_id, last_seen = excluded.last_seen",
                [(record_id, host, source_id, now, now) for record_id in ids],
            )
            return not seen

    async def add_detail(self, source_id: str, follow_path: str, fields: dict[str, str], summary: Redacted) -> int:
        """Merges a detail page into every record this source sighted with that follow path, including rows
        a cluster sibling stored first."""
        await refuse_secrets(*fields.values(), *fields.keys())
        check_summary(summary)
        async with self.db.write() as db:
            rows = await db.execute_fetchall(
                "SELECT id, fields, redactions, hashes FROM records WHERE follow_path = ?"
                " AND id IN (SELECT record_id FROM record_hosts WHERE source_id = ?)",
                (follow_path, source_id),
            )
            for row in rows:
                merged = json.loads(row["fields"]) | fields
                counts = json.loads(row["redactions"])
                for kind, count in summary.counts.items():
                    counts[kind] = counts.get(kind, 0) + count
                hashes = sorted(set(json.loads(row["hashes"])) | set(summary.hashes))
                await db.execute(
                    "UPDATE records SET fields = ?, redactions = ?, hashes = ? WHERE id = ?",
                    (json.dumps(merged), json.dumps(counts), json.dumps(hashes), row["id"]),
                )
                await db.execute("DELETE FROM records_fts WHERE rowid = ?", (row["id"],))
                await db.execute("INSERT INTO records_fts (rowid, text) VALUES (?, ?)", (row["id"], fts_text(merged)))
            return len(rows)

    async def save_snapshot(self, source_id: str, path: str, kind: str, html: str) -> str:
        await refuse_secrets(html)
        digest = self._write_snapshot(html)
        now = self.clock()
        async with self.db.write() as db:
            await db.execute("INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, 0)",
                             (digest, source_id, path, kind, stamp(now), stamp(now + self.snapshot_retention)))
        return digest

    async def save_baselines(self, source_id: str, pages: list[tuple[str, str]]) -> None:
        """Golive's seed snapshots, together the source's known-good layout. They replace any earlier set."""
        await refuse_secrets(*(html for _, html in pages))
        digests = [(path, self._write_snapshot(html)) for path, html in pages]
        now = self.clock()
        async with self.db.write() as db:
            await db.execute("UPDATE snapshots SET baseline = 0 WHERE source_id = ?", (source_id,))
            await db.executemany(
                "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, 1)",
                [(digest, source_id, path, "listing", stamp(now), stamp(now + self.snapshot_retention))
                 for path, digest in digests],
            )

    def _write_snapshot(self, html: str) -> str:
        data = html.encode()
        digest = hashlib.sha256(data).hexdigest()
        target = self.snapshot_path(digest)
        if not target.exists():
            target.parent.mkdir(mode=0o750, exist_ok=True)
            temp = target.with_suffix(".tmp")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(temp, target)
        return digest

    async def save_fingerprint(self, host: str, path: str, seed: bool, fingerprint: Fingerprint) -> None:
        async with self.db.write() as db:
            await db.execute(
                "INSERT INTO fingerprints VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (host, path) DO UPDATE SET"
                " seed = excluded.seed, content = excluded.content, structure = excluded.structure,"
                " words = excluded.words, seen_at = excluded.seen_at",
                (host, path, int(seed), to_hex(fingerprint.content), to_hex(fingerprint.structure), fingerprint.words,
                 stamp(self.clock())),
            )

    async def seed_fingerprints(self) -> dict[str, list[Fingerprint]]:
        rows = await self.db.rows("SELECT host, content, structure, words FROM fingerprints WHERE seed = 1")
        found = {}
        for row in rows:
            found.setdefault(row["host"], []).append(
                Fingerprint(int(row["content"], 16), int(row["structure"], 16), row["words"]))
        return found

    async def latest_snapshot(self, source_id: str, kind: str) -> tuple[str, str, str] | None:
        """(path, taken_at, redacted html) of the newest snapshot of a kind."""
        rows = await self.db.rows(
            "SELECT digest, path, taken_at FROM snapshots WHERE source_id = ? AND kind = ?"
            " ORDER BY taken_at DESC, rowid DESC LIMIT 1", (source_id, kind),
        )
        if not rows:
            return None
        return rows[0]["path"], rows[0]["taken_at"], self.snapshot_path(rows[0]["digest"]).read_text()

    async def baseline_for(self, source_id: str, path: str) -> tuple[str, str] | None:
        rows = await self.db.rows(
            "SELECT digest, taken_at FROM snapshots WHERE source_id = ? AND path = ? AND baseline = 1", (source_id, path))
        return (rows[0]["taken_at"], self.snapshot_path(rows[0]["digest"]).read_text()) if rows else None

    async def merge(self, source_ids: tuple[str, ...]) -> tuple[int, int]:
        """Backfills cluster dedup: rows of these sources sharing a content hash become the oldest of them.
        It keeps the earliest first_seen and gains every host sighting, the latest last_seen and any field a
        detail page added to a copy. Returns (hashes merged, rows removed)."""
        marks = ", ".join("?" * len(source_ids))
        rows = await self.db.rows(
            f"SELECT * FROM records WHERE source_id IN ({marks}) AND content_hash IN (SELECT content_hash FROM records"
            f" WHERE source_id IN ({marks}) GROUP BY content_hash HAVING COUNT(*) > 1)"
            " ORDER BY content_hash, first_seen, id", (*source_ids, *source_ids),
        )
        merged = []
        for _, group in itertools.groupby(rows, key=lambda row: row["content_hash"]):
            keep, *rest = group
            fields, counts, hashes = {}, {}, set()
            for row in [*reversed(rest), keep]:
                fields |= json.loads(row["fields"])
                for kind, count in json.loads(row["redactions"]).items():
                    counts[kind] = max(counts.get(kind, 0), count)
                hashes |= set(json.loads(row["hashes"]))
            follow = next((row["follow_path"] for row in (keep, *rest) if row["follow_path"]), None)
            merged.append((keep, rest, fields, counts, sorted(hashes), follow))
        await refuse_secrets(*(text for _, _, fields, *_ in merged for text in (*fields.values(), *fields.keys())))
        async with self.db.write() as db:
            for keep, rest, fields, counts, hashes, follow in merged:
                losers = [row["id"] for row in rest]
                gone = ", ".join("?" * len(losers))
                await db.execute(
                    "INSERT INTO record_hosts SELECT ?, host, source_id, first_seen, last_seen FROM record_hosts"
                    f" WHERE record_id IN ({gone}) ON CONFLICT (record_id, host) DO UPDATE SET"
                    " first_seen = MIN(first_seen, excluded.first_seen), last_seen = MAX(last_seen, excluded.last_seen)",
                    (keep["id"], *losers),
                )
                for table, column in (("record_hosts", "record_id"), ("records_fts", "rowid"), ("records", "id")):
                    await db.execute(f"DELETE FROM {table} WHERE {column} IN ({gone})", losers)
                await db.execute(
                    "UPDATE records SET fields = ?, redactions = ?, hashes = ?, follow_path = ?, last_seen = ?,"
                    " expires_at = ? WHERE id = ?",
                    (json.dumps(fields), json.dumps(counts), json.dumps(hashes), follow,
                     max(row["last_seen"] for row in (keep, *rest)), max(row["expires_at"] for row in (keep, *rest)),
                     keep["id"]),
                )
                await db.execute("DELETE FROM records_fts WHERE rowid = ?", (keep["id"],))
                await db.execute("INSERT INTO records_fts (rowid, text) VALUES (?, ?)", (keep["id"], fts_text(fields)))
        return len(merged), sum(len(rest) for _, rest, *_ in merged)

    async def relabel(self, source_id: str, into: str, category: str) -> int:
        """Moves a merged-away source's rows and sightings to the source it became. Merge them first, so no
        content hash is left under both."""
        async with self.db.write() as db:
            cursor = await db.execute("UPDATE records SET source_id = ?, category = ? WHERE source_id = ?",
                                      (into, category, source_id))
            await db.execute("UPDATE record_hosts SET source_id = ? WHERE source_id = ?", (into, source_id))
            return cursor.rowcount

    async def search(self, query: str, source: str | None = None, category: str | None = None,
                     since: datetime | None = None, until: datetime | None = None,
                     limit: int = search.LIMIT) -> list[dict]:
        bound = search.parameters(query, source, category, since and stamp(since), until and stamp(until), limit)
        try:
            rows = await self.db.rows(search.SQL, bound)
        except sqlite3.OperationalError as exc:
            raise ValueError(f"search query: {exc}") from None
        return [dict(row) | {"fields": json.loads(row["fields"]), "sources": sorted((row["sources"] or "").split(","))}
                for row in rows]

    async def sweep(self) -> tuple[int, int]:
        # Section 3's clocks. A source's baseline snapshot outlives the clock until a newer baseline replaces it.
        now = stamp(self.clock())
        async with self.db.write() as db:
            records = await db.execute_fetchall("DELETE FROM records WHERE expires_at < ? RETURNING id", (now,))
            await db.executemany("DELETE FROM records_fts WHERE rowid = ?", [(row["id"],) for row in records])
            await db.executemany("DELETE FROM record_hosts WHERE record_id = ?", [(row["id"],) for row in records])
            # Seed fingerprints are what clustering compares and are refreshed every run; the rest age out with
            # the snapshots they describe.
            await db.execute("DELETE FROM fingerprints WHERE seed = 0 AND seen_at < ?",
                             (stamp(self.clock() - self.snapshot_retention),))
            snapshots = await db.execute_fetchall(
                "DELETE FROM snapshots WHERE expires_at < ? AND baseline = 0 RETURNING digest", (now,)
            )
            kept = {row[0] for row in await db.execute_fetchall("SELECT digest FROM snapshots")}
        for digest in {row["digest"] for row in snapshots} - kept:
            self.snapshot_path(digest).unlink(missing_ok=True)
        return len(records), len(snapshots)

    async def counts(self) -> dict:
        (records,), = await self.db.rows("SELECT COUNT(*) FROM records")
        (snapshots,), = await self.db.rows("SELECT COUNT(*) FROM snapshots")
        return {"records": records, "snapshots": snapshots}

    def snapshot_path(self, digest: str) -> Path:
        return self.snapshot_dir / digest[:2] / f"{digest}.html"
