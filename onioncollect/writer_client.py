"""The crawler's side of the write socket: one connection per op, a bounded wait for the reply, typed errors.
Its methods carry the names the source table's had, so the fetcher, PinnedHost and Logins take it in the table's
place. The crawler holds no connection to any store file; the only database it opens is its frontier."""
import asyncio
import dataclasses
import json
from pathlib import Path

from onioncollect import wire
from onioncollect.db import PageMetric, Task
from onioncollect.matching import Fingerprint
from onioncollect.sources import RefusedChange, Source

TIMEOUT = 60.0
CONNECT_ATTEMPTS = 3
RETRY_PAUSE = 1.0


class WriterUnavailable(Exception):
    """No writer answered on the socket."""


class WriterError(Exception):
    """The writer could not read a request as one of its ops."""


class WriteRefused(Exception):
    """A payload the writer would not store: the detector tripped on it, or it was over the line cap."""


class Writer:
    def __init__(self, path: Path, timeout: float = TIMEOUT, retry_pause: float = RETRY_PAUSE):
        self.path = path
        self.timeout = timeout
        self.retry_pause = retry_pause

    async def call(self, op: str, **fields):
        line = wire.encode({"op": op, **fields})
        if len(line) > wire.LINE_CAP:
            raise WriteRefused(wire.OVERSIZE)
        # Only the connect is retried: once a request is sent, a second try could apply a write twice.
        for attempt in range(1, CONNECT_ATTEMPTS + 1):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(self.path, limit=wire.LINE_CAP), self.timeout)
                break
            except (OSError, TimeoutError) as exc:
                if attempt == CONNECT_ATTEMPTS:
                    raise WriterUnavailable(f"no writer at {self.path} ({type(exc).__name__})") from None
                await asyncio.sleep(self.retry_pause)
        try:
            writer.write(line)
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), self.timeout)
        except (OSError, TimeoutError) as exc:
            raise WriterUnavailable(f"the writer did not answer {op} ({type(exc).__name__})") from None
        finally:
            writer.close()
        if not reply:
            raise WriterUnavailable(f"the writer closed the connection on {op} unanswered")
        answer = json.loads(reply)
        if answer["ok"]:
            return answer["result"]
        if answer["error"] == wire.NOT_CHANGED:
            raise RefusedChange(answer["reason"])
        if answer["error"] == wire.REFUSED:
            raise WriteRefused(answer["reason"])
        raise WriterError(f"{op}: {answer['error']}, {answer['reason']}")

    async def ping(self) -> None:
        await self.call("ping")

    async def resolve(self, source_id: str) -> Source | None:
        found = await self.call("resolve", source_id=source_id)
        return found and Source(**found | {"hosts": frozenset(found["hosts"])})

    async def get(self, source_id: str) -> dict | None:
        return await self.call("get", source_id=source_id)

    async def collecting(self) -> list[str]:
        return await self.call("collecting")

    async def cluster_of(self, source_id: str) -> tuple[str, ...]:
        return tuple(await self.call("cluster_of", source_id=source_id))

    async def members(self) -> dict[str, str]:
        return await self.call("members")

    async def due_sources(self) -> list[str]:
        return await self.call("due_sources")

    async def due_probes(self, interval) -> list[tuple[str, str]]:
        return [tuple(pair) for pair in await self.call("due_probes", interval_seconds=interval.total_seconds())]

    async def stats(self) -> dict:
        return await self.call("stats")

    async def open_item(self, item_id: int) -> dict:
        return await self.call("open_item", item_id=item_id)

    async def source_matches(self, source_id: str) -> list[tuple[str, tuple[int, int]]]:
        return [(other, tuple(near)) for other, near in await self.call("source_matches", source_id=source_id)]

    async def run_start(self, source_id: str) -> int:
        return await self.call("run_start", source_id=source_id)

    async def page_done(self, task: Task, metric: PageMetric) -> None:
        await self.call("page_done", run_id=task.run_id, source_id=task.source_id, kind=task.kind, path=task.path,
                        metric=dataclasses.asdict(metric))

    async def run_finish(self, run_id: int, cadence_seconds: float, expect: dict | None) -> dict:
        return await self.call("run_finish", run_id=run_id, cadence_seconds=cadence_seconds, expect=expect)

    async def probe_result(self, host: str, up: bool) -> None:
        await self.call("probe_result", host=host, up=up)

    async def add_candidates(self, hosts, found_on: str | None) -> int:
        return await self.call("add_candidates", hosts=sorted(hosts), found_on=found_on)

    async def add_redirect_target(self, source_id: str, target: str) -> int:
        return await self.call("add_redirect_target", source_id=source_id, target=target)

    async def disable_for_safety(self, source_id: str) -> None:
        await self.call("disable_for_safety", source_id=source_id)

    async def set_active_host(self, source_id: str, host: str) -> str:
        return await self.call("set_active_host", source_id=source_id, host=host)

    async def redaction_events(self, source_id: str, events: int, run_id: int | None) -> int:
        return await self.call("redaction_events", source_id=source_id, events=events, run_id=run_id)

    async def store_too_large(self, source_id: str, run_id: int | None) -> None:
        await self.call("store_too_large", source_id=source_id, run_id=run_id)

    async def store_records(self, task: Task, host: str, records) -> int:
        return await self.call("store_records", source_id=task.source_id, run_id=task.run_id, kind=task.kind,
                               path=task.path, host=host, records=[
                                   {"content_hash": record.content_hash, "follow_path": record.follow_path,
                                    "fields": record.fields, "counts": record.summary.counts,
                                    "hashes": list(record.summary.hashes)} for record in records])

    async def save_snapshot(self, task: Task, html: str) -> str:
        return await self.call("save_snapshot", source_id=task.source_id, run_id=task.run_id, kind=task.kind,
                               path=task.path, html=html)

    async def save_fingerprint(self, host: str, path: str, seed: bool, fingerprint: Fingerprint) -> None:
        await self.call("save_fingerprint", host=host, path=path, seed=seed,
                        fingerprint=dataclasses.asdict(fingerprint))

    async def mirrors_refresh(self) -> None:
        await self.call("mirrors_refresh")

    async def went_live(self, source_id: str, pages: list[tuple[str, str]]) -> int:
        """Golive's seed snapshots as the source's baselines, one request a page, then the source live."""
        staged = [[path, await self.call("stage_baseline", source_id=source_id, html=html)] for path, html in pages]
        return await self.call("went_live", source_id=source_id, baselines=staged)

    async def fold(self, source_id: str, mirror_of: str, config_text: str) -> list[str]:
        return await self.call("fold", source_id=source_id, mirror_of=mirror_of, config_text=config_text)

    async def save_report(self, source_id: str, passed: bool, lines: list[tuple[bool, str]]) -> None:
        await self.call("save_report", source_id=source_id, passed=passed, lines=[list(line) for line in lines])

    async def resolve_item(self, item_id: int, disposition: str, note: str, detail: str) -> None:
        await self.call("resolve_item", item_id=item_id, disposition=disposition, note=note, detail=detail)

    async def refuse_item(self, item_id: int, disposition: str, note: str, detail: str) -> None:
        await self.call("refuse_item", item_id=item_id, disposition=disposition, note=note, detail=detail)
