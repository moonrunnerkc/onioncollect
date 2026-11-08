"""Everything the crawler may ask of the stores, one op each: its fields, typed, and what it does. writer.py reads
a request, checks it against the op's spec and calls the op; nothing else reaches the stores from the crawler.
No op takes SQL or a file path, and the writer, not the crawler, decides category, cluster, decided-by and
every health item's text."""
import os
import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from onioncollect import health, lifecycle, mirrors, safety, scheduler
from onioncollect.db import DETAIL, LISTING, Database, PageMetric, open_collect
from onioncollect.health_queue import HealthQueue
from onioncollect.matching import Fingerprint
from onioncollect.records import RecordStore, RefusedWrite, refuse_secrets
from onioncollect.redact import Redacted
from onioncollect.runs import RunLog
from onioncollect.sources import RefusedChange, SourceTable

KIND = ("one_of", LISTING, DETAIL)
CHECKED = ("one_of", health.FIXED, health.MIRROR_SWAPPED)
METRIC = {"host": "str", "elapsed": "float", "status": "int?", "error": "str?", "bytes": "int", "items": "int",
          "incomplete": "int", "fields_resolved": "int", "fields_declared": "int", "below_expectation": "bool",
          "redactions": "int", "records_new": "int", "field_hits": ("map", "int"), "field_items": "int"}
RECORD = {"content_hash": "str", "follow_path": "str?", "fields": ("map", "str"), "counts": ("map", "int"),
          "hashes": ("list", "str")}
FINGERPRINT = {"content": "int", "structure": "int", "words": "int"}
EXPECT = {"min_items": "int", "required": ("list", "str"), "category": "str"}

OPS = {}


def op(name: str, **spec):
    def register(handler):
        OPS[name] = (spec, handler)
        return handler
    return register


@dataclass
class Stores:
    collect: Database
    sources: SourceTable
    health: HealthQueue
    runs: RunLog
    records: RecordStore
    configs_dir: Path
    crawler: str

    @classmethod
    async def open(cls, data_dir: Path, configs_dir: Path, crawler: str, record_days: int, snapshot_days: int):
        data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        collect = await open_collect(data_dir / "collect.db")
        records = RecordStore(data_dir, timedelta(days=record_days), timedelta(days=snapshot_days))
        await records.open()
        sources = SourceTable(collect)
        return cls(collect, sources, HealthQueue(collect, sources), RunLog(collect), records, configs_dir, crawler)

    async def close(self) -> None:
        await self.records.close()
        await self.collect.close()


async def refused(stores: Stores, source_id: str, run_id: int | None, why: str) -> None:
    # Section 11: a refused write raises a top-priority item, here in the writer, whatever the crawler does next.
    await stores.health.raise_item(source_id, health.redaction(f"write refused: {why}"), run_id)


@op("ping")
async def ping(stores, req):
    return "pong"


@op("resolve", source_id="str")
async def resolve(stores, req):
    source = await stores.sources.resolve(req["source_id"])
    return source and asdict(source) | {"hosts": sorted(source.hosts)}


@op("get", source_id="str")
async def get(stores, req):
    return await stores.sources.get(req["source_id"])


@op("collecting")
async def collecting(stores, req):
    return await stores.runs.collecting()


@op("cluster_of", source_id="str")
async def cluster_of(stores, req):
    return list(await stores.sources.cluster_of(req["source_id"]))


@op("members")
async def members(stores, req):
    return await stores.sources.members()


@op("due_sources")
async def due_sources(stores, req):
    return await stores.runs.due_sources()


@op("due_probes", interval_seconds="float")
async def due_probes(stores, req):
    return [list(pair) for pair in await stores.runs.due_probes(timedelta(seconds=req["interval_seconds"]))]


@op("stats")
async def stats(stores, req):
    return await stores.runs.stats()


@op("open_item", item_id="int")
async def open_item(stores, req):
    return await stores.health.open_item(req["item_id"])


@op("source_matches", source_id="str")
async def source_matches(stores, req):
    return [[other, list(near)] for other, near in
            await mirrors.source_matches(req["source_id"], stores.sources, stores.records)]


@op("run_start", source_id="str")
async def run_start(stores, req):
    return await stores.runs.start(req["source_id"])


@op("page_done", run_id="int", source_id="str", kind=KIND, path="str", metric=METRIC)
async def page_done(stores, req):
    await stores.runs.record_page(req["run_id"], req["source_id"], req["kind"], req["path"], PageMetric(**req["metric"]))


@op("run_finish", run_id="int", cadence_seconds="float", expect=("nullable", EXPECT))
async def run_finish(stores, req):
    now, cadence = datetime.now(UTC), timedelta(seconds=req["cadence_seconds"])
    run = await stores.runs.finish(req["run_id"],
                                   lambda row: scheduler.next_run(cadence, row["failed_runs"], row["pages"] == 0, now))
    if run is None:
        return {"run": None, "findings": []}
    expect = req["expect"]
    found = await stores.health.after_run(run, expect["min_items"], tuple(expect["required"]), expect["category"]) \
        if expect is not None else []
    return {"run": dict(run), "findings": [[finding.kind, finding.priority] for finding in found]}


@op("probe_result", host="str", up="bool")
async def probe_result(stores, req):
    await stores.runs.record_probe(req["host"], req["up"])


@op("add_candidates", hosts=("list", "str"), found_on="str?")
async def add_candidates(stores, req):
    return await stores.sources.add_candidates(req["hosts"], req["found_on"])


@op("add_redirect_target", source_id="str", target="str")
async def add_redirect_target(stores, req):
    return await stores.sources.add_redirect_target(req["source_id"], req["target"])


@op("disable_for_safety", source_id="str")
async def disable_for_safety(stores, req):
    await stores.sources.change_state(req["source_id"], lifecycle.DISABLED, f"safety: {safety.EXCLUDING}")


@op("set_active_host", source_id="str", host="str")
async def set_active_host(stores, req):
    return await stores.sources.set_active_host(req["source_id"], req["host"])


@op("redaction_events", source_id="str", events="int", run_id="int?")
async def redaction_events(stores, req):
    return await stores.health.raise_item(req["source_id"], health.redaction(f"{req['events']} redaction events"),
                                          req["run_id"])


@op("store_too_large", source_id="str", run_id="int?")
async def store_too_large(stores, req):
    await refused(stores, req["source_id"], req["run_id"], "over the writer's line cap")


@op("store_records", source_id="str", run_id="int", kind=KIND, path="str", host="str", records=("list", RECORD))
async def store_records(stores, req):
    source_id, records = req["source_id"], req["records"]
    source = await stores.sources.resolve(source_id)
    if source is None or req["host"] not in source.hosts:
        raise RefusedChange("records name a host outside the source's set")
    try:
        # Every record is checked before any is written, so a refusal leaves nothing behind.
        await refuse_secrets(*(text for record in records for item in record["fields"].items() for text in item))
        new = 0
        for record in records:
            summary = Redacted("", record["counts"], tuple(record["hashes"]), 0)
            if req["kind"] == DETAIL:
                await stores.records.add_detail(source_id, req["path"], record["fields"], summary)
            else:
                new += await stores.records.add(
                    source_id, source.category, record["content_hash"], record["follow_path"], record["fields"],
                    summary, host=req["host"], cluster=await stores.sources.cluster_of(source_id))
    except RefusedWrite:
        await refused(stores, source_id, req["run_id"], "a secret survived")
        raise
    return new


@op("save_snapshot", source_id="str", run_id="int", kind=KIND, path="str", html="str")
async def save_snapshot(stores, req):
    try:
        return await stores.records.save_snapshot(req["source_id"], req["path"], req["kind"], req["html"])
    except RefusedWrite:
        await refused(stores, req["source_id"], req["run_id"], "a secret survived")
        raise


@op("save_fingerprint", host="str", path="str", seed="bool", fingerprint=FINGERPRINT)
async def save_fingerprint(stores, req):
    if req["host"] not in await stores.sources.members():
        raise RefusedChange("a fingerprint names a host in no source")
    await stores.records.save_fingerprint(req["host"], req["path"], req["seed"], Fingerprint(**req["fingerprint"]))


@op("mirrors_refresh")
async def mirrors_refresh(stores, req):
    await mirrors.refresh(stores.sources, stores.records)


@op("stage_baseline", source_id="str", html="str")
async def stage_baseline(stores, req):
    await approved(stores, req["source_id"])
    return await stores.records.stage_snapshot(req["html"])


@op("went_live", source_id="str", baselines=("list", ("pair", "str", "str")))
async def went_live(stores, req):
    source_id = req["source_id"]
    await approved(stores, source_id)
    await stores.records.mark_baselines(source_id, [tuple(pair) for pair in req["baselines"]])
    await stores.sources.change_state(source_id, lifecycle.LIVE)
    await mirrors.refresh(stores.sources, stores.records)
    # A source back from `sources reapprove` may still carry the items that sent it there; this pass fixes them.
    return await stores.health.close_source(source_id, health.FIXED, health.PASSED_GOLIVE, stores.crawler)


@op("fold", source_id="str", mirror_of="str", config_text="str")
async def fold(stores, req):
    source_id, mirror_of = req["source_id"], req["mirror_of"]
    source = await approved(stores, source_id)
    if mirror_of not in dict(await mirrors.source_matches(source_id, stores.sources, stores.records)):
        raise RefusedChange(f"{source_id} does not match {mirror_of}")
    path = stores.configs_dir / f"{mirror_of}.toml"
    try:
        old, new = tomllib.loads(path.read_text()), tomllib.loads(req["config_text"])
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RefusedChange(f"{mirror_of}'s config: {type(exc).__name__}") from None
    # The new text may differ from the old only by gaining the folded source's hosts.
    if set(new.pop("hosts", ())) != set(old.pop("hosts", ())) | source.hosts or new != old:
        raise RefusedChange(f"the new config for {mirror_of} changes more than its hosts")
    moved = await stores.sources.merge(source_id, mirror_of, frozenset({lifecycle.APPROVED}), f"mirror of {mirror_of}")
    temp = path.with_suffix(".toml.tmp")
    # Group-readable: the configs dir's group is the crawler's, which reads every config and writes none.
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write(req["config_text"])
    os.chmod(temp, 0o640)
    os.replace(temp, path)
    await mirrors.refresh(stores.sources, stores.records)
    return moved


@op("save_report", source_id="str", passed="bool", lines=("list", ("pair", "bool", "str")))
async def save_report(stores, req):
    await stores.sources.add_golive_report(req["source_id"], req["passed"], req["lines"])


@op("resolve_item", item_id="int", disposition=CHECKED, note="str", detail="str")
async def resolve_item(stores, req):
    await stores.health.resolve(req["item_id"], req["disposition"], req["note"], stores.crawler, req["detail"])


@op("refuse_item", item_id="int", disposition=CHECKED, note="str", detail="str")
async def refuse_item(stores, req):
    await stores.health.refused(req["item_id"], req["disposition"], req["note"], stores.crawler, req["detail"])


async def approved(stores: Stores, source_id: str):
    source = await stores.sources.resolve(source_id)
    if source is None or source.state != lifecycle.APPROVED:
        raise RefusedChange(f"{source_id} is not approved")
    return source
