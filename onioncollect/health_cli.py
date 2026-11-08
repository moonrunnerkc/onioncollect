import argparse

from onioncollect import crawl_cli, health, lifecycle
from onioncollect.config import Settings, load_config
from onioncollect.golive import Report, recheck
from onioncollect.health_queue import HealthQueue
from onioncollect.records import RecordStore
from onioncollect.source_config import ConfigError
from onioncollect.sources import RefusedChange, SourceTable
from onioncollect.stores import operator, reading, with_stores
from onioncollect.tor_pool import TorPool
from onioncollect.writer_client import Writer

# These two prove themselves with go-live checks 1, 4 and 5, so they fetch, and need Tor and the run lock.
CHECKED = (health.FIXED, health.MIRROR_SWAPPED)


def add_commands(commands) -> None:
    queue = commands.add_parser("health", help="the health queue, by priority then age")
    queue.set_defaults(command=queue_command, reader=True)
    sub = queue.add_subparsers()
    runs = sub.add_parser("runs", help="a source's per-run metrics, newest first")
    runs.add_argument("id")
    runs.add_argument("--limit", type=int, default=20)
    runs.set_defaults(command=runs_command, reader=True)
    log = sub.add_parser("log", help="every disposition, applied or refused, oldest first")
    log.add_argument("--source")
    log.set_defaults(command=log_command, reader=True)
    resolve = sub.add_parser("resolve", help="record a disposition; fixed and mirror-swapped must pass go-live"
                                             " checks 1, 4 and 5 first")
    resolve.add_argument("item", type=int)
    resolve.add_argument("--disposition", required=True, choices=health.DISPOSITIONS)
    resolve.add_argument("--note", required=True)
    resolve.add_argument("--to", metavar="HOST", help="mirror-swapped: the host of the source's own set to move to")
    resolve.add_argument("--runs", type=int, help="watching: how many finished runs to snooze for")
    resolve.set_defaults(command=resolve_command, crawl=needs_tor, reader=False)


def needs_tor(args: argparse.Namespace) -> bool:
    return args.disposition in CHECKED


def queue_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read(table: SourceTable, store: RecordStore):
        items = await HealthQueue(table.db, table).queue()
        siblings = {}
        for source_id in {item["source_id"] for item in items if item["kind"] == health.UNREACHABLE}:
            cluster = set(await table.cluster_of(source_id))
            active = (await table.get(source_id))["active_host"]
            siblings[source_id] = [row for row in await table.hosts(lifecycle.MEMBER)
                                   if row["source_id"] in cluster and row["host"] != active]
        return items, siblings

    items, siblings = reading(settings, read)
    watched = [item for item in items if item["snoozed_until_run"] is not None]
    for item in items:
        if item in watched:
            continue
        print(f"#{item['id']:<4d} priority {item['priority']:<4d} {item['source_id']:24s} {item['kind']:20s}"
              f" open since {item['opened_at'][:16]}, seen {item['occurrences']}x, last {item['last_seen'][:16]}")
        print(f"      {item['detail']}")
        for row in siblings.get(item["source_id"], []):
            own = row["source_id"] == item["source_id"]
            print(f"      {'sibling' if own else 'cluster'} {row['host']}  last up {(row['last_up'] or 'never')[:16]}"
                  f"  last down {(row['last_down'] or 'never')[:16]}"
                  + (f"  swap: health resolve {item['id']} --disposition mirror-swapped --to {row['host']}" if own
                     else f"  (of {row['source_id']}: sources merge first)"))
    for item in watched:
        print(f"watching #{item['id']} {item['source_id']} {item['kind']} until run {item['snoozed_until_run']}")
    print(f"{len(items) - len(watched)} open, {len(watched)} watched")


def runs_command(settings: Settings, args: argparse.Namespace) -> None:
    rows = reading(settings, lambda table, store: HealthQueue(table.db, table).run_metrics(args.id, args.limit))
    print("run    started           pages failed reached status  mean   max  items complete  hit  new redacted refused")
    for row in rows:
        hit = row["fields_resolved"] / row["fields_declared"] if row["fields_declared"] else 0.0
        print(f"{row['id']:<6d} {row['started_at'][:16]}  {row['pages']:5d} {row['failures']:6d}"
              f" {row['answered']:3d}/{row['attempts']:<3d} {row['status'] or '-':>6}"
              f" {row['mean_elapsed'] or 0:5.1f} {row['max_elapsed'] or 0:5.1f} {row['items']:6d}"
              f" {row['items'] - row['incomplete']:8d} {hit:5.2f} {row['records_new']:4d} {row['redactions']:8d}"
              f" {row['parse_refused'] or 0:7d}" + ("" if row["finished_at"] else "  (open)"))


def log_command(settings: Settings, args: argparse.Namespace) -> None:
    rows = reading(settings, lambda table, store: HealthQueue(table.db, table).log(args.source))
    for row in rows:
        print(f"{row['decided_at'][:16]}  #{row['item_id']} {row['source_id']} {row['kind']} -> {row['disposition']}"
              f" ({'applied' if row['applied'] else 'refused'}) by {row['decided_by']}: {row['note']}"
              + (f" [{row['detail']}]" if row["detail"] else ""))


def resolve_command(settings: Settings, args: argparse.Namespace) -> None:
    if not args.note.strip():
        raise SystemExit("onioncollect: not changed, a disposition needs a note")
    if (args.to is not None) != (args.disposition == health.MIRROR_SWAPPED):
        raise SystemExit("onioncollect: not changed, --to goes with mirror-swapped, which needs it")
    if (args.runs is not None) != (args.disposition == health.WATCHING):
        raise SystemExit("onioncollect: not changed, --runs goes with watching, which needs it")
    if args.disposition not in CHECKED:
        with_stores(settings, lambda table, store: decide(args, table))
        print(f"item {args.item}: {args.disposition}")
        return
    # As the crawler, which fetches: everything it records goes through the writer.
    with crawl_cli.run_lock(settings):
        report = crawl_cli.through_writer(lambda: checked(settings, args, Writer(settings.writer_socket)))
    for ok, line in report.lines:
        print(f"{'PASS' if ok else 'FAIL'}  {line}")
    if not report.passed:
        raise SystemExit(f"onioncollect: item {args.item} stays open; the attempt is in health log")


async def decide(args: argparse.Namespace, table: SourceTable) -> None:
    queue = HealthQueue(table.db, table)
    item = await queue.open_item(args.item)
    if args.disposition == health.WATCHING:
        await queue.watch(args.item, args.runs, args.note, operator())
        return
    # A source the safety check already disabled still has its items to close.
    if (await table.get(item["source_id"]))["state"] != lifecycle.DISABLED:
        await table.change_state(item["source_id"], lifecycle.DISABLED, args.note)
    await queue.resolve(args.item, health.DISABLED, args.note, operator())
    await queue.close_source(item["source_id"], health.DISABLED, args.note, operator())


async def checked(settings: Settings, args: argparse.Namespace, writer: Writer) -> Report:
    item = await writer.open_item(args.item)
    source_id = item["source_id"]
    try:
        config = load_config(settings.configs_dir, source_id)
    except ConfigError as exc:
        raise RefusedChange(str(exc)) from None
    source = await writer.resolve(source_id)
    host = (args.to or source.active_host).lower()
    if args.disposition == health.MIRROR_SWAPPED and host == source.active_host:
        raise RefusedChange(f"{host} is already {source_id}'s active host")
    if host not in source.hosts:
        owner = (await writer.members()).get(host)
        raise RefusedChange(f"{host} is not in {source_id}'s host set"
                            + (f"; it belongs to {owner}, so run sources merge first" if owner else ""))
    pool = TorPool(settings)
    try:
        await pool.start()
        report = await recheck(source_id, host, config, settings, writer, pool.instances)
    finally:
        pool.stop()
    if not report.passed:
        await writer.refuse_item(args.item, args.disposition, args.note, f"{host}: {report.failure}")
        return report
    if args.disposition == health.MIRROR_SWAPPED:
        detail = f"active host {await writer.set_active_host(source_id, host)} -> {host}"
    else:
        detail = f"go-live checks 1, 4 and 5 passed on {host}"
    await writer.resolve_item(args.item, args.disposition, args.note, detail)
    report.check(True, detail)
    return report
