import argparse
import json
import os
from datetime import UTC, date, datetime
from pathlib import Path

from onioncollect import config_cli, crawl_cli, fingerprint, health, health_cli, lifecycle, mirrors, source_config
from onioncollect.config import Settings, config_path, write_config
from onioncollect.health_queue import HealthQueue
from onioncollect.records import RecordStore
from onioncollect.source_config import ConfigError
from onioncollect.sources import RefusedChange, SourceTable, approvable
from onioncollect.stores import operator, reading, with_records, with_stores

def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if os.geteuid() == 0:
        raise SystemExit("onioncollect: refusing to run as root")
    # Closed to others, readable by the group: in the guest the data dir's group is the analyst's, which reads.
    os.umask(0o027)
    # A command that may fetch decides from its own arguments whether it needs the crawler's Tor settings.
    crawl = args.crawl(args) if callable(args.crawl) else args.crawl
    try:
        settings = Settings.load(args.settings, crawl=crawl, reader=args.reader)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"onioncollect: {exc}") from None
    if args.reader:
        # A reader opens both stores read-only, so it may run against a data dir another user owns.
        if not settings.data_dir.is_dir():
            raise SystemExit(f"onioncollect: no data directory at {settings.data_dir}")
    else:
        settings.data_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
        if settings.data_dir.stat().st_uid != os.geteuid():
            raise SystemExit(f"onioncollect: {settings.data_dir} is not owned by this user")
    args.command(settings, args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="onioncollect")
    parser.add_argument("--settings", type=Path, required=True, help="path to settings.toml")
    commands = parser.add_subparsers(required=True)

    triage = commands.add_parser("triage", help="work the candidate queue").add_subparsers(required=True)
    triage.add_parser("list", help="candidates by age, with where each was found").set_defaults(
        command=candidates_command, reader=True)
    approve = triage.add_parser("approve", help="approve a host as a new source and scaffold its config, or as a"
                                                " mirror of an existing source")
    approve.add_argument("host")
    target = approve.add_mutually_exclusive_group(required=True)
    target.add_argument("--as", dest="id", help="the new source id")
    target.add_argument("--as-mirror-of", dest="mirror_of", metavar="ID",
                        help="add the host to this source's host set and config; the source keeps its state")
    approve.add_argument("--category", choices=lifecycle.CATEGORIES, help="required for a new source")
    approve.add_argument("--note", required=True)
    approve.set_defaults(command=approve_command)
    decline = triage.add_parser("decline", help="decline a host, with the policy reason")
    decline.add_argument("host")
    decline.add_argument("--reason", required=True)
    decline.set_defaults(command=decline_command)

    sources = commands.add_parser("sources", help="the source table").add_subparsers(required=True)
    listing = sources.add_parser("list")
    listing.add_argument("--state", choices=lifecycle.HOST_STATES[:2] + lifecycle.SOURCE_STATES)
    listing.set_defaults(command=sources_command, reader=True)
    disable = sources.add_parser("disable", help="take a source out of rotation")
    disable.add_argument("id")
    disable.add_argument("--reason", required=True)
    disable.set_defaults(command=disable_command)
    sources.add_parser("export", help="the source table as JSON lines").set_defaults(command=export_command, reader=True)
    reapprove = sources.add_parser("reapprove", help="disabled back to approved, to go through golive again")
    reapprove.add_argument("id")
    reapprove.add_argument("--note", required=True)
    reapprove.set_defaults(command=reapprove_command)
    merge = sources.add_parser("merge", help="fold a live source into its live twin: hosts, config entries, records")
    merge.add_argument("id")
    merge.add_argument("--into", required=True, metavar="ID")
    merge.add_argument("--force", action="store_true", help="merge although the seed pages do not match")
    merge.add_argument("--note", help="why, required with --force")
    merge.set_defaults(command=merge_command)

    records = commands.add_parser("records", help="the record store").add_subparsers(required=True)
    backfill = records.add_parser("merge", help="merge rows sharing a content hash across a mirror cluster")
    backfill.add_argument("cluster")
    backfill.set_defaults(command=records_merge_command)

    cluster = commands.add_parser("mirrors", help="a source's mirror cluster, from stored fingerprints, no fetch")
    cluster.add_argument("id")
    cluster.set_defaults(command=mirrors_command)


    search = commands.add_parser("search", help="full-text search over records")
    search.add_argument("query")
    search.add_argument("--source")
    search.add_argument("--category", choices=lifecycle.CATEGORIES)
    search.add_argument("--since", type=date.fromisoformat)
    search.add_argument("--until", type=date.fromisoformat)
    search.set_defaults(command=search_command, reader=True)

    retention = commands.add_parser("retention").add_subparsers(required=True)
    retention.add_parser("sweep", help="apply the retention clocks").set_defaults(command=sweep_command)

    crawl_cli.add_commands(commands)
    config_cli.add_commands(commands)
    health_cli.add_commands(commands)
    # The analyst's commands by default; the crawler's own subcommands override this. Commands that only read
    # set `reader` and open the stores read-only.
    parser.set_defaults(crawl=False, reader=False)
    return parser


def candidates_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read(table: SourceTable, store: RecordStore):
        rows = await table.hosts(lifecycle.CANDIDATE)
        hosts = [row["host"] for row in rows]
        return rows, await mirrors.host_matches(hosts, table, store), await table.redirected_from(hosts)

    rows, matched, redirected = reading(settings, read)
    for row in rows:
        print(f"{row['first_seen'][:16]}  {row['host']}  found on {row['found_on'] or 'request'}")
        for source_id, near in matched.get(row["host"], []):
            print(f"    candidate matches source {source_id} ({fingerprint.describe(near)})")
        for source_id in redirected.get(row["host"], []):
            print(f"    candidate was the redirect target of source {source_id}")
    print(f"{len(rows)} candidates")


def approve_command(settings: Settings, args: argparse.Namespace) -> None:
    if args.mirror_of:
        return approve_mirror(settings, args)
    if args.category is None:
        raise SystemExit("onioncollect: not changed, a new source needs --category")
    path = config_path(settings.configs_dir, args.id)
    if path.exists():
        raise SystemExit(f"onioncollect: not changed, {path} already exists")
    with_stores(settings, lambda table, store: table.approve(
        args.host, args.id, args.category, args.note, operator(), settings.exclusions))
    write_config(settings.configs_dir, args.id, source_config.scaffold(args.id, args.host.lower(), args.category))
    print(f"{args.host.lower()} approved as {args.id}; fill in {path}, then run golive {args.id}")


def approve_mirror(settings: Settings, args: argparse.Namespace) -> None:
    async def approve(table: SourceTable, store: RecordStore):
        host = approvable(args.host, args.note, settings.exclusions)
        source = await table.get(args.mirror_of)
        if source is None:
            raise RefusedChange(f"no source {args.mirror_of}")
        if args.category not in (None, source["category"]):
            raise RefusedChange(f"{args.mirror_of} is {source['category']}, and a mirror takes its source's category")
        # The config edit is proven before the approval is written, so a refusal changes neither.
        try:
            text = source_config.with_hosts(config_path(settings.configs_dir, args.mirror_of).read_text(), [host])
        except (OSError, ConfigError) as exc:
            raise RefusedChange(f"{args.mirror_of}'s config: {exc}") from None
        await table.add_mirror(host, args.mirror_of, args.note, operator(), settings.exclusions)
        return host, source["state"], text

    host, state, text = with_stores(settings, approve)
    path = write_config(settings.configs_dir, args.mirror_of, text)
    print(f"{host} approved as a mirror of {args.mirror_of}, which stays {state}; added to {path}")


def decline_command(settings: Settings, args: argparse.Namespace) -> None:
    with_stores(settings, lambda table, store: table.decline(args.host, args.reason, operator()))
    print(f"{args.host.lower()} declined")


def sources_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read(table: SourceTable):
        hosts = [] if args.state in lifecycle.SOURCE_STATES else await table.hosts(args.state)
        sources = [] if args.state in lifecycle.HOST_STATES else await table.sources(args.state)
        return [row for row in hosts if row["state"] != lifecycle.MEMBER], sources

    hosts, sources = reading(settings, lambda table, store: read(table))
    for row in sources:
        print(f"{row['id']:24s} {row['state']:9s} {row['category']:24s} {row['active_host']}"
              + (f"  ({row['reason']})" if row["reason"] else "")
              + (f"  [cluster {row['cluster_id']}]" if row["cluster_id"] else ""))
    for row in hosts:
        print(f"{'-':24s} {row['state']:9s} {'-':24s} {row['host']}" + (f"  ({row['reason']})" if row["reason"] else ""))


def disable_command(settings: Settings, args: argparse.Namespace) -> None:
    async def disable(table: SourceTable):
        await table.change_state(args.id, lifecycle.DISABLED, args.reason)
        return await HealthQueue(table.db, table).close_source(args.id, health.DISABLED, args.reason, operator())

    closed = with_stores(settings, lambda table, store: disable(table))
    print(f"{args.id} disabled" + (f", {closed} open health items closed" if closed else ""))


def reapprove_command(settings: Settings, args: argparse.Namespace) -> None:
    with_stores(settings, lambda table, store: table.reapprove(args.id, args.note, operator()))
    print(f"{args.id} approved again; run golive {args.id}")


def merge_command(settings: Settings, args: argparse.Namespace) -> None:
    if args.force and not (args.note or "").strip():
        raise SystemExit("onioncollect: not changed, --force needs a --note saying why")

    async def merge(table: SourceTable, store: RecordStore):
        for source_id in (args.id, args.into):
            source = await table.resolve(source_id)
            if source is None or source.state not in lifecycle.COLLECTING:
                raise RefusedChange(f"{source_id} is {source.state if source else 'not a source'}, not live")
        near = dict(await mirrors.source_matches(args.id, table, store)).get(args.into)
        if near is None and not args.force:
            raise RefusedChange(f"{args.id}'s seed pages are not within {fingerprint.MIRROR_MAX_BITS} bits of"
                                f" {args.into}'s (see mirrors {args.id}); --force --note to merge anyway")
        # Proven before anything changes, as in the fold.
        try:
            text = source_config.with_hosts(config_path(settings.configs_dir, args.into).read_text(),
                                            sorted((await table.resolve(args.id)).hosts))
        except (OSError, ConfigError) as exc:
            raise RefusedChange(f"{args.into}'s config: {exc}") from None
        reason = f"merged into {args.into}" + (f", forced: {args.note}" if near is None else "")
        moved = await table.merge(args.id, args.into, lifecycle.COLLECTING, reason, into_states=lifecycle.COLLECTING)
        write_config(settings.configs_dir, args.into, text)
        merged = await store.merge((args.id, args.into))
        await store.relabel(args.id, args.into, (await table.get(args.into))["category"])
        await mirrors.refresh(table, store)
        await HealthQueue(table.db, table).close_source(args.id, health.DISABLED, reason, operator())
        return moved, merged, near

    moved, (hashes, removed), near = with_stores(settings, merge)
    print(f"{args.id} merged into {args.into}" + (f" ({fingerprint.describe(near)})" if near else " (forced)")
          + f": {', '.join(moved)} added to {args.into} and its config; {hashes} shared records merged,"
            f" {removed} duplicate rows removed; {args.id} is disabled, and {config_path(settings.configs_dir, args.id)}"
            f" is yours to delete")


def records_merge_command(settings: Settings, args: argparse.Namespace) -> None:
    async def merge(table: SourceTable, store: RecordStore):
        members = await table.in_cluster(args.cluster)
        if len(members) < 2:
            raise RefusedChange(f"no cluster {args.cluster}; mirrors <id> names a source's cluster")
        return members, await store.merge(members)

    members, (hashes, removed) = with_stores(settings, merge)
    print(f"cluster {args.cluster} ({', '.join(members)}): {hashes} shared records merged, {removed} duplicate rows removed")


def export_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read(table: SourceTable):
        return ([await table.get(row["id"]) for row in await table.sources()],
                [row for row in await table.hosts() if row["state"] != lifecycle.MEMBER])

    sources, hosts = reading(settings, lambda table, store: read(table))
    for row in sources:
        print(json.dumps({"kind": "source"} | row, sort_keys=True))
    for row in hosts:
        print(json.dumps({"kind": "host"} | row, sort_keys=True))


def mirrors_command(settings: Settings, args: argparse.Namespace) -> None:
    cluster, rows = with_stores(settings, lambda table, store: mirrors.cluster_report(args.id, table, store))
    print(f"{args.id}: " + (f"cluster {cluster}" if cluster else "in no cluster, its own hosts only")
          + f"; * marks each source's active host; distances are from {args.id}'s,"
            f" a match is {fingerprint.MIRROR_MAX_BITS} bits or fewer on each")
    for row in rows:
        near = (fingerprint.describe(row["distance"]) if row["distance"] else
                "not comparable" if row["fingerprinted"] else "no seed fingerprint")
        print(f"{'*' if row['active'] else ' '} {row['host']}  {row['source_id']} ({row['source_state']})"
              f"  last up {(row['last_up'] or 'never')[:16]}  last down {(row['last_down'] or 'never')[:16]}  {near}")


def search_command(settings: Settings, args: argparse.Namespace) -> None:
    since = datetime.combine(args.since, datetime.min.time(), UTC) if args.since else None
    until = datetime.combine(args.until, datetime.max.time(), UTC) if args.until else None
    try:
        rows = reading(settings, lambda table, store: store.search(args.query, args.source, args.category, since, until))
    except ValueError as exc:
        raise SystemExit(f"onioncollect: {exc}") from None
    for row in rows:
        title = next(iter(row["fields"].values()), "")
        sources = ",".join(row["sources"]) or row["source_id"]
        print(f"{row['id']:7d}  {sources:24s} {row['last_seen'][:10]}  {title[:100]}"
              + (f"  ({row['hosts']} hosts)" if row["hosts"] > 1 else ""))
    print(f"{len(rows)} records")


def sweep_command(settings: Settings, args: argparse.Namespace) -> None:
    records, snapshots = with_records(settings, lambda store: store.sweep())
    print(f"retention: {records} records and {snapshots} snapshots past their clock removed")
