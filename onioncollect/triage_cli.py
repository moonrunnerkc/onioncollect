"""triage list / approve / decline / request (analyst). Nothing here fetches: a candidate is a row until a human
approves it and golive passes."""
import argparse

from onioncollect import config_text, lifecycle, matching, mirrors, onion, safety
from onioncollect.config import Settings, config_path, write_config
from onioncollect.records import RecordStore
from onioncollect.source_config import ConfigError
from onioncollect.sources import RefusedChange, SourceTable, approvable
from onioncollect.stores import operator, reading, with_stores

REQUEST = "request"
FOUND_AT_MAX = 200


def add_commands(commands) -> None:
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
    request = triage.add_parser("request", help="enter a host someone asked for as a candidate; nothing is fetched")
    request.add_argument("host")
    request.add_argument("--found-at", required=True, metavar="TEXT", help="where the address was seen")
    request.set_defaults(command=request_command)


def candidates_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read(table: SourceTable, store: RecordStore):
        rows = await table.hosts(lifecycle.CANDIDATE)
        hosts = [row["host"] for row in rows]
        return rows, await mirrors.host_matches(hosts, table, store), await table.redirected_from(hosts)

    rows, matched, redirected = reading(settings, read)
    for row in rows:
        print(f"{row['first_seen'][:16]}  {row['host']}  found on {row['found_on'] or 'request'}")
        for source_id, near in matched.get(row["host"], []):
            print(f"    candidate matches source {source_id} ({matching.describe(near)})")
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
    write_config(settings.configs_dir, args.id, config_text.scaffold(args.id, args.host.lower(), args.category))
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
            text = config_text.with_hosts(config_path(settings.configs_dir, args.mirror_of).read_text(), [host])
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


def request_command(settings: Settings, args: argparse.Namespace) -> None:
    """A sourcing request: the host becomes a candidate with where it was seen, exactly as if a page had named
    it. A host already known, in any state, is left as it was."""
    host = args.host.strip().lower()
    found_at = " ".join(args.found_at.split())
    if not onion.is_v3_onion(host):
        raise SystemExit("onioncollect: not added, that is not a v3 onion host (56 characters, checksum, .onion)")
    if safety.is_excluded(host, settings.exclusions):
        raise SystemExit("onioncollect: not added, the host is on the exclusion list")
    if not found_at or len(found_at) > FOUND_AT_MAX or onion.find_onions_in_text(found_at):
        raise SystemExit(f"onioncollect: not added, --found-at is 1 to {FOUND_AT_MAX} characters and names no onion")
    added = with_stores(settings, lambda table, store: table.add_candidates({host}, f"{REQUEST}: {found_at}"))
    print(f"{host} added as a candidate" if added else f"{host} is already known; nothing changed")
