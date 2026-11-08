import argparse
import json

from selectolax.lexbor import LexborHTMLParser

from onioncollect import extractor, fingerprint, parser, source_config
from onioncollect.config import Settings, load_config
from onioncollect.db import DETAIL, LISTING
from onioncollect.records import RecordStore
from onioncollect.source_config import ConfigError
from onioncollect.stores import with_records

SAMPLE_RECORDS = 3


def add_commands(commands) -> None:
    config = commands.add_parser("config", help="collection configs").add_subparsers(required=True)
    for name, command, text in (("validate", validate_command, "schema check"),
                                ("test", test_command, "schema check, then a dry extraction on the latest snapshot,"
                                                       " set against the golive baseline")):
        sub = config.add_parser(name, help=text)
        sub.add_argument("id")
        sub.set_defaults(command=command)


def checked_config(settings: Settings, source_id: str):
    try:
        return load_config(settings.configs_dir, source_id)
    except ConfigError as exc:
        raise SystemExit(f"onioncollect: {exc}") from None


def validate_command(settings: Settings, args: argparse.Namespace) -> None:
    config = checked_config(settings, args.id)
    print(f"{args.id}: valid, {len(config.hosts)} hosts, {len(config.seeds)} seeds, {len(config.fields)} listing fields,"
          f" {len(config.detail_fields)} detail fields")


def test_command(settings: Settings, args: argparse.Namespace) -> None:
    config = checked_config(settings, args.id)

    async def latest(store: RecordStore):
        snapshots = [await store.latest_snapshot(args.id, kind) for kind in (LISTING, DETAIL)]
        return snapshots, snapshots[0] and await store.baseline_for(args.id, snapshots[0][0])

    snapshots, baseline = with_records(settings, latest)
    if snapshots[0] is None:
        raise SystemExit(f"onioncollect: no snapshot of {args.id} yet; golive writes the first")
    for kind, snapshot in zip((LISTING, DETAIL), snapshots):
        if snapshot is None or (kind == DETAIL and not config.detail_fields):
            continue
        path, taken, html = snapshot
        page_url = f"{config.scheme}://{config.hosts[0]}{path}"
        extract = extractor.listing if kind == LISTING else extractor.detail
        found = extract(LexborHTMLParser(html), page_url, config)
        print(f"{kind} {path} at {taken[:16]}: " + described(found, config, kind))
        if kind == LISTING:
            diff_baseline(config, page_url, html, found, baseline)
        for record in found.records[:SAMPLE_RECORDS]:
            print("  " + json.dumps(record, sort_keys=True)[:300])


def described(found: extractor.Extraction, config: source_config.SourceConfig, kind: str) -> str:
    return (f"{found.items} items, {found.items - found.incomplete} complete (expect {config.min_items_per_page}),"
            f" hit rate {found.hit_rate:.2f}" + (f", next page {'found' if found.next_page else 'missing'}"
                                                 if kind == LISTING and config.next_page else ""))


def diff_baseline(config, page_url: str, html: str, found: extractor.Extraction, baseline) -> None:
    """Section 12: the latest listing against the known-good one golive stored, field by field and by layout."""
    if baseline is None:
        print("  no baseline for this path; golive writes one")
        return
    taken, known = baseline
    then = extractor.listing(LexborHTMLParser(known), page_url, config)
    print(f"  baseline at {taken[:16]}: " + described(then, config, LISTING))
    for name in config.fields:
        before, after = then.field_hits[name], found.field_hits[name]
        if (before, then.field_items) != (after, found.field_items):
            print(f"  {name}: {before} of {then.field_items} items at baseline, {after} of {found.field_items} now"
                  + ("  LOST" if before and not after else ""))
    near = fingerprint.distance(page_print(known), page_print(html))
    print(f"  layout: {fingerprint.describe(near)} from the baseline"
          + ("" if fingerprint.is_match(near) else f", past the {fingerprint.MIRROR_MAX_BITS}-bit mirror threshold"))


def page_print(html: str) -> fingerprint.Fingerprint:
    return fingerprint.of_page(parser.visible_text(LexborHTMLParser(html)), LexborHTMLParser(html))
