import argparse
import asyncio
import contextlib
import dataclasses
import fcntl
import logging
import re
import sys
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path

from onioncollect import lifecycle
from onioncollect.config import Settings, load_config
from onioncollect.crawler import Crawler
from onioncollect.db import RATE_WINDOW, Frontier, open_collect
from onioncollect.golive import go_live, leak_tests, save_report
from onioncollect.records import RecordStore
from onioncollect.source_config import ConfigError
from onioncollect.sources import SourceTable
from onioncollect.tor_pool import CONTROL_ERRORS, TorPool

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_BYTES = 50 * 1024 * 1024
LOG_FILES = 5
LOG_TAIL_BYTES = 256 * 1024
HEALTH_LINE = re.compile(r"tor (\d+): success (\d\.\d\d) over (\d+) fetches")
URL_STATUSES = ("queued", "leased", "done", "failed")


def add_commands(commands) -> None:
    crawl = commands.add_parser("crawl", help="collection over Tor, run as the crawler user").add_subparsers(required=True)
    run = crawl.add_parser("run", help="collect from due live sources until Ctrl-C")
    run.add_argument("--workers", type=int, help="workers per Tor instance")
    run.add_argument("--until-idle", action="store_true",
                     help="the timer's mode: start what is due, stop when no page is left to fetch")
    status = crawl.add_parser("status", help="frontier and source counts and per-instance Tor health")
    golive = commands.add_parser("golive", help="section 14's checks; a clean pass makes an approved source live")
    golive.add_argument("id")
    decision = golive.add_mutually_exclusive_group()
    decision.add_argument("--confirm-new-source", action="store_true",
                          help="go live although the seed pages match another source's")
    decision.add_argument("--as-mirror-of", metavar="ID", help="fold this source's hosts into a source it matches")
    for parser, command in ((run, run_command), (status, status_command), (golive, golive_command)):
        parser.set_defaults(command=command, crawl=True)


@contextlib.contextmanager
def run_lock(settings: Settings):
    # Held for the whole of `run` and `golive`. Two crawls on one database would double every per-source
    # limit, and a go-live under a crawl would race it for the source's state.
    with open(settings.data_dir / "run.lock", "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("onioncollect: a crawl or go-live is running on this data directory") from None
        yield


def run_command(settings: Settings, args: argparse.Namespace) -> None:
    if args.workers is not None:
        settings = dataclasses.replace(settings, workers_per_instance=args.workers)
    with run_lock(settings):
        # Before Tor, before a client: a leak test result older than the current deploy or 36 h stops the crawl.
        fresh, line = leak_tests(settings.leak_test_result, datetime.now(UTC))
        if not fresh:
            raise SystemExit(f"onioncollect: crawl refused, {line}")
        configure_logging(settings.data_dir / "crawl.log")
        try:
            asyncio.run(Crawler(settings).run(args.until_idle))
        except ConfigError as exc:
            raise SystemExit(f"onioncollect: crawl refused, {exc}") from None


def golive_command(settings: Settings, args: argparse.Namespace) -> None:
    try:
        config = load_config(settings.configs_dir, args.id)
    except ConfigError as exc:
        raise SystemExit(f"onioncollect: {exc}") from None

    async def check():
        collect = await open_collect(settings.data_dir / "collect.db")
        records = RecordStore(settings.data_dir, timedelta(days=settings.record_retention_days),
                              timedelta(days=settings.snapshot_retention_days))
        await records.open()
        pool = TorPool(settings)
        table = SourceTable(collect)
        try:
            await pool.start()
            report = await go_live(args.id, config, settings, table, records, pool.instances,
                                   args.confirm_new_source, args.as_mirror_of)
            await save_report(table, args.id, report, datetime.now(UTC))
            return report
        finally:
            pool.stop()
            await records.close()
            await collect.close()

    with run_lock(settings):
        report = asyncio.run(check())
    for ok, line in report.lines:
        print(f"{'PASS' if ok else 'FAIL'}  {line}")
    if not report.passed:
        raise SystemExit(f"onioncollect: {args.id} stays {lifecycle.APPROVED}")


def status_command(settings: Settings, args: argparse.Namespace) -> None:
    async def read():
        collect = await open_collect(settings.data_dir / "collect.db")
        try:
            return await Frontier(collect, settings.per_source_concurrency).stats()
        finally:
            await collect.close()

    stats = asyncio.run(read())
    urls, fetches = stats["urls"], stats["fetches_last_hour"]
    up = 100 * stats["up_last_hour"] / fetches if fetches else 0.0
    print("sources  " + "  ".join(f"{state} {stats['sources'].get(state, 0)}" for state in lifecycle.SOURCE_STATES)
          + f"  (open runs {stats['open_runs']})")
    print("hosts    " + "  ".join(f"{state} {stats['hosts'].get(state, 0)}" for state in lifecycle.HOST_STATES))
    print("urls     " + "  ".join(f"{status} {urls.get(status, 0)}" for status in URL_STATUSES))
    print(f"fetches  {fetches} in the last hour, {up:.0f}% reached the host;"
          f" {stats['fetches_recent'] / RATE_WINDOW.total_seconds():.2f}/s over the last {RATE_WINDOW.seconds // 60} min")
    print("tor      port   circuit   built  streams  success, last logged")
    logged = last_logged_health(settings.data_dir / "crawl.log")
    for instance in TorPool(settings).instances:
        try:
            instance.connect()
            ready = "ready" if instance.is_ready() else "building"
            circuits, streams = instance.open_counts()
        except CONTROL_ERRORS as exc:
            print(f"         {instance.socks_port}  unreachable ({type(exc).__name__})")
            continue
        finally:
            instance.close()
        print(f"         {instance.socks_port}  {ready:8s} {circuits:6d} {streams:8d}  "
              f"{logged.get(instance.socks_port, 'none yet')}")


def last_logged_health(path: Path) -> dict[int, str]:
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        f.seek(max(path.stat().st_size - LOG_TAIL_BYTES, 0))
        tail = f.read().decode("utf-8", errors="replace")
    return {int(port): f"{rate} over {count}" for port, rate, count in HEALTH_LINE.findall(tail)}


def configure_logging(path: Path) -> None:
    # Libraries get WARNING and up only. httpx logs every request line, full URL included, at INFO, and
    # stem sets its own logger to TRACE, so the root level alone would not keep either out.
    formatter = logging.Formatter(LOG_FORMAT)
    handlers = [logging.StreamHandler(sys.stderr), RotatingFileHandler(path, maxBytes=LOG_BYTES, backupCount=LOG_FILES)]
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(lambda record: record.name.startswith("onioncollect.") or record.levelno >= logging.WARNING)
    logging.basicConfig(level=logging.INFO, handlers=handlers)
