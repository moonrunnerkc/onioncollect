import argparse
import asyncio
import contextlib
import dataclasses
import fcntl
import logging
import os
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from onioncrawl import onion
from onioncrawl.config import Settings
from onioncrawl.crawler import Crawler
from onioncrawl.db import RATE_WINDOW, Frontier
from onioncrawl.storage import PageStore
from onioncrawl.tor_pool import CONTROL_ERRORS, TorPool

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_BYTES = 50 * 1024 * 1024
LOG_FILES = 5
LOG_TAIL_BYTES = 256 * 1024
HEALTH_LINE = re.compile(r"tor (\d+): success (\d\.\d\d) over (\d+) fetches")
URL_STATUSES = ("queued", "leased", "done", "parked")
HOST_STATES = ("up", "unknown", "dead", "gated", "excluded")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if os.geteuid() == 0:
        raise SystemExit("onioncrawl: refusing to run as root")
    os.umask(0o077)
    settings = Settings.load(args.settings)
    if settings.data_dir.stat().st_uid != os.geteuid():
        raise SystemExit(f"onioncrawl: {settings.data_dir} is not owned by this user")
    args.command(settings, args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="onioncrawl")
    parser.add_argument("--settings", type=Path, required=True, help="path to settings.toml")
    commands = parser.add_subparsers(required=True)
    seed = commands.add_parser("seed", help="queue onion URLs or bare hosts from a file")
    seed.add_argument("file", type=Path)
    seed.set_defaults(command=seed_command)
    run = commands.add_parser("run", help="crawl until Ctrl-C")
    run.add_argument("--workers", type=int, help="workers per Tor instance")
    run.set_defaults(command=run_command)
    status = commands.add_parser("status", help="frontier counts and per-instance Tor health")
    status.set_defaults(command=status_command)
    unexclude = commands.add_parser("unexclude", help="lift a safety exclusion the crawler made")
    unexclude.add_argument("host")
    unexclude.set_defaults(command=unexclude_command)
    return parser


async def with_frontier(settings: Settings, action):
    frontier = Frontier(settings)
    await frontier.open(settings.data_dir / "crawl.db")
    try:
        return await action(frontier)
    finally:
        await frontier.close()


@contextlib.contextmanager
def run_lock(settings: Settings):
    # Held for the whole of `run`. A crawl keeps its own copy of the excluded hosts, so a change made
    # under it would be undone, and two crawls on one database would double every per-host limit.
    with open(settings.data_dir / "run.lock", "w") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("onioncrawl: a crawl is running on this data directory") from None
        yield


def seed_command(settings: Settings, args: argparse.Namespace) -> None:
    lines = [line.strip() for line in args.file.read_text().splitlines()]
    entries = [line if "://" in line else f"http://{line}/" for line in lines if line and not line.startswith("#")]
    accepted, rejected = asyncio.run(with_frontier(settings, lambda frontier: frontier.seed(entries)))
    print(f"seeded {accepted}, rejected {rejected}")


def run_command(settings: Settings, args: argparse.Namespace) -> None:
    if args.workers is not None:
        settings = dataclasses.replace(settings, workers_per_instance=args.workers)
    with run_lock(settings):
        configure_logging(settings.data_dir / "crawl.log")
        asyncio.run(Crawler(settings).run())


def unexclude_command(settings: Settings, args: argparse.Namespace) -> None:
    host = args.host.strip().lower()
    if not onion.is_v3_onion(host):
        raise SystemExit(f"onioncrawl: {args.host} is not a v3 onion host")
    if host in settings.exclusions:
        raise SystemExit(f"onioncrawl: {host} is on the exclusion list; remove it there first")
    with run_lock(settings):
        requeued = asyncio.run(with_frontier(settings, lambda frontier: frontier.unexclude(host)))
    print(f"{host} is not excluded" if requeued is None else f"{host} unexcluded, {requeued} URLs queued again")


def status_command(settings: Settings, args: argparse.Namespace) -> None:
    stats = asyncio.run(with_frontier(settings, lambda frontier: frontier.stats()))
    urls, hosts, fetches = stats["urls"], stats["hosts"], stats["fetches_last_hour"]
    up = 100 * stats["up_last_hour"] / fetches if fetches else 0.0
    print("urls     " + "  ".join(f"{status} {urls.get(status, 0)}" for status in URL_STATUSES))
    print("hosts    " + "  ".join(f"{state} {hosts.get(state, 0)}" for state in HOST_STATES))
    print(f"leases   {stats['leased_hosts']} hosts hold leases, at most {stats['max_leased_per_host']} on one host"
          f" (limit {settings.per_host_concurrency})")
    print(f"pages    {stats['pages']} stored, {PageStore(settings.data_dir).size_on_disk() / 1e6:.1f} MB on disk")
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
        handler.addFilter(lambda record: record.name.startswith("onioncrawl.") or record.levelno >= logging.WARNING)
    logging.basicConfig(level=logging.INFO, handlers=handlers)
