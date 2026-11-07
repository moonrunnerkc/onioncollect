import argparse
import asyncio
import dataclasses
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from onioncrawl.config import Settings
from onioncrawl.crawler import Crawler
from onioncrawl.db import Frontier

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_BYTES = 50 * 1024 * 1024
LOG_FILES = 5


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
    return parser


def seed_command(settings: Settings, args: argparse.Namespace) -> None:
    lines = [line.strip() for line in args.file.read_text().splitlines()]
    entries = [line if "://" in line else f"http://{line}/" for line in lines if line and not line.startswith("#")]

    async def seed() -> tuple[int, int]:
        frontier = Frontier(settings)
        await frontier.open(settings.data_dir / "crawl.db")
        try:
            return await frontier.seed(entries)
        finally:
            await frontier.close()

    accepted, rejected = asyncio.run(seed())
    print(f"seeded {accepted}, rejected {rejected}")


def run_command(settings: Settings, args: argparse.Namespace) -> None:
    if args.workers is not None:
        settings = dataclasses.replace(settings, workers_per_instance=args.workers)
    configure_logging(settings.data_dir / "crawl.log")
    asyncio.run(Crawler(settings).run())


def configure_logging(path: Path) -> None:
    # Libraries get WARNING and up only. httpx logs every request line, full URL included, at INFO, and
    # stem sets its own logger to TRACE, so the root level alone would not keep either out.
    formatter = logging.Formatter(LOG_FORMAT)
    handlers = [logging.StreamHandler(sys.stderr), RotatingFileHandler(path, maxBytes=LOG_BYTES, backupCount=LOG_FILES)]
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(lambda record: record.name.startswith("onioncrawl.") or record.levelno >= logging.WARNING)
    logging.basicConfig(level=logging.INFO, handlers=handlers)
