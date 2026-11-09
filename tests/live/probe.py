"""Live checks for build steps 2 to 4. Guest only, as crawler: python -m tests.live.probe SETTINGS.

Prints hosts, status codes, byte counts, timings and error names, never paths or bodies.
"""
import asyncio
import sys
import tempfile
import time
from pathlib import Path

from onioncollect import lifecycle, source_config
from onioncollect.config import Settings
from onioncollect.db import open_collect
from onioncollect.fetcher import Fetcher
from onioncollect.sources import SourceTable
from onioncollect.tor_pool import TorPool

LIVE_ONIONS = {
    "probe-ahmia": ("http", "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion", "directories"),
    "probe-ddg": ("https", "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "privacy-services"),
    "probe-torproject": ("http", "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
                         "software-infrastructure"),
}
# Each must be refused before a client exists: an id with no source, and paths that are not paths.
REFUSED = [("no-such-source", "/"), ("probe-ahmia", "http://example.com/"), ("probe-ahmia", "https://1.1.1.1/")]
PROBE_CONFIG = """id = "{id}"
hosts = ["{host}"]
category = "{category}"
cadence = "6h"
scheme = "{scheme}"
seeds = ["/"]
[listing]
item = "a"
[listing.fields]
title = "a"
[expect]
min_items_per_page = 1
required_fields = ["title"]
[auth]
type = "none"
"""


async def throwaway_sources(collect) -> tuple:
    # The fetcher only goes where the source table says, so these three public onions are made live in a
    # database that lives as long as the probe.
    table = SourceTable(collect)
    configs = {}
    for source_id, (scheme, host, category) in LIVE_ONIONS.items():
        await table.approve(host, source_id, category, "leak test probe", "probe", frozenset())
        await table.change_state(source_id, lifecycle.LIVE)
        configs[source_id] = source_config.parse(
            PROBE_CONFIG.format(id=source_id, host=host, category=category, scheme=scheme), source_id)
    return table, configs


def check_dead_port_rejected(settings_path: Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete_on_close=False) as f:
        f.write(settings_path.read_text() + "tor_instances = [[10051, 11051], [10059, 11059]]\n")
        f.close()
        try:
            Settings.load(Path(f.name), crawl=True)
        except RuntimeError as exc:
            print(f"step 2: dead port rejected: {exc}")
            return
    raise SystemExit("step 2: FAIL, Settings.load accepted a dead port")


async def main(settings_path: Path) -> None:
    check_dead_port_rejected(settings_path)
    settings = Settings.load(settings_path, crawl=True)
    scratch = tempfile.TemporaryDirectory()
    collect = await open_collect(Path(scratch.name) / "collect.db")
    pool = TorPool(settings)
    fetchers = []
    # Everything is closed on every exit. A failure that skipped collect.close() left aiosqlite's worker thread
    # running, and the interpreter waited on it forever, so the leak test hung instead of failing.
    try:
        table, configs = await throwaway_sources(collect)
        started = time.monotonic()
        await pool.start()
        print(f"step 3: {len(pool.instances)} instances ready in {time.monotonic() - started:.1f}s")

        first = pool.instances[0]
        started = time.monotonic()
        await first.rotate()
        after_first = time.monotonic() - started
        await first.rotate()
        after_second = time.monotonic() - started - after_first
        print(f"step 3: tor {first.socks_port} NEWNYM sent in {after_first:.2f}s, second NEWNYM waited {after_second:.1f}s")
        if after_second < 9:
            raise SystemExit("step 3: FAIL, the NEWNYM rate limit was not respected")

        fetchers = [Fetcher(settings, pool.assign(n), table, configs, lifecycle.COLLECTING)
                    for n in range(len(pool.instances))]
        for n, (source_id, path) in enumerate([(source_id, "/") for source_id in LIVE_ONIONS] + REFUSED):
            fetcher = fetchers[n % len(fetchers)]
            result = await fetcher.fetch(source_id, path)
            size = len(result.body) if result.body is not None else 0
            print(
                f"step 4: tor {fetcher.tor.socks_port} {source_id} status={result.status} bytes={size} "
                f"elapsed={result.elapsed:.2f}s error={result.error}"
            )
            if (source_id, path) in REFUSED and result.error not in ("not_approved", "bad_path"):
                raise SystemExit(f"step 4: FAIL, {source_id} was not refused before sending")

        for instance in pool.instances:
            print(f"step 3: tor {instance.socks_port} success rate {instance.success_rate():.2f} over {len(instance.outcomes)}")
    finally:
        for fetcher in fetchers:
            await fetcher.close()
        pool.stop()
        await collect.close()
        scratch.cleanup()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
