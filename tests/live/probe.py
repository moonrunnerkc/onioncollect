"""Live checks for build steps 2 to 4. Guest only, as crawler: python -m tests.live.probe SETTINGS.

Prints hosts, status codes, byte counts, timings and error names, never paths or bodies.
"""
import asyncio
import sys
import tempfile
import time
from pathlib import Path

from onioncrawl.config import Settings
from onioncrawl.fetcher import Fetcher
from onioncrawl.tor_pool import TorPool

LIVE_ONIONS = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
    "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/",
]
CLEARNET = ["http://example.com/", "https://1.1.1.1/"]


def check_dead_port_rejected(settings_path: Path) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete_on_close=False) as f:
        f.write(settings_path.read_text() + "tor_instances = [[10051, 11051], [10059, 11059]]\n")
        f.close()
        try:
            Settings.load(Path(f.name))
        except RuntimeError as exc:
            print(f"step 2: dead port rejected: {exc}")
            return
    raise SystemExit("step 2: FAIL, Settings.load accepted a dead port")


async def main(settings_path: Path) -> None:
    check_dead_port_rejected(settings_path)
    settings = Settings.load(settings_path)
    pool = TorPool(settings)
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

    fetchers = [Fetcher(settings, pool.assign(n), set(settings.exclusions)) for n in range(len(pool.instances))]
    for n, url in enumerate(LIVE_ONIONS + CLEARNET):
        fetcher = fetchers[n % len(fetchers)]
        result = await fetcher.fetch(url)
        size = len(result.body) if result.body is not None else 0
        host = url.split("/")[2]
        print(
            f"step 4: tor {fetcher.tor.socks_port} {host} status={result.status} bytes={size} "
            f"elapsed={result.elapsed:.2f}s error={result.error}"
        )
        if url in CLEARNET and result.error != "not_onion":
            raise SystemExit(f"step 4: FAIL, {host} was not rejected before sending")

    for instance in pool.instances:
        print(f"step 3: tor {instance.socks_port} success rate {instance.success_rate():.2f} over {len(instance.outcomes)}")
    for fetcher in fetchers:
        await fetcher.close()
    pool.stop()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1])))
