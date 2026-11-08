"""Operator check for a safety pattern file: pattern_timing.py PATTERNS_FILE

Runs the file's patterns, then the parser, extractor and redaction gate under a throwaway config,
over hostile 2 MB bodies the way the crawler does, in a worker thread. Reports per body the check
time, the slowest pattern by line number, the whole inspection time, and the longest the event loop
went without a turn. Never prints pattern text.
Exits 1 if any loop stall reaches STALL_LIMIT_MS: a pattern that holds the GIL that long in one C call
stalls every worker's fetch, and needs a lookbehind start or possessive quantifiers.
"""
import asyncio
import sys
import time
from pathlib import Path

from onioncollect import extractor, safety, source_config
from onioncollect.pages import inspect
from onioncollect.db import LISTING
from onioncollect.fetcher import FetchResult

SIZE = 2_000_000
STALL_LIMIT_MS = 100
TIMING_HOST = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
TIMING_CONFIG = source_config.parse(f"""id = "timing"
hosts = ["{TIMING_HOST}"]
category = "directories"
cadence = "6h"
seeds = ["/"]
[pagination]
next = "a.next"
max_pages = 2
[listing]
item = "p"
[listing.fields]
text = "p"
link = "a@href"
[expect]
min_items_per_page = 1
required_fields = ["text"]
[auth]
type = "none"
""", "timing")
TIMING_SALT = b"timing-only-salt" * 2
UNITS = {
    "letters": "a", "digits": "4", "spaces": " ", "newlines": "\n", "dots": "a.", "tags": "<p>", "br": "<br>",
    "digit groups": "4444 ", "dashed cards": "4111-1111-1111-1112 ", "card runs": "4111111111111112 ",
    "emails": "a@b.cc:", "two entries": "ab@cd.ef:pw\nab@cd.ef:pw\n\n", "near hash": "abcd:" + "f" * 31 + "\n",
    "html words": "<p>hello world</p>", "distinct words": None, "tags under cap": None,
}


def body_for(name: str) -> bytes:
    if name == "distinct words":
        return b" ".join(b"word%d" % n for n in range(SIZE // 11))[:SIZE]
    if name == "tags under cap":
        # The tag-dense bodies above are refused unparsed; this one is the most markup the parser ever sees.
        tags = extractor.MAX_TAGS - 1
        return (b"<p>" + b"w " * ((SIZE // tags - 3) // 2)) * tags
    unit = UNITS[name]
    return (unit * (SIZE // len(unit) + 1))[:SIZE].encode()


def numbered(text: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), 1) if line.strip() and not line.lstrip().startswith("#")]


async def worst_stall(work) -> float:
    gaps, done = [], asyncio.Event()

    async def ticker():
        last = time.perf_counter()
        while not done.is_set():
            await asyncio.sleep(0.001)
            now = time.perf_counter()
            gaps.append(now - last)
            last = now

    ticking = asyncio.create_task(ticker())
    await asyncio.sleep(0.01)
    await asyncio.to_thread(work)
    done.set()
    await ticking
    return max(gaps)


async def main(path: Path) -> int:
    text = path.read_text()
    patterns = safety.parse_patterns(text)
    lines = numbered(text)
    failed = False
    for name in UNITS:
        body = body_for(name)
        decoded = body.decode()
        times = []
        for pattern in patterns:
            started = time.perf_counter()
            safety.body_triggers_exclusion(decoded, (pattern,))
            times.append(time.perf_counter() - started)
        slowest = max(range(len(times)), key=times.__getitem__)
        result = FetchResult("timing", "/", host=TIMING_HOST, url=f"http://{TIMING_HOST}/", status=200, body=body)
        started = time.perf_counter()
        stall = await worst_stall(lambda: inspect(result, LISTING, TIMING_CONFIG, patterns, TIMING_SALT))
        both = time.perf_counter() - started
        failed |= stall * 1000 >= STALL_LIMIT_MS
        print(f"{name:15s} check {sum(times) * 1000:5.0f} ms, slowest line {lines[slowest]:3d}"
              f" {times[slowest] * 1000:5.0f} ms | inspect in a thread {both * 1000:5.0f} ms,"
              f" loop stall {stall * 1000:4.0f} ms{'  OVER LIMIT' if stall * 1000 >= STALL_LIMIT_MS else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(Path(sys.argv[1]))))
