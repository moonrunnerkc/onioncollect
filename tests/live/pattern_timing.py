"""Operator check for a safety pattern file: pattern_timing.py PATTERNS_FILE

Runs the file's patterns, and the parser, against hostile 2 MB bodies the way the crawler does, in a
worker thread, and reports per body the check time, the slowest pattern by line number and category,
the parse time, and the longest the event loop went without a turn. Never prints pattern text.
Exits 1 if any loop stall reaches STALL_LIMIT_MS: a pattern that holds the GIL that long in one C call
stalls every worker's fetch, and needs a lookbehind start or possessive quantifiers.
"""
import asyncio
import sys
import time
from pathlib import Path

from onioncrawl import safety
from onioncrawl.crawler import inspect
from onioncrawl.fetcher import FetchResult

SIZE = 2_000_000
STALL_LIMIT_MS = 100
UNITS = {
    "letters": "a", "digits": "4", "spaces": " ", "newlines": "\n", "dots": "a.", "tags": "<p>", "br": "<br>",
    "digit groups": "4444 ", "dashed cards": "4111-1111-1111-1112 ", "card runs": "4111111111111112 ",
    "emails": "a@b.cc:", "two entries": "ab@cd.ef:pw\nab@cd.ef:pw\n\n", "near hash": "abcd:" + "f" * 31 + "\n",
    "html words": "<p>hello world</p>", "distinct words": None,
}


def body_for(name: str) -> bytes:
    if UNITS[name] is None:
        return b" ".join(b"word%d" % n for n in range(SIZE // 11))[:SIZE]
    unit = UNITS[name]
    return (unit * (SIZE // len(unit) + 1))[:SIZE].encode()


def numbered(text: str, patterns: tuple) -> list[tuple[int, str]]:
    lines = [(n, line.split()[0]) for n, line in enumerate(text.splitlines(), 1)
             if line.strip() and not line.lstrip().startswith("#")]
    lines.sort(key=lambda entry: safety.CATEGORIES.index(entry[1]))
    assert [category for _, category in lines] == [safety.category_of(p) for p in patterns]
    return lines


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
    lines = numbered(text, patterns)
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
        result = FetchResult(url="http://x.onion/", final_url="http://x.onion/", status=200, body=body)
        started = time.perf_counter()
        stall = await worst_stall(lambda: inspect(result, patterns))
        both = time.perf_counter() - started
        failed |= stall * 1000 >= STALL_LIMIT_MS
        number, category = lines[slowest]
        print(f"{name:15s} check {sum(times) * 1000:5.0f} ms, slowest line {number:3d} {category:18s}"
              f" {times[slowest] * 1000:5.0f} ms | parse and check in a thread {both * 1000:5.0f} ms,"
              f" loop stall {stall * 1000:4.0f} ms{'  OVER LIMIT' if stall * 1000 >= STALL_LIMIT_MS else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(Path(sys.argv[1]))))
