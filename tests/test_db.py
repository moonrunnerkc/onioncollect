import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from onioncrawl.db import Frontier, PageInfo, signed64, stamp, unstamp
from tests.fixtures import LISTED, throwaway_settings
from tests.test_onion import build_address

HOSTS = [build_address(bytes([n] * 32), 3) for n in range(1, 6)]
A, B, C, D, E = HOSTS


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


def page(sha: str = "a" * 64, links=(), text_onions=(), gated=False, title="t", simhash=1) -> PageInfo:
    return PageInfo(
        title=title, headings=[], links=set(links), text_onions=set(text_onions), sha256=sha, simhash=simhash,
        server=None, gated=gated, word_count=10, http_code=200, size=100,
    )


class FrontierTestCase(unittest.IsolatedAsyncioTestCase):
    settings = throwaway_settings(per_host_concurrency=2, max_depth=2)

    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "crawl.db"
        self.clock = Clock()
        self.frontier = Frontier(self.settings, clock=self.clock)
        await self.frontier.open(self.path)

    async def asyncTearDown(self):
        await self.frontier.close()
        self.dir.cleanup()

    async def rows(self, sql: str, *params) -> list[tuple]:
        return list(await self.frontier.db.execute_fetchall(sql, params))

    async def status_of(self, url: str) -> str:
        (status,), = await self.rows("SELECT status FROM urls WHERE url = ?", url)
        return status

    async def host_state(self, host: str) -> str:
        (state,), = await self.rows("SELECT state FROM hosts WHERE host = ?", host)
        return state


class SeedTest(FrontierTestCase):
    async def test_seed_normalizes_and_counts(self):
        accepted, rejected = await self.frontier.seed([f"http://{A}", f"HTTP://{B.upper()}/x#frag", "http://example.com/"])
        self.assertEqual((accepted, rejected), (2, 1))
        urls = {row[0] for row in await self.rows("SELECT url FROM urls")}
        self.assertEqual(urls, {f"http://{A}/", f"http://{B}/x"})
        self.assertEqual(await self.rows("SELECT state FROM hosts WHERE host = ?", A), [("unknown",)])

    async def test_reseeding_is_harmless(self):
        await self.frontier.seed([f"http://{A}/"])
        await self.frontier.seed([f"http://{A}/"])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls"), [(1,)])


class ClaimTest(FrontierTestCase):
    async def test_per_host_concurrency_within_one_batch(self):
        await self.frontier.seed([f"http://{A}/{n}" for n in range(4)] + [f"http://{B}/"])
        tasks = await self.frontier.claim(5)
        hosts = sorted(task.host for task in tasks)
        self.assertEqual(hosts, sorted([A, A, B]))

    async def test_per_host_concurrency_across_claims(self):
        await self.frontier.seed([f"http://{A}/{n}" for n in range(4)])
        first = await self.frontier.claim(1)
        second = await self.frontier.claim(1)
        third = await self.frontier.claim(1)
        self.assertEqual((len(first), len(second), third), (1, 1, []))

    async def test_saturated_host_does_not_starve_others(self):
        await self.frontier.seed([f"http://{A}/{n}" for n in range(200)])
        self.clock.advance(seconds=1)
        await self.frontier.seed([f"http://{B}/"])
        await self.frontier.claim(2)
        (task,) = await self.frontier.claim(1)
        self.assertEqual(task.host, B)

    async def test_lease_is_written(self):
        await self.frontier.seed([f"http://{A}/"])
        (task,) = await self.frontier.claim(1)
        rows = await self.rows("SELECT status, lease_until FROM urls WHERE url = ?", task.url)
        self.assertEqual(rows, [("leased", stamp(self.clock.now + timedelta(minutes=10)))])

    async def test_not_due_is_not_claimed(self):
        await self.frontier.seed([f"http://{A}/"])
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, 1, self.clock.now + timedelta(minutes=2), host_answered=False)
        self.assertEqual(await self.frontier.claim(1), [])
        self.clock.advance(minutes=2)
        self.assertEqual(len(await self.frontier.claim(1)), 1)

    async def test_discovery_beats_recrawl_then_depth(self):
        await self.frontier.seed([f"http://{A}/"])
        (root,) = await self.frontier.claim(1)
        await self.frontier.complete(root, page(links=[f"http://{B}/deep"]), self.clock.now, "p")
        await self.frontier.seed([f"http://{C}/"])
        order = [(await self.frontier.claim(1))[0].url for _ in range(3)]
        self.assertEqual(order, [f"http://{C}/", f"http://{B}/deep", f"http://{A}/"])


class CompleteTest(FrontierTestCase):
    async def claimed(self, url: str):
        await self.frontier.seed([url])
        (task,) = await self.frontier.claim(1)
        return task

    async def test_complete_writes_all_four_tables(self):
        task = await self.claimed(f"http://{A}/")
        due = self.clock.now + timedelta(hours=24)
        await self.frontier.complete(task, page(links=[f"http://{B}/x"], text_onions=[C]), due, "pages/aa/aa/a.gz")
        self.assertEqual(
            await self.rows("SELECT status, priority, last_hash, last_code, next_due FROM urls WHERE url = ?", task.url),
            [("done", 1, "a" * 64, 200, stamp(due))],
        )
        self.assertEqual(await self.rows("SELECT state, title, unchanged_streak FROM hosts WHERE host = ?", A), [("up", "t", 0)])
        self.assertEqual(await self.rows("SELECT url, bytes, path FROM pages"), [(task.url, 100, "pages/aa/aa/a.gz")])
        self.assertEqual(await self.rows("SELECT host, up FROM uptime"), [(A, 1)])
        self.assertEqual(
            await self.rows("SELECT url, depth FROM urls WHERE depth = 1 ORDER BY url"),
            sorted([(f"http://{B}/x", 1), (f"http://{C}/", 1)]),
        )

    async def test_unchanged_streak(self):
        task = await self.claimed(f"http://{A}/")
        for _ in range(3):
            await self.frontier.complete(task, page(), self.clock.now, "p")
            task.last_hash = "a" * 64
        self.assertEqual(await self.rows("SELECT unchanged_streak FROM hosts WHERE host = ?", A), [(2,)])
        await self.frontier.complete(task, page(sha="b" * 64), self.clock.now, "p")
        self.assertEqual(await self.rows("SELECT unchanged_streak FROM hosts WHERE host = ?", A), [(0,)])

    async def test_claim_carries_streak(self):
        task = await self.claimed(f"http://{A}/")
        await self.frontier.complete(task, page(), self.clock.now, "p")
        task.last_hash = "a" * 64
        await self.frontier.complete(task, page(), self.clock.now, "p")
        (again,) = await self.frontier.claim(1)
        self.assertEqual((again.last_hash, again.unchanged_streak), ("a" * 64, 1))

    async def test_title_only_from_root(self):
        task = await self.claimed(f"http://{A}/about")
        await self.frontier.complete(task, page(title="inner"), self.clock.now, "p")
        self.assertEqual(await self.rows("SELECT title FROM hosts WHERE host = ?", A), [(None,)])

    async def test_max_depth_and_high_simhash(self):
        await self.frontier.seed([f"http://{A}/"])
        (task,) = await self.frontier.claim(1)
        task.depth = 2
        await self.frontier.complete(task, page(links=[f"http://{B}/"], simhash=(1 << 64) - 1), self.clock.now, "p")
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ?", B), [(0,)])
        self.assertEqual(await self.rows("SELECT simhash FROM pages"), [(signed64((1 << 64) - 1),)])

    async def test_gated_marks_host_and_skips_links(self):
        task = await self.claimed(f"http://{A}/")
        await self.frontier.complete(task, page(links=[f"http://{B}/"], gated=True), self.clock.now, None)
        self.assertEqual(await self.host_state(A), "gated")
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM pages"), [(0,)])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ?", B), [(0,)])
        await self.frontier.seed([f"http://{A}/other"])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ?", A), [(1,)])


class FailTest(FrontierTestCase):
    async def test_retry_then_park(self):
        await self.frontier.seed([f"http://{A}/"])
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, 1, self.clock.now + timedelta(minutes=2), host_answered=False)
        self.assertEqual(await self.rows("SELECT status, retries FROM urls"), [("queued", 1)])
        self.assertEqual(await self.rows("SELECT consecutive_failures, last_down FROM hosts WHERE host = ?", A), [(1, stamp(self.clock.now))])
        await self.frontier.fail(task, 3, None, host_answered=False)
        self.assertEqual(await self.rows("SELECT status, retries FROM urls"), [("parked", 3)])
        self.assertEqual(await self.rows("SELECT up FROM uptime"), [(0,), (0,)])

    async def test_host_that_answered_is_up(self):
        await self.frontier.seed([f"http://{A}/file.pdf"])
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, 0, None, host_answered=True)
        self.assertEqual(await self.host_state(A), "up")
        self.assertEqual(await self.rows("SELECT consecutive_failures FROM hosts WHERE host = ?", A), [(0,)])
        self.assertEqual(await self.rows("SELECT up FROM uptime"), [(1,)])

    async def test_recent_failures_since_last_up(self):
        await self.frontier.seed([f"http://{A}/"])
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, 1, self.clock.now, host_answered=False)
        self.clock.advance(hours=1)
        await self.frontier.complete(task, page(), self.clock.now, "p")
        times = []
        for _ in range(2):
            self.clock.advance(hours=1)
            times.append(self.clock.now)
            await self.frontier.fail(task, 1, self.clock.now, host_answered=False)
        self.assertEqual(await self.frontier.recent_failures(A), times)

    async def test_mark_dead_parks_and_blocks_discovery(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2"])
        await self.frontier.mark_dead(A)
        self.assertEqual(await self.host_state(A), "dead")
        self.assertEqual(await self.rows("SELECT DISTINCT status FROM urls"), [("parked",)])
        await self.frontier.seed([f"http://{A}/3"])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls"), [(2,)])


class ExcludeTest(FrontierTestCase):
    async def test_exclude_parks_host_and_still_queues_links(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2", f"http://{A}/3"])
        task, _ = await self.frontier.claim(2)
        await self.frontier.exclude(task, page(links=[f"http://{B}/"], text_onions=[C]))
        self.assertEqual(await self.host_state(A), "excluded")
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ? AND status = 'queued'", A), [(0,)])
        self.assertEqual(await self.status_of(task.url), "parked")
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM pages"), [(0,)])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host IN (?, ?)", B, C), [(2,)])
        self.assertEqual(await self.frontier.excluded_hosts(), {A, LISTED})

    async def test_excluded_host_never_returns_to_up(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2"])
        first, second = await self.frontier.claim(2)
        await self.frontier.exclude(first, page())
        await self.frontier.complete(second, page(sha="b" * 64), self.clock.now, None)
        await self.frontier.fail(second, 0, None, host_answered=True)
        self.assertEqual(await self.host_state(A), "excluded")
        await self.frontier.seed([f"http://{A}/new"])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE url = ?", f"http://{A}/new"), [(0,)])


class ListedHostTest(FrontierTestCase):
    async def reopen(self, **overrides) -> None:
        await self.frontier.close()
        self.frontier = Frontier(throwaway_settings(**overrides), clock=self.clock)
        await self.frontier.open(self.path)

    async def test_open_excludes_listed_hosts_and_parks_every_row(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2", f"http://{A}/3"])
        done, leased = await self.frontier.claim(2)
        await self.frontier.complete(done, page(title="kept until listed"), self.clock.now, "p")
        await self.reopen(exclusions=frozenset({LISTED, A}))
        self.assertEqual(await self.rows("SELECT state, title FROM hosts WHERE host = ?", A), [("excluded", None)])
        self.assertEqual(await self.rows("SELECT DISTINCT status FROM urls WHERE host = ?", A), [("parked",)])
        self.assertEqual(await self.frontier.claim(5), [])

    async def test_listed_host_is_never_seeded_or_discovered(self):
        self.assertEqual(await self.host_state(LISTED), "excluded")
        await self.frontier.seed([f"http://{LISTED}/", f"http://{A}/"])
        (task,) = await self.frontier.claim(5)
        await self.frontier.complete(task, page(links=[f"http://{LISTED}/x"], text_onions=[LISTED]), self.clock.now, "p")
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ?", LISTED), [(0,)])

    async def test_row_in_flight_when_its_host_was_excluded_is_parked_on_failure(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2"])
        first, second = await self.frontier.claim(2)
        await self.frontier.exclude(first, page())
        await self.frontier.fail(second, 1, self.clock.now + timedelta(minutes=2), host_answered=False)
        self.assertEqual(await self.status_of(second.url), "parked")

    async def test_reopen_parks_a_crashed_runs_row_of_an_excluded_host(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2"])
        first, second = await self.frontier.claim(2)
        await self.frontier.exclude(first, page())
        self.clock.advance(minutes=11)
        await self.reopen()
        self.assertEqual(await self.status_of(second.url), "parked")


class UnexcludeTest(FrontierTestCase):
    async def test_unexclude_requeues_parked_urls_at_discovery_priority(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2"])
        task, _ = await self.frontier.claim(2)
        await self.frontier.complete(task, page(), self.clock.now + timedelta(days=1), "p")
        await self.frontier.exclude(task, page())
        self.clock.advance(minutes=1)
        self.assertEqual(await self.frontier.unexclude(A), 1)
        self.assertEqual(await self.host_state(A), "unknown")
        self.assertEqual(await self.rows("SELECT status, priority, retries, next_due FROM urls WHERE url = ?", task.url),
                         [("queued", 0, 0, stamp(self.clock.now))])
        (again,) = await self.frontier.claim(5)
        self.assertEqual(again.url, task.url)

    async def test_unexclude_of_a_host_that_is_not_excluded_changes_nothing(self):
        await self.frontier.seed([f"http://{A}/"])
        self.assertIsNone(await self.frontier.unexclude(A))
        self.assertIsNone(await self.frontier.unexclude(B))
        self.assertEqual(await self.host_state(A), "unknown")


class LeaseRecoveryTest(FrontierTestCase):
    async def test_crash_recovery(self):
        await self.frontier.seed([f"http://{A}/", f"http://{B}/"])
        leased = await self.frontier.claim(2)
        self.assertEqual(len(leased), 2)
        await self.frontier.close()

        self.clock.advance(minutes=9)
        self.frontier = Frontier(self.settings, clock=self.clock)
        await self.frontier.open(self.path)
        self.assertEqual(await self.frontier.claim(2), [])

        self.clock.advance(minutes=2)
        self.assertEqual(await self.frontier.release_stale_leases(), 2)
        self.assertEqual(await self.rows("SELECT DISTINCT status, lease_until FROM urls"), [("queued", None)])
        self.assertEqual(sorted(task.url for task in await self.frontier.claim(2)), sorted(t.url for t in leased))

    async def test_open_releases_expired_leases(self):
        await self.frontier.seed([f"http://{A}/"])
        await self.frontier.claim(1)
        await self.frontier.close()
        self.clock.advance(minutes=11)
        self.frontier = Frontier(self.settings, clock=self.clock)
        await self.frontier.open(self.path)
        self.assertEqual(await self.status_of(f"http://{A}/"), "queued")


class StatsTest(FrontierTestCase):
    async def test_stats(self):
        await self.frontier.seed([f"http://{A}/", f"http://{B}/"])
        task, _ = await self.frontier.claim(2)
        await self.frontier.complete(task, page(), self.clock.now, "p")
        stats = await self.frontier.stats()
        self.assertEqual(stats["urls"], {"done": 1, "leased": 1})
        self.assertEqual(stats["hosts"], {"up": 1, "unknown": 1, "excluded": 1})
        self.assertEqual((stats["pages"], stats["fetches_last_hour"], stats["up_last_hour"]), (1, 1, 1))
        self.assertEqual((stats["leased_hosts"], stats["max_leased_per_host"]), (1, 1))
        self.clock.advance(minutes=6)
        self.assertEqual(((await self.frontier.stats())["fetches_recent"], stats["fetches_recent"]), (0, 1))

    async def test_leases_per_host(self):
        await self.frontier.seed([f"http://{A}/", f"http://{A}/2", f"http://{A}/3", f"http://{B}/"])
        await self.frontier.claim(4)
        stats = await self.frontier.stats()
        self.assertEqual((stats["leased_hosts"], stats["max_leased_per_host"]), (2, 2))
        await self.frontier.release_stale_leases()

    def test_stamp_round_trip(self):
        moment = datetime(2026, 11, 7, 12, 0, 0, 123000, tzinfo=UTC)
        self.assertEqual(unstamp(stamp(moment)), moment)


if __name__ == "__main__":
    unittest.main()
