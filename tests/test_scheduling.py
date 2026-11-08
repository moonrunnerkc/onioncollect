"""Section 9's scheduling as the timer runs it: cadence decides what is due, a failing source is retried sooner for
a bounded number of runs and then slowed and handed to the health queue, one crawl at a time, and no crawl at all
without a leak test from after the current deploy and under 36 hours old, or with a config that fails the loader.
Selection itself is Frontier.due_sources (db.py), the multiplier scheduler.next_run, applied in Crawler.finish_run."""
import asyncio
import logging
from datetime import UTC, datetime, timedelta
from unittest import mock

from onioncollect import crawl_cli, crawler as crawler_module, golive, health, lifecycle, scheduler
from onioncollect import fetcher as fetcher_module
from onioncollect.db import stamp
from onioncollect.fetcher import FetchResult
from tests.fixtures import NEWS_CONFIG, TESTONION, TESTONION_CONFIG, listing_page, make_live, write_leak_result
from tests.live import log_audit
from tests.test_cli import CliTestCase
from tests.test_crawler import CrawlerTestCase, FakeTor

CADENCE = timedelta(hours=6)


class FakePool:
    """The Tor pool with no Tor: instances to count workers against, nothing started."""

    def __init__(self):
        self.instances = [FakeTor()]
        self.started = False

    async def start(self):
        self.started = True

    def assign(self, worker_id):
        return self.instances[0]

    async def health_loop(self):
        await asyncio.Event().wait()

    def stop(self):
        pass


class DueSelectionTest(CrawlerTestCase):
    async def next_run(self) -> datetime:
        (row,) = await self.rows("SELECT next_run, failed_runs FROM sources WHERE id = 'news'")
        return datetime.fromisoformat(row["next_run"]).replace(tzinfo=UTC)

    async def make_due(self):
        await self.crawler.collect.conn.execute("UPDATE sources SET next_run = ? WHERE id = 'news'",
                                                (stamp(datetime.now(UTC) - timedelta(seconds=1)),))
        await self.crawler.collect.conn.commit()

    async def test_a_source_not_yet_due_is_not_fetched(self):
        await self.crawl({"/articles/": listing_page("A", "B")})
        self.assertAlmostEqual((await self.next_run() - datetime.now(UTC)).total_seconds(), CADENCE.total_seconds(),
                               delta=60)
        fetcher = await self.crawl({"/articles/": listing_page("A", "B")})
        self.assertEqual(fetcher.calls, [])
        (runs,), = await self.rows("SELECT COUNT(*) FROM runs")
        self.assertEqual(runs, 1)

    async def test_the_timer_run_with_nothing_due_builds_no_request_and_stops(self):
        await self.crawler.collect.conn.execute("UPDATE sources SET next_run = ? WHERE id = 'news'",
                                                (stamp(datetime.now(UTC) + CADENCE),))
        await self.crawler.collect.conn.commit()
        await self.crawler.close()
        self.crawler.tor_pool = FakePool()
        built = []
        with mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=lambda **kw: built.append(kw)), \
                self.assertLogs("onioncollect.crawler", logging.INFO) as logs:
            await asyncio.wait_for(self.crawler.run(until_idle=True), 10)
        self.assertEqual(built, [])
        self.assertIn("INFO:onioncollect.crawler:crawler: no page left to fetch", logs.output)

    async def test_a_failing_source_is_retried_sooner_then_slowed_and_queued(self):
        quick = max(CADENCE / scheduler.QUICK_RETRY_DIVISOR, scheduler.MIN_RETRY)
        for run in range(1, scheduler.QUICK_RETRY_RUNS + 2):
            fetcher = await self.crawl({})
            self.assertTrue(fetcher.calls, run)
            wait = await self.next_run() - datetime.now(UTC)
            expected = quick if run <= scheduler.QUICK_RETRY_RUNS else CADENCE * scheduler.SLOWED_MULTIPLIER
            self.assertAlmostEqual(wait.total_seconds(), expected.total_seconds(), delta=60, msg=run)
            items = [item["kind"] for item in await self.crawler.health.queue()]
            self.assertEqual(items, [] if run <= scheduler.QUICK_RETRY_RUNS else [health.UNREACHABLE], run)
            self.assertEqual((await self.crawl({})).calls, [], f"run {run}: not due again before its time")
            await self.make_due()
        self.assertEqual((await self.crawler.sources.get("news"))["state"], lifecycle.DEGRADED)


class TimerModeTest(CrawlerTestCase):
    async def test_until_idle_finishes_what_was_due_then_stops(self):
        await self.crawler.close()
        self.crawler.tor_pool = FakePool()
        fetched = []

        async def fetch(fetcher, source_id, path):
            fetched.append(path)
            return FetchResult(source_id, path, host="x", error="timeout", elapsed=0.1)

        with mock.patch.object(crawler_module.Fetcher, "fetch", fetch), \
                mock.patch.object(crawler_module.random, "uniform", return_value=0.0), \
                mock.patch.object(crawler_module, "IDLE_SLEEP", 0.05), \
                self.assertLogs("onioncollect.crawler", logging.INFO) as logs:
            await asyncio.wait_for(self.crawler.run(until_idle=True), 10)
        self.assertEqual(fetched, ["/articles/"])
        self.assertIn("INFO:onioncollect.crawler:crawler: no page left to fetch", logs.output)
        self.assertIn("INFO:onioncollect.crawler:crawler: form-session sources: none", logs.output)
        for line in logs.output:
            message = line.split(":", 2)[2]
            self.assertTrue(any(shape.fullmatch(message) for shape in log_audit.SHAPES.values()), line)


class ConfigGateTest(CrawlerTestCase):
    async def test_a_config_that_fails_the_loader_stops_the_crawl_before_tor(self):
        (self.root / "configs" / "news.toml").write_text(NEWS_CONFIG.replace('cadence = "6h"', 'cadence = "soon"'))
        await self.crawler.close()
        pool = self.crawler.tor_pool = FakePool()
        with self.assertRaisesRegex(crawler_module.ConfigError, "configs that fail validation: news"), \
                self.assertLogs("onioncollect.crawler", logging.ERROR):
            await self.crawler.run(until_idle=True)
        self.assertFalse(pool.started)

    async def test_form_session_sources_are_named_at_the_start(self):
        await make_live(self.crawler.sources, "testonion", TESTONION, "self-hosted")
        (self.root / "configs" / "testonion.toml").write_text(TESTONION_CONFIG)
        with self.assertLogs("onioncollect.crawler", logging.INFO) as logs:
            await self.crawler.check_configs()
        self.assertEqual(logs.output, ["INFO:onioncollect.crawler:crawler: form-session sources: testonion"])


class CrawlRunGateTest(CliTestCase):
    """`crawl run` from the CLI: the lock, then the leak test result, before Tor or a client exists."""

    def setUp(self):
        super().setUp()
        self.built = []
        for target, name in ((crawl_cli, "Crawler"), (fetcher_module, "AsyncProxyTransport")):
            patcher = mock.patch.object(target, name, side_effect=lambda *a, name=name, **kw: self.built.append(name) or mock.DEFAULT)
            patcher.start()
            self.addCleanup(patcher.stop)

    def refused(self, *args: str) -> str:
        message = super().refused(*args)
        self.assertEqual(self.built, [])
        return message

    def test_a_second_crawl_exits_non_zero_and_builds_nothing(self):
        settings = mock.Mock(data_dir=self.data)
        with crawl_cli.run_lock(settings):
            with self.assertRaises(SystemExit) as caught:
                self.cli("crawl", "run", "--until-idle")
        self.assertNotIn(caught.exception.code, (0, None))
        self.assertIn("a crawl or go-live is running", str(caught.exception))
        self.assertEqual(self.built, [])

    def test_refused_when_the_leak_test_predates_the_current_deploy(self):
        write_leak_result(self.root / "leak-test.json", seen="2026-11-01T09:00:00Z 0ldd3p10")
        self.assertIn("crawl refused, leak tests: the last run predates the current deploy",
                      self.refused("crawl", "run", "--until-idle"))

    def test_refused_when_the_leak_test_is_older_than_36_hours(self):
        write_leak_result(self.root / "leak-test.json", age=timedelta(hours=36, minutes=1))
        self.assertIn("crawl refused, leak tests: last run", self.refused("crawl", "run"))

    def test_refused_without_a_deploy_stamp(self):
        (self.root / golive.DEPLOY_STAMP).unlink()
        self.assertIn("deploy-stamp; run make deploy", self.refused("crawl", "run", "--until-idle"))

    def test_a_fresh_result_lets_it_start(self):
        with mock.patch.object(crawl_cli, "configure_logging"), mock.patch.object(crawl_cli.asyncio, "run"):
            self.cli("crawl", "run", "--until-idle")
        self.assertEqual(self.built, ["Crawler"])
