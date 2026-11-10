import asyncio
import json
import logging
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from onioncollect import health, lifecycle, pages, scheduler
from onioncollect import fetcher as fetcher_module
from onioncollect.crawler import Crawler
from onioncollect.db import DETAIL, LISTING
from onioncollect.fetcher import Fetcher, FetchResult
from onioncollect.pages import inspect
from onioncollect.records import RefusedWrite
from tests.fixtures import (CANDIDATE, DECLINED, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, detail_page, headlines,
                            listing_page, make_live, throwaway_settings)
from tests.test_onion import AHMIA, DUCKDUCKGO
from tests.writer_harness import start_writer

# Synthetic credentials. Each plaintext below must never be found anywhere under the data directory.
PLAINTEXT = ("SynthPassw0rd!", "bob.synthetic@example.org", "4111 1111 1111 1111")
LEAKY = "<p>bob.synthetic@example.org:SynthPassw0rd!</p><p>card 4111 1111 1111 1111</p>"


class FakeTor:
    def success_rate(self):
        return 1.0


class ScriptedFetcher:
    """Stands in for the network: one canned result per path, every call recorded."""

    def __init__(self, pages, hosts=None):
        self.pages = pages
        self.hosts = hosts or {}
        self.calls = []
        self.tor = FakeTor()

    async def fetch(self, source_id: str, path: str) -> FetchResult:
        self.calls.append((source_id, path))
        host = self.hosts.get(source_id, NEWS)
        page = self.pages.get(path)
        if isinstance(page, FetchResult):
            return page
        if page is None:
            return FetchResult(source_id, path, host=host, url=f"http://{host}{path}", error="timeout", elapsed=0.1)
        return FetchResult(source_id, path, host=host, url=f"http://{host}{path}", status=200,
                           headers={"content-type": "text/html"}, body=page, elapsed=0.4)


class CrawlerTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "configs").mkdir()
        (self.root / "data").mkdir()
        (self.root / "configs" / "news.toml").write_text(NEWS_CONFIG)
        self.harness = await start_writer(self.root / "data", self.root / "configs")
        self.stores = self.harness.stores
        self.settings = throwaway_settings(data_dir=self.root / "data", configs_dir=self.root / "configs",
                                           state_dir=self.root / "state", writer_socket=self.harness.socket,
                                           tor_instances=((10051, 11051),), max_retries=1)
        self.crawler = Crawler(self.settings)
        await self.crawler.open()
        await make_live(self.stores.sources)

    async def asyncTearDown(self):
        await self.crawler.close()
        await self.harness.stop()
        self.tmp.cleanup()

    async def claim(self):
        return await self.crawler.frontier.claim(1, await self.crawler.writer.collecting())

    async def crawl(self, pages, hosts=None) -> ScriptedFetcher:
        """One scheduler pass, then workers until nothing is claimable."""
        fetcher = ScriptedFetcher(pages, hosts)
        await self.crawler.start_due_runs()
        while tasks := await self.claim():
            await self.crawler.handle(tasks[0], fetcher)
        return fetcher

    async def rows(self, sql: str, *params):
        # The frontier is the crawler's own database; everything else is the writer's.
        database = self.crawler.queue if " urls" in sql else self.stores.collect
        return await database.rows(sql, params)

    async def records(self):
        return await self.stores.records.db.rows("SELECT * FROM records ORDER BY id")

    def everything_on_disk(self) -> bytes:
        return b"".join(path.read_bytes() for path in self.root.rglob("*") if path.is_file())


class ApprovalGateTest(CrawlerTestCase):
    """Section 17, test 1: candidates, declined hosts and sources not live are never fetched."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        table = self.stores.sources
        await table.change_state("news", lifecycle.DISABLED, "reviewer pulled it")
        await table.approve(AHMIA, "directory", "directories", "listing index", "tester", frozenset())
        await table.add_candidates({CANDIDATE, DECLINED}, None)
        await table.decline(DECLINED, "sells data", "tester")
        (self.root / "configs" / "directory.toml").write_text(
            NEWS_CONFIG.replace('"news"', '"directory"').replace(NEWS, AHMIA).replace("journalism-publishing", "directories"))

    async def test_scheduler_starts_nothing_and_writes_nothing_beyond_the_source_table(self):
        fetcher = await self.crawl({"/articles/": listing_page("A", "B")})
        self.assertEqual(fetcher.calls, [])
        for table in ("urls", "runs", "page_metrics", "uptime"):
            (count,), = await self.rows(f"SELECT COUNT(*) FROM {table}")
            self.assertEqual(count, 0, table)
        self.assertEqual(await self.records(), [])
        self.assertEqual(list((self.root / "data" / "snapshots").rglob("*")), [])

    async def test_direct_fetcher_calls_build_no_request(self):
        built = []
        configs = {"news": mock.Mock(hosts=(NEWS,), scheme="http"), "directory": mock.Mock(hosts=(AHMIA,), scheme="http")}
        with mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=lambda **kw: built.append(kw)):
            fetcher = Fetcher(self.settings, mock.Mock(), self.crawler.writer, configs, lifecycle.COLLECTING)
            for source_id in ("news", "directory", CANDIDATE, DECLINED, "nothing-here"):
                result = await fetcher.fetch(source_id, "/")
                self.assertEqual(result.error, "not_approved", source_id)
        self.assertEqual(built, [])


class FrontierContainmentTest(CrawlerTestCase):
    """Section 17, test 2: off-source onion links become candidates and reach no frontier."""

    async def test_off_source_links_land_in_the_candidate_table_only(self):
        await self.stores.sources.approve(DUCKDUCKGO, "search", "privacy-services", "search", "tester", frozenset())
        links = "".join(f"<a href='http://{host}/x'>x</a>" for host in (AHMIA, OFF_SOURCE, DUCKDUCKGO))
        page = listing_page("A", "B", extra=links + f"<p>mirror at {CANDIDATE}</p>")
        await self.crawl({"/articles/": page, "/articles/1": detail_page("one"), "/articles/2": detail_page("two")})
        candidates = await self.stores.sources.hosts(lifecycle.CANDIDATE)
        self.assertEqual({row["host"] for row in candidates}, {AHMIA, OFF_SOURCE, CANDIDATE})
        self.assertEqual({row["found_on"] for row in candidates}, {"news"})
        queued = await self.rows("SELECT source_id, path FROM urls ORDER BY path")
        self.assertEqual([tuple(row) for row in queued],
                         [("news", "/articles/"), ("news", "/articles/1"), ("news", "/articles/2")])

    async def test_with_a_host_prefix_off_source_links_are_still_candidates_only(self):
        (self.root / "configs" / "news.toml").write_text(
            NEWS_CONFIG.replace('cadence = "6h"', 'cadence = "6h"\nhost_prefix = "www"'))
        links = "".join(f"<a href='http://{host}/x'>x</a>" for host in (AHMIA, f"www.{OFF_SOURCE}", f"www.{NEWS}"))
        page = listing_page("A", "B", extra=links)
        await self.crawl({"/articles/": page, "/articles/1": detail_page("one"), "/articles/2": detail_page("two")})
        candidates = await self.stores.sources.hosts(lifecycle.CANDIDATE)
        self.assertEqual({row["host"] for row in candidates}, {AHMIA, OFF_SOURCE})
        queued = await self.rows("SELECT source_id, path FROM urls ORDER BY path")
        self.assertEqual([tuple(row) for row in queued],
                         [("news", "/articles/"), ("news", "/articles/1"), ("news", "/articles/2")])

    async def test_redirect_off_the_source_is_recorded_not_followed(self):
        moved = FetchResult("news", "/articles/", host=NEWS, status=302, error="redirect",
                            redirect_to=f"http://{OFF_SOURCE}/articles/")
        fetcher = await self.crawl({"/articles/": moved})
        self.assertEqual(fetcher.calls, [("news", "/articles/")])
        self.assertEqual([row["host"] for row in await self.stores.sources.hosts(lifecycle.CANDIDATE)], [OFF_SOURCE])
        (status,), = await self.rows("SELECT status FROM urls WHERE path = '/articles/'")
        self.assertEqual(status, "failed")
        self.assertEqual(await self.stores.sources.redirected_from([OFF_SOURCE]), {OFF_SOURCE: ["news"]})

    async def test_redirect_within_the_source_is_queued_as_its_own_fetch(self):
        (self.root / "configs" / "news.toml").write_text(NEWS_CONFIG.replace('["/articles/"]', '["/articles"]'))
        moved = FetchResult("news", "/articles", host=NEWS, status=301, error="redirect",
                            redirect_to=f"http://{NEWS}/articles/")
        fetcher = await self.crawl({"/articles": moved, "/articles/": listing_page("A", "B"),
                                    "/articles/1": detail_page("one"), "/articles/2": detail_page("two")})
        self.assertEqual(fetcher.calls[:2], [("news", "/articles"), ("news", "/articles/")])
        self.assertEqual(len(await self.records()), 2)


class RedactionGateTest(CrawlerTestCase):
    """Section 17, test 3: tags and hashes reach disk, plaintext never does, and a top-priority health item
    is raised."""

    async def test_synthetic_credentials_are_redacted_everywhere_on_disk(self):
        # An item already at the most the shortfall formula gives, on a heavier category, to rank against.
        await self.stores.sources.approve(AHMIA, "directory", "directories", "listing index", "tester", frozenset())
        await self.stores.health.raise_item("directory", health.Finding(health.UNREACHABLE, 100, "down"), None)
        with self.assertLogs("onioncollect.crawler", logging.INFO) as logs:
            await self.crawl({"/articles/": listing_page("A " + LEAKY, "B", extra=LEAKY),
                              "/articles/1": detail_page(LEAKY), "/articles/2": detail_page("two")})
        records = await self.records()
        self.assertEqual(len(records), 2)
        self.assertIn("[email_password]", records[0]["fields"])
        self.assertIn("[card]", records[0]["fields"])
        self.assertIn('"email_password": 2', records[0]["redactions"])
        disk = self.everything_on_disk()
        for secret in PLAINTEXT:
            self.assertNotIn(secret.encode(), disk, secret)
        (events,), = await self.rows("SELECT redactions FROM runs")
        self.assertGreater(events, 0)
        top, *rest = await self.stores.health.queue()
        self.assertEqual((top["source_id"], top["kind"], top["priority"]), ("news", health.REDACTION, health.REDACTION_PRIORITY))
        self.assertTrue(all(item["priority"] < top["priority"] for item in rest))
        self.assertEqual((await self.stores.sources.get("news"))["state"], lifecycle.DEGRADED)
        self.assertFalse(any("WARNING" in line for line in logs.output), "the item replaced the warning line")
        for secret in PLAINTEXT:
            self.assertNotIn(secret, "\n".join(logs.output))

    async def test_refused_write_is_logged_without_the_record_and_raised(self):
        with mock.patch.object(self.stores.records, "add", side_effect=RefusedWrite("x")):
            with self.assertLogs("onioncollect.crawler", logging.WARNING) as logs:
                await self.crawl({"/articles/": listing_page("A", "B")})
        self.assertIn("news write refused", "\n".join(logs.output))
        (item,) = [item for item in await self.stores.health.queue() if item["kind"] == health.REDACTION]
        self.assertEqual(item["detail"], "write refused: a secret survived")


class CollectionTest(CrawlerTestCase):
    async def test_pagination_detail_and_run_close(self):
        pages = {
            "/articles/": listing_page("A", "B", next_href="/articles/?page=2"),
            "/articles/?page=2": listing_page("A", "B", next_href="/articles/?page=3"),
            "/articles/?page=3": listing_page("A", "B", next_href="/articles/?page=4"),
            **{f"/articles/{n}": detail_page(f"story {n}") for n in (1, 2)},
        }
        fetcher = await self.crawl(pages)
        listings = [path for _, path in fetcher.calls if "page" in path or path == "/articles/"]
        self.assertEqual(listings, ["/articles/", "/articles/?page=2", "/articles/?page=3"])
        records = await self.records()
        self.assertEqual(len(records), 2, "the three listing pages repeat the same two articles")
        self.assertIn("story 1", records[0]["fields"])
        run, = await self.rows("SELECT * FROM runs")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual((run["pages"], run["failures"], run["below_expectation"]), (5, 0, 0))
        source = await self.stores.sources.get("news")
        self.assertGreater(source["next_run"], run["finished_at"])
        kinds = await self.stores.records.db.rows("SELECT kind, COUNT(*) FROM snapshots GROUP BY kind ORDER BY kind")
        self.assertEqual([tuple(row) for row in kinds], [(DETAIL, 1), (LISTING, 3)])

    async def test_second_run_refreshes_records_and_skips_known_details(self):
        pages = {"/articles/": listing_page("A", "B"), "/articles/1": detail_page("one"), "/articles/2": detail_page("two")}
        await self.crawl(pages)
        await self.stores.collect.conn.execute("UPDATE sources SET next_run = NULL")
        await self.stores.collect.conn.commit()
        fetcher = await self.crawl(pages)
        self.assertEqual(fetcher.calls, [("news", "/articles/")])
        self.assertEqual(len(await self.records()), 2)
        (runs,), = await self.rows("SELECT COUNT(*) FROM runs WHERE finished_at IS NOT NULL")
        self.assertEqual(runs, 2)

    async def test_thin_page_is_below_expectation(self):
        await self.crawl({"/articles/": listing_page("only one"), "/articles/1": detail_page("x")})
        run, = await self.rows("SELECT below_expectation, items FROM runs")
        self.assertEqual(tuple(run), (1, 1))

    async def test_run_that_fetched_nothing_counts_as_failed(self):
        await self.crawl({})
        run, = await self.rows("SELECT pages, failures, finished_at FROM runs")
        self.assertEqual((run["pages"], run["failures"]), (0, 1))
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual((await self.stores.sources.get("news"))["failed_runs"], 1)

    async def test_body_tripping_the_safety_check_disables_the_source_and_stores_nothing(self):
        with self.assertLogs("onioncollect.crawler", logging.WARNING):
            await self.crawl({"/articles/": listing_page("A forbiddenterm", "B")})
        source = await self.stores.sources.get("news")
        self.assertEqual((source["state"], source["reason"]), ("disabled", "safety: child_exploitation"))
        self.assertEqual(await self.stores.records.counts(), {"records": 0, "snapshots": 0})
        (open_runs,), = await self.rows("SELECT COUNT(*) FROM runs WHERE finished_at IS NULL")
        self.assertEqual(open_runs, 0)

    async def test_gated_page_stores_nothing(self):
        gate = b"<html><head><title>Checking your browser</title></head><body>wait</body></html>"
        await self.crawl({"/articles/": gate})
        self.assertEqual(await self.stores.records.counts(), {"records": 0, "snapshots": 0})
        (error,), = await self.rows("SELECT error FROM page_metrics")
        self.assertEqual(error, "gated")

    async def test_broken_config_is_not_scheduled_and_logged_once(self):
        (self.root / "configs" / "news.toml").write_text(NEWS_CONFIG.replace('item = "article"', 'item = "//x"'))
        with self.assertLogs("onioncollect.crawler", logging.ERROR) as logs:
            await self.crawl({})
            await self.crawl({})
        self.assertEqual(len(logs.output), 1)
        (runs,), = await self.rows("SELECT COUNT(*) FROM runs")
        self.assertEqual(runs, 0)

    async def test_config_naming_an_unapproved_host_is_not_scheduled(self):
        (self.root / "configs" / "news.toml").write_text(
            NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{OFF_SOURCE}"]'))
        with self.assertLogs("onioncollect.crawler", logging.ERROR):
            fetcher = await self.crawl({})
        self.assertEqual(fetcher.calls, [])

    async def test_logs_never_carry_paths_titles_or_text(self):
        pages = {"/articles/": listing_page("Secret Title Words", "Other " + LEAKY,
                                            extra=f"<a href='http://{AHMIA}/q?s=1'>x</a>"),
                 "/articles/1": detail_page("story")}
        with self.assertLogs("onioncollect", logging.DEBUG) as logs:
            await self.crawl(pages)
        text = "\n".join(logs.output)
        for forbidden in ("/articles", "Secret Title", "q?s=1", AHMIA, *PLAINTEXT):
            self.assertNotIn(forbidden, text)
        self.assertIn("news listing status=200", text)

    async def test_hostile_body_does_not_stall_the_loop(self):
        await self.crawler.start_due_runs()
        (task,) = await self.claim()
        fetcher = ScriptedFetcher({"/articles/": b"<p>" + b"a" * 1_999_000 + b"</p>"})
        # The test runner's debug mode logs every slow step, which is itself slow enough to blur the measure.
        asyncio.get_running_loop().set_debug(False)
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
        started = time.perf_counter()
        await self.crawler.handle(task, fetcher)
        took = time.perf_counter() - started
        done.set()
        await ticking
        self.assertLess(max(gaps), took / 2)


class HealthTest(CrawlerTestCase):
    """Section 13's entry rules, raised as runs finish."""

    async def again(self, pages):
        await self.stores.collect.conn.execute("UPDATE sources SET next_run = NULL")
        await self.stores.collect.conn.commit()
        return await self.crawl(pages)

    async def items(self):
        return [(item["kind"], item["priority"]) for item in await self.stores.health.queue()]

    async def test_a_thin_run_raises_by_how_far_below_and_degrades_the_source(self):
        await self.crawl({"/articles/": listing_page("only one"), "/articles/1": detail_page("x")})
        self.assertEqual(await self.items(), [(health.BELOW_EXPECTATION, 50)])
        self.assertEqual((await self.stores.sources.get("news"))["state"], lifecycle.DEGRADED)
        fetcher = await self.again({"/articles/": listing_page("only one")})
        self.assertEqual(fetcher.calls, [("news", "/articles/")], "a degraded source still collects")
        (item,) = await self.stores.health.queue()
        self.assertEqual(item["occurrences"], 2)

    async def test_a_required_field_lost_across_the_run(self):
        page = b"<html><body>" + b"<article><time datetime='2026-11-07'>x</time></article>" * 3 + b"</body></html>"
        await self.crawl({"/articles/": page})
        self.assertEqual(await self.items(), [(health.REQUIRED_FIELD_LOST, 100)])
        (item,) = await self.stores.health.queue()
        self.assertEqual(item["detail"], "title, url resolved on none of 3 items")

    async def test_per_field_hits_are_kept_per_run(self):
        await self.crawl({"/articles/": listing_page("A", "B"), "/articles/1": detail_page("one"),
                          "/articles/2": b"<html><body>gone</body></html>"})
        rows = await self.rows("SELECT kind, field, resolved, declared FROM run_fields ORDER BY kind, field")
        self.assertEqual([tuple(row) for row in rows], [("detail", "body", 1, 2), ("listing", "published", 2, 2),
                                                        ("listing", "title", 2, 2), ("listing", "url", 2, 2)])

    async def test_unreachable_only_once_the_quick_retries_are_spent(self):
        for run in range(1, scheduler.QUICK_RETRY_RUNS + 2):
            await self.again({})
            raised = await self.items()
            self.assertEqual(raised, [] if run <= scheduler.QUICK_RETRY_RUNS else [(health.UNREACHABLE, 100)], run)
        (item,) = await self.stores.health.queue()
        self.assertEqual(item["detail"], "nothing fetched in 4 runs in a row, last error timeout")

    async def test_a_body_over_the_tag_cap_is_never_parsed(self):
        # Step 5 measured lexbor at 30 s on this body.
        body = b"<div>" * 200_000
        result = FetchResult("news", "/articles/", host=NEWS, url=f"http://{NEWS}/articles/", status=200, body=body)
        started = time.perf_counter()
        with mock.patch.object(pages, "LexborHTMLParser", side_effect=AssertionError("parsed")):
            found = inspect(result, LISTING, self.crawler.configs.get("news") or await self.crawler.config_for("news"),
                            self.settings.safety_patterns, self.settings.redaction_salt)
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertTrue(found.refused)
        fetcher = await self.crawl({"/articles/": body})
        self.assertEqual(fetcher.calls, [("news", "/articles/")], "a refusal is not retried")
        (error,), = await self.rows("SELECT error FROM page_metrics")
        self.assertEqual(error, "parse_refused")
        self.assertEqual(await self.stores.records.counts(), {"records": 0, "snapshots": 0})
        self.assertEqual(await self.stores.records.seed_fingerprints(), {})
        self.assertEqual(await self.items(), [(health.PARSE_REFUSED, 100)])

    async def test_a_disabled_source_raises_nothing_more(self):
        with self.assertLogs("onioncollect.crawler", logging.WARNING):
            await self.crawl({"/articles/": listing_page("A forbiddenterm")})
        self.assertEqual(await self.items(), [])


class MirrorClusterTest(CrawlerTestCase):
    """Two live sources serving the same pages from two addresses: one cluster, one row per article."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.stores.sources, "paper", NEWS_MIRROR)
        (self.root / "configs" / "paper.toml").write_text(
            NEWS_CONFIG.replace('id = "news"', 'id = "paper"').replace(NEWS, NEWS_MIRROR))
        self.pages = {"/articles/": listing_page(*headlines("monday")),
                      **{f"/articles/{n}": detail_page(f"story {n} body") for n in range(1, 6)}}

    async def test_fingerprints_are_stored_per_host_and_path_with_the_seed_marked(self):
        await self.crawl(self.pages, {"paper": NEWS_MIRROR})
        rows = await self.stores.records.db.rows("SELECT host, path, seed FROM fingerprints ORDER BY host, path")
        self.assertEqual({(row["host"], row["path"]) for row in rows if row["seed"]}, {(NEWS, "/articles/"),
                                                                                       (NEWS_MIRROR, "/articles/")})
        self.assertEqual(len(rows), 12)

    async def test_records_dedupe_across_the_cluster_from_the_first_run(self):
        await self.crawl(self.pages, {"paper": NEWS_MIRROR})
        self.assertEqual(await self.stores.sources.cluster_of("news"), ("news", "paper"))
        records = await self.records()
        self.assertEqual(len(records), 5)
        self.assertTrue(all("body" in json.loads(row["fields"]) for row in records))
        sightings = await self.stores.records.db.rows("SELECT record_id, host, source_id FROM record_hosts")
        self.assertEqual(len(sightings), 10)
        self.assertEqual({(row["host"], row["source_id"]) for row in sightings}, {(NEWS, "news"), (NEWS_MIRROR, "paper")})
        (found,) = await self.stores.records.search('"monday story 3"', source="paper")
        self.assertEqual(found["sources"], ["news", "paper"])

    async def only_due(self, source_id: str) -> None:
        await self.stores.collect.conn.execute(
            "UPDATE sources SET next_run = CASE WHEN id = ? THEN NULL ELSE '2999-01-01' END", (source_id,))
        await self.stores.collect.conn.commit()

    async def test_a_template_only_match_is_two_sources_with_their_own_rows(self):
        await self.only_due("news")
        await self.crawl(self.pages)
        await self.only_due("paper")
        await self.crawl(self.pages | {"/articles/": listing_page(*headlines("tuesday"))}, {"paper": NEWS_MIRROR})
        self.assertEqual(await self.stores.sources.cluster_of("paper"), ("paper",))
        self.assertEqual(len(await self.records()), 10)
        self.assertEqual({row["source_id"] for row in await self.records()}, {"news", "paper"})


if __name__ == "__main__":
    unittest.main()
