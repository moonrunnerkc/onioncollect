import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx

from onioncollect import probes
from onioncollect.db import open_collect
from onioncollect.runs import RunLog
from onioncollect.fetcher import Fetcher
from onioncollect.sources import SourceTable
from tests.fixtures import NEWS, NEWS_CONFIG, NEWS_MIRROR, make_live, news_config, throwaway_settings
from tests.test_db import Clock
from tests.test_fetcher import HTML, FetcherTestCase, TrackingStream

TWO_HOSTS = news_config(NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]'))


class Direct:
    """The writer ops a prober uses, straight against the stores, so the test's clock drives them. The crawler
    tests run the same calls through the socket."""

    def __init__(self, table: SourceTable, runs: RunLog):
        self.table, self.runs = table, runs

    async def resolve(self, source_id):
        return await self.table.resolve(source_id)

    async def due_probes(self, interval):
        return await self.runs.due_probes(interval)

    async def probe_result(self, host, up):
        await self.runs.record_probe(host, up)


class Captured(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class ProbeTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.db = await open_collect(Path(self.dir.name) / "collect.db")
        self.table = SourceTable(self.db, clock=self.clock)
        await make_live(self.table)
        await self.table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset())
        self.prober = probes.Prober(throwaway_settings(), Direct(self.table, RunLog(self.db, clock=self.clock)),
                                    clock=self.clock)
        self.config = TWO_HOSTS
        self.requested = []

    async def asyncTearDown(self):
        await self.db.close()
        self.dir.cleanup()

    async def probe(self, answer=200):
        async def get(fetcher, result, url):
            # The real resolve ran first: this is the URL the fetcher built from the source id and the path.
            self.requested.append(url)
            if isinstance(answer, Exception):
                raise answer
            result.status, result.body = answer, b"<html>dropped unread</html>"

        async def config_for(source_id):
            return self.config

        logs = Captured()
        logger = logging.getLogger("onioncollect.probes")
        logger.addHandler(logs)
        level, logger.level = logger.level, logging.INFO
        try:
            with mock.patch.object(Fetcher, "_get", get):
                count = await self.prober.probe_due(config_for, lambda n: mock.Mock())
        finally:
            logger.removeHandler(logs)
            logger.setLevel(level)
        for line in logs.lines:
            self.assertNotIn(NEWS_MIRROR, line)
            self.assertNotIn("/articles/", line)
        return count, logs.lines

    async def sighting(self):
        (row,) = await self.db.rows("SELECT last_up, last_down FROM hosts WHERE host = ?", (NEWS_MIRROR,))
        return tuple(row)

    async def test_the_sibling_is_fetched_by_source_id_through_its_own_set(self):
        count, logs = await self.probe()
        self.assertEqual(count, 1)
        self.assertEqual(self.requested, [f"http://{NEWS_MIRROR}/articles/"])
        self.assertIsNotNone((await self.sighting())[0])
        self.assertIn("news sibling probe status=200", logs[0])
        (uptime,) = await self.db.rows("SELECT host, up FROM uptime")
        self.assertEqual(tuple(uptime), (NEWS_MIRROR, 1))
        tables = {row[0] for row in await self.db.rows("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertNotIn("records", tables, "a probe has nowhere to store a page")

    async def test_an_unanswered_probe_marks_the_host_down(self):
        await self.probe(httpx.ConnectTimeout("x"))
        last_up, last_down = await self.sighting()
        self.assertIsNone(last_up)
        self.assertIsNotNone(last_down)

    async def test_once_a_day(self):
        await self.probe()
        self.clock.advance(hours=23)
        self.assertEqual((await self.probe())[0], 0)
        self.clock.advance(hours=2)
        self.assertEqual((await self.probe())[0], 1)
        self.assertEqual(len(self.requested), 2)

    async def test_a_refused_probe_records_nothing_and_is_not_retried_every_pass(self):
        self.config = news_config()
        count, logs = await self.probe()
        self.assertEqual(count, 1)
        self.assertEqual(self.requested, [])
        self.assertIn("news sibling probe refused: not_source_host", logs[0])
        self.assertEqual(await self.sighting(), (None, None))
        self.assertEqual(await self.db.rows("SELECT * FROM uptime"), [])
        self.clock.advance(hours=1)
        self.assertEqual(await self.probe(), (0, []))

    async def test_the_active_host_is_never_probed(self):
        await self.table.set_active_host("news", NEWS_MIRROR)
        await self.probe()
        self.assertEqual(self.requested, [f"http://{NEWS}/articles/"])


class ProbeFetcherControlsTest(FetcherTestCase):
    """A probe is a Fetcher.fetch like any other: the Content-Type allowlist and the cap apply before and while
    the body is read, though the probe then drops it."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset())
        self.prober = probes.Prober(throwaway_settings(max_body_bytes=1000), Direct(self.table, RunLog(self.db)))

    async def test_a_binary_answer_is_refused_before_a_byte_of_its_body_is_read(self):
        stream = TrackingStream([b"PK\x03\x04" * 100])
        self.route("/articles/", headers={"content-type": "application/zip"}, stream=stream, host=NEWS_MIRROR)
        self.assertTrue(await self.prober.probe("news", NEWS_MIRROR, TWO_HOSTS, self.tor))
        self.assertEqual(stream.consumed, 0)

    async def test_a_text_answer_is_read_no_further_than_the_cap(self):
        stream = TrackingStream([b"a" * 600] * 10)
        self.route("/articles/", headers=HTML, stream=stream, host=NEWS_MIRROR)
        self.assertTrue(await self.prober.probe("news", NEWS_MIRROR, TWO_HOSTS, self.tor))
        self.assertEqual(stream.consumed, 2, "the read stops at the chunk that crosses 1000 bytes")


if __name__ == "__main__":
    unittest.main()
