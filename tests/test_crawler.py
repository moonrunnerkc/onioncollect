import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from onioncrawl.config import Settings
from onioncrawl.crawler import Crawler
from onioncrawl.db import stamp
from onioncrawl.fetcher import FetchResult
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT

PATTERNS = "child_exploitation \\bforbiddenterm\\b\ncredential_dump zzcredzz\ncard_number 4111111111111111\n"
TITLE = "Secret Title Words"
PAGE = f"<title>{TITLE}</title><p>hello there</p><a href='/inner/path?q=secret'>x</a><!-- {TORPROJECT} -->".encode()


def ok(url: str, body: bytes = PAGE, final_url: str | None = None, status: int = 200) -> FetchResult:
    return FetchResult(url=url, final_url=final_url or url, status=status, headers={"content-type": "text/html"},
                       body=body, elapsed=1.5)


class FakeTor:
    def __init__(self, rate=1.0):
        self.rate = rate

    def success_rate(self):
        return self.rate


class CrawlerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "exclusions.txt").write_text(f"# listed\n{DUCKDUCKGO}\n")
        (root / "patterns.txt").write_text(PATTERNS)
        self.settings = Settings(
            control_password="x", data_dir=root / "data", tor_instances=((10051, 11051),),
            exclusions_file=root / "exclusions.txt", safety_patterns_file=root / "patterns.txt",
        )
        (root / "data").mkdir()
        self.crawler = Crawler(self.settings)
        await self.crawler.frontier.open(root / "data" / "crawl.db")

    async def asyncTearDown(self):
        await self.crawler.frontier.close()
        self.tmp.cleanup()

    async def claim(self, url: str):
        await self.crawler.frontier.seed([url])
        (task,) = await self.crawler.frontier.claim(1)
        return task

    async def rows(self, sql: str, *params):
        return list(await self.crawler.frontier.db.execute_fetchall(sql, params))

    def stored_files(self) -> list[Path]:
        return list((self.settings.data_dir / "pages").rglob("*.gz"))

    async def test_success_saves_and_completes(self):
        task = await self.claim(f"http://{AHMIA}/")
        with self.assertLogs("onioncrawl.crawler", "INFO") as logs:
            await self.crawler.handle_success(task, ok(task.url))
        self.assertEqual(len(self.stored_files()), 1)
        self.assertEqual(await self.rows("SELECT status FROM urls WHERE url = ?", task.url), [("done",)])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM pages"), [(1,)])
        self.assertEqual(logs.output, [
            f"INFO:onioncrawl.crawler:{AHMIA} status=200 bytes={len(PAGE)} links=1 onions=1 changed=yes elapsed=1.5s"
        ])

    async def test_listed_host_is_never_saved(self):
        task = await self.claim(f"http://{DUCKDUCKGO}/")
        with self.assertLogs("onioncrawl.crawler") as logs:
            await self.crawler.handle_success(task, ok(task.url))
        self.assertEqual(self.stored_files(), [])
        self.assertEqual(await self.rows("SELECT state FROM hosts WHERE host = ?", DUCKDUCKGO), [("excluded",)])
        self.assertEqual(logs.output, [f"WARNING:onioncrawl.crawler:{DUCKDUCKGO} excluded: listed"])

    async def test_body_trigger_excludes_host_and_keeps_links(self):
        await self.crawler.frontier.seed([f"http://{AHMIA}/other"])
        task = await self.claim(f"http://{AHMIA}/")
        body = PAGE + b" forbiddenterm 4111111111111111"
        with self.assertLogs("onioncrawl.crawler") as logs:
            await self.crawler.handle_success(task, ok(task.url, body))
        self.assertEqual(self.stored_files(), [])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM pages"), [(0,)])
        self.assertEqual(await self.rows("SELECT DISTINCT status FROM urls WHERE host = ?", AHMIA), [("parked",)])
        self.assertEqual(await self.rows("SELECT COUNT(*) FROM urls WHERE host = ?", TORPROJECT), [(1,)])
        self.assertEqual(logs.output, [f"WARNING:onioncrawl.crawler:{AHMIA} excluded: child_exploitation"])
        self.assertIn(AHMIA, self.crawler.exclusions)

    async def test_second_in_flight_page_of_an_excluded_host_is_not_saved(self):
        await self.crawler.frontier.seed([f"http://{AHMIA}/a", f"http://{AHMIA}/b"])
        first, second = await self.crawler.frontier.claim(2)
        await self.crawler.handle_success(first, ok(first.url, PAGE + b" zzcredzz"))
        await self.crawler.handle_success(second, ok(second.url))
        self.assertEqual(self.stored_files(), [])
        self.assertEqual(await self.rows("SELECT state FROM hosts WHERE host = ?", AHMIA), [("excluded",)])

    async def test_redirect_onto_a_listed_host_is_not_saved(self):
        task = await self.claim(f"http://{AHMIA}/go")
        await self.crawler.handle_success(task, ok(task.url, final_url=f"http://{DUCKDUCKGO}/landing"))
        self.assertEqual(self.stored_files(), [])

    async def test_gated_page_is_not_saved_and_recrawled_weekly(self):
        task = await self.claim(f"http://{AHMIA}/")
        gate = b"<title>DDoS protection</title><form><input type=password></form>"
        await self.crawler.handle_success(task, ok(task.url, gate))
        self.assertEqual(self.stored_files(), [])
        (state,), = await self.rows("SELECT state FROM hosts WHERE host = ?", AHMIA)
        (due,), = await self.rows("SELECT next_due FROM urls WHERE url = ?", task.url)
        self.assertEqual(state, "gated")
        self.assertGreater(datetime.fromisoformat(due).replace(tzinfo=UTC), datetime.now(UTC) + timedelta(days=6))

    async def test_failure_logs_host_and_error_and_rotates_a_sick_instance(self):
        task = await self.claim(f"http://{AHMIA}/deep/path?q=1")
        fetcher = mock.Mock(tor=FakeTor(rate=0.2))
        result = FetchResult(url=task.url, final_url=task.url, error="tor_unreachable", elapsed=20.0)
        with mock.patch.object(self.crawler.tor_pool, "rotate_for", mock.AsyncMock()) as rotate, \
                self.assertLogs("onioncrawl.crawler") as logs:
            await self.crawler.handle_failure(task, result, fetcher)
        rotate.assert_awaited_once_with(fetcher.tor)
        self.assertEqual(logs.output, [f"INFO:onioncrawl.crawler:{AHMIA} error=tor_unreachable elapsed=20.0s"])
        self.assertEqual(await self.rows("SELECT status, retries FROM urls"), [("queued", 1)])

    async def test_host_dies_after_spread_failures(self):
        task = await self.claim(f"http://{AHMIA}/")
        start = datetime.now(UTC) - timedelta(hours=30)
        for hours in (0, 6, 12, 18):
            await self.crawler.frontier.db.execute(
                "INSERT INTO uptime VALUES (?, ?, 0)", (AHMIA, stamp(start + timedelta(hours=hours)))
            )
        result = FetchResult(url=task.url, final_url=task.url, error="timeout", elapsed=45.0)
        with self.assertLogs("onioncrawl.crawler") as logs:
            await self.crawler.handle_failure(task, result, mock.Mock(tor=FakeTor()))
        self.assertEqual(await self.rows("SELECT state FROM hosts"), [("dead",)])
        self.assertEqual(await self.rows("SELECT status FROM urls"), [("parked",)])
        self.assertIn(f"INFO:onioncrawl.crawler:{AHMIA} marked dead", logs.output)

    async def test_host_that_answered_is_not_counted_down(self):
        task = await self.claim(f"http://{AHMIA}/file.pdf")
        result = FetchResult(url=task.url, final_url=task.url, status=200, error="not_text", elapsed=2.0)
        await self.crawler.handle_failure(task, result, mock.Mock(tor=FakeTor()))
        self.assertEqual(await self.rows("SELECT state, consecutive_failures FROM hosts"), [("up", 0)])
        self.assertEqual(await self.rows("SELECT status FROM urls"), [("parked",)])

    async def test_logs_never_carry_paths_queries_or_titles(self):
        task = await self.claim(f"http://{AHMIA}/inner/path?q=secret")
        with self.assertLogs("onioncrawl", "DEBUG") as logs:
            await self.crawler.handle_success(task, ok(task.url))
            await self.crawler.handle_failure(task, FetchResult(url=task.url, final_url=task.url, error="timeout"),
                                              mock.Mock(tor=FakeTor()))
        joined = "\n".join(logs.output)
        for leak in ("/inner", "path", "secret", "Secret", TITLE, "hello"):
            self.assertNotIn(leak, joined)


if __name__ == "__main__":
    unittest.main()
