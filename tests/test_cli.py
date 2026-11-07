import asyncio
import fcntl
import io
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import stem

from onioncrawl import cli
from onioncrawl.config import Settings
from tests.test_db import page
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT


class LoggingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = logging.getLogger().handlers[:]

    def tearDown(self):
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if handler not in self.saved:
                root.removeHandler(handler)
                handler.close()
        self.tmp.cleanup()

    def test_library_info_never_reaches_the_log(self):
        path = Path(self.tmp.name) / "crawl.log"
        with mock.patch("sys.stderr", io.StringIO()):
            cli.configure_logging(path)
            logging.getLogger("stem").setLevel(5)
            logging.getLogger("httpx").setLevel(logging.INFO)
            logging.getLogger("httpx").info(f'HTTP Request: GET http://{AHMIA}/secret/path "HTTP/1.1 200 OK"')
            logging.getLogger("stem").info("control message")
            logging.getLogger("stem").warning("stem warning")
            logging.getLogger("onioncrawl.crawler").info(f"{AHMIA} status=200")
        text = path.read_text()
        self.assertNotIn("secret", text)
        self.assertNotIn("control message", text)
        self.assertIn("stem warning", text)
        self.assertIn(f"{AHMIA} status=200", text)


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "data").mkdir()
        (self.root / "pw").write_text("pw")
        (self.root / "pw").chmod(0o600)
        self.settings_path = self.root / "settings.toml"
        (self.root / "exclusions.txt").write_text(f"{TORPROJECT}\n")
        (self.root / "patterns.txt").write_text("child_exploitation x\ncredential_dump y\ncard_number z\n")
        self.settings_path.write_text(
            f'control_password_file = "{self.root / "pw"}"\ndata_dir = "{self.root / "data"}"\n'
            f'exclusions_file = "{self.root / "exclusions.txt"}"\nsafety_patterns_file = "{self.root / "patterns.txt"}"\n'
        )
        umask = os.umask(0o022)
        self.addCleanup(os.umask, umask)
        real_load = Settings.load
        patcher = mock.patch.object(Settings, "load", side_effect=lambda path: real_load(path, port_check=lambda port: True))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args: str) -> str:
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["--settings", str(self.settings_path), *args])
        return out.getvalue()

    def frontier_do(self, action):
        settings = Settings.load(self.settings_path)
        return asyncio.run(cli.with_frontier(settings, action))


class MainTest(CliTestCase):
    def test_refuses_root(self):
        with mock.patch("os.geteuid", return_value=0), self.assertRaisesRegex(SystemExit, "root"):
            cli.main(["--settings", str(self.settings_path), "seed", "x"])

    def test_refuses_data_dir_owned_by_someone_else(self):
        with mock.patch("os.geteuid", return_value=4242), self.assertRaisesRegex(SystemExit, "not owned"):
            cli.main(["--settings", str(self.settings_path), "seed", "x"])

    def test_seed_accepts_urls_and_bare_hosts(self):
        seeds = self.root / "seeds.txt"
        seeds.write_text(f"# comment\n\n{AHMIA}\nhttp://{DUCKDUCKGO}/x\nexample.com\n")
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["--settings", str(self.settings_path), "seed", str(seeds)])
        self.assertEqual(out.getvalue().strip(), "seeded 2, rejected 1")


class UnexcludeTest(CliTestCase):
    def exclude(self, host: str) -> None:
        async def action(frontier):
            await frontier.seed([f"http://{host}/", f"http://{host}/2"])
            first, second = await frontier.claim(2)
            await frontier.exclude(first, page())
            await frontier.fail(second, 0, None, host_answered=True)
        self.frontier_do(action)

    def test_unexclude_lifts_a_crawler_exclusion(self):
        self.exclude(AHMIA)
        self.assertEqual(self.cli("unexclude", AHMIA.upper()), f"{AHMIA} unexcluded, 2 URLs queued again\n")
        states = self.frontier_do(lambda f: f.db.execute_fetchall("SELECT DISTINCT status FROM urls WHERE host = ?", (AHMIA,)))
        self.assertEqual(list(states), [("queued",)])

    def test_host_that_is_not_excluded(self):
        self.assertEqual(self.cli("unexclude", DUCKDUCKGO), f"{DUCKDUCKGO} is not excluded\n")

    def test_refuses_a_host_on_the_exclusion_list(self):
        with self.assertRaisesRegex(SystemExit, "on the exclusion list"):
            self.cli("unexclude", TORPROJECT)
        self.assertEqual(self.frontier_do(lambda f: f.excluded_hosts()), {TORPROJECT})

    def test_refuses_what_is_not_a_v3_host(self):
        with self.assertRaisesRegex(SystemExit, "not a v3 onion host"):
            self.cli("unexclude", "example.com")

    def test_refuses_while_a_crawl_holds_the_lock(self):
        self.exclude(AHMIA)
        with open(self.root / "data" / "run.lock", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with self.assertRaisesRegex(SystemExit, "a crawl is running"):
                self.cli("unexclude", AHMIA)
        self.assertEqual(self.frontier_do(lambda f: f.excluded_hosts()), {AHMIA, TORPROJECT})


class FakeInstance:
    def __init__(self, socks_port, fails=False):
        self.socks_port, self.fails, self.closed = socks_port, fails, False

    def connect(self):
        if self.fails:
            raise stem.SocketError("refused")

    def is_ready(self):
        return True

    def open_counts(self):
        return 4, 3

    def close(self):
        self.closed = True


class StatusTest(CliTestCase):
    def test_status_table(self):
        self.frontier_do(lambda f: f.seed([f"http://{AHMIA}/", f"http://{AHMIA}/2", f"http://{DUCKDUCKGO}/"]))
        self.frontier_do(lambda f: f.claim(3))
        (self.root / "data" / "crawl.log").write_text(
            "2026-11-07 12:00:00,000 INFO onioncrawl.tor_pool: tor 10051: success 0.50 over 20 fetches, last rotation never\n"
            "2026-11-07 12:01:00,000 INFO onioncrawl.tor_pool: tor 10051: success 0.75 over 40 fetches, last rotation never\n"
        )
        instances = [FakeInstance(10051), FakeInstance(10052, fails=True)]
        with mock.patch.object(cli, "TorPool", return_value=mock.Mock(instances=instances)):
            lines = self.cli("status").splitlines()
        self.assertEqual(lines[0], "urls     queued 0  leased 3  done 0  parked 0")
        self.assertEqual(lines[1], "hosts    up 0  unknown 2  dead 0  gated 0  excluded 1")
        self.assertEqual(lines[2], "leases   2 hosts hold leases, at most 2 on one host (limit 2)")
        self.assertEqual(lines[3], "pages    0 stored, 0.0 MB on disk")
        self.assertEqual(lines[4], "fetches  0 in the last hour, 0% reached the host; 0.00/s over the last 5 min")
        self.assertEqual(lines[6].split(), ["10051", "ready", "4", "3", "0.75", "over", "40"])
        self.assertEqual(lines[7].split(), ["10052", "unreachable", "(SocketError)"])
        self.assertTrue(all(instance.closed for instance in instances))


if __name__ == "__main__":
    unittest.main()
