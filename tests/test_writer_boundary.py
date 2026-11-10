"""The write socket as a boundary. The crawler reaches the stores through it and no other way, a crawl does not
start without it, and the writer itself can reach nothing but its one unix socket and the stores."""
import ast
import grp
import os
import pwd
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import aiosqlite

from onioncollect import crawler as crawler_module
from onioncollect import fetcher as fetcher_module
from tests.fixtures import detail_page, listing_page
from tests.test_cli import CliTestCase
from tests.test_crawler import CrawlerTestCase
from tests.test_scheduling import FakePool
from tests.test_ui_entry import closure, own_imports
from tests.writer_harness import ThreadedWriter

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "onioncollect"

WRITER_CLOSURE = {f"onioncollect.{name}" for name in (
    "writer", "writer_ops", "wire", "db", "schema", "lifecycle", "sources", "onion", "records", "detect", "redact",
    "search", "matching", "health", "health_queue", "scheduler", "runs", "mirrors", "safety")}
NETWORK = {f"onioncollect.{name}" for name in (
    "fetcher", "tor_pool", "crawler", "crawl_cli", "session", "probes", "golive", "cli", "config", "source_config",
    "health_cli", "ui", "ui_main", "writer_client", "pages", "parser", "fingerprint", "extractor")}
# asyncio loads ssl itself; nothing in the writer's closure calls it (test_its_only_socket_is_one_af_unix_listener).
NEVER_LOADED = ("httpx", "httpcore", "httpx_socks", "python_socks", "socks", "socksio", "h11", "h2", "anyio", "stem",
                "selectolax", "urllib.request", "http.client", "http.server", "smtplib", "ftplib")
# The crawler's side of a crawl, golive and the fetching dispositions.
CRAWLER_PATH = ("crawler", "crawl_cli", "fetcher", "extractor", "redact", "scheduler", "writer_client", "pages", "probes",
                "session", "golive", "parser")
STORE_MODULES = {f"onioncollect.{name}" for name in (
    "records", "health_queue", "runs", "stores", "writer_ops", "writer", "mirrors")}
STORE_OPENERS = {"open_collect", "RecordStore", "SourceTable", "HealthQueue", "RunLog", "with_stores", "with_records",
                 "reading", "Stores", "Database"}
FRONTIER_SIDE = {"Frontier", "open_frontier", "Task", "PageMetric", "LISTING", "DETAIL", "RATE_WINDOW", "stamp"}


def tree(module: str) -> ast.AST:
    return ast.parse((PACKAGE / f"{module}.py").read_text())


def called(node: ast.AST) -> set[str]:
    return {ast.unparse(call.func).split(".")[-1] for call in ast.walk(node) if isinstance(call, ast.Call)}


class CrawlerPathTest(unittest.TestCase):
    def test_no_module_on_the_crawler_path_reaches_a_store(self):
        for module in CRAWLER_PATH:
            with self.subTest(module=module):
                imports = own_imports(f"onioncollect.{module}")
                self.assertEqual(imports & STORE_MODULES, set())
                self.assertEqual(imports & {"sqlite3", "aiosqlite"}, set())
                self.assertEqual(called(tree(module)) & STORE_OPENERS, set())
                from_db = {alias.name for node in ast.walk(tree(module)) if isinstance(node, ast.ImportFrom)
                           and node.module == "onioncollect.db" for alias in node.names}
                self.assertLessEqual(from_db, FRONTIER_SIDE)

    def test_the_frontier_is_the_only_database_the_crawler_opens(self):
        (opener,) = [node for node in ast.walk(tree("db")) if isinstance(node, ast.AsyncFunctionDef)
                     and node.name == "open_frontier"]
        self.assertIn("database.open(path, schema.FRONTIER)", ast.unparse(opener))
        self.assertIn("open_frontier", called(tree("crawler")))

    def test_the_fetching_dispositions_write_through_the_writer_only(self):
        (checked,) = [node for node in ast.walk(ast.parse((PACKAGE / "health_cli.py").read_text()))
                      if isinstance(node, ast.AsyncFunctionDef) and node.name == "checked"]
        self.assertEqual(called(checked) & STORE_OPENERS, set())
        self.assertNotIn("table", ast.unparse(checked))


class CrawlerSeparationTest(CrawlerTestCase):
    """A crawl with every store file closed to everyone. Only the writer, which opened them first and holds its
    handles, can reach them, and the crawl completes through it."""

    async def test_a_crawl_completes_with_the_store_files_mode_000(self):
        files = [path for path in (self.root / "data").iterdir() if path.is_file()]
        self.assertTrue({"collect.db", "records.db"} <= {path.name for path in files})
        for path in files:
            path.chmod(0)
        opened = []
        real_connect = aiosqlite.connect
        try:
            with self.assertRaises(sqlite3.OperationalError):
                sqlite3.connect(f"file:{self.root / 'data' / 'collect.db'}?mode=ro", uri=True).execute("SELECT 1")
            with mock.patch.object(aiosqlite, "connect", side_effect=lambda path, **kw: opened.append(str(path))
                                   or real_connect(path, **kw)):
                await self.crawl({"/articles/": listing_page("A", "B"), "/articles/1": detail_page("one"),
                                  "/articles/2": detail_page("two")})
        finally:
            for path in files:
                path.chmod(0o600)
        self.assertFalse([path for path in opened if str(self.root / "data") in path], opened)
        self.assertEqual(len(await self.records()), 2)
        (run,) = await self.rows("SELECT pages, finished_at FROM runs")
        self.assertEqual(run["pages"], 3)
        self.assertIsNotNone(run["finished_at"])


class StartGateTest(CliTestCase):
    """`crawl run` with no writer to store what it would fetch: refused before Tor or a client exists."""

    def setUp(self):
        super().setUp()
        self.built, self.pools = [], []
        patchers = (mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=lambda **kw: self.built.append(kw)),
                    mock.patch.object(crawler_module, "TorPool", side_effect=lambda settings: self.pools.append(FakePool())
                                      or self.pools[-1]))
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_refused_before_tor(self, why: str) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.cli("crawl", "run", "--until-idle")
        self.assertNotIn(caught.exception.code, (0, None))
        self.assertRegex(str(caught.exception), why)
        self.assertEqual(self.built, [])
        self.assertFalse(any(pool.started for pool in self.pools))

    def test_no_writer(self):
        self.assert_refused_before_tor("crawl refused, no writer at")

    def test_a_writer_that_refuses_this_user(self):
        writer = ThreadedWriter(self.data, self.configs, crawler_uid=os.getuid() + 1)
        try:
            self.settings_path.write_text(self.settings_path.read_text().replace(
                str(self.root / "no-writer.sock"), str(writer.socket)))
            # The writer closes on a peer it refuses without reading its line. The crawler sees the close as an
            # empty reply on macOS and as a reset on Linux, where the guest and CI run.
            self.assert_refused_before_tor(r"crawl refused, the writer (closed the connection on ping unanswered"
                                           r"|did not answer ping \(ConnectionResetError\))")
        finally:
            writer.stop()


class WriterContainmentTest(unittest.TestCase):
    def test_the_writer_reaches_exactly_these(self):
        self.assertEqual(set(closure("onioncollect.writer")), WRITER_CLOSURE)
        self.assertEqual(WRITER_CLOSURE & NETWORK, set())

    def test_outside_the_standard_library_only_aiosqlite(self):
        outside = {name.split(".")[0] for names in closure("onioncollect.writer").values() for name in names
                   if not name.startswith("onioncollect.")}
        self.assertEqual(outside - sys.stdlib_module_names, {"aiosqlite"})

    def test_its_only_socket_is_one_af_unix_listener(self):
        for module in WRITER_CLOSURE:
            source = (PACKAGE / f"{module.split('.')[-1]}.py").read_text()
            for word in ("AF_INET", "create_connection", "open_connection(", "getaddrinfo", "start_server", "connect_ex"):
                self.assertNotIn(word, source, module)
        sockets = [ast.unparse(node) for node in ast.walk(tree("writer")) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == "socket.socket"]
        self.assertEqual(sockets, ["socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"])

    def test_loaded_in_a_clean_interpreter(self):
        # serve_forever is swapped for a listing of sys.modules, taken once the stores are open and the socket bound.
        home = tempfile.mkdtemp(prefix="w")
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(
                [sys.executable, "-I", "-c", "import os, signal, sys; sys.path.insert(0, sys.argv[1]);"
                 " from onioncollect import writer\n"
                 "async def listed(server):\n"
                 "    print(' '.join(sorted(sys.modules)), flush=True); os.kill(os.getpid(), signal.SIGTERM)\n"
                 "writer.WriterServer.serve_forever = listed; writer.main(sys.argv[2:])",
                 str(ROOT), "--data-dir", f"{tmp}/data", "--configs-dir", f"{tmp}/configs", "--socket", f"{home}/w.sock",
                 "--crawler-user", pwd.getpwuid(os.getuid()).pw_name, "--socket-group", grp.getgrgid(os.getgid()).gr_name],
                capture_output=True, text=True, timeout=60, env={"PATH": os.environ.get("PATH", "")})
        os.rmdir(home)
        self.assertEqual(done.returncode, 0, done.stderr)
        loaded = done.stdout.split()
        self.assertEqual({name for name in loaded if name.startswith("onioncollect.")}, WRITER_CLOSURE)
        self.assertEqual([name for name in loaded if name in NEVER_LOADED or name.split(".")[0] in NEVER_LOADED], [])
        self.assertEqual({name.split(".")[0] for name in loaded} - sys.stdlib_module_names - {"__main__", "onioncollect"},
                         {"aiosqlite"})


if __name__ == "__main__":
    unittest.main()
