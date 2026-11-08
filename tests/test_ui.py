"""The search UI: read-only stores, everything escaped, literal search terms, ids checked before any path, and the
users it refuses. UIContainmentTest in test_network_boundary covers what it can reach."""
import asyncio
import http.client
import io
import logging
import os
import re
import sqlite3
import stat
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest import mock

from onioncollect import health, ui, ui_main
from onioncollect.config import Settings
from onioncollect.db import open_collect
from onioncollect.health_queue import HealthQueue
from onioncollect.records import RecordStore
from onioncollect.redact import Redacted
from onioncollect.sources import SourceTable
from tests.live import log_audit
from tests.fixtures import CANDIDATE, NEWS, make_live, throwaway_settings

HOSTILE = "<script>alert(1)</script>"
ONION_LINK = f"http://{CANDIDATE}/leak"
FIELDS = {"title": f"relay notes {HOSTILE}", "url": ONION_LINK}
SNAPSHOT = f"<html><body><h1>relay notes {HOSTILE}</h1><a href='{ONION_LINK}'>next</a></body></html>"


def build_stores(settings: Settings) -> str:
    """A live source with one record, its page's snapshot and an open health item, written the crawler's way."""
    async def build():
        collect = await open_collect(settings.data_dir / "collect.db")
        store = RecordStore(settings.data_dir, timedelta(days=180), timedelta(days=30))
        await store.open()
        try:
            table = SourceTable(collect)
            await make_live(table)
            await HealthQueue(collect, table).raise_item("news", health.redaction(f"detail {HOSTILE}"), None)
            await store.add("news", "journalism-publishing", "h1", "/articles/1", FIELDS, Redacted("", {}, (), 0),
                            host=NEWS, cluster=())
            return await store.save_snapshot("news", "/articles/1", "detail", SNAPSHOT)
        finally:
            await store.close()
            await collect.close()
    return asyncio.run(build())


class UITestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.settings = throwaway_settings(data_dir=root / "data", configs_dir=root / "configs")
        self.settings.data_dir.mkdir()
        self.digest = build_stores(self.settings)
        self.app = ui.App(self.settings.data_dir, self.settings.configs_dir)

    def tearDown(self):
        self.tmp.cleanup()

    def get(self, target: str, status: int = 200) -> str:
        route, got, html, _ = self.app.answer(target)
        self.assertEqual(got, status, (target, html))
        return html


class ReadOnlyTest(UITestCase):
    def test_a_write_through_the_ui_connection_raises(self):
        for name, sql in (("records.db", "DELETE FROM records"), ("records.db", "INSERT INTO snapshots VALUES"
                                                                                 " ('x', 'news', '/', 'listing', '', '', 0)"),
                          ("collect.db", "UPDATE sources SET state = 'disabled'"), ("collect.db", "CREATE TABLE t (a)")):
            db = self.app.stores.open(name)
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.OperationalError, "readonly|read-only"):
                db.execute(sql)
            db.close()
        self.assertIn("relay notes", self.get("/record/1"))

    def test_each_of_the_two_read_only_layers_holds_alone(self):
        db = self.app.stores.open("records.db")
        self.assertEqual(db.execute("PRAGMA query_only").fetchone()[0], 1)
        db.execute("PRAGMA query_only = OFF")
        with self.assertRaisesRegex(sqlite3.OperationalError, "readonly database"):
            db.execute("DELETE FROM records")
        db.close()

    def test_it_reads_a_store_whose_wal_files_it_cannot_write_after_the_writer_closed(self):
        for path in self.settings.data_dir.iterdir():
            if path.is_file():
                path.chmod(0o440)
        self.settings.data_dir.chmod(0o550)
        try:
            self.assertIn("1 records", self.get("/?q=relay"))
            self.assertIn("journalism-publishing", self.get("/source/news"))
        finally:
            self.settings.data_dir.chmod(0o750)


class EscapingTest(UITestCase):
    def assert_inert(self, html: str) -> None:
        self.assertNotIn("<script", html.lower())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        hrefs = re.findall(r"href=['\"]([^'\"]*)", html)
        self.assertTrue(hrefs and all(href.startswith("/") for href in hrefs), hrefs)
        self.assertNotIn(f"href='{ONION_LINK}", html)

    def test_the_record_renders_escaped_on_every_route_that_shows_it(self):
        for target in ("/?q=relay", "/record/1", f"/snapshot/{self.digest}", "/source/news"):
            with self.subTest(target=target):
                html = self.get(target)
                self.assert_inert(html)
        self.assertIn(ONION_LINK, self.get("/record/1"), "the onion link is shown as text, never as a link")
        self.assertIn(f"&lt;a href=&#x27;{ONION_LINK}&#x27;&gt;", self.get(f"/snapshot/{self.digest}"))

    def test_form_values_echo_escaped(self):
        html = self.get("/?q=%27%3E%3Cscript%3Ex&source=")
        self.assertNotIn("<script", html.lower())
        self.assertIn("value='&#x27;&gt;&lt;script&gt;x'", html)


class SearchTest(UITestCase):
    def test_fts_syntax_is_quoted_down_to_literal_terms(self):
        for query in ("relay+notes", "%22relay", "RELAY+Notes"):
            with self.subTest(query=query):
                self.assertIn("1 records", self.get(f"/?q={query}"))
        for query in ("relay+OR+nothing", "rel%2A", "NEAR%28relay+notes%29", "text%3Arelay", "%29%28"):
            with self.subTest(query=query):
                self.assertIn("0 records", self.get(f"/?q={query}"))

    def test_query_text_reaches_sqlite_only_as_a_bound_parameter(self):
        seen = []
        real = ui.Stores.rows
        with mock.patch.object(ui.Stores, "rows", lambda stores, name, sql, params=(): seen.append((sql, params))
                               or real(stores, name, sql, params)):
            self.get("/?q=relay%27%3B+DROP+TABLE+records%3B--")
        sql, params = seen[0]
        self.assertNotIn("DROP", sql)
        self.assertEqual(params["match"], '"relay\';" "DROP" "TABLE" "records;--"')

    def test_bad_input_is_a_400(self):
        for query in ("q=a%00b", "q=" + "+".join(["w"] * 17), "q=x&since=yesterday", "q=x&category=nope",
                      "q=x&source=..%2Fetc"):
            with self.subTest(query=query):
                self.get(f"/?{query}", 400)

    def test_filters(self):
        self.assertIn("1 records", self.get("/?q=relay&source=news&category=journalism-publishing&since=2000-01-01"))
        self.assertIn("0 records", self.get("/?q=relay&until=2000-01-01"))
        self.assertIn("0 records", self.get("/?q=relay&source=elsewhere"))


class NotFoundTest(UITestCase):
    def test_a_bad_snapshot_id_is_404_before_a_query_or_a_path_exists(self):
        class NoPath:
            def __truediv__(self, other):
                raise AssertionError("a path was built")

        app = ui.App(NoPath(), self.settings.configs_dir)
        with mock.patch.object(ui.Stores, "rows", side_effect=AssertionError("a query ran")):
            for key in ("..", "..%2F..%2Fsettings.toml", self.digest.upper(), self.digest[:-1], self.digest + "0",
                        "%2e%2e", f"{self.digest}.html", "0" * 63 + "g"):
                with self.subTest(key=key):
                    self.assertEqual(app.answer(f"/snapshot/{key}")[1], 404)

    def test_an_unknown_snapshot_record_source_or_route_is_404(self):
        for target in ("/snapshot/" + "0" * 64, "/record/99", "/record/0", "/record/1x", "/source/nope",
                       "/source/NEWS", "/admin", "/record/", "/record/1/2", "//record/1"):
            with self.subTest(target=target):
                self.get(target, 404)

    def test_a_snapshot_past_its_clock_is_404(self):
        self.app.answer(f"/snapshot/{self.digest}")
        (self.settings.data_dir / "snapshots" / self.digest[:2] / f"{self.digest}.html").unlink()
        self.get(f"/snapshot/{self.digest}", 404)


class SourcePageTest(UITestCase):
    def test_state_category_config_path_history_and_open_items(self):
        html = self.get("/source/news")
        for shown in ("live", "journalism-publishing", str(self.settings.configs_dir / "news.toml"),
                      "Hit rate, newest run first", "redaction", NEWS):
            self.assertIn(shown, html)


class ServerTest(UITestCase):
    def setUp(self):
        super().setUp()
        self.server = ui.UIServer(self.settings.data_dir, self.settings.configs_dir, 0)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method: str, target: str, host: str | None = None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        connection.putrequest(method, target, skip_host=True)
        connection.putheader("Host", host or f"localhost:{self.server.server_address[1]}")
        connection.endheaders()
        response = connection.getresponse()
        answer = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return answer

    def test_listens_on_loopback_and_sends_the_policy_headers(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        status, headers, body = self.request("GET", "/?q=relay")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Security-Policy"], "default-src 'none'; style-src 'unsafe-inline'")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn(b"1 records", body)

    def test_only_get(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            self.assertEqual(self.request(method, "/")[0], 405, method)

    def test_another_sites_name_is_refused(self):
        self.assertEqual(self.request("GET", "/record/1", host="rebind.example:8470")[0], 400)
        self.assertEqual(self.request("GET", "/record/1", host="127.0.0.1:9999")[0], 200)

    def test_logs_route_status_timing_and_counts_never_the_query(self):
        with self.assertLogs("onioncollect.ui", logging.INFO) as logs:
            self.request("GET", "/?q=relay+secretword")
            self.request("GET", "/record/1")
        text = "\n".join(logs.output)
        self.assertNotIn("secretword", text)
        self.assertNotIn("relay", text)
        self.assertRegex(logs.output[0], r"ui search status=200 results=0 elapsed=\d+\.\d{3}s$")
        self.assertRegex(logs.output[1], r"ui record status=200 results=1 elapsed=\d+\.\d{3}s$")
        for line in logs.output:
            self.assertTrue(log_audit.SHAPES["ui"].fullmatch(line.split(":", 2)[2]), line)


class WhoMayRunItTest(UITestCase):
    def refused(self, uid: int, name: str) -> str:
        user = mock.Mock(pw_name=name)
        with mock.patch("os.geteuid", return_value=uid), mock.patch("pwd.getpwuid", return_value=user), \
                mock.patch.object(ui, "UIServer", side_effect=AssertionError("listened")), \
                self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()):
            ui_main.main(["--data-dir", str(self.settings.data_dir), "--configs-dir", str(self.settings.configs_dir)])
        return str(caught.exception)

    def test_refuses_root_the_crawler_and_anyone_who_can_write_the_stores(self):
        self.assertIn("refusing to run as root", self.refused(0, "root"))
        self.assertIn("never as the crawler", self.refused(os.geteuid(), "crawler"))
        self.assertIn(f"this user can write {self.settings.data_dir}", self.refused(os.geteuid(), "analyst"))

    def test_a_user_who_can_only_read_may(self):
        everything = [*self.settings.data_dir.rglob("*"), self.settings.data_dir]
        for path in everything:
            path.chmod(0o550 if path.is_dir() else 0o440)
        try:
            self.assertIsNone(ui.refusal(self.settings.data_dir, os.geteuid(), "analyst"))
            self.assertEqual(stat.S_IMODE(self.settings.data_dir.stat().st_mode), 0o550)
        finally:
            for path in reversed(everything):
                path.chmod(0o750 if path.is_dir() else 0o640)


if __name__ == "__main__":
    unittest.main()
