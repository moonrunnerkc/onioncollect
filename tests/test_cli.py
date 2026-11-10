import asyncio
import io
import json
import logging
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest import mock

import stem

from onioncollect import cli, crawl_cli, health, lifecycle
from onioncollect.health_queue import HealthQueue
from onioncollect.config import Settings
from onioncollect.db import open_collect
from onioncollect.records import RecordStore
from onioncollect.redact import Redacted
from onioncollect.sources import SourceTable
from onioncollect.matching import MIRROR_MAX_BITS
from tests.fixtures import (CANDIDATE, EXCLUDED, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, headlines, listing_page,
                            leak_result_owned_by_root, make_live, write_leak_result)
from tests.test_fingerprint import print_of
from tests.test_onion import AHMIA
from tests.writer_harness import ThreadedWriter


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
            crawl_cli.configure_logging(path)
            logging.getLogger("stem").setLevel(5)
            logging.getLogger("httpx").setLevel(logging.INFO)
            logging.getLogger("httpx").info(f'HTTP Request: GET http://{AHMIA}/secret/path "HTTP/1.1 200 OK"')
            logging.getLogger("stem").info("control message")
            logging.getLogger("stem").warning("stem warning")
            logging.getLogger("onioncollect.crawler").info("news listing status=200")
        text = path.read_text()
        self.assertNotIn("secret", text)
        self.assertNotIn("control message", text)
        self.assertIn("stem warning", text)
        self.assertIn("news listing status=200", text)


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data, self.configs = self.root / "data", self.root / "configs"
        for name, text in (("pw", "pw"), ("salt", "s" * 40)):
            (self.root / name).write_text(text)
            (self.root / name).chmod(0o600)
        (self.root / "exclusions.txt").write_text(f"{EXCLUDED}\n")
        (self.root / "patterns.txt").write_text("child_exploitation forbiddenterm\n")
        self.settings_path = self.root / "settings.toml"
        self.settings_path.write_text("\n".join(f'{key} = "{self.root / name}"' for key, name in (
            ("control_password_file", "pw"), ("redaction_salt_file", "salt"), ("exclusions_file", "exclusions.txt"),
            ("safety_patterns_file", "patterns.txt"), ("data_dir", "data"), ("configs_dir", "configs"),
            ("leak_test_result", "leak-test.json"), ("state_dir", "state"), ("log_dir", "log"),
            ("writer_socket", "no-writer.sock"),
        )) + "\n")
        write_leak_result(self.root / "leak-test.json")
        leak_result_owned_by_root(self)
        umask = os.umask(0o022)
        self.addCleanup(os.umask, umask)
        real_load = Settings.load
        patcher = mock.patch.object(
            Settings, "load", side_effect=lambda path, crawl=False, reader=False: real_load(
                path, crawl, reader, port_check=lambda port: True)
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # In the guest the writer creates both stores when it starts; readers never create one.
        self.table_do(lambda table: asyncio.sleep(0))
        self.store_do(lambda store: asyncio.sleep(0))

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args: str) -> str:
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["--settings", str(self.settings_path), *args])
        return out.getvalue()

    def refused(self, *args: str) -> str:
        with self.assertRaises(SystemExit) as caught:
            self.cli(*args)
        return str(caught.exception)

    def table_do(self, action):
        self.data.mkdir(mode=0o700, exist_ok=True)

        async def run():
            collect = await open_collect(self.data / "collect.db")
            try:
                return await action(SourceTable(collect))
            finally:
                await collect.close()
        return asyncio.run(run())

    def store_do(self, action):
        async def run():
            store = RecordStore(self.data, timedelta(days=180), timedelta(days=30))
            await store.open()
            try:
                return await action(store)
            finally:
                await store.close()
        return asyncio.run(run())

    def live_news(self):
        self.table_do(make_live)
        self.configs.mkdir(exist_ok=True)
        (self.configs / "news.toml").write_text(NEWS_CONFIG)


class MainTest(CliTestCase):
    def test_refuses_root(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertIn("root", self.refused("sources", "list"))

    def test_a_writer_refuses_a_directory_owned_by_someone_else(self):
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertIn("not owned by this user", self.refused("triage", "decline", CANDIDATE, "--reason", "r"))

    def test_a_reader_opens_another_users_stores_read_only_and_never_creates_one(self):
        with mock.patch("os.geteuid", return_value=os.geteuid() + 1):
            self.assertIn("0 candidates", self.cli("triage", "list"))
        (self.data / "records.db").unlink()
        self.assertIn("records.db yet; the writer creates it when it starts", self.refused("sources", "export"))
        self.assertFalse((self.data / "records.db").exists())

    def test_bad_settings_is_a_clean_exit(self):
        self.settings_path.write_text(self.settings_path.read_text() + "nonsense = 1\n")
        self.assertIn("unknown settings ['nonsense']", self.refused("sources", "list"))


class TriageTest(CliTestCase):
    def test_list_approve_and_scaffold(self):
        self.table_do(lambda table: table.add_candidates({CANDIDATE}, "news"))
        self.assertIn(f"{CANDIDATE}  found on news", self.cli("triage", "list"))
        out = self.cli("triage", "approve", CANDIDATE.upper(), "--as", "docs", "--category", "software-infrastructure",
                       "--note", "distro docs mirror")
        self.assertIn("approved as docs", out)
        scaffold = (self.configs / "docs.toml").read_text()
        self.assertIn(CANDIDATE, scaffold)
        # The crawler reads configs through the configs dir's group; the stores are the analyst's alone.
        self.assertEqual(stat.S_IMODE((self.configs / "docs.toml").stat().st_mode), 0o640)
        self.assertEqual(os.umask(0o022), 0o077, "the analyst's commands leave nothing open to others")
        self.assertIn("not valid", self.refused("config", "validate", "docs").replace("must be a CSS", "not valid"))
        self.assertEqual(self.cli("triage", "list").strip(), "0 candidates")
        source = self.table_do(lambda table: table.get("docs"))
        self.assertEqual((source["state"], source["reviewer"]), (lifecycle.APPROVED, cli.operator()))

    def test_approve_refuses_a_category_outside_the_policy(self):
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                self.cli("triage", "approve", CANDIDATE, "--as", "shop", "--category", "market", "--note", "x")

    def test_approve_refuses_an_excluded_host_and_writes_no_config(self):
        message = self.refused("triage", "approve", EXCLUDED, "--as", "x1", "--category", "directories", "--note", "n")
        self.assertIn("exclusion list", message)
        self.assertFalse((self.configs / "x1.toml").exists())

    def test_approve_never_overwrites_a_config(self):
        self.configs.mkdir()
        (self.configs / "docs.toml").write_text("keep me")
        self.assertIn("already exists", self.refused(
            "triage", "approve", CANDIDATE, "--as", "docs", "--category", "directories", "--note", "n"))
        self.assertEqual((self.configs / "docs.toml").read_text(), "keep me")

    def test_list_shows_a_redirect_from_a_source(self):
        self.live_news()
        self.table_do(lambda table: table.add_redirect_target("news", CANDIDATE))
        self.assertIn(f"{CANDIDATE}  found on news\n    candidate was the redirect target of source news",
                      self.cli("triage", "list"))

    def test_decline_is_final(self):
        self.assertIn("declined", self.cli("triage", "decline", CANDIDATE, "--reason", "sells account data"))
        self.assertIn("already reviewed", self.refused(
            "triage", "approve", CANDIDATE, "--as", "x1", "--category", "directories", "--note", "n"))
        self.assertIn("(sells account data)", self.cli("sources", "list", "--state", "declined"))


class SourcesTest(CliTestCase):
    def test_list_disable_export(self):
        self.live_news()
        self.table_do(lambda table: table.add_candidates({CANDIDATE}, "news"))
        listing = self.cli("sources", "list")
        self.assertIn(f"news                     live      journalism-publishing    {NEWS}", listing)
        self.assertIn(CANDIDATE, listing)
        self.assertNotIn(CANDIDATE, self.cli("sources", "list", "--state", "live"))
        self.assertIn("disabling a source needs a reason", self.refused("sources", "disable", "news", "--reason", " "))
        self.cli("sources", "disable", "news", "--reason", "layout gone")
        rows = [json.loads(line) for line in self.cli("sources", "export").splitlines()]
        self.assertEqual([(row["kind"], row["state"]) for row in rows], [("source", "disabled"), ("host", "candidate")])
        self.assertEqual(rows[0]["hosts"], [NEWS])

    def test_disable_closes_the_sources_open_items(self):
        self.live_news()
        self.table_do(lambda table: HealthQueue(table.db, table).raise_item("news", health.redaction("2 events"), None))
        self.assertIn("news disabled, 1 open health items closed", self.cli("sources", "disable", "news", "--reason", "creds"))
        (row,) = self.table_do(lambda table: HealthQueue(table.db, table).log())
        self.assertEqual((row["disposition"], row["note"]), ("disabled", "creds"))

    def test_reapprove_after_disable_then_golive_can_run(self):
        self.live_news()
        self.assertIn("from live to approved", self.refused("sources", "reapprove", "news", "--note", "baseline"))
        self.cli("sources", "disable", "news", "--reason", "re-run golive for a baseline")
        self.assertIn("approved again; run golive news", self.cli("sources", "reapprove", "news", "--note", "baseline"))
        self.assertEqual(self.table_do(lambda table: table.get("news"))["state"], lifecycle.APPROVED)


class SearchAndRetentionTest(CliTestCase):
    def add(self, title: str, source: str = "news", category: str = "journalism-publishing"):
        fields = {"title": title, "url": f"http://{NEWS}/{title}"}
        self.store_do(lambda store: store.add(source, category, title, None, fields, Redacted("", {}, (), 0),
                                              host=NEWS, cluster=()))

    def test_search_with_filters(self):
        self.data.mkdir(exist_ok=True)
        self.add("relay operators meetup")
        self.add("relay directory update", source="docs", category="software-infrastructure")
        self.assertIn("2 records", self.cli("search", "relay"))
        out = self.cli("search", "relay", "--category", "software-infrastructure")
        self.assertIn("docs", out)
        self.assertIn("1 records", out)
        self.assertIn("0 records", self.cli("search", "relay", "--since", "2999-01-01"))
        self.assertIn("0 records", self.cli("search", "relay", "--until", "2000-01-01"))
        self.assertIn("2 records", self.cli("search", "relay", "--until", "2999-01-01"))
        self.assertIn("0 records", self.cli("search", "relay OR anything"), "operators are literal terms")
        self.assertIn("search query: nothing to search for", self.refused("search", "  "))

    def test_sweep(self):
        self.data.mkdir(exist_ok=True)
        self.assertIn("0 records and 0 snapshots", self.cli("retention", "sweep"))


class MirrorTest(CliTestCase):
    def setUp(self):
        super().setUp()
        self.live_news()
        self.table_do(lambda table: table.approve(OFF_SOURCE, "docs", "software-infrastructure", "n", "t", frozenset()))
        (self.configs / "docs.toml").write_text("keep me")
        self.table_do(lambda table: table.add_candidates({NEWS_MIRROR, CANDIDATE}, "news"))
        self.front = print_of(listing_page(*headlines("monday")))

    def test_approve_as_mirror_alters_only_that_sources_host_set_and_config(self):
        before = self.table_do(lambda table: table.get("docs"))
        out = self.cli("triage", "approve", NEWS_MIRROR, "--as-mirror-of", "news", "--note", "listed on its about page")
        self.assertIn(f"{NEWS_MIRROR} approved as a mirror of news, which stays live", out)
        news = self.table_do(lambda table: table.get("news"))
        self.assertEqual((news["state"], news["active_host"], news["hosts"]),
                         (lifecycle.LIVE, NEWS, sorted([NEWS, NEWS_MIRROR])))
        self.assertEqual(self.table_do(lambda table: table.get("docs")), before)
        self.assertEqual((self.configs / "news.toml").read_text(),
                         NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]'))
        self.assertEqual(sorted(path.name for path in self.configs.iterdir()), ["docs.toml", "news.toml"])
        self.assertIn("valid, 2 hosts", self.cli("config", "validate", "news"))

    def test_approve_as_mirror_refusals_change_nothing(self):
        for args, why in (
            (("--as-mirror-of", "nothing"), "no source nothing"),
            (("--as-mirror-of", "news", "--category", "directories"), "a mirror takes its source's category"),
            (("--as-mirror-of", "docs"), "docs's config"),
        ):
            self.assertIn(why, self.refused("triage", "approve", NEWS_MIRROR, *args, "--note", "n"))
        self.assertIn("exclusion list", self.refused("triage", "approve", EXCLUDED, "--as-mirror-of", "news", "--note", "n"))
        self.assertIn("needs --category", self.refused("triage", "approve", NEWS_MIRROR, "--as", "x1", "--note", "n"))
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                self.cli("triage", "approve", NEWS_MIRROR, "--as", "x1", "--as-mirror-of", "news", "--note", "n")
        self.assertEqual(self.table_do(lambda table: table.get("news"))["hosts"], [NEWS])
        self.assertEqual((self.configs / "news.toml").read_text(), NEWS_CONFIG)
        self.assertEqual((self.configs / "docs.toml").read_text(), "keep me")

    def test_triage_list_shows_a_stored_match(self):
        self.store_do(lambda store: store.save_fingerprint(NEWS, "/articles/", True, self.front))
        self.store_do(lambda store: store.save_fingerprint(NEWS_MIRROR, "/", True, self.front))
        out = self.cli("triage", "list")
        self.assertIn(f"{NEWS_MIRROR}  found on news\n    candidate matches source news"
                      " (content 0, structure 0 bits apart)", out)
        self.assertNotIn(f"{CANDIDATE}  found on news\n    candidate", out)

    def test_mirrors_shows_the_cluster_from_stored_fingerprints(self):
        self.cli("triage", "approve", NEWS_MIRROR, "--as-mirror-of", "news", "--note", "about page")
        self.table_do(lambda table: table.approve(CANDIDATE, "paper", "journalism-publishing", "n", "t", frozenset()))
        for host in (NEWS, CANDIDATE):
            self.store_do(lambda store: store.save_fingerprint(host, "/articles/", True, self.front))
        with mock.patch("onioncollect.fetcher.Fetcher.fetch", side_effect=AssertionError("no fetch")):
            lines = self.cli("mirrors", "news").splitlines()
        self.assertEqual(lines[0], "news: cluster news; * marks each source's active host; distances are from news's,"
                                   f" a match is {MIRROR_MAX_BITS} bits or fewer on each")
        self.assertEqual([line.split()[:3] for line in lines[1:]], [
            ["*", NEWS, "news"], [NEWS_MIRROR, "news", "(live)"], ["*", CANDIDATE, "paper"]])
        self.assertTrue(lines[1].endswith("content 0, structure 0 bits apart"))
        self.assertTrue(lines[2].endswith("no seed fingerprint"))
        self.assertTrue(lines[3].endswith("content 0, structure 0 bits apart"))
        self.assertIn("[cluster news]", self.cli("sources", "list", "--state", "approved"))
        self.assertIn("in no cluster", self.cli("mirrors", "docs"))
        self.assertIn("no source nothing", self.refused("mirrors", "nothing"))

    def test_search_shows_every_source_a_record_was_read_under(self):
        fields = {"title": "relay operators meetup", "url": f"http://{NEWS}/a"}
        for source, host in (("news", NEWS), ("docs", OFF_SOURCE)):
            self.store_do(lambda store: store.add(source, "journalism-publishing", "same", None, fields,
                                                  Redacted("", {}, (), 0), host=host, cluster=("docs", "news")))
        out = self.cli("search", "relay", "--source", "docs")
        self.assertIn("docs,news", out)
        self.assertIn("(2 hosts)", out)
        self.assertIn("1 records", out)


class SourcesMergeTest(CliTestCase):
    """Two live sources found to be one site: hosts, config entries and records end up under one source."""

    def setUp(self):
        super().setUp()
        self.live_news()
        self.table_do(lambda table: make_live(table, "paper", NEWS_MIRROR))
        (self.configs / "paper.toml").write_text(NEWS_CONFIG.replace('id = "news"', 'id = "paper"').replace(NEWS, NEWS_MIRROR))
        fields = {"title": "relay operators meetup", "url": f"http://{NEWS}/a"}
        for source, host in (("news", NEWS), ("paper", NEWS_MIRROR)):
            self.store_do(lambda store: store.add(source, "journalism-publishing", "same", None, fields,
                                                  Redacted("", {}, (), 0), host=host, cluster=()))

    def fingerprint(self, host, edition):
        self.store_do(lambda store: store.save_fingerprint(host, "/articles/", True, print_of(listing_page(*headlines(edition)))))

    def test_matching_twins_merge(self):
        self.fingerprint(NEWS, "monday")
        self.fingerprint(NEWS_MIRROR, "monday")
        out = self.cli("sources", "merge", "paper", "--into", "news")
        self.assertIn(f"paper merged into news (content 0, structure 0 bits apart): {NEWS_MIRROR} added to news", out)
        self.assertIn("1 shared records merged, 1 duplicate rows removed", out)
        self.assertIn("paper.toml is yours to delete", out)
        news, paper = self.table_do(lambda table: table.get("news")), self.table_do(lambda table: table.get("paper"))
        self.assertEqual(news["hosts"], sorted([NEWS, NEWS_MIRROR]))
        self.assertEqual((paper["state"], paper["reason"]), (lifecycle.DISABLED, "merged into news"))
        self.assertEqual((self.configs / "news.toml").read_text(),
                         NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]'))
        self.assertTrue((self.configs / "paper.toml").exists())
        (found,) = self.store_do(lambda store: store.search("relay"))
        self.assertEqual((found["source_id"], found["sources"], found["hosts"]), ("news", ["news"], 2))

    def test_no_match_needs_force_and_a_note(self):
        self.fingerprint(NEWS, "monday")
        self.fingerprint(NEWS_MIRROR, "tuesday")
        self.assertIn("not within 8 bits", self.refused("sources", "merge", "paper", "--into", "news"))
        self.assertIn("--force needs a --note", self.refused("sources", "merge", "paper", "--into", "news", "--force"))
        self.assertEqual(self.table_do(lambda table: table.get("paper"))["state"], lifecycle.LIVE)
        self.assertIn("(forced)", self.cli("sources", "merge", "paper", "--into", "news", "--force", "--note", "same desk"))
        self.assertEqual(self.table_do(lambda table: table.get("paper"))["reason"], "merged into news, forced: same desk")

    def test_refusals_change_nothing(self):
        self.table_do(lambda table: table.approve(CANDIDATE, "docs", "directories", "n", "t", frozenset()))
        for args, why in ((("paper", "--into", "docs"), "docs is approved, not live"),
                          (("docs", "--into", "news"), "docs is approved, not live"),
                          (("nothing", "--into", "news"), "nothing is not a source"),
                          (("paper", "--into", "paper", "--force", "--note", "n"), "no other source")):
            self.assertIn(why, self.refused("sources", "merge", *args))
        (self.configs / "news.toml").write_text(NEWS_CONFIG.replace("hosts = [", "hosts = [ # [x]\n"))
        self.assertIn("news's config", self.refused("sources", "merge", "paper", "--into", "news", "--force", "--note", "n"))
        self.assertEqual(self.table_do(lambda table: table.get("paper"))["hosts"], [NEWS_MIRROR])


class RecordsMergeTest(CliTestCase):
    def test_merge_a_named_cluster(self):
        self.data.mkdir(exist_ok=True)
        fields = {"title": "relay operators meetup", "url": f"http://{NEWS}/a"}
        for source, host in (("news", NEWS), ("paper", NEWS_MIRROR)):
            self.table_do(lambda table: make_live(table, source, host))
            self.store_do(lambda store: store.add(source, "journalism-publishing", "same", None, fields,
                                                  Redacted("", {}, (), 0), host=host, cluster=()))
        self.assertIn("no cluster news", self.refused("records", "merge", "news"))
        self.table_do(lambda table: table.set_clusters({"news": "news", "paper": "news"}))
        self.assertIn("cluster news (news, paper): 1 shared records merged, 1 duplicate rows removed",
                      self.cli("records", "merge", "news"))
        self.assertIn("1 records", self.cli("search", "relay"))


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


class WriterCliTestCase(CliTestCase):
    """The crawler's commands, which write through a writer serving the test's data dir."""

    def setUp(self):
        super().setUp()
        self.writer = ThreadedWriter(self.data, self.configs)
        self.settings_path.write_text(self.settings_path.read_text().replace(
            str(self.root / "no-writer.sock"), str(self.writer.socket)))

    def tearDown(self):
        self.writer.stop()
        super().tearDown()


class StatusTest(WriterCliTestCase):
    def test_status_table(self):
        self.live_news()
        self.table_do(lambda table: table.add_candidates({CANDIDATE}, "news"))
        (self.root / "log").mkdir()
        (self.root / "log" / "crawl.log").write_text(
            "2026-11-07 12:00:00,000 INFO onioncollect.tor_pool: tor 10051: success 0.50 over 20 fetches, last rotation never\n"
            "2026-11-07 12:01:00,000 INFO onioncollect.tor_pool: tor 10051: success 0.75 over 40 fetches, last rotation never\n"
        )
        instances = [FakeInstance(10051), FakeInstance(10052, fails=True)]
        with mock.patch.object(crawl_cli, "TorPool", return_value=mock.Mock(instances=instances)):
            lines = self.cli("crawl", "status").splitlines()
        self.assertEqual(lines[0], "sources  approved 0  live 1  degraded 0  disabled 0  (open runs 0)")
        self.assertEqual(lines[1], "hosts    candidate 1  declined 0  member 1")
        self.assertEqual(lines[2], "urls     queued 0  leased 0  done 0  failed 0")
        self.assertEqual(lines[3], "fetches  0 in the last hour, 0% reached the host; 0.00/s over the last 5 min")
        self.assertEqual(lines[5].split(), ["10051", "ready", "4", "3", "0.75", "over", "40"])
        self.assertEqual(lines[6].split(), ["10052", "unreachable", "(SocketError)"])
        self.assertTrue(all(instance.closed for instance in instances))


class GoLiveCommandTest(WriterCliTestCase):
    def test_failed_check_exits_nonzero_and_stays_approved(self):
        self.table_do(lambda table: table.approve(NEWS, "news", "journalism-publishing", "n", "t", frozenset()))
        self.configs.mkdir()
        (self.configs / "news.toml").write_text(NEWS_CONFIG)
        pool = mock.Mock(instances=[], start=mock.AsyncMock())
        with mock.patch.object(crawl_cli, "TorPool", return_value=pool):
            with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()) as out:
                cli.main(["--settings", str(self.settings_path), "golive", "news"])
        self.assertIn("news stays approved", str(caught.exception))
        self.assertIn("FAIL  reachability: 0 of 2 instances", out.getvalue())
        self.assertTrue(pool.stop.called)

    def test_mirror_decision_reaches_the_checks_and_takes_one_answer(self):
        self.table_do(lambda table: table.approve(NEWS, "news", "journalism-publishing", "n", "t", frozenset()))
        self.configs.mkdir()
        (self.configs / "news.toml").write_text(NEWS_CONFIG)
        pool = mock.Mock(instances=[], start=mock.AsyncMock())
        checks = mock.AsyncMock(return_value=mock.Mock(lines=[(True, "mirror: folded")], passed=True))
        with mock.patch.object(crawl_cli, "TorPool", return_value=pool), mock.patch.object(crawl_cli, "go_live", checks):
            self.assertIn("PASS  mirror: folded", self.cli("golive", "news", "--as-mirror-of", "paper"))
            self.cli("golive", "news", "--confirm-new-source")
        self.assertEqual([call.args[-2:] for call in checks.call_args_list], [(False, "paper"), (True, None)])
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            self.cli("golive", "news", "--confirm-new-source", "--as-mirror-of", "paper")


if __name__ == "__main__":
    unittest.main()
