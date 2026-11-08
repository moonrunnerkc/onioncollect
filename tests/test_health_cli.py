import fcntl
import unittest
from unittest import mock

from onioncollect import golive, health, health_cli, lifecycle
from onioncollect.config import Settings
from onioncollect.health_queue import HealthQueue
from tests.fixtures import CANDIDATE, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, listing_page, make_live
from tests.test_cli import WriterCliTestCase
from tests.test_golive import GOOD, ScriptedFetcher

TWO_HOSTS = NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]')


def crawl_settings_loaded() -> list[bool]:
    return [call.kwargs["crawl"] for call in Settings.load.call_args_list]


class HealthCliTestCase(WriterCliTestCase):
    def setUp(self):
        super().setUp()
        self.live_news()
        self.table_do(lambda table: table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset()))
        (self.configs / "news.toml").write_text(TWO_HOSTS)
        self.down = self.raise_item("news", health.Finding(health.UNREACHABLE, 100, "nothing fetched in 4 runs in a row"))

    def raise_item(self, source_id, finding):
        return self.table_do(lambda table: HealthQueue(table.db, table).raise_item(source_id, finding, None))

    def queue_do(self, action):
        return self.table_do(lambda table: action(HealthQueue(table.db, table)))

    def with_tor(self, pages, *args):
        """Runs a command whose checks fetch: a scripted fetch per path, through two fake Tor instances."""
        ScriptedFetcher.instances = []
        pool = mock.Mock(instances=[mock.Mock(pages=pages) for _ in range(2)], start=mock.AsyncMock())
        with mock.patch.object(health_cli, "TorPool", return_value=pool), mock.patch.object(golive, "Fetcher", ScriptedFetcher):
            try:
                return self.cli(*args)
            finally:
                self.assertEqual(pool.stop.called, pool.start.called)

    def state(self):
        return self.table_do(lambda table: table.get("news"))


class QueueTest(HealthCliTestCase):
    def test_unreachable_items_show_the_siblings_and_the_swap(self):
        self.table_do(lambda table: make_live(table, "paper", CANDIDATE))
        self.table_do(lambda table: table.set_clusters({"news": "news", "paper": "news"}))
        watched = self.raise_item("news", health.Finding(health.BELOW_EXPECTATION, 30, "thin"))
        self.queue_do(lambda queue: queue.watch(watched, 3, "seasonal", "analyst"))
        lines = self.cli("health").splitlines()
        self.assertTrue(lines[0].startswith(f"#{self.down}    priority 100  news"))
        self.assertIn("unreachable", lines[0])
        self.assertEqual(lines[1], "      nothing fetched in 4 runs in a row")
        self.assertIn(f"sibling {NEWS_MIRROR}  last up never  last down never  swap: health resolve {self.down}"
                      f" --disposition mirror-swapped --to {NEWS_MIRROR}", lines[2])
        self.assertIn(f"cluster {CANDIDATE}", lines[3])
        self.assertIn("(of paper: sources merge first)", lines[3])
        self.assertEqual(lines[4], f"watching #{watched} news below-expectation until run 3")
        self.assertEqual(lines[5], "1 open, 1 watched")

    def test_runs_and_log(self):
        self.assertIn("run    started", self.cli("health", "runs", "news"))
        self.cli("health", "resolve", str(self.down), "--disposition", "watching", "--runs", "2", "--note", "flaky night")
        self.assertIn(f"#{self.down} news unreachable -> watching (applied) by", self.cli("health", "log"))
        self.assertEqual(self.cli("health", "log", "--source", "paper"), "")


class ResolveTest(HealthCliTestCase):
    def test_watching_and_disabled_need_no_tor(self):
        Settings.load.reset_mock()
        self.cli("health", "resolve", str(self.down), "--disposition", "watching", "--runs", "2", "--note", "n")
        other = self.raise_item("news", health.redaction("2 redaction events"))
        self.assertIn(f"item {other}: disabled",
                      self.cli("health", "resolve", str(other), "--disposition", "disabled", "--note", "posts creds"))
        self.assertEqual(crawl_settings_loaded(), [False, False])
        self.assertEqual((self.state()["state"], self.state()["reason"]), (lifecycle.DISABLED, "posts creds"))
        self.assertEqual(self.queue_do(lambda queue: queue.queue()), [], "disabling closed the watched item too")

    def test_disabled_closes_items_of_a_source_already_disabled(self):
        self.table_do(lambda table: table.change_state("news", lifecycle.DISABLED, "safety: child_exploitation"))
        self.cli("health", "resolve", str(self.down), "--disposition", "disabled", "--note", "tripped the safety check")
        self.assertEqual(self.queue_do(lambda queue: queue.queue()), [])
        self.assertEqual(self.state()["reason"], "safety: child_exploitation", "the safety reason stays")

    def test_flag_and_note_refusals(self):
        for args, why in ((("--disposition", "mirror-swapped", "--note", "n"), "--to goes with mirror-swapped"),
                          (("--disposition", "fixed", "--to", NEWS_MIRROR, "--note", "n"), "--to goes with"),
                          (("--disposition", "watching", "--note", "n"), "--runs goes with watching"),
                          (("--disposition", "disabled", "--runs", "2", "--note", "n"), "--runs goes with"),
                          (("--disposition", "disabled", "--note", " "), "needs a note")):
            self.assertIn(why, self.refused("health", "resolve", str(self.down), *args))
        self.assertIn("no health item 99", self.refused("health", "resolve", "99", "--disposition", "disabled", "--note", "n"))
        self.assertEqual(self.state()["state"], lifecycle.DEGRADED)

    def test_mirror_swap_passes_checks_1_4_5_on_the_new_host_then_moves(self):
        Settings.load.reset_mock()
        out = self.with_tor({"/articles/": GOOD}, "health", "resolve", str(self.down), "--disposition",
                            "mirror-swapped", "--to", NEWS_MIRROR.upper(), "--note", "old address down for days")
        self.assertEqual(crawl_settings_loaded(), [True], "a fetching disposition loads the crawler's Tor settings")
        self.assertIn(f"PASS  host: {NEWS_MIRROR} is in news's host set and config", out)
        self.assertIn("PASS  reachability: 2 of 2 instances", out)
        self.assertIn(f"PASS  active host {NEWS} -> {NEWS_MIRROR}", out)
        self.assertTrue(all(fetcher.allowed_states == lifecycle.COLLECTING for fetcher in ScriptedFetcher.instances))
        self.assertEqual({call for fetcher in ScriptedFetcher.instances for call in fetcher.calls}, {("news", "/articles/")})
        self.assertEqual((self.state()["active_host"], self.state()["state"]), (NEWS_MIRROR, lifecycle.LIVE))
        (row,) = self.queue_do(lambda queue: queue.log())
        self.assertEqual((row["disposition"], row["applied"], row["detail"]),
                         (health.MIRROR_SWAPPED, 1, f"active host {NEWS} -> {NEWS_MIRROR}"))

    def test_a_failed_check_records_the_attempt_and_leaves_the_active_host(self):
        with self.assertRaises(SystemExit) as caught:
            self.with_tor({"/articles/": listing_page("one")}, "health", "resolve", str(self.down), "--disposition",
                          "mirror-swapped", "--to", NEWS_MIRROR, "--note", "try the mirror")
        self.assertIn("stays open; the attempt is in health log", str(caught.exception))
        self.assertEqual((self.state()["active_host"], self.state()["state"]), (NEWS, lifecycle.DEGRADED))
        (row,) = self.queue_do(lambda queue: queue.log())
        self.assertEqual((row["applied"], row["detail"]),
                         (0, f"{NEWS_MIRROR}: seed 1: 1 complete items of 2 expected, hit rate 1.00, redaction events 0"))

    def test_swap_targets_must_be_in_the_sources_own_set(self):
        self.table_do(lambda table: table.approve(OFF_SOURCE, "docs", "directories", "n", "t", frozenset()))
        for host, why in ((NEWS, "already news's active host"), (OFF_SOURCE, "it belongs to docs, so run sources merge"),
                          (CANDIDATE, f"{CANDIDATE} is not in news's host set")):
            self.assertIn(why, self.with_tor_refused(host))
        self.assertEqual(ScriptedFetcher.instances, [], "refused before any fetch")

    def with_tor_refused(self, host):
        with self.assertRaises(SystemExit) as caught:
            self.with_tor({"/articles/": GOOD}, "health", "resolve", str(self.down), "--disposition", "mirror-swapped",
                          "--to", host, "--note", "n")
        return str(caught.exception)

    def test_fixed_rechecks_the_active_host(self):
        out = self.with_tor({"/articles/": GOOD}, "health", "resolve", str(self.down), "--disposition", "fixed",
                            "--note", "tor pool was down")
        self.assertIn(f"PASS  go-live checks 1, 4 and 5 passed on {NEWS}", out)
        self.assertEqual(self.state()["state"], lifecycle.LIVE)

    def test_a_checked_disposition_waits_for_a_running_crawl(self):
        (self.root / "state").mkdir(exist_ok=True)
        with open(self.root / "state" / "run.lock", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            message = self.with_tor_refused(NEWS_MIRROR)
        self.assertIn("a crawl or go-live is running", message)


if __name__ == "__main__":
    unittest.main()
