import dataclasses
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from onioncollect import golive, health, lifecycle
from onioncollect.config import write_config
from onioncollect.fetcher import FetchResult
from onioncollect.writer_client import Writer
from tests.fixtures import (CANDIDATE, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, headlines, listing_page, make_live,
                            leak_result_owned_by_root, news_config, testonion_config, throwaway_settings,
                            write_leak_result)
from tests.test_fingerprint import print_of
from tests.writer_harness import start_writer

GOOD = listing_page("A", "B", "C")


class ScriptedFetcher:
    instances = []

    def __init__(self, settings, tor, sources, configs, allowed_states, sessions=None):
        self.tor, self.sources, self.allowed_states, self.calls = tor, sources, allowed_states, []
        ScriptedFetcher.instances.append(self)

    async def log_in(self, source_id):
        self.calls.append((source_id, "POST"))
        host = (await self.sources.resolve(source_id)).active_host
        return FetchResult(source_id, "/login", host=host, status=303, error="redirect",
                           redirect_to=f"http://{host}/members/")

    async def fetch(self, source_id, path):
        self.calls.append((source_id, path))
        host = (await self.sources.resolve(source_id)).active_host
        page = self.tor.pages.get(path)
        if isinstance(page, FetchResult):
            return page
        if page is None:
            return FetchResult(source_id, path, host=host, error="timeout")
        return FetchResult(source_id, path, host=host, url=f"http://{host}{path}", status=200, body=page)

    async def close(self):
        pass


class GoLiveTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        leak_result_owned_by_root(self)
        self.settings = throwaway_settings(data_dir=root, configs_dir=root / "configs",
                                           leak_test_result=write_leak_result(root / "leak-test.json"))
        self.harness = await start_writer(root, root / "configs")
        self.collect, self.sources = self.harness.stores.collect, self.harness.stores.sources
        self.records, self.queue = self.harness.stores.records, self.harness.stores.health
        self.writer = Writer(self.harness.socket)
        await self.sources.approve(NEWS, "news", "journalism-publishing", "newsroom mirror", "tester", frozenset())
        ScriptedFetcher.instances = []
        patcher = mock.patch.object(golive, "Fetcher", ScriptedFetcher)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        await self.harness.stop()
        self.tmp.cleanup()

    async def go(self, pages, instances=2, config=None, **decision):
        tors = [mock.Mock(pages=pages) for _ in range(instances)]
        return await golive.go_live("news", config or news_config(), self.settings, self.writer, tors, **decision)

    async def state(self) -> str:
        return (await self.sources.get("news"))["state"]


class GoLiveTest(GoLiveTestCase):
    async def test_clean_pass_writes_baselines_and_goes_live(self):
        report = await self.go({"/articles/": GOOD})
        self.assertTrue(report.passed, report.lines)
        self.assertEqual(await self.state(), lifecycle.LIVE)
        baselines = await self.records.db.rows("SELECT path, baseline FROM snapshots")
        self.assertEqual([tuple(row) for row in baselines], [("/articles/", 1)])
        self.assertTrue(all(f.allowed_states == lifecycle.UNDER_TEST for f in ScriptedFetcher.instances))

    async def test_reachability_needs_two_instances(self):
        report = await self.go({"/articles/": GOOD}, instances=1)
        self.assertFalse(report.passed)
        self.assertIn("reachability: 1 of 2", report.lines[-1][1])
        self.assertEqual(await self.state(), lifecycle.APPROVED)

    async def test_unreachable_seed_fails(self):
        report = await self.go({})
        self.assertFalse(report.passed)
        self.assertIn("timeout", report.lines[-1][1])

    async def test_thin_sample_stays_approved_and_writes_nothing(self):
        report = await self.go({"/articles/": listing_page("only one")})
        self.assertFalse(report.passed)
        self.assertIn("1 complete items of 2 expected", report.lines[-1][1])
        self.assertEqual(await self.state(), lifecycle.APPROVED)
        self.assertEqual(await self.records.counts(), {"records": 0, "snapshots": 0})

    async def test_any_redaction_event_fails_the_sample(self):
        report = await self.go({"/articles/": listing_page("A", "B", extra="<pre>\nadmin:Synth3ticPass\n</pre>")})
        self.assertFalse(report.passed)
        self.assertIn("redaction events 1", report.lines[-1][1])

    async def test_safety_trip_disables_the_source(self):
        report = await self.go({"/articles/": listing_page("A", "B forbiddenterm")})
        self.assertFalse(report.passed)
        self.assertEqual(await self.state(), lifecycle.DISABLED)

    async def test_unapproved_host_in_the_config_fails_before_any_fetch(self):
        config = news_config(NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{OFF_SOURCE}"]'))
        report = await self.go({"/articles/": GOOD}, config=config)
        self.assertFalse(report.passed)
        self.assertIn(f"not approved: {OFF_SOURCE}", report.lines[-1][1])
        self.assertEqual(ScriptedFetcher.instances, [])

    async def test_only_an_approved_source_can_go_live(self):
        await self.go({"/articles/": GOOD})
        ScriptedFetcher.instances = []
        report = await self.go({"/articles/": GOOD})
        self.assertFalse(report.passed)
        self.assertEqual(report.lines, [(False, "state is approved (found live)")])
        self.assertEqual(ScriptedFetcher.instances, [])

    async def test_every_seed_is_a_baseline(self):
        config = news_config(NEWS_CONFIG.replace('["/articles/"]', '["/articles/", "/archive/"]'))
        report = await self.go({"/articles/": GOOD, "/archive/": listing_page("D", "E")}, config=config)
        self.assertTrue(report.passed, report.lines)
        rows = await self.records.db.rows("SELECT path, baseline FROM snapshots ORDER BY path")
        self.assertEqual([tuple(row) for row in rows], [("/archive/", 1), ("/articles/", 1)])

    async def test_a_pass_closes_the_items_a_reapproved_source_still_carries(self):
        queue = self.queue
        await queue.raise_item("news", health.Finding(health.BELOW_EXPECTATION, 40, "thin"), None)
        report = await self.go({"/articles/": GOOD})
        self.assertTrue(report.passed, report.lines)
        self.assertIn("1 open health items closed as fixed", report.lines[-1][1])
        (row,) = await queue.log()
        self.assertEqual((row["disposition"], row["note"], row["decided_by"]), (health.FIXED, "passed go-live", self.harness.stores.crawler))
        self.assertEqual(await self.state(), lifecycle.LIVE)

    async def test_a_seed_redirecting_off_the_source_leaves_evidence_for_triage(self):
        moved = FetchResult("news", "/articles/", host=NEWS, status=301, error="redirect",
                            redirect_to=f"http://{CANDIDATE}/articles/")
        report = await self.go({"/articles/": moved})
        self.assertFalse(report.passed)
        self.assertEqual(await self.sources.redirected_from([CANDIDATE]), {CANDIDATE: ["news"]})

    async def test_discovered_hosts_become_candidates(self):
        await self.go({"/articles/": listing_page("A", "B", extra=f"<a href='http://{OFF_SOURCE}/'>x</a>")})
        self.assertEqual([row["host"] for row in await self.sources.hosts(lifecycle.CANDIDATE)], [OFF_SOURCE])


class LeakTestGateTest(GoLiveTestCase):
    """Check 3: no fetch unless a recent, complete, passing leak test result that only its owner can write."""

    async def refused_with(self, why: str):
        report = await self.go({"/articles/": GOOD})
        self.assertFalse(report.passed)
        self.assertEqual(report.lines[-1][0], False)
        self.assertIn(why, report.lines[-1][1])
        self.assertEqual(ScriptedFetcher.instances, [])
        self.assertEqual(await self.state(), lifecycle.APPROVED)

    async def test_pass_names_the_run(self):
        report = await self.go({"/articles/": GOOD})
        self.assertIn((True, "leak tests: all 4 passed 1 h ago, run by tester"), report.lines)
        self.assertLess([line for _, line in report.lines].index("leak tests: all 4 passed 1 h ago, run by tester"),
                        [line for _, line in report.lines].index("reachability: 2 of 2 instances"))

    async def test_missing(self):
        self.settings.leak_test_result.unlink()
        await self.refused_with(f"no {self.settings.leak_test_result}; run make deploy")

    async def test_older_than_36_hours(self):
        write_leak_result(self.settings.leak_test_result, age=golive.LEAK_TEST_MAX_AGE + timedelta(minutes=1))
        await self.refused_with("more than 36 h ago")

    async def test_run_before_the_current_deploy(self):
        for seen in ("2026-11-01T09:00:00Z 0ldd3p10", None):
            ScriptedFetcher.instances = []
            write_leak_result(self.settings.leak_test_result, seen=seen)
            await self.refused_with("the last run predates the current deploy")

    async def test_no_deploy_stamp(self):
        self.settings.leak_test_result.with_name(golive.DEPLOY_STAMP).unlink()
        await self.refused_with("deploy-stamp; run make deploy")

    async def test_a_stamp_anyone_but_root_could_have_written(self):
        stamp = self.settings.leak_test_result.with_name(golive.DEPLOY_STAMP)
        stamp.chmod(0o666)
        await self.refused_with(f"{stamp} is writable by someone other than its owner")

    async def test_dated_in_the_future(self):
        write_leak_result(self.settings.leak_test_result, age=-timedelta(hours=1))
        await self.refused_with("in the future")

    async def test_any_test_failed(self):
        write_leak_result(self.settings.leak_test_result, failed=("dns-block",))
        await self.refused_with("dns-block did not pass")

    async def test_a_test_missing_from_the_result(self):
        write_leak_result(self.settings.leak_test_result, tests=golive.LEAK_TESTS[:3])
        await self.refused_with("redirect-trap did not pass")

    async def test_writable_by_group_or_others(self):
        for mode in (0o664, 0o646, 0o666):
            ScriptedFetcher.instances = []
            write_leak_result(self.settings.leak_test_result, mode=mode)
            await self.refused_with("writable by someone other than its owner")

    async def test_owned_by_anyone_but_root(self):
        with mock.patch.object(golive, "ROOT", os.geteuid() + 1):
            await self.refused_with("is not owned by root, so make deploy or make leak-test did not write it")

    async def test_not_a_result(self):
        for text in ("not json", "{}", '{"run_at": "2026-11-07", "run_by": "x", "tests": [1]}', "[]"):
            ScriptedFetcher.instances = []
            self.settings.leak_test_result.write_text(text)
            await self.refused_with("is not a leak test result")


def with_form_session(config):
    """A config carrying the self-hosted onion's auth table. The loader would refuse it for any id but testonion;
    golive leaves that check to the loader and the fetcher."""
    return dataclasses.replace(config, auth=testonion_config().auth)


class FormSessionGoLiveTest(GoLiveTestCase):
    async def test_a_form_session_config_is_refused_before_any_fetch(self):
        report = await self.go({"/articles/": GOOD}, config=with_form_session(news_config()))
        self.assertEqual(report.lines[-1], (False, "auth: form-session; go live with auth.type none on the public"
                                                   " pages first"))
        self.assertEqual(ScriptedFetcher.instances, [])
        self.assertEqual(await self.state(), lifecycle.APPROVED)


class RecheckTest(GoLiveTestCase):
    """Checks 1, 4 and 5 against one host of a collecting source: what fixed and mirror-swapped must pass."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.sources.change_state("news", lifecycle.LIVE)
        await self.sources.add_mirror(NEWS_MIRROR, "news", "second address", "tester", frozenset())
        self.config = news_config(NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]'))

    async def recheck(self, host, pages, config=None):
        tors = [mock.Mock(pages=pages) for _ in range(2)]
        return await golive.recheck("news", host, config or self.config, self.settings, self.writer, tors)

    async def test_a_sibling_passes_through_the_collecting_state_and_is_fingerprinted(self):
        report = await self.recheck(NEWS_MIRROR, {"/articles/": GOOD})
        self.assertTrue(report.passed, report.lines)
        self.assertTrue(all(f.allowed_states == lifecycle.COLLECTING for f in ScriptedFetcher.instances))
        self.assertIn(NEWS_MIRROR, await self.records.seed_fingerprints())
        self.assertEqual((await self.sources.resolve("news")).active_host, NEWS, "a recheck changes no host")
        self.assertEqual(await self.records.counts(), {"records": 0, "snapshots": 0})

    async def test_a_host_outside_the_config_is_refused_before_any_fetch(self):
        report = await self.recheck(NEWS_MIRROR, {"/articles/": GOOD}, config=news_config())
        self.assertEqual(report.lines[-1], (False, f"host: {NEWS_MIRROR} is in news's host set and config"))
        self.assertEqual(ScriptedFetcher.instances, [])

    async def test_a_thin_sample_fails(self):
        report = await self.recheck(NEWS_MIRROR, {"/articles/": listing_page("one")})
        self.assertFalse(report.passed)
        self.assertEqual(report.failure, "seed 1: 1 complete items of 2 expected, hit rate 1.00, redaction events 0")

    async def test_a_form_session_source_signs_in_once_on_its_active_host_then_rechecks(self):
        signed = b"<html><body><p id='signed-in'>Signed in</p></body></html>"
        report = await self.recheck(NEWS, {"/members/": signed, "/articles/": GOOD}, with_form_session(self.config))
        self.assertTrue(report.passed, report.lines)
        self.assertIn((True, "session: signed in, success selector found"), report.lines)
        posts = [call for fetcher in ScriptedFetcher.instances for call in fetcher.calls if call[1] == "POST"]
        self.assertEqual(posts, [("news", "POST")])

    async def test_a_form_session_source_is_rechecked_on_its_active_host_only(self):
        report = await self.recheck(NEWS_MIRROR, {"/articles/": GOOD}, with_form_session(self.config))
        self.assertEqual(report.failure, f"auth: a form-session source logs in on its active host only, {NEWS}")
        self.assertEqual(ScriptedFetcher.instances, [])

    async def test_a_failed_sign_in_fails_the_recheck_before_the_seeds(self):
        report = await self.recheck(NEWS, {"/articles/": GOOD}, with_form_session(self.config))
        self.assertEqual(report.failure, "session: not signed in (timeout)")
        self.assertNotIn(("news", "/articles/"), ScriptedFetcher.instances[0].calls)

    async def test_only_a_collecting_source(self):
        await self.sources.change_state("news", lifecycle.DISABLED, "pulled")
        report = await self.recheck(NEWS_MIRROR, {"/articles/": GOOD})
        self.assertEqual(report.lines, [(False, "state is live or degraded (found disabled)")])


FRONT = listing_page(*headlines("monday"))
PAPER_CONFIG = NEWS_CONFIG.replace('id = "news"', 'id = "paper"').replace(NEWS, NEWS_MIRROR)


class MirrorCheckTest(GoLiveTestCase):
    """Check 6: a source whose seed pages match another's waits for the analyst's call."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.sources, "paper", NEWS_MIRROR)
        write_config(self.settings.configs_dir, "paper", PAPER_CONFIG)
        await self.records.save_fingerprint(NEWS_MIRROR, "/articles/", True, print_of(FRONT))

    async def test_unconfirmed_match_refuses_and_writes_no_baseline(self):
        report = await self.go({"/articles/": FRONT})
        self.assertFalse(report.passed)
        self.assertEqual(report.lines[-1], (False, "mirror: matches paper (content 0, structure 0 bits apart);"
                                                   " rerun with --confirm-new-source or --as-mirror-of paper"))
        self.assertEqual(await self.state(), lifecycle.APPROVED)
        self.assertEqual((await self.records.counts())["snapshots"], 0)
        self.assertIn(NEWS, await self.records.seed_fingerprints(), "kept, so mirrors and triage can show it unfetched")

    async def test_confirmed_new_source_goes_live_in_the_cluster(self):
        report = await self.go({"/articles/": FRONT}, confirm_new_source=True)
        self.assertTrue(report.passed, report.lines)
        self.assertIn("mirror: matches paper (content 0, structure 0 bits apart), confirmed as a new source",
                      [line for _, line in report.lines])
        self.assertEqual(await self.state(), lifecycle.LIVE)
        self.assertEqual(await self.sources.cluster_of("paper"), ("news", "paper"))

    async def test_as_mirror_of_folds_the_hosts_into_that_source_only(self):
        report = await self.go({"/articles/": FRONT}, mirror_of="paper")
        self.assertTrue(report.passed, report.lines)
        self.assertIn(f"{NEWS} added to paper", report.lines[-1][1])
        paper, news = await self.sources.get("paper"), await self.sources.get("news")
        self.assertEqual((paper["state"], paper["active_host"], paper["hosts"]),
                         (lifecycle.LIVE, NEWS_MIRROR, sorted([NEWS, NEWS_MIRROR])))
        self.assertEqual((news["state"], news["reason"], news["hosts"]), (lifecycle.DISABLED, "mirror of paper", []))
        config = (self.settings.configs_dir / "paper.toml").read_text()
        self.assertEqual(config, PAPER_CONFIG.replace(f'["{NEWS_MIRROR}"]', f'["{NEWS_MIRROR}", "{NEWS}"]'))
        self.assertEqual((await self.records.counts())["snapshots"], 0)

    async def test_as_mirror_of_a_source_it_does_not_match_changes_nothing(self):
        await self.records.save_fingerprint(NEWS_MIRROR, "/articles/", True, print_of(listing_page(*headlines("tue"))))
        report = await self.go({"/articles/": FRONT}, mirror_of="paper")
        self.assertFalse(report.passed)
        self.assertEqual(report.lines[-1], (False, "mirror: news does not match paper, so it is not its mirror"))
        self.assertEqual(await self.state(), lifecycle.APPROVED)
        self.assertEqual((await self.sources.get("paper"))["hosts"], [NEWS_MIRROR])
        self.assertEqual((self.settings.configs_dir / "paper.toml").read_text(), PAPER_CONFIG)

    async def test_template_only_match_is_no_match(self):
        await self.records.save_fingerprint(NEWS_MIRROR, "/articles/", True, print_of(listing_page(*headlines("tue"))))
        report = await self.go({"/articles/": FRONT})
        self.assertTrue(report.passed, report.lines)
        self.assertIn((True, "mirror: no other source matches"), report.lines)

    async def test_a_config_it_cannot_edit_changes_nothing(self):
        write_config(self.settings.configs_dir, "paper", PAPER_CONFIG.replace("hosts = [", "hosts = [ # [x]\n"))
        report = await self.go({"/articles/": FRONT}, mirror_of="paper")
        self.assertFalse(report.passed)
        self.assertIn("paper's config", report.lines[-1][1])
        self.assertEqual((await self.sources.get("paper"))["hosts"], [NEWS_MIRROR])
        self.assertEqual(await self.state(), lifecycle.APPROVED)


if __name__ == "__main__":
    unittest.main()
