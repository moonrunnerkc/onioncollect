import unittest
from datetime import timedelta

from unittest import mock

from onioncollect import fetcher as fetcher_module
from onioncollect import lifecycle
from onioncollect.db import stamp
from onioncollect.fetcher import Fetcher, FetchResult
from onioncollect.sources import PinnedHost, RefusedChange, Source
from tests.fixtures import (CANDIDATE, DECLINED, EXCLUDED, NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, make_live,
                            news_config, throwaway_settings)
from tests.test_db import CollectTestCase

CATEGORY = "journalism-publishing"
APPROVED_ONLY = frozenset({lifecycle.APPROVED})


class CandidatesTest(CollectTestCase):
    async def test_add_is_idempotent_and_counts_new_hosts_only(self):
        self.assertEqual(await self.table.add_candidates({CANDIDATE, DECLINED}, "news"), 2)
        self.assertEqual(await self.table.add_candidates({CANDIDATE, DECLINED}, "other"), 0)
        rows = await self.table.hosts(lifecycle.CANDIDATE)
        self.assertEqual({row["host"]: row["found_on"] for row in rows}, {CANDIDATE: "news", DECLINED: "news"})

    async def test_an_uppercase_spelling_is_the_same_host(self):
        await self.table.add_candidates({CANDIDATE}, "news")
        self.assertEqual(await self.table.add_candidates({CANDIDATE.upper()[:-6] + ".onion"}, "other"), 0)
        self.assertEqual([row["host"] for row in await self.table.hosts()], [CANDIDATE])

    async def test_rediscovery_never_resurrects_a_declined_host(self):
        await self.table.decline(DECLINED, "sells data", "t")
        self.assertEqual(await self.table.add_candidates({DECLINED}, "news"), 0)
        (row,) = await self.table.hosts(lifecycle.DECLINED)
        self.assertEqual((row["host"], row["reason"]), (DECLINED, "sells data"))

    async def test_member_hosts_stay_members(self):
        await make_live(self.table)
        self.assertEqual(await self.table.add_candidates({NEWS}, "elsewhere"), 0)
        (row,) = await self.table.hosts(lifecycle.MEMBER)
        self.assertEqual(row["source_id"], "news")

    async def test_anything_but_a_v3_host_is_ignored(self):
        self.assertEqual(await self.table.add_candidates({"example.com", "abc.onion", CANDIDATE[1:]}, None), 0)
        self.assertEqual(await self.table.hosts(), [])


class ApproveTest(CollectTestCase):
    async def approve(self, host=CANDIDATE, source_id="news", category=CATEGORY, note="public mirror",
                      excluded=frozenset({EXCLUDED})):
        await self.table.approve(host, source_id, category, note, "analyst", excluded)

    async def test_a_candidate_becomes_a_member_of_a_new_approved_source(self):
        await self.table.add_candidates({CANDIDATE}, "dir")
        await self.approve(CANDIDATE.upper()[:-6] + ".onion")
        row = await self.table.get("news")
        self.assertEqual((row["state"], row["category"], row["active_host"], row["reviewer"], row["note"]),
                         (lifecycle.APPROVED, CATEGORY, CANDIDATE, "analyst", "public mirror"))
        self.assertEqual(row["hosts"], [CANDIDATE])
        (host,) = await self.table.hosts(lifecycle.MEMBER)
        self.assertEqual((host["found_on"], host["decided_by"]), ("dir", "analyst"))

    async def test_a_requested_host_never_discovered_can_be_approved(self):
        await self.approve()
        self.assertEqual((await self.table.get("news"))["hosts"], [CANDIDATE])

    async def test_refusals(self):
        await self.table.decline(DECLINED, "market", "t")
        await self.approve(NEWS, "taken")
        cases = [
            ({"host": EXCLUDED}, "exclusion list"),
            ({"host": DECLINED}, "already reviewed"),
            ({"host": NEWS}, "already reviewed"),
            ({"source_id": "taken"}, "already exists"),
            ({"host": "example.com"}, "not a v3"),
        ]
        for kwargs, message in cases:
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(RefusedChange, message):
                await self.approve(**kwargs)
        for kwargs in ({"category": "market"}, {"note": "  "}, {"source_id": "Bad Id"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await self.approve(**kwargs)
        self.assertEqual([row["id"] for row in await self.table.sources()], ["taken"])
        self.assertEqual((await self.table.hosts(lifecycle.DECLINED))[0]["host"], DECLINED)

    async def test_a_refused_duplicate_id_leaves_the_host_a_candidate(self):
        await self.approve(NEWS, "news")
        await self.table.add_candidates({CANDIDATE}, "news")
        with self.assertRaises(RefusedChange):
            await self.approve(CANDIDATE, "news")
        (row,) = await self.table.hosts(lifecycle.CANDIDATE)
        self.assertEqual(row["host"], CANDIDATE)


class DeclineTest(CollectTestCase):
    async def test_decline_records_the_reason_and_reviewer(self):
        await self.table.add_candidates({DECLINED}, "dir")
        await self.table.decline(DECLINED, "sells credentials", "analyst")
        (row,) = await self.table.hosts(lifecycle.DECLINED)
        self.assertEqual((row["reason"], row["decided_by"], row["found_on"]), ("sells credentials", "analyst", "dir"))

    async def test_decline_needs_a_reason_and_an_undecided_v3_host(self):
        with self.assertRaisesRegex(RefusedChange, "reason"):
            await self.table.decline(DECLINED, " ", "t")
        with self.assertRaisesRegex(RefusedChange, "v3"):
            await self.table.decline("example.com", "x", "t")
        await make_live(self.table)
        with self.assertRaisesRegex(RefusedChange, "already reviewed"):
            await self.table.decline(NEWS, "changed my mind", "t")


class ChangeStateTest(CollectTestCase):
    async def test_going_live_sets_live_at_and_next_run(self):
        await self.table.approve(NEWS, "news", CATEGORY, "n", "t", frozenset())
        self.clock.advance(hours=1)
        await self.table.change_state("news", lifecycle.LIVE)
        row = await self.table.get("news")
        now = stamp(self.clock.now)
        self.assertEqual((row["state"], row["live_at"], row["next_run"], row["state_changed_at"]),
                         (lifecycle.LIVE, now, now, now))

    async def test_degraded_and_back_keeps_live_at(self):
        await make_live(self.table)
        live_at = (await self.table.get("news"))["live_at"]
        self.clock.advance(hours=1)
        await self.table.change_state("news", lifecycle.DEGRADED)
        await self.table.change_state("news", lifecycle.LIVE)
        self.assertEqual((await self.table.get("news"))["live_at"], live_at)

    async def test_disabling_needs_a_reason_and_closes_open_runs(self):
        await make_live(self.table)
        run_id = await self.frontier.start_run("news", ("/",))
        with self.assertRaisesRegex(RefusedChange, "reason"):
            await self.table.change_state("news", lifecycle.DISABLED)
        await self.table.change_state("news", lifecycle.DISABLED, "layout gone")
        row = await self.table.get("news")
        self.assertEqual((row["state"], row["reason"]), (lifecycle.DISABLED, "layout gone"))
        (run,) = await self.rows("SELECT finished_at FROM runs WHERE id = ?", run_id)
        self.assertEqual(run[0], stamp(self.clock.now))

    async def test_illegal_transitions_and_unknown_sources(self):
        await self.table.approve(NEWS, "news", CATEGORY, "n", "t", frozenset())
        for target in (lifecycle.DEGRADED, lifecycle.APPROVED):
            with self.subTest(target=target), self.assertRaisesRegex(RefusedChange, "cannot go"):
                await self.table.change_state("news", target)
        with self.assertRaisesRegex(RefusedChange, "no source"):
            await self.table.change_state("ghost", lifecycle.LIVE)
        await self.table.change_state("news", lifecycle.DISABLED, "x")
        with self.assertRaisesRegex(RefusedChange, "cannot go"):
            await self.table.change_state("news", lifecycle.LIVE)
        await self.table.change_state("news", lifecycle.APPROVED)
        self.assertEqual((await self.table.get("news"))["state"], lifecycle.APPROVED)


class ReadTest(CollectTestCase):
    async def test_resolve_returns_member_hosts_only(self):
        await make_live(self.table)
        await self.table.add_candidates({NEWS_MIRROR}, "news")
        self.assertEqual(await self.table.resolve("news"),
                         Source("news", lifecycle.LIVE, CATEGORY, NEWS, frozenset({NEWS})))
        self.assertIsNone(await self.table.resolve("ghost"))
        self.assertIsNone(await self.table.resolve(NEWS_MIRROR))

    async def test_listings_filter_by_state(self):
        await make_live(self.table)
        await self.table.approve(CANDIDATE, "other", "directories", "n", "t", frozenset())
        self.clock.advance(minutes=1)
        await self.table.add_candidates({NEWS_MIRROR}, "news")
        self.assertEqual([row["id"] for row in await self.table.sources()], ["news", "other"])
        self.assertEqual([row["id"] for row in await self.table.sources(lifecycle.LIVE)], ["news"])
        self.assertEqual([row["host"] for row in await self.table.hosts(lifecycle.CANDIDATE)], [NEWS_MIRROR])
        self.assertEqual(len(await self.table.hosts()), 3)
        self.assertIsNone(await self.table.get("ghost"))

    async def test_next_run_untouched_by_a_later_state_change(self):
        await make_live(self.table)
        later = stamp(self.clock.now + timedelta(hours=6))
        await self.db.conn.execute("UPDATE sources SET next_run = ?", (later,))
        await self.db.conn.commit()
        await self.table.change_state("news", lifecycle.DEGRADED)
        self.assertEqual((await self.table.get("news"))["next_run"], later)


class MirrorTest(CollectTestCase):
    """Approving a host as a mirror alters the named source's host set and nothing else."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        await self.table.approve(OFF_SOURCE, "docs", "software-infrastructure", "distro docs", "t", frozenset())
        await self.table.add_candidates({NEWS_MIRROR, CANDIDATE}, "news")

    async def test_add_mirror_joins_the_host_set_and_keeps_state_and_active_host(self):
        before = await self.table.get("docs")
        await self.table.add_mirror(NEWS_MIRROR.upper()[:-6] + ".onion", "news", "listed on its about page", "t",
                                    frozenset())
        news = await self.table.get("news")
        self.assertEqual((news["state"], news["active_host"], news["hosts"]), (lifecycle.LIVE, NEWS, sorted([NEWS, NEWS_MIRROR])))
        self.assertEqual(await self.table.get("docs"), before)
        (row,) = [row for row in await self.table.hosts() if row["host"] == NEWS_MIRROR]
        self.assertEqual((row["state"], row["source_id"], row["reason"]), (lifecycle.MEMBER, "news", "listed on its about page"))
        self.assertEqual([row["host"] for row in await self.table.hosts(lifecycle.CANDIDATE)], [CANDIDATE])
        self.assertEqual((await self.table.resolve("news")).hosts, {NEWS, NEWS_MIRROR})

    async def test_add_mirror_refusals(self):
        await self.table.decline(CANDIDATE, "sells data", "t")
        for host, source_id, note, excluded, why in (
            (CANDIDATE, "news", "n", frozenset(), "already reviewed"),
            (NEWS_MIRROR, "nothing", "n", frozenset(), "no source nothing"),
            (NEWS_MIRROR, "news", " ", frozenset(), "reviewer note"),
            (NEWS_MIRROR, "news", "n", frozenset({NEWS_MIRROR}), "exclusion list"),
            (OFF_SOURCE, "news", "n", frozenset(), "already reviewed"),
            ("example.onion", "news", "n", frozenset(), "not a v3"),
        ):
            with self.assertRaises(RefusedChange) as caught:
                await self.table.add_mirror(host, source_id, note, "t", excluded)
            self.assertIn(why, str(caught.exception))
        self.assertEqual((await self.table.get("news"))["hosts"], [NEWS])

    async def test_merge_folds_an_approved_source_into_another(self):
        self.assertEqual(await self.table.merge("docs", "news", APPROVED_ONLY, "mirror of news"), [OFF_SOURCE])
        news, docs = await self.table.get("news"), await self.table.get("docs")
        self.assertEqual((news["state"], news["hosts"]), (lifecycle.LIVE, sorted([NEWS, OFF_SOURCE])))
        self.assertEqual((docs["state"], docs["reason"], docs["hosts"]), (lifecycle.DISABLED, "mirror of news", []))

    async def test_merge_refusals(self):
        for source_id, into, why in (("news", "docs", "only approved"), ("docs", "docs", "no other source"),
                                     ("docs", "nothing", "no other source"), ("nothing", "news", "only approved")):
            with self.assertRaises(RefusedChange) as caught:
                await self.table.merge(source_id, into, APPROVED_ONLY, "mirror")
            self.assertIn(why, str(caught.exception))
        self.assertEqual((await self.table.get("docs"))["hosts"], [OFF_SOURCE])


class LiveMergeTest(CollectTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        await make_live(self.table, "paper", NEWS_MIRROR)
        await self.db.conn.execute("INSERT INTO runs (source_id, started_at) VALUES ('paper', '2026')")
        await self.db.conn.commit()

    async def test_a_live_source_merges_into_its_live_twin_and_its_open_run_closes(self):
        moved = await self.table.merge("paper", "news", lifecycle.COLLECTING, "merged into news",
                                       into_states=lifecycle.COLLECTING)
        self.assertEqual(moved, [NEWS_MIRROR])
        paper = await self.table.get("paper")
        self.assertEqual((paper["state"], paper["reason"], paper["hosts"]), (lifecycle.DISABLED, "merged into news", []))
        (open_runs,), = await self.rows("SELECT COUNT(*) FROM runs WHERE finished_at IS NULL")
        self.assertEqual(open_runs, 0)

    async def test_into_must_be_in_the_named_states(self):
        await self.table.change_state("news", lifecycle.DISABLED, "gone")
        with self.assertRaises(RefusedChange) as caught:
            await self.table.merge("paper", "news", lifecycle.COLLECTING, "x", into_states=lifecycle.COLLECTING)
        self.assertIn("news is disabled", str(caught.exception))
        self.assertEqual((await self.table.get("paper"))["hosts"], [NEWS_MIRROR])


class ActiveHostTest(CollectTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        await self.table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset())

    async def test_moves_within_the_host_set_only(self):
        self.assertEqual(await self.table.set_active_host("news", NEWS_MIRROR), NEWS)
        self.assertEqual((await self.table.resolve("news")).active_host, NEWS_MIRROR)
        await self.table.approve(OFF_SOURCE, "docs", CATEGORY, "n", "t", frozenset())
        for host in (OFF_SOURCE, CANDIDATE):
            with self.assertRaises(RefusedChange):
                await self.table.set_active_host("news", host)
        self.assertEqual((await self.table.resolve("news")).active_host, NEWS_MIRROR)


class PinnedHostTest(CollectTestCase):
    """Sibling probes and the swap checks fetch a non-active host through this view, never a URL. The view
    moves the active host only; the fetcher's own checks still decide."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        await self.table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset())
        self.config = news_config(NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{NEWS_MIRROR}"]'))

    async def resolve(self, host, states=lifecycle.COLLECTING, config=None):
        built = []
        with mock.patch.object(fetcher_module, "AsyncProxyTransport", side_effect=lambda **kw: built.append(kw)):
            fetcher = Fetcher(throwaway_settings(), mock.Mock(), PinnedHost(self.table, host),
                              {"news": config or self.config}, states)
            result = FetchResult("news", "/articles/")
            url = await fetcher.resolve(result)
        self.assertEqual(built, [])
        return result.error, url

    async def test_a_sibling_in_the_set_and_the_config_resolves(self):
        self.assertEqual(await self.resolve(NEWS_MIRROR), (None, f"http://{NEWS_MIRROR}/articles/"))

    async def test_the_fetchers_own_checks_still_refuse(self):
        await self.table.approve(OFF_SOURCE, "docs", CATEGORY, "n", "t", frozenset())
        self.assertEqual(await self.resolve(OFF_SOURCE), ("not_source_host", None), "another source's host")
        self.assertEqual(await self.resolve(CANDIDATE), ("not_source_host", None), "a host of no source")
        self.assertEqual(await self.resolve(NEWS_MIRROR, config=news_config()), ("not_source_host", None),
                         "in the set but not the config")
        self.assertEqual(await self.resolve(NEWS_MIRROR, states=lifecycle.UNDER_TEST), ("not_approved", None))
        await self.table.change_state("news", lifecycle.DISABLED, "pulled")
        self.assertEqual(await self.resolve(NEWS_MIRROR), ("not_approved", None))

    async def test_a_source_that_does_not_exist_resolves_to_nothing(self):
        self.assertIsNone(await PinnedHost(self.table, NEWS).resolve("nothing"))


class RedirectEvidenceTest(CollectTestCase):
    async def test_a_redirect_target_is_a_candidate_with_its_source_on_record(self):
        await make_live(self.table)
        self.assertEqual(await self.table.add_redirect_target("news", CANDIDATE.upper()), 1)
        self.assertEqual(await self.table.add_redirect_target("news", CANDIDATE), 0)
        self.assertEqual([row["host"] for row in await self.table.hosts(lifecycle.CANDIDATE)], [CANDIDATE])
        self.assertEqual(await self.table.redirected_from([CANDIDATE, OFF_SOURCE]), {CANDIDATE: ["news"]})
        self.assertEqual(await self.table.add_redirect_target("news", "example.com"), 0)
        (count,), = await self.rows("SELECT COUNT(*) FROM redirects")
        self.assertEqual(count, 1)


class ReapproveTest(CollectTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)

    async def test_disabled_back_to_approved_with_the_note(self):
        await self.table.change_state("news", lifecycle.DISABLED, "take a baseline")
        await self.table.reapprove("news", "re-run golive for a baseline", "analyst")
        source = await self.table.get("news")
        self.assertEqual((source["state"], source["reason"], source["reviewer"]),
                         (lifecycle.APPROVED, "reapproved: re-run golive for a baseline", "analyst"))

    async def test_refusals(self):
        with self.assertRaises(RefusedChange) as caught:
            await self.table.reapprove("news", "n", "t")
        self.assertIn("from live to approved", str(caught.exception))
        await self.table.change_state("news", lifecycle.DISABLED, "safety: child_exploitation")
        for note, why in (("n", "safety check"), ("  ", "note")):
            with self.assertRaises(RefusedChange) as caught:
                await self.table.reapprove("news", note, "t")
            self.assertIn(why, str(caught.exception))
        await self.table.approve(OFF_SOURCE, "docs", CATEGORY, "n", "t", frozenset())
        await self.table.merge("docs", "news", APPROVED_ONLY, "mirror of news")
        with self.assertRaises(RefusedChange) as caught:
            await self.table.reapprove("docs", "n", "t")
        self.assertIn("no hosts left", str(caught.exception))


class ClusterTest(CollectTestCase):
    async def test_set_clusters_and_cluster_of(self):
        for source_id, host in (("news", NEWS), ("mirror", NEWS_MIRROR), ("docs", OFF_SOURCE)):
            await self.table.approve(host, source_id, CATEGORY, "n", "t", frozenset())
        self.assertEqual(await self.table.members(), {NEWS: "news", NEWS_MIRROR: "mirror", OFF_SOURCE: "docs"})
        await self.table.set_clusters({"news": "mirror", "mirror": "mirror"})
        self.assertEqual(await self.table.cluster_of("news"), ("mirror", "news"))
        self.assertEqual(await self.table.cluster_of("docs"), ("docs",))
        self.assertEqual((await self.table.get("news"))["cluster_id"], "mirror")
        await self.table.set_clusters({})
        self.assertEqual(await self.table.cluster_of("news"), ("news",))
        self.assertIsNone((await self.table.get("mirror"))["cluster_id"])

    async def test_set_clusters_names_the_clusters_that_gained_a_source(self):
        for source_id, host in (("news", NEWS), ("mirror", NEWS_MIRROR), ("docs", OFF_SOURCE)):
            await self.table.approve(host, source_id, CATEGORY, "n", "t", frozenset())
        self.assertEqual(await self.table.set_clusters({"news": "mirror", "mirror": "mirror"}), {"mirror"})
        self.assertEqual(await self.table.set_clusters({"news": "mirror", "mirror": "mirror"}), set())
        self.assertEqual(await self.table.set_clusters({"news": "docs", "mirror": "docs", "docs": "docs"}), {"docs"})
        self.assertEqual(await self.table.set_clusters({"news": "mirror", "mirror": "mirror"}), set(), "shrinking")
        self.assertEqual(await self.table.in_cluster("mirror"), ("mirror", "news"))


if __name__ == "__main__":
    unittest.main()
