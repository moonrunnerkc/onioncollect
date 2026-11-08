import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from onioncollect import lifecycle
from onioncollect.db import DETAIL, LISTING, Frontier, PageMetric, open_collect, stamp, unstamp
from onioncollect.sources import SourceTable
from tests.fixtures import EXCLUDED, NEWS, NEWS_MIRROR, make_live
from tests.test_onion import build_address

OTHER = build_address(bytes([0x11] * 32), 3)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta) -> None:
        self.now += timedelta(**delta)


def metric(**overrides) -> PageMetric:
    return PageMetric(**{"host": NEWS, "elapsed": 1.0, "status": 200} | overrides)


class CollectTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.db = await open_collect(Path(self.dir.name) / "collect.db")
        self.table = SourceTable(self.db, clock=self.clock)
        self.frontier = Frontier(self.db, per_source=2, clock=self.clock)

    async def asyncTearDown(self):
        await self.db.close()
        self.dir.cleanup()

    async def rows(self, sql: str, *params) -> list:
        return await self.db.rows(sql, params)

    async def status_of(self, path: str, source_id: str = "news") -> str:
        (row,) = await self.rows("SELECT status FROM urls WHERE source_id = ? AND path = ?", source_id, path)
        return row[0]

    async def live_run(self, source_id: str = "news", host: str = NEWS, seeds=("/",)) -> int:
        await make_live(self.table, source_id, host)
        return await self.frontier.start_run(source_id, seeds)


class DueSourcesTest(CollectTestCase):
    async def test_a_live_source_is_due_at_once(self):
        await make_live(self.table)
        self.assertEqual(await self.frontier.due_sources(), ["news"])

    async def test_approval_gate_approved_disabled_and_candidates_are_never_due(self):
        await self.table.approve(NEWS, "news", "journalism-publishing", "note", "t", frozenset())
        await self.table.add_candidates({OTHER}, None)
        self.assertEqual(await self.frontier.due_sources(), [])
        await self.table.change_state("news", lifecycle.DISABLED, "gone")
        self.assertEqual(await self.frontier.due_sources(), [])

    async def test_a_source_with_an_open_run_is_not_due(self):
        await self.live_run()
        self.assertEqual(await self.frontier.due_sources(), [])

    async def test_next_run_in_the_future_is_not_due(self):
        await make_live(self.table)
        await self.db.conn.execute("UPDATE sources SET next_run = ?", (stamp(self.clock.now + timedelta(hours=1)),))
        await self.db.conn.commit()
        self.assertEqual(await self.frontier.due_sources(), [])
        self.clock.advance(hours=1)
        self.assertEqual(await self.frontier.due_sources(), ["news"])


class StartRunTest(CollectTestCase):
    async def test_queues_each_seed_as_page_one_of_the_run(self):
        run_id = await self.live_run(seeds=("/a/", "/b/"))
        rows = await self.rows("SELECT path, kind, page, run_id, status FROM urls ORDER BY path")
        self.assertEqual([tuple(row) for row in rows],
                         [("/a/", LISTING, 1, run_id, "queued"), ("/b/", LISTING, 1, run_id, "queued")])
        (run,) = await self.rows("SELECT source_id, finished_at FROM runs WHERE id = ?", run_id)
        self.assertEqual(tuple(run), ("news", None))

    async def test_a_new_run_requeues_a_done_seed(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], [])
        await self.frontier.finish_if_done(run_id, lambda run: self.clock.now)
        second = await self.frontier.start_run("news", ("/",))
        (row,) = await self.rows("SELECT status, run_id FROM urls")
        self.assertEqual(tuple(row), ("queued", second))


class ClaimTest(CollectTestCase):
    async def test_per_source_concurrency_within_one_batch(self):
        await self.live_run(seeds=("/1", "/2", "/3", "/4"))
        tasks = await self.frontier.claim(10)
        self.assertEqual(len(tasks), 2)
        self.assertEqual(await self.frontier.claim(10), [])

    async def test_saturated_source_does_not_starve_others(self):
        await self.live_run(seeds=("/1", "/2", "/3"))
        await self.live_run("other", OTHER, seeds=("/x",))
        tasks = await self.frontier.claim(10)
        self.assertEqual(sorted(task.source_id for task in tasks), ["news", "news", "other"])

    async def test_task_fields_and_lease(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        self.assertEqual((task.source_id, task.path, task.kind, task.page, task.run_id, task.retries),
                         ("news", "/", LISTING, 1, run_id, 0))
        (row,) = await self.rows("SELECT status, lease_until FROM urls")
        self.assertEqual(row[0], "leased")
        self.assertEqual(unstamp(row[1]), self.clock.now + timedelta(minutes=10))

    async def test_rows_of_a_source_that_stops_collecting_are_never_claimed(self):
        await self.live_run()
        await self.table.change_state("news", lifecycle.DISABLED, "policy")
        self.assertEqual(await self.frontier.claim(5), [])
        (row,) = await self.rows("SELECT status FROM urls")
        self.assertEqual(row[0], "queued")

    async def test_not_due_is_not_claimed(self):
        await self.live_run()
        await self.db.conn.execute("UPDATE urls SET next_due = ?", (stamp(self.clock.now + timedelta(minutes=5)),))
        await self.db.conn.commit()
        self.assertEqual(await self.frontier.claim(1), [])
        self.clock.advance(minutes=5)
        self.assertEqual(len(await self.frontier.claim(1)), 1)


class CompleteTest(CollectTestCase):
    async def test_queues_the_next_listing_page_and_details(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [("/?p=2", 2)], ["/story/1", "/story/2"])
        rows = await self.rows("SELECT path, kind, page, run_id, status FROM urls ORDER BY path")
        self.assertEqual([tuple(row) for row in rows], [
            ("/", LISTING, 1, run_id, "done"), ("/?p=2", LISTING, 2, run_id, "queued"),
            ("/story/1", DETAIL, 0, run_id, "queued"), ("/story/2", DETAIL, 0, run_id, "queued"),
        ])

    async def test_a_detail_is_queued_once_ever(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], ["/story/1"])
        (detail,) = await self.frontier.claim(1)
        await self.frontier.complete(detail, metric(), [], [])
        await self.frontier.finish_if_done(run_id, lambda run: self.clock.now)
        await self.frontier.start_run("news", ("/",))
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], ["/story/1"])
        self.assertEqual(await self.status_of("/story/1"), "done")

    async def test_a_listing_page_is_not_queued_twice_in_one_run(self):
        await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [("/?p=2", 2)], [])
        (second,) = await self.frontier.claim(1)
        # A pager that loops back to the seed.
        await self.frontier.complete(second, metric(), [("/", 3)], [])
        self.assertEqual(await self.status_of("/"), "done")
        self.assertEqual(await self.frontier.claim(1), [])

    async def test_metrics_and_run_aggregates(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        page = metric(bytes=500, items=4, incomplete=1, fields_resolved=10, fields_declared=12,
                      below_expectation=True, redactions=2, records_new=3)
        await self.frontier.complete(task, page, [], [])
        (row,) = await self.rows("SELECT run_id, source_id, host, kind, status, error, bytes, items, fields_resolved,"
                                 " fields_declared, redactions FROM page_metrics")
        self.assertEqual(tuple(row), (run_id, "news", NEWS, LISTING, 200, None, 500, 4, 10, 12, 2))
        (run,) = await self.rows("SELECT pages, failures, items, incomplete, fields_resolved, fields_declared,"
                                 " below_expectation, redactions, records_new FROM runs")
        self.assertEqual(tuple(run), (1, 0, 4, 1, 10, 12, 1, 2, 3))
        (host,) = await self.rows("SELECT last_up, last_down FROM hosts WHERE host = ?", NEWS)
        self.assertEqual(tuple(host), (stamp(self.clock.now), None))
        (uptime,) = await self.rows("SELECT host, up FROM uptime")
        self.assertEqual(tuple(uptime), (NEWS, 1))

    async def test_field_hits_add_up_across_a_runs_pages(self):
        await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(field_hits={"title": 4, "url": 0}, field_items=4), [("/?p=2", 2)], [])
        (second,) = await self.frontier.claim(1)
        await self.frontier.complete(second, metric(field_hits={"title": 1, "url": 2}, field_items=3), [], [])
        rows = await self.rows("SELECT kind, field, resolved, declared FROM run_fields ORDER BY field")
        self.assertEqual([tuple(row) for row in rows], [(LISTING, "title", 5, 7), (LISTING, "url", 2, 7)])


class ProbeTest(CollectTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        await self.table.add_mirror(NEWS_MIRROR, "news", "second address", "t", frozenset())

    async def test_non_active_hosts_of_collecting_sources_are_due_once_a_day(self):
        self.assertEqual(await self.frontier.due_probes(timedelta(days=1)), [("news", NEWS_MIRROR)])
        await self.frontier.record_probe(NEWS_MIRROR, False)
        (host,) = await self.rows("SELECT last_up, last_down FROM hosts WHERE host = ?", NEWS_MIRROR)
        self.assertEqual(tuple(host), (None, stamp(self.clock.now)))
        self.assertEqual(await self.frontier.due_probes(timedelta(days=1)), [])
        self.clock.advance(days=1, seconds=1)
        self.assertEqual(await self.frontier.due_probes(timedelta(days=1)), [("news", NEWS_MIRROR)])
        await self.table.change_state("news", lifecycle.DISABLED, "pulled")
        self.assertEqual(await self.frontier.due_probes(timedelta(days=1)), [])


class FailTest(CollectTestCase):
    async def test_retry_then_park(self):
        await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, metric(status=None, error="timeout"), 1, self.clock.now + timedelta(minutes=2))
        (row,) = await self.rows("SELECT status, retries, next_due FROM urls")
        self.assertEqual(tuple(row), ("queued", 1, stamp(self.clock.now + timedelta(minutes=2))))
        self.clock.advance(minutes=2)
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, metric(status=None, error="timeout"), 3, None)
        self.assertEqual(await self.status_of("/"), "failed")

    async def test_unanswered_failure_marks_the_host_down(self):
        await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, metric(status=None, error="timeout"), 1, None)
        (host,) = await self.rows("SELECT last_up, last_down FROM hosts WHERE host = ?", NEWS)
        self.assertEqual(tuple(host), (None, stamp(self.clock.now)))
        (run,) = await self.rows("SELECT pages, failures FROM runs")
        self.assertEqual(tuple(run), (0, 1))
        (uptime,) = await self.rows("SELECT up FROM uptime")
        self.assertEqual(uptime[0], 0)

    async def test_a_host_that_answered_is_up(self):
        await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, metric(status=404, error="not_text"), 2, None)
        (uptime,) = await self.rows("SELECT up FROM uptime")
        self.assertEqual(uptime[0], 1)


class FinishTest(CollectTestCase):
    async def test_returns_the_run_once_and_schedules_the_source(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], [])
        due = self.clock.now + timedelta(hours=6)
        run = await self.frontier.finish_if_done(run_id, lambda row: due)
        self.assertEqual((run["id"], run["pages"], run["failed_runs"]), (run_id, 1, 0))
        self.assertIsNone(await self.frontier.finish_if_done(run_id, lambda row: due))
        (source,) = await self.rows("SELECT next_run, failed_runs FROM sources")
        self.assertEqual(tuple(source), (stamp(due), 0))
        (finished,) = await self.rows("SELECT finished_at FROM runs")
        self.assertEqual(finished[0], stamp(self.clock.now))

    async def test_open_work_keeps_the_run_open(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], ["/story/1"])
        self.assertIsNone(await self.frontier.finish_if_done(run_id, lambda row: self.clock.now))

    async def test_a_run_that_fetched_nothing_counts_as_failed(self):
        run_id = await self.live_run()
        (task,) = await self.frontier.claim(1)
        await self.frontier.fail(task, metric(status=None, error="timeout"), 3, None)
        seen = []
        await self.frontier.finish_if_done(run_id, lambda row: seen.append(row["failed_runs"]) or self.clock.now)
        self.assertEqual(seen, [0])
        (source,) = await self.rows("SELECT failed_runs FROM sources")
        self.assertEqual(source[0], 1)
        second = await self.frontier.start_run("news", ("/",))
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], [])
        await self.frontier.finish_if_done(second, lambda row: self.clock.now)
        (source,) = await self.rows("SELECT failed_runs FROM sources")
        self.assertEqual(source[0], 0)


class LeaseRecoveryTest(CollectTestCase):
    async def test_stale_leases_return_to_the_queue(self):
        await self.live_run(seeds=("/1", "/2"))
        await self.frontier.claim(1)
        self.assertEqual(await self.frontier.release_stale_leases(), 0)
        self.clock.advance(minutes=11)
        self.assertEqual(await self.frontier.release_stale_leases(), 1)
        self.assertEqual(len(await self.frontier.claim(5)), 2)


class StatsTest(CollectTestCase):
    async def test_stats(self):
        await self.live_run(seeds=("/1", "/2"))
        await self.table.add_candidates({OTHER}, "news")
        await self.table.decline(EXCLUDED, "on the exclusion list", "t")
        (task,) = await self.frontier.claim(1)
        await self.frontier.complete(task, metric(), [], [])
        stats = await self.frontier.stats()
        self.assertEqual(stats["urls"], {"done": 1, "queued": 1})
        self.assertEqual(stats["sources"], {"live": 1})
        self.assertEqual(stats["hosts"], {"member": 1, "candidate": 1, "declined": 1})
        self.assertEqual((stats["open_runs"], stats["fetches_last_hour"], stats["up_last_hour"],
                          stats["fetches_recent"]), (1, 1, 1, 1))

    def test_stamp_round_trip(self):
        moment = datetime(2026, 11, 7, 12, 0, 1, 250000, tzinfo=UTC)
        self.assertEqual(unstamp(stamp(moment)), moment)


if __name__ == "__main__":
    unittest.main()
