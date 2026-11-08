import unittest

from onioncollect import health, lifecycle
from onioncollect.health import Finding
from onioncollect.health_queue import HealthQueue
from onioncollect.sources import RefusedChange
from tests.fixtures import NEWS_MIRROR, make_live, news_config
from tests.test_db import CollectTestCase, metric

THIN = Finding(health.BELOW_EXPECTATION, 50, "2 complete items on 1 listing pages, expected 5 a page")
DOWN = Finding(health.UNREACHABLE, 100, "nothing fetched in 4 runs in a row")


class QueueTestCase(CollectTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await make_live(self.table)
        self.queue = HealthQueue(self.db, self.table, clock=self.clock)

    async def state(self, source_id: str = "news") -> str:
        return (await self.table.get(source_id))["state"]

    async def finish_run(self, *metrics):
        """One run of news through the frontier, closed as the crawler closes it."""
        await self.db.conn.execute("UPDATE sources SET next_run = NULL")
        await self.db.conn.commit()
        await self.frontier.start_run("news", ("/",))
        (task,) = await self.frontier.claim(1)
        for page in metrics:
            if page.error:
                await self.frontier.fail(task, page, 9, None)
            else:
                await self.frontier.complete(task, page, [], [])
        return await self.frontier.finish_if_done(task.run_id, lambda row: self.clock.now)


class RaiseTest(QueueTestCase):
    async def test_an_item_degrades_the_source_and_refreshes_rather_than_repeats(self):
        first = await self.queue.raise_item("news", THIN, None)
        self.assertEqual(await self.state(), lifecycle.DEGRADED)
        self.clock.advance(hours=6)
        again = await self.queue.raise_item("news", Finding(health.BELOW_EXPECTATION, 80, "worse"), 7)
        self.assertEqual(first, again)
        (item,) = await self.queue.queue()
        self.assertEqual((item["priority"], item["detail"], item["occurrences"], item["last_run_id"]), (80, "worse", 2, 7))
        self.assertLess(item["opened_at"], item["last_seen"])
        self.assertNotEqual(await self.queue.raise_item("news", DOWN, None), first)

    async def test_a_source_not_live_keeps_its_state(self):
        await self.table.approve(NEWS_MIRROR, "paper", "directories", "n", "t", frozenset())
        await self.queue.raise_item("paper", THIN, None)
        self.assertEqual(await self.state("paper"), lifecycle.APPROVED)

    async def test_priority_then_age(self):
        await make_live(self.table, "paper", NEWS_MIRROR)
        old_low = await self.queue.raise_item("news", THIN, None)
        self.clock.advance(minutes=1)
        high = await self.queue.raise_item("paper", DOWN, None)
        self.clock.advance(minutes=1)
        top = await self.queue.raise_item("paper", health.redaction("1 redaction events"), None)
        self.clock.advance(minutes=1)
        young_low = await self.queue.raise_item("paper", Finding(health.PARSE_REFUSED, 50, "x"), None)
        self.assertEqual([item["id"] for item in await self.queue.queue()], [top, high, old_low, young_low])


class DispositionTest(QueueTestCase):
    async def test_closing_the_last_open_item_makes_the_source_live_again(self):
        thin = await self.queue.raise_item("news", THIN, None)
        down = await self.queue.raise_item("news", DOWN, None)
        await self.queue.resolve(thin, health.FIXED, "selector updated", "analyst", "checks passed")
        self.assertEqual(await self.state(), lifecycle.DEGRADED)
        await self.queue.resolve(down, health.MIRROR_SWAPPED, "address moved", "analyst", "a -> b")
        self.assertEqual(await self.state(), lifecycle.LIVE)
        log = await self.queue.log()
        self.assertEqual([(row["item_id"], row["disposition"], row["applied"], row["decided_by"]) for row in log],
                         [(thin, health.FIXED, 1, "analyst"), (down, health.MIRROR_SWAPPED, 1, "analyst")])
        self.assertEqual((log[0]["kind"], log[0]["note"], log[0]["detail"]),
                         (health.BELOW_EXPECTATION, "selector updated", "checks passed"))
        self.assertEqual((await self.queue.item(thin))["status"], health.FIXED)

    async def test_refusals(self):
        item = await self.queue.raise_item("news", THIN, None)
        for disposition, note, why in ((health.FIXED, "  ", "needs a note"), ("ignored", "n", "must be one of")):
            with self.assertRaises(RefusedChange) as caught:
                await self.queue.resolve(item, disposition, note, "analyst")
            self.assertIn(why, str(caught.exception))
        await self.queue.resolve(item, health.FIXED, "n", "analyst")
        with self.assertRaises(RefusedChange):
            await self.queue.resolve(item, health.FIXED, "n", "analyst")
        with self.assertRaises(RefusedChange):
            await self.queue.item(999)

    async def test_a_refused_attempt_is_on_record_and_the_item_stays_open(self):
        item = await self.queue.raise_item("news", DOWN, None)
        await self.queue.refused(item, health.MIRROR_SWAPPED, "try the mirror", "analyst", "x.onion: reachability 0 of 2")
        (row,) = await self.queue.log()
        self.assertEqual((row["applied"], row["detail"]), (0, "x.onion: reachability 0 of 2"))
        self.assertEqual([entry["id"] for entry in await self.queue.queue()], [item])

    async def test_close_source_closes_every_open_item(self):
        await self.queue.raise_item("news", THIN, None)
        await self.queue.raise_item("news", DOWN, None)
        await self.table.change_state("news", lifecycle.DISABLED, "gone")
        self.assertEqual(await self.queue.close_source("news", health.DISABLED, "gone", "analyst"), 2)
        self.assertEqual(await self.queue.queue(), [])
        self.assertEqual(await self.state(), lifecycle.DISABLED)


class WatchTest(QueueTestCase):
    async def test_no_recurrence_while_watched_closes_the_item_itself(self):
        item = await self.queue.raise_item("news", THIN, None)
        await self.queue.watch(item, 2, "one bad night", "analyst")
        (row,) = await self.queue.queue()
        self.assertEqual(row["snoozed_until_run"], 2)
        healthy = metric(items=5, field_hits={"title": 5, "url": 5}, field_items=5)
        self.clock.advance(minutes=1)
        await self.queue.after_run(await self.finish_run(healthy), news_config())
        self.assertEqual(len(await self.queue.queue()), 1, "still snoozed after one run")
        self.clock.advance(minutes=1)
        await self.queue.after_run(await self.finish_run(healthy), news_config())
        self.assertEqual(await self.queue.queue(), [])
        self.assertEqual(await self.state(), lifecycle.LIVE)
        log = await self.queue.log()
        self.assertEqual([(row["disposition"], row["decided_by"], row["note"]) for row in log],
                         [(health.WATCHING, "analyst", "one bad night"),
                          (health.WATCHING, "health", "no recurrence while watched")])

    async def test_a_recurrence_while_watched_brings_it_back(self):
        item = await self.queue.raise_item("news", THIN, None)
        await self.queue.watch(item, 1, "one bad night", "analyst")
        self.clock.advance(minutes=1)
        await self.queue.after_run(await self.finish_run(metric(items=1, field_hits={"title": 1, "url": 1},
                                                                field_items=1)), news_config())
        (row,) = await self.queue.queue()
        self.assertEqual((row["id"], row["snoozed_until_run"], row["occurrences"]), (item, None, 2))

    async def test_watching_needs_a_run(self):
        item = await self.queue.raise_item("news", THIN, None)
        with self.assertRaises(RefusedChange):
            await self.queue.watch(item, 0, "n", "analyst")


class AfterRunTest(QueueTestCase):
    async def test_summary_reads_page_metrics_and_field_hits(self):
        run = await self.finish_run(metric(items=3, incomplete=1, field_hits={"title": 2, "url": 3}, field_items=3))
        summary = await self.queue.summary(run)
        self.assertEqual((summary.pages, summary.listing_pages, summary.items, summary.incomplete, summary.failed_runs),
                         (1, 1, 3, 1, 0))
        self.assertEqual(summary.field_hits, {"title": 2, "url": 3})

    async def test_raises_what_the_run_calls_for(self):
        run = await self.finish_run(metric(items=1, field_hits={"title": 1, "url": 1}, field_items=1))
        (found,) = await self.queue.after_run(run, news_config())
        self.assertEqual((found.kind, found.priority), (health.BELOW_EXPECTATION, 50))
        self.assertEqual(await self.state(), lifecycle.DEGRADED)

    async def test_a_parse_refusal_counts_from_the_metrics(self):
        run = await self.finish_run(metric(error="parse_refused"))
        (found,) = await self.queue.after_run(run, news_config())
        self.assertEqual(found.kind, health.PARSE_REFUSED)

    async def test_nothing_for_a_source_no_longer_collecting(self):
        run = await self.finish_run(metric(items=1, field_hits={"title": 1, "url": 1}, field_items=1))
        await self.table.change_state("news", lifecycle.DISABLED, "gone")
        self.assertEqual(await self.queue.after_run(run, news_config()), [])
        self.assertEqual(await self.queue.queue(), [])

    async def test_run_metrics(self):
        await self.finish_run(metric(items=4, fields_resolved=10, fields_declared=12, elapsed=2.0))
        (row,) = await self.queue.run_metrics("news", 5)
        self.assertEqual((row["pages"], row["answered"], row["attempts"], row["status"], row["parse_refused"]),
                         (1, 1, 1, 200, 0))
        self.assertEqual((row["items"], row["fields_resolved"], row["mean_elapsed"]), (4, 10, 2.0))


if __name__ == "__main__":
    unittest.main()
