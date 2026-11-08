"""The write socket: what a request must look like, who may connect, and section 17's storage refusal test, which
now runs where it runs in the guest, in the writer, behind the socket, under a different user from the gate."""
import asyncio
import contextlib
import json
import logging
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from onioncollect import health, lifecycle, wire, writer
from onioncollect.db import LISTING, PageMetric, Task
from onioncollect.pages import Record
from onioncollect.redact import Redacted
from onioncollect.sources import RefusedChange
from onioncollect.writer_client import WriteRefused, Writer
from tests.fixtures import CANDIDATE, NEWS, NEWS_CONFIG, OFF_SOURCE, headlines, listing_page, make_live
from tests.test_fingerprint import print_of
from tests.writer_harness import start_writer

SECRET = "bob.synthetic@example.com:SynthPassw0rd!"
CLEAN = Redacted("", {}, (), 0)
TASK = Task("news", "/articles/", LISTING, 1, 1, 0)
FRONT = listing_page(*headlines("monday"))


def record(summary: Redacted = CLEAN, **fields) -> Record:
    return Record("h1", "/articles/1", fields or {"title": "relay notes"}, summary)


class WriterTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = Path(self.tmp.name) / "data"
        self.harness = await start_writer(self.data, Path(self.tmp.name) / "configs")
        self.stores = self.harness.stores
        self.writer = Writer(self.harness.socket, retry_pause=0.01)
        await make_live(self.stores.sources)
        self.run_id = await self.writer.run_start("news")

    async def asyncTearDown(self):
        await self.harness.stop()
        self.tmp.cleanup()

    async def exchange(self, payload: bytes) -> tuple[dict, bool]:
        """One raw line to the socket: the reply, and whether the writer then closed the connection."""
        reader, sender = await asyncio.open_unix_connection(self.harness.socket, limit=2 * wire.LINE_CAP)
        sender.write(payload)
        reply = json.loads(await reader.readline())
        try:
            closed = await asyncio.wait_for(reader.read(), 0.3) == b""
        except TimeoutError:
            closed = False
        sender.close()
        return reply, closed

    def request(self, op: str, **fields) -> bytes:
        return wire.encode({"op": op, **fields})


class ProtocolTest(WriterTestCase):
    async def refused_and_closed(self, payload: bytes, code: str) -> dict:
        reply, closed = await self.exchange(payload)
        self.assertEqual((reply["ok"], reply["error"]), (False, code), reply)
        self.assertTrue(closed, code)
        return reply

    async def test_unknown_op(self):
        await self.refused_and_closed(self.request("execute", sql="DROP TABLE records"), wire.UNKNOWN_OP)

    async def test_missing_field(self):
        reply = await self.refused_and_closed(self.request("add_candidates", hosts=[CANDIDATE]), wire.BAD_REQUEST)
        self.assertEqual(reply["reason"], "add_candidates: missing found_on")

    async def test_extra_field(self):
        reply = await self.refused_and_closed(self.request("resolve", source_id="news", path="/etc/passwd"),
                                              wire.BAD_REQUEST)
        self.assertEqual(reply["reason"], "resolve: unexpected path")

    async def test_wrong_types(self):
        for fields in ({"source_id": 7}, {"source_id": None}, {"source_id": ["news"]}):
            with self.subTest(fields=fields):
                await self.refused_and_closed(self.request("resolve", **fields), wire.BAD_REQUEST)
        for up in (1, "yes", None):
            await self.refused_and_closed(self.request("probe_result", host=NEWS, up=up), wire.BAD_REQUEST)
        await self.refused_and_closed(b'{"op": "run_finish", "run_id": true, "cadence_seconds": 1, "expect": null}\n',
                                      wire.BAD_REQUEST)
        await self.refused_and_closed(self.request("page_done", run_id=1, source_id="news", kind="index", path="/",
                                                   metric={}), wire.BAD_REQUEST)

    async def test_not_json_and_not_an_object(self):
        await self.refused_and_closed(b"\xff\xfe not json\n", wire.NOT_JSON)
        await self.refused_and_closed(b'["ping"]\n', wire.BAD_REQUEST)

    async def test_oversize_line(self):
        reply = await self.refused_and_closed(b"x" * (wire.LINE_CAP + 10) + b"\n", wire.OVERSIZE)
        self.assertIn(str(wire.LINE_CAP), reply["reason"])

    async def test_the_client_never_sends_a_line_over_the_cap(self):
        with self.assertRaisesRegex(WriteRefused, wire.OVERSIZE):
            await self.writer.save_snapshot(TASK, "x" * wire.LINE_CAP)

    async def test_a_refused_change_answers_and_keeps_the_connection(self):
        reply, closed = await self.exchange(self.request("set_active_host", source_id="news", host=CANDIDATE))
        self.assertEqual(reply["error"], wire.NOT_CHANGED)
        self.assertFalse(closed)

    async def test_the_log_has_op_outcome_size_and_time_only(self):
        with self.assertLogs("onioncollect.writer", logging.INFO) as logs:
            await self.writer.add_candidates({CANDIDATE}, "news")
            await self.exchange(self.request("resolve", source_id="news", path="/x"))
        self.assertRegex(logs.output[0], r"writer op=add_candidates outcome=ok bytes=\d+ elapsed=\d+\.\d{3}s$")
        self.assertRegex(logs.output[1], r"writer op=resolve outcome=bad_request bytes=\d+ elapsed=\d+\.\d{3}s$")
        self.assertNotIn(CANDIDATE, "\n".join(logs.output))


class OpsWriteWhatTheyShouldTest(WriterTestCase):
    async def rows(self, sql: str):
        return [tuple(row) for row in await self.stores.collect.rows(sql)]

    async def test_run_metrics_and_sightings(self):
        await self.writer.page_done(Task("news", "/articles/", LISTING, 1, self.run_id, 0),
                                    PageMetric(NEWS, 0.5, 200, items=3, field_hits={"title": 3}, field_items=3))
        self.assertEqual(await self.rows("SELECT run_id, source_id, kind, status, items FROM page_metrics"),
                         [(self.run_id, "news", LISTING, 200, 3)])
        self.assertEqual(await self.rows("SELECT pages, items FROM runs"), [(1, 3)])
        self.assertEqual(await self.rows("SELECT path FROM visited_paths"), [("/articles/",)])
        finished = await self.writer.run_finish(self.run_id, 3600.0, {"min_items": 2, "required": ["title"],
                                                                        "category": "journalism-publishing"})
        self.assertEqual((finished["run"]["id"], finished["findings"]), (self.run_id, []))
        self.assertEqual((await self.writer.run_finish(self.run_id, 3600.0, None))["run"], None, "closed once")
        await self.writer.probe_result(NEWS, False)
        self.assertEqual(await self.rows("SELECT host, up FROM uptime ORDER BY rowid"), [(NEWS, 1), (NEWS, 0)])

    async def test_records_snapshot_fingerprint_and_report(self):
        task = Task("news", "/articles/", LISTING, 1, self.run_id, 0)
        self.assertEqual(await self.writer.store_records(task, NEWS, [record()]), 1)
        (stored,) = await self.stores.records.db.rows("SELECT source_id, category FROM records")
        self.assertEqual(tuple(stored), ("news", "journalism-publishing"), "the writer, not the client, names the category")
        digest = await self.writer.save_snapshot(task, "<p>relay notes</p>")
        self.assertTrue(self.stores.records.snapshot_path(digest).is_file())
        await self.writer.save_report("news", False, [(False, "reachability: 1 of 2 instances")])
        self.assertEqual(await self.rows("SELECT passed FROM golive_reports"), [(0,)])

    async def test_triage_evidence_and_the_safety_disable(self):
        self.assertEqual(await self.writer.add_redirect_target("news", CANDIDATE), 1)
        self.assertEqual(await self.rows("SELECT target, source_id FROM redirects"), [(CANDIDATE, "news")])
        await self.writer.disable_for_safety("news")
        source = await self.writer.get("news")
        self.assertEqual((source["state"], source["reason"]), (lifecycle.DISABLED, "safety: child_exploitation"))

    async def test_records_naming_a_host_outside_the_source_are_refused(self):
        with self.assertRaisesRegex(Exception, "outside the source's set"):
            await self.writer.store_records(TASK, CANDIDATE, [record()])
        self.assertEqual(await self.stores.records.counts(), {"records": 0, "snapshots": 0})

    async def test_a_run_starts_only_for_a_collecting_source(self):
        await self.stores.sources.change_state("news", lifecycle.DISABLED, "pulled")
        with self.assertRaisesRegex(Exception, "not collecting"):
            await self.writer.run_start("news")


class WriterSideChecksTest(WriterTestCase):
    """What the writer checks itself, whatever the crawler sent."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.stores.sources.approve(CANDIDATE, "docs", "journalism-publishing", "n", "t", frozenset())
        self.config = self.stores.configs_dir / "news.toml"
        self.config.parent.mkdir()
        self.config.write_text(NEWS_CONFIG)

    async def matching_seeds(self):
        for host in (NEWS, CANDIDATE):
            await self.stores.records.save_fingerprint(host, "/articles/", True, print_of(FRONT))

    async def test_a_fold_needs_a_match_and_may_add_only_the_folded_hosts(self):
        added = NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{CANDIDATE}"]')
        with self.assertRaisesRegex(RefusedChange, "does not match news"):
            await self.writer.fold("docs", "news", added)
        await self.matching_seeds()
        for text in (added.replace('cadence = "6h"', 'cadence = "1m"'),
                     NEWS_CONFIG.replace(f'["{NEWS}"]', f'["{NEWS}", "{OFF_SOURCE}"]'), "not = toml = at all"):
            with self.subTest(text=text[:20]), self.assertRaises(RefusedChange):
                await self.writer.fold("docs", "news", text)
        self.assertEqual(self.config.read_text(), NEWS_CONFIG)
        self.assertEqual(await self.writer.fold("docs", "news", added), [CANDIDATE])
        self.assertEqual(self.config.read_text(), added)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)

    async def test_baselines_and_live_only_for_an_approved_source(self):
        for send in (lambda: self.writer.went_live("news", [("/", "<p>x</p>")]),
                     lambda: self.writer.call("went_live", source_id="news", baselines=[])):
            with self.assertRaisesRegex(RefusedChange, "news is not approved"):
                await send()
        with self.assertRaisesRegex(WriteRefused, "a baseline names no staged snapshot"):
            await self.writer.call("went_live", source_id="docs", baselines=[["/", "0" * 64]])
        self.assertEqual((await self.writer.get("docs"))["state"], lifecycle.APPROVED)

    async def test_a_fingerprint_only_for_a_host_in_a_source(self):
        with self.assertRaisesRegex(RefusedChange, "a host in no source"):
            await self.writer.save_fingerprint(OFF_SOURCE, "/", True, print_of(FRONT))
        self.assertEqual(await self.stores.records.seed_fingerprints(), {})


class DetectorRefusalTest(WriterTestCase):
    """Section 17, test 4. A secret the redaction gate missed reaches the socket; the writer's own detector refuses
    it, writes nothing, and raises the top-priority item itself."""

    async def assert_refused_and_nothing_written(self):
        self.assertEqual(await self.stores.records.db.rows("SELECT * FROM records"), [])
        self.assertEqual(await self.stores.records.db.rows("SELECT * FROM records_fts"), [])
        self.assertEqual(await self.stores.records.db.rows("SELECT * FROM snapshots"), [])
        self.assertEqual(list(self.data.rglob("*.html")), [])
        for path in self.data.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SynthPassw0rd", path.read_bytes(), path.name)
        items = [(item["kind"], item["priority"], item["detail"]) for item in await self.stores.health.queue()]
        self.assertIn((health.REDACTION, health.REDACTION_PRIORITY, "write refused: a secret survived"), items)

    async def refused(self, send):
        with self.assertRaises(WriteRefused):
            await send()
        await self.assert_refused_and_nothing_written()

    async def test_a_secret_in_a_record_value(self):
        await self.refused(lambda: self.writer.store_records(TASK, NEWS, [record(), record(body=f"leaked {SECRET}")]))

    async def test_a_secret_in_a_field_name(self):
        await self.refused(lambda: self.writer.store_records(TASK, NEWS, [record(**{SECRET: "x"})]))

    async def test_a_secret_in_a_detail_page(self):
        detail = Task("news", "/articles/1", "detail", 0, self.run_id, 0)
        await self.refused(lambda: self.writer.store_records(detail, NEWS, [record(body=SECRET)]))

    async def test_a_secret_in_a_snapshot(self):
        await self.refused(lambda: self.writer.save_snapshot(TASK, f"<p>{SECRET}</p>"))

    async def test_every_kind_the_detector_knows(self):
        for text in ("card 4111 1111 1111 1111", "ssn 123-45-6789", "key AKIAabcdefGHIJ1234567890xyz",
                     "admin:Hunter2Synthetic", "contact bob@example.com"):
            with self.subTest(text=text):
                await self.refused(lambda: self.writer.store_records(TASK, NEWS, [record(body=text)]))

    async def test_hashes_must_be_keyed_digests(self):
        for hashes in (("plaintext",), ("A" * 64,), ("0" * 63,)):
            with self.subTest(hashes=hashes):
                await self.refused(lambda: self.writer.store_records(
                    TASK, NEWS, [record(Redacted("", {"email": 1}, hashes, 1))]))

    async def test_a_baseline_with_a_secret_is_refused_before_any_file(self):
        await self.stores.sources.approve(CANDIDATE, "docs", "directories", "n", "t", frozenset())
        with self.assertRaises(WriteRefused):
            await self.writer.went_live("docs", [("/", f"<p>{SECRET}</p>")])
        self.assertEqual(list(self.data.rglob("*.html")), [])
        self.assertEqual((await self.writer.get("docs"))["state"], lifecycle.APPROVED)


class PeerCheckTest(unittest.IsolatedAsyncioTestCase):
    def test_only_the_crawler_and_never_root(self):
        self.assertTrue(writer.admitted(1001, 1001))
        self.assertFalse(writer.admitted(1002, 1001))
        self.assertFalse(writer.admitted(0, 1001))
        self.assertFalse(writer.admitted(0, 0), "root is refused even when named as the crawler")

    def test_the_writer_refuses_to_run_as_root_or_as_the_crawler(self):
        self.assertIn("root", writer.refusal(0, "root"))
        self.assertIn("never as the crawler", writer.refusal(1001, "crawler"))
        self.assertIsNone(writer.refusal(1002, "analyst"))

    async def test_another_user_is_closed_before_a_byte_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = await start_writer(Path(tmp) / "data", Path(tmp) / "configs", crawler_uid=os.getuid() + 1)
            try:
                with mock.patch.object(writer, "parse", side_effect=AssertionError("read a request")), \
                        mock.patch.object(writer.WriterServer, "serve", side_effect=AssertionError("served")), \
                        self.assertLogs("onioncollect.writer", logging.WARNING) as logs:
                    reader, sender = await asyncio.open_unix_connection(harness.socket)
                    with contextlib.suppress(ConnectionError):
                        sender.write(wire.encode({"op": "ping"}))
                        await sender.drain()
                    try:
                        answered = await asyncio.wait_for(reader.read(), 5)
                    except ConnectionError:
                        answered = b""
                    self.assertEqual(answered, b"", "closed, unanswered")
                    sender.close()
                self.assertEqual(logs.output, [f"WARNING:onioncollect.writer:writer refused a connection from uid"
                                               f" {os.getuid()}"])
            finally:
                await harness.stop()


if __name__ == "__main__":
    unittest.main()
