import json
import stat
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from onioncollect import redact
from onioncollect.db import stamp
from onioncollect.fingerprint import Fingerprint
from onioncollect.records import RecordStore, RefusedWrite
from onioncollect.redact import Redacted
from tests.fixtures import NEWS, NEWS_MIRROR, SALT
from tests.test_db import Clock

CLEAN = Redacted("", {}, (), 0)
SECRET = "bob.synthetic@example.com:SynthPassw0rd!"


def record(**fields) -> dict[str, str]:
    return {"title": "Tor Browser 15 released", "url": "http://x.onion/blog/15"} | fields


class RecordStoreTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name) / "data"
        self.clock = Clock()
        self.store = RecordStore(self.root, timedelta(days=180), timedelta(days=30), clock=self.clock)
        await self.store.open()

    async def asyncTearDown(self):
        await self.store.close()
        self.dir.cleanup()

    async def rows(self, sql: str, *params) -> list:
        return await self.store.db.rows(sql, params)

    async def add(self, content_hash="h1", follow_path="/blog/15", fields=None, summary=CLEAN,
                  source_id="news", category="journalism-publishing", host=NEWS, cluster=()) -> bool:
        return await self.store.add(source_id, category, content_hash, follow_path, fields or record(), summary,
                                    host=host, cluster=cluster)

    def files(self) -> list[Path]:
        return [path for path in self.root.rglob("*") if path.is_file()]


class AddTest(RecordStoreTestCase):
    async def test_new_record_then_the_same_hash_refreshes_it(self):
        self.assertTrue(await self.add())
        self.clock.advance(days=1)
        self.assertFalse(await self.add(fields=record(title="changed")))
        (row,) = await self.rows("SELECT fields, first_seen, last_seen, expires_at FROM records")
        later = self.clock.now
        self.assertEqual(json.loads(row["fields"])["title"], "Tor Browser 15 released")
        self.assertEqual((row["first_seen"], row["last_seen"], row["expires_at"]),
                         (stamp(later - timedelta(days=1)), stamp(later), stamp(later + timedelta(days=180))))

    async def test_the_same_hash_on_another_source_is_another_record(self):
        await self.add()
        self.assertTrue(await self.add(source_id="other"))

    async def test_redaction_summary_is_stored(self):
        fields, summary = redact.redact_fields({"body": "write to press@example.org"}, SALT)
        await self.add(fields=fields, summary=summary)
        (row,) = await self.rows("SELECT fields, redactions, hashes FROM records")
        self.assertEqual(json.loads(row["fields"]), {"body": "write to [email]"})
        self.assertEqual(json.loads(row["redactions"]), {"email": 1})
        self.assertEqual(json.loads(row["hashes"]), list(summary.hashes))


class StorageRefusalTest(RecordStoreTestCase):
    """Section 17's storage refusal test: the store's own detector refuses what the gate missed."""

    async def assert_nothing_written(self):
        self.assertEqual(await self.rows("SELECT * FROM records"), [])
        self.assertEqual(await self.rows("SELECT * FROM records_fts"), [])
        self.assertEqual(await self.rows("SELECT * FROM snapshots"), [])
        self.assertEqual(list(self.store.snapshot_dir.rglob("*.html")), [])
        for path in self.files():
            self.assertNotIn(b"SynthPassw0rd", path.read_bytes(), path.name)

    async def test_add_refuses_a_secret_in_a_value(self):
        with self.assertRaises(RefusedWrite):
            await self.add(fields=record(body=f"leaked {SECRET}"))
        await self.assert_nothing_written()

    async def test_add_refuses_a_secret_in_a_field_name(self):
        with self.assertRaises(RefusedWrite):
            await self.add(fields={SECRET: "x"})
        await self.assert_nothing_written()

    async def test_add_detail_refuses_and_leaves_the_record_untouched(self):
        await self.add()
        with self.assertRaises(RefusedWrite):
            await self.store.add_detail("news", "/blog/15", {"body": SECRET}, CLEAN)
        (row,) = await self.rows("SELECT fields FROM records")
        self.assertNotIn("body", json.loads(row["fields"]))

    async def test_snapshot_refused_before_any_file_exists(self):
        with self.assertRaises(RefusedWrite):
            await self.store.save_snapshot("news", "/", "listing", f"<p>{SECRET}</p>")
        await self.assert_nothing_written()

    async def test_every_kind_the_detector_knows_is_refused(self):
        for text in ("card 4111 1111 1111 1111", "ssn 123-45-6789", "key AKIAabcdefGHIJ1234567890xyz",
                     "admin:Hunter2Synthetic", "contact bob@example.com"):
            with self.subTest(text=text), self.assertRaises(RefusedWrite):
                await self.add(fields=record(body=text))
        await self.assert_nothing_written()

    async def test_hashes_must_be_keyed_digests(self):
        for hashes in (("plaintext",), ("A" * 64,), ("0" * 63,)):
            with self.subTest(hashes=hashes), self.assertRaisesRegex(RefusedWrite, "keyed"):
                await self.add(summary=Redacted("", {"email": 1}, hashes, 1))
        await self.assert_nothing_written()


class DetailAndSearchTest(RecordStoreTestCase):
    async def test_detail_merges_by_follow_path_and_reaches_the_index(self):
        await self.add()
        fields, summary = redact.redact_fields({"body": "onion services and circuits, mail press@example.org"}, SALT)
        self.assertEqual(await self.store.add_detail("news", "/blog/15", fields, summary), 1)
        self.assertEqual(await self.store.add_detail("news", "/blog/unknown", fields, summary), 0)
        (row,) = await self.rows("SELECT fields, redactions, hashes FROM records")
        self.assertEqual(set(json.loads(row["fields"])), {"title", "url", "body"})
        self.assertEqual(json.loads(row["redactions"]), {"email": 1})
        self.assertEqual(len(json.loads(row["hashes"])), 1)
        (found,) = await self.store.search("circuits")
        self.assertEqual(found["fields"]["body"], "onion services and circuits, mail [email]")
        self.assertEqual(len(await self.rows("SELECT * FROM records_fts")), 1)

    async def test_filters(self):
        await self.add("h1", fields=record(title="bridges explained"))
        await self.add("h2", fields=record(title="bridges in debian"), source_id="debian",
                       category="software-infrastructure")
        self.clock.advance(days=3)
        await self.add("h3", fields=record(title="bridges again"))
        self.assertEqual(len(await self.store.search("bridges")), 3)
        self.assertEqual({row["source_id"] for row in await self.store.search("bridges", source="debian")}, {"debian"})
        self.assertEqual(len(await self.store.search("bridges", category="journalism-publishing")), 2)
        since = await self.store.search("bridges", since=self.clock.now - timedelta(days=1))
        self.assertEqual([row["fields"]["title"] for row in since], ["bridges again"])
        self.assertEqual(await self.store.search("nothingmatches"), [])

    async def test_operator_syntax_is_matched_as_literal_terms(self):
        await self.add("h1", fields=record(title="circuits and relays"))
        # Each of these would match as FTS5 syntax (or fail to parse); as literal terms none is in the record.
        for query in ("circuits OR nothing", "circ*", "NEAR(circuits relays)", "text:relays", '"unbalanced', "(("):
            with self.subTest(query=query):
                self.assertEqual(await self.store.search(query), [])
        # And these are words of the record, matched as words: AND is "and", a stray quote is dropped.
        for query in ("AND", "circuits AND relays", 'circuits"', "CIRCUITS"):
            with self.subTest(query=query):
                self.assertEqual(len(await self.store.search(query)), 1)
        for query in ("", "   ", "a\x00b"):
            with self.subTest(query=query), self.assertRaises(ValueError):
                await self.store.search(query)


class SnapshotAndSweepTest(RecordStoreTestCase):
    async def test_snapshot_is_content_addressed_and_closed_to_others(self):
        digest = await self.store.save_snapshot("news", "/", "listing", "<p>hello</p>")
        again = await self.store.save_snapshot("news", "/", "listing", "<p>hello</p>")
        self.assertEqual(digest, again)
        path = self.store.snapshot_path(digest)
        self.assertEqual(path.read_text(), "<p>hello</p>")
        # The group may read (the analyst's, in the guest); nobody else may, and only the crawler writes.
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        for directory in (self.root, self.store.snapshot_dir, path.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o750, directory)
        self.assertEqual(len(await self.rows("SELECT * FROM snapshots")), 2)

    async def test_latest_snapshot_by_kind(self):
        self.assertIsNone(await self.store.latest_snapshot("news", "listing"))
        await self.store.save_snapshot("news", "/", "listing", "<p>one</p>")
        self.clock.advance(minutes=1)
        await self.store.save_snapshot("news", "/?p=2", "listing", "<p>two</p>")
        await self.store.save_snapshot("news", "/story", "detail", "<p>story</p>")
        path, taken, html = await self.store.latest_snapshot("news", "listing")
        self.assertEqual((path, html), ("/?p=2", "<p>two</p>"))
        self.assertGreater(taken, "2026")
        self.assertEqual((await self.store.latest_snapshot("news", "detail"))[::2], ("/story", "<p>story</p>"))

    async def test_sweep_applies_both_clocks_and_keeps_the_baseline(self):
        await self.add("old", fields=record(title="old story"))
        await self.store.save_baselines("news", [("/", "<p>baseline</p>")])
        (baseline,), = await self.rows("SELECT digest FROM snapshots WHERE baseline = 1")
        shared = await self.store.save_snapshot("news", "/", "listing", "<p>shared</p>")
        expired = await self.store.save_snapshot("news", "/?p=2", "listing", "<p>expiring</p>")
        self.clock.advance(days=29)
        await self.store.save_snapshot("other", "/", "listing", "<p>shared</p>")
        await self.add("fresh", fields=record(title="fresh story"))
        self.clock.advance(days=2)
        self.assertEqual(await self.store.sweep(), (0, 2))
        self.assertTrue(self.store.snapshot_path(baseline).exists())
        self.assertTrue(self.store.snapshot_path(shared).exists())
        self.assertFalse(self.store.snapshot_path(expired).exists())
        self.clock.advance(days=150)
        self.assertEqual(await self.store.sweep(), (1, 1))
        self.assertFalse(self.store.snapshot_path(shared).exists())
        self.assertTrue(self.store.snapshot_path(baseline).exists())
        self.assertEqual([row["fields"]["title"] for row in await self.store.search("story")], ["fresh story"])
        self.assertEqual(len(await self.rows("SELECT * FROM records_fts")), 1)

    async def test_a_newer_baseline_set_replaces_the_old_one(self):
        await self.store.save_baselines("news", [("/", "<p>v1</p>"), ("/b", "<p>b1</p>")])
        first = {row["path"]: row["digest"] for row in await self.rows("SELECT path, digest FROM snapshots")}
        self.clock.advance(days=40)
        await self.store.save_baselines("news", [("/", "<p>v2</p>")])
        self.assertEqual(await self.store.sweep(), (0, 2))
        self.assertFalse(self.store.snapshot_path(first["/"]).exists())
        self.assertEqual((await self.store.baseline_for("news", "/"))[1], "<p>v2</p>")
        self.assertIsNone(await self.store.baseline_for("news", "/b"))

    async def test_every_seed_of_one_golive_stays_a_baseline(self):
        await self.store.save_baselines("news", [("/", "<p>front</p>"), ("/archive", "<p>archive</p>")])
        rows = await self.rows("SELECT path, baseline FROM snapshots ORDER BY path")
        self.assertEqual([tuple(row) for row in rows], [("/", 1), ("/archive", 1)])
        self.assertEqual((await self.store.baseline_for("news", "/archive"))[1], "<p>archive</p>")

    async def test_baselines_are_refused_whole(self):
        with self.assertRaises(RefusedWrite):
            await self.store.save_baselines("news", [("/", "<p>fine</p>"), ("/b", f"<p>{SECRET}</p>")])
        self.assertEqual(list(self.store.snapshot_dir.rglob("*.html")), [])
        self.assertEqual(await self.rows("SELECT * FROM snapshots"), [])

    async def test_counts(self):
        await self.add()
        await self.store.save_snapshot("news", "/", "listing", "<p>x</p>")
        self.assertEqual(await self.store.counts(), {"records": 1, "snapshots": 1})


class ClusterDedupTest(RecordStoreTestCase):
    """One article read from two addresses is one row, sighted under both."""

    async def test_same_hash_across_a_cluster_is_one_row_sighted_under_each_host(self):
        self.assertTrue(await self.add(source_id="news", host=NEWS, cluster=("mirror", "news")))
        self.clock.advance(hours=6)
        self.assertFalse(await self.add(source_id="mirror", host=NEWS_MIRROR, cluster=("mirror", "news"),
                                        fields=record(url=f"http://{NEWS_MIRROR}/blog/15")))
        (row,) = await self.rows("SELECT id, source_id, fields, first_seen, last_seen FROM records")
        self.assertEqual((row["source_id"], json.loads(row["fields"])["url"]), ("news", "http://x.onion/blog/15"))
        self.assertEqual(row["last_seen"], stamp(self.clock.now))
        sightings = await self.rows("SELECT host, source_id FROM record_hosts ORDER BY source_id")
        self.assertEqual([tuple(sighting) for sighting in sightings], [(NEWS_MIRROR, "mirror"), (NEWS, "news")])
        self.assertEqual(len(await self.rows("SELECT * FROM records_fts")), 1)

    async def test_outside_the_cluster_the_same_hash_is_another_row(self):
        await self.add(source_id="news", cluster=("news",))
        self.assertTrue(await self.add(source_id="other", host=NEWS_MIRROR, cluster=("other",)))
        self.assertEqual(len(await self.rows("SELECT * FROM records")), 2)

    async def test_one_source_read_from_two_of_its_hosts(self):
        await self.add(host=NEWS)
        self.assertFalse(await self.add(host=NEWS_MIRROR))
        self.assertFalse(await self.add(host=NEWS_MIRROR))
        self.assertEqual(len(await self.rows("SELECT * FROM records")), 1)
        self.assertEqual({row["host"] for row in await self.rows("SELECT host FROM record_hosts")}, {NEWS, NEWS_MIRROR})

    async def test_search_finds_the_row_under_either_source(self):
        cluster = ("mirror", "news")
        await self.add(fields=record(title="bridges explained"), source_id="news", host=NEWS, cluster=cluster)
        await self.add(fields=record(title="bridges explained"), source_id="mirror", host=NEWS_MIRROR, cluster=cluster)
        for source in (None, "news", "mirror"):
            (found,) = await self.store.search("bridges", source=source)
            self.assertEqual((found["source_id"], found["sources"], found["hosts"]), ("news", ["mirror", "news"], 2))
        self.assertEqual(await self.store.search("bridges", source="elsewhere"), [])

    async def test_a_sibling_detail_page_reaches_the_shared_row(self):
        cluster = ("mirror", "news")
        await self.add(source_id="news", host=NEWS, cluster=cluster)
        await self.add(source_id="mirror", host=NEWS_MIRROR, cluster=cluster)
        self.assertEqual(await self.store.add_detail("mirror", "/blog/15", {"body": "read on the mirror"}, CLEAN), 1)
        self.assertEqual(await self.store.add_detail("elsewhere", "/blog/15", {"body": "x"}, CLEAN), 0)
        (found,) = await self.store.search("mirror", source="news")
        self.assertEqual(found["fields"]["body"], "read on the mirror")

    async def test_sweep_removes_sightings_with_their_record(self):
        await self.add(host=NEWS)
        await self.add(host=NEWS_MIRROR)
        self.clock.advance(days=181)
        self.assertEqual(await self.store.sweep(), (1, 0))
        self.assertEqual(await self.rows("SELECT * FROM record_hosts"), [])


class MergeTest(RecordStoreTestCase):
    """Open item 4: dedup backfill for rows stored before their sources shared a cluster."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.add("h1", fields=record(title="shared story"))
        await self.add("h2", "/blog/16", fields=record(title="paper only"), source_id="paper", host=NEWS_MIRROR)
        self.clock.advance(days=1)
        await self.add("h1", fields=record(title="shared story"), source_id="paper", host=NEWS_MIRROR,
                       category="software-infrastructure")
        await self.store.add_detail("paper", "/blog/15", {"body": "full text"}, Redacted("", {"email": 1}, ("a" * 64,), 0))

    async def test_rows_sharing_a_hash_become_the_oldest_with_every_sighting(self):
        self.assertEqual(await self.store.merge(("news", "paper")), (1, 1))
        rows = await self.rows("SELECT * FROM records ORDER BY id")
        self.assertEqual([row["content_hash"] for row in rows], ["h1", "h2"])
        kept = rows[0]
        self.assertEqual(kept["source_id"], "news")
        self.assertLess(kept["first_seen"], kept["last_seen"])
        self.assertEqual(json.loads(kept["fields"])["body"], "full text", "the detail page a copy carried survives")
        self.assertEqual(json.loads(kept["redactions"]), {"email": 1})
        sightings = await self.rows("SELECT host, source_id FROM record_hosts WHERE record_id = ? ORDER BY host", kept["id"])
        self.assertEqual({tuple(row) for row in sightings}, {(NEWS, "news"), (NEWS_MIRROR, "paper")})
        self.assertEqual(len(await self.rows("SELECT * FROM records_fts")), 2)
        (found,) = await self.store.search('"full text"', source="paper")
        self.assertEqual(found["sources"], ["news", "paper"])

    async def test_category_filters_on_the_surviving_row(self):
        await self.store.merge(("news", "paper"))
        self.assertEqual([row["fields"]["title"] for row in await self.store.search("story", category="journalism-publishing")],
                         ["shared story"])
        self.assertEqual(await self.store.search("shared", category="software-infrastructure"), [])

    async def test_merge_twice_is_a_no_op_and_outside_the_named_sources_nothing_moves(self):
        await self.add("h1", fields=record(title="shared story"), source_id="other")
        await self.store.merge(("news", "paper"))
        self.assertEqual(await self.store.merge(("news", "paper")), (0, 0))
        (count,), = await self.rows("SELECT COUNT(*) FROM records WHERE content_hash = 'h1'")
        self.assertEqual(count, 2, "the row of a source outside the cluster stays its own")

    async def test_relabel_after_merge_moves_rows_and_sightings(self):
        await self.store.merge(("news", "paper"))
        self.assertEqual(await self.store.relabel("paper", "news", "journalism-publishing"), 1)
        rows = await self.rows("SELECT source_id, category FROM records")
        self.assertEqual({tuple(row) for row in rows}, {("news", "journalism-publishing")})
        self.assertEqual({row["source_id"] for row in await self.rows("SELECT source_id FROM record_hosts")}, {"news"})

    async def test_a_merge_that_would_store_a_secret_is_refused(self):
        await self.store.db.conn.execute("UPDATE records SET fields = ? WHERE source_id = 'paper' AND content_hash = 'h1'",
                                         (json.dumps(record(body=SECRET)),))
        await self.store.db.conn.commit()
        with self.assertRaises(RefusedWrite):
            await self.store.merge(("news", "paper"))
        (count,), = await self.rows("SELECT COUNT(*) FROM records")
        self.assertEqual(count, 3)


class FingerprintStoreTest(RecordStoreTestCase):
    async def test_latest_print_per_host_and_path_and_seed_pages_only(self):
        await self.store.save_fingerprint(NEWS, "/", True, Fingerprint(1, 2, 60))
        await self.store.save_fingerprint(NEWS, "/", True, Fingerprint(0xFFFF_FFFF_FFFF_FFFF, 3, 70))
        await self.store.save_fingerprint(NEWS, "/story", False, Fingerprint(5, 6, 80))
        await self.store.save_fingerprint(NEWS_MIRROR, "/", True, Fingerprint(1, 2, 60))
        self.assertEqual(await self.store.seed_fingerprints(), {
            NEWS: [Fingerprint(0xFFFF_FFFF_FFFF_FFFF, 3, 70)], NEWS_MIRROR: [Fingerprint(1, 2, 60)]})
        (row,) = await self.rows("SELECT content, structure FROM fingerprints WHERE host = ? AND path = '/'", NEWS)
        self.assertEqual(tuple(row), ("ffffffffffffffff", "0000000000000003"))

    async def test_sweep_ages_out_detail_prints_and_keeps_seed_prints(self):
        await self.store.save_fingerprint(NEWS, "/", True, Fingerprint(1, 2, 60))
        await self.store.save_fingerprint(NEWS, "/story", False, Fingerprint(5, 6, 80))
        self.clock.advance(days=31)
        await self.store.sweep()
        self.assertEqual([row["path"] for row in await self.rows("SELECT path FROM fingerprints")], ["/"])


if __name__ == "__main__":
    unittest.main()
