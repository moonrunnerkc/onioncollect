import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from onioncollect import mirrors
from onioncollect.db import open_collect
from onioncollect.records import RecordStore
from onioncollect.redact import Redacted
from onioncollect.sources import SourceTable
from tests.fixtures import NEWS, NEWS_MIRROR, headlines, listing_page, make_live
from tests.test_fingerprint import print_of


class RefreshTest(unittest.IsolatedAsyncioTestCase):
    """Open item 4: a cluster that gains a source has its earlier duplicate rows merged."""

    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.collect = await open_collect(root / "collect.db")
        self.sources = SourceTable(self.collect)
        self.records = RecordStore(root, timedelta(days=180), timedelta(days=30))
        await self.records.open()
        fields = {"title": "relay operators meetup", "url": f"http://{NEWS}/a"}
        for source_id, host in (("news", NEWS), ("paper", NEWS_MIRROR)):
            await make_live(self.sources, source_id, host)
            await self.records.add(source_id, "journalism-publishing", "same", None, fields, Redacted("", {}, (), 0),
                                   host=host, cluster=())

    async def asyncTearDown(self):
        await self.records.close()
        await self.collect.close()
        self.dir.cleanup()

    async def test_the_cluster_forming_merges_once(self):
        front = print_of(listing_page(*headlines("monday")))
        await self.records.save_fingerprint(NEWS, "/articles/", True, front)
        self.assertEqual(await mirrors.refresh(self.sources, self.records), {})
        self.assertEqual(len(await self.records.db.rows("SELECT * FROM records")), 2)
        await self.records.save_fingerprint(NEWS_MIRROR, "/articles/", True, front)
        self.assertEqual(await mirrors.refresh(self.sources, self.records), {"news": "news", "paper": "news"})
        (row,) = await self.records.db.rows("SELECT * FROM records")
        self.assertEqual(row["source_id"], "news")
        with mock.patch.object(self.records, "merge", side_effect=AssertionError("merged again")):
            await mirrors.refresh(self.sources, self.records)


if __name__ == "__main__":
    unittest.main()
