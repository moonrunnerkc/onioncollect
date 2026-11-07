import gzip
import hashlib
import tempfile
import unittest
from pathlib import Path

from onioncrawl.storage import PageStore

BODY = b"<html><title>x</title><body>hello</body></html>"
SHA = hashlib.sha256(BODY).hexdigest()


class PageStoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = PageStore(Path(self.dir.name))

    def tearDown(self):
        self.dir.cleanup()

    def test_layout(self):
        path = self.store.path_for(SHA)
        self.assertEqual(path.relative_to(self.store.root).parts, ("pages", SHA[:2], SHA[2:4], f"{SHA}.gz"))

    def test_save_load_round_trip(self):
        self.assertTrue(self.store.save(SHA, BODY))
        self.assertEqual(self.store.load(SHA), BODY)
        self.assertEqual(gzip.decompress(self.store.path_for(SHA).read_bytes()), BODY)

    def test_second_save_is_a_no_op(self):
        self.store.save(SHA, BODY)
        self.assertFalse(self.store.save(SHA, b"different"))
        self.assertEqual(self.store.load(SHA), BODY)

    def test_modes(self):
        self.store.save(SHA, BODY)
        path = self.store.path_for(SHA)
        self.assertEqual(self.store.pages.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_no_temp_file_left(self):
        self.store.save(SHA, BODY)
        self.assertEqual([p.name for p in self.store.path_for(SHA).parent.iterdir()], [f"{SHA}.gz"])

    def test_identical_output_for_identical_input(self):
        self.store.save(SHA, BODY)
        first = self.store.path_for(SHA).read_bytes()
        self.assertEqual(first, gzip.compress(BODY, compresslevel=6, mtime=0))

    def test_size_on_disk(self):
        self.assertEqual(self.store.size_on_disk(), 0)
        self.store.save(SHA, BODY)
        self.assertEqual(self.store.size_on_disk(), self.store.path_for(SHA).stat().st_size)


if __name__ == "__main__":
    unittest.main()
