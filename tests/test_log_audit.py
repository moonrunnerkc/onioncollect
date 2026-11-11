"""The log audit's leak check: a stored value in a log line fails it, a line's own timestamp does not count."""
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tests.live import log_audit

MODIFIED = "2026-11-10 22:15"
STARTED = f"{MODIFIED}:49,277 INFO onioncollect.crawler: crawler: form-session sources: none"


class LeakCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        collect = sqlite3.connect(self.root / "collect.db")
        collect.execute("CREATE TABLE visited_paths (path TEXT)")
        collect.execute("INSERT INTO visited_paths VALUES ('/debian/dists?sort=newest')")
        collect.commit()
        collect.close()
        records = sqlite3.connect(self.root / "records.db")
        records.execute("CREATE TABLE records (fields TEXT)")
        records.execute("INSERT INTO records VALUES (?)", (json.dumps({"name": "dists/", "last_modified": MODIFIED}),))
        records.commit()
        records.close()

    def tearDown(self):
        self.tmp.cleanup()

    def audit(self, *lines: str) -> tuple[int, str]:
        log = self.root / "crawl.log"
        log.write_text("".join(f"{line}\n" for line in lines))
        out = io.StringIO()
        with redirect_stdout(out):
            code = log_audit.main([log], self.root, self.root / "no-credentials")
        return code, out.getvalue()

    def test_a_field_equal_to_a_lines_own_timestamp_is_not_a_leak(self):
        code, out = self.audit(STARTED)
        self.assertIn("checked against the logs: 3, found: 0", out)
        self.assertEqual(code, 0)

    def test_the_same_value_anywhere_else_in_a_line_is_one(self):
        for line in (f"{STARTED} {MODIFIED}", f"2026-11-11 09:00:00,000 INFO onioncollect.crawler: {MODIFIED}:49,277 x",
                     f" {STARTED}", f"x{MODIFIED}:49,277 INFO onioncollect.crawler: crawler: stopped"):
            code, out = self.audit(line)
            self.assertIn("found: 1", out, line)
            self.assertEqual(code, 1, line)

    def test_a_visited_path_or_query_in_a_message_still_fails(self):
        for leak in ("/debian/dists", "sort=newest"):
            code, out = self.audit(f"2026-11-11 09:00:00,000 INFO onioncollect.crawler: crawler: stopped {leak}")
            self.assertIn("found: 1", out, leak)
            self.assertEqual(code, 1, leak)


if __name__ == "__main__":
    unittest.main()
