"""The write-up tooling: writeup-check fails while a [PASTE: ...] marker is left, and writeup-capture writes a
bundle with no testonion address, no credential value and no host IP, or writes nothing at all."""
import asyncio
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path
from unittest import mock

from onioncollect.db import open_collect
from onioncollect.records import RecordStore
from onioncollect.sources import SourceTable
from tests.fixtures import (CANDIDATE, DECLINED, TESTONION, TESTONION_PASSWORD, TESTONION_USER, make_live,
                            write_leak_result)

TOOLS = Path(__file__).resolve().parent.parent / "tools"
PLANTED_IPS = ("192.168.5.15", "10.0.2.2", "fe80::5055:55ff:fe12:3456", "2001:db8::42")


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load("writeup_check")
capture = load("writeup_capture")


class WriteupCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, *texts: str) -> tuple[int, str]:
        paths = []
        for n, text in enumerate(texts):
            paths.append(self.root / f"doc{n}.md")
            paths[-1].write_text(text)
        out = io.StringIO()
        with redirect_stdout(out):
            code = check.main(paths)
        return code, out.getvalue()

    def test_fails_and_lists_every_marker_while_any_is_left(self):
        code, out = self.run_check("# Mirrors\n[PASTE: mirrors output for news]\n",
                                   "intro\n\n| a | b |\n[PASTE: health runs table] and [PASTE: churn count]\n"
                                   "[PASTE: a marker that\nwraps]\n")
        self.assertEqual(code, 1)
        self.assertIn("doc1.md:5: [PASTE: a marker that wraps]", out)
        self.assertIn("doc0.md:2: [PASTE: mirrors output for news]", out)
        self.assertIn("doc1.md:4: [PASTE: churn count]", out)
        self.assertIn("4 markers left in 2 files", out)

    def test_passes_once_none_is_left(self):
        self.assertEqual(self.run_check("All numbers pasted.\nPASTE markers are described, not left.\n")[0], 0)


class StripTest(unittest.TestCase):
    TIME_AND_VERSION = "2026-11-08 12:30:45.123 python 3.13.1 hit 0.95"

    def planted(self) -> dict[str, str]:
        return {"sources-export.jsonl": json.dumps({"host": TESTONION, "note": f"login {TESTONION_USER}"}) + "\n",
                "leak-test.json": json.dumps({"guest": PLANTED_IPS[0], "gateway": PLANTED_IPS[1],
                                              "v6": [PLANTED_IPS[2], PLANTED_IPS[3]]}),
                "tor-lines.txt": f"{self.TIME_AND_VERSION} {TESTONION.removesuffix('.onion')} {TESTONION_PASSWORD}\n"}

    def test_nothing_planted_survives_and_nothing_else_is_touched(self):
        with tempfile.TemporaryDirectory() as out:
            target = capture.write_bundle(Path(out), self.planted(), {TESTONION}, {TESTONION_USER, TESTONION_PASSWORD})
            written = "".join(path.read_text() for path in target.iterdir())
        for planted in (TESTONION, TESTONION.removesuffix(".onion"), TESTONION_USER, TESTONION_PASSWORD, *PLANTED_IPS):
            self.assertNotIn(planted, written)
        self.assertIn(self.TIME_AND_VERSION, written)
        self.assertIn("replaced: [testonion address] x2, [credential] x2, [ip] x4", written)

    def test_if_anything_survives_nothing_is_written(self):
        with tempfile.TemporaryDirectory() as out, \
                mock.patch.object(capture, "strip", lambda texts, hosts, secrets: (texts, {})):
            with self.assertRaisesRegex(SystemExit, "nothing written, still present after stripping"):
                capture.write_bundle(Path(out), self.planted(), {TESTONION}, {TESTONION_PASSWORD})
            self.assertEqual(list(Path(out).iterdir()), [])


class CaptureTest(unittest.TestCase):
    """The whole capture, as the analyst would run it, over stores with all three planted."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.data, self.creds, self.out = root / "data", root / "creds", root / "out"
        for directory in (self.data, self.creds):
            directory.mkdir()
        (self.creds / "testonion.env").write_text(f"username={TESTONION_USER}\npassword={TESTONION_PASSWORD}\n")
        leak = write_leak_result(root / "leak-test.json")
        result = json.loads(leak.read_text()) | {"guest_address": PLANTED_IPS[0], "route": PLANTED_IPS[3]}
        leak.write_text(json.dumps(result))
        self.settings = root / "settings.toml"
        self.settings.write_text(f'data_dir = "{self.data}"\nconfigs_dir = "{root / "configs"}"\n'
                                 f'log_dir = "{root / "log"}"\nleak_test_result = "{leak}"\n')
        asyncio.run(self.stores())
        (root / "log").mkdir()
        (root / "log" / "crawl.log").write_text(
            "2026-11-08 09:00:00,000 INFO onioncollect.tor_pool: tor 10051: success 0.97 over 120 fetches,"
            " last rotation never\n"
            f"2026-11-08 09:01:00,000 INFO onioncollect.crawler: news run 3 started {TESTONION}\n"
            "2026-11-08 09:02:00,000 INFO onioncollect.tor_pool: tor 10052: rotated circuits\n")

    async def stores(self):
        collect = await open_collect(self.data / "collect.db")
        store = RecordStore(self.data, timedelta(days=180), timedelta(days=30))
        await store.open()
        table = SourceTable(collect)
        await make_live(table)
        await make_live(table, "testonion", TESTONION, "self-hosted")
        await table.add_candidates({CANDIDATE, DECLINED}, "news")
        await table.decline(DECLINED, f"sells logins like {TESTONION_USER}:{TESTONION_PASSWORD} from {PLANTED_IPS[1]}",
                            "tester")
        for passed in (False, True):
            await table.add_golive_report("testonion", passed, [(passed, f"reachability: {TESTONION} answered")])
        await store.close()
        await collect.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_bundle_has_the_evidence_and_none_of_the_three(self):
        with redirect_stdout(io.StringIO()), mock.patch.object(capture.Path, "home", return_value=self.data):
            self.assertEqual(capture.main(["--settings", str(self.settings), "--credentials", str(self.creds),
                                           "--out", str(self.out)]), 0)
        (bundle,) = self.out.iterdir()
        files = {path.name: path.read_text() for path in bundle.iterdir()}
        self.assertLessEqual({"sources-export.jsonl", "triage-list.txt", "health-queue.txt", "health-log.txt",
                              "health-runs-news.txt", "health-runs-testonion.txt", "golive-testonion.txt",
                              "leak-test.json", "tor-lines.txt", "log-audit.txt", "MANIFEST.txt"}, set(files))
        everything = "".join(files.values())
        for planted in (TESTONION, TESTONION.removesuffix(".onion"), TESTONION_USER, TESTONION_PASSWORD,
                        PLANTED_IPS[0], PLANTED_IPS[1], PLANTED_IPS[3]):
            self.assertNotIn(planted, everything)
        self.assertIn("[testonion address]", files["sources-export.jsonl"])
        self.assertIn("[credential]", files["sources-export.jsonl"])
        self.assertIn('"guest_address": "[ip]"', files["leak-test.json"])
        self.assertEqual(files["golive-testonion.txt"].count("FAIL  reachability: [testonion address] answered"), 1)
        self.assertIn("passed\nPASS  reachability", files["golive-testonion.txt"])
        self.assertEqual(files["tor-lines.txt"].count("onioncollect.tor_pool"), 2)
        self.assertNotIn("news run 3", files["tor-lines.txt"], "only the Tor lines of the crawl log")
        self.assertIn("credential values checked against the logs and every file under the data dir: 2",
                      files["log-audit.txt"])
        self.assertIn(DECLINED, files["sources-export.jsonl"], "declines and their reasons are kept")


if __name__ == "__main__":
    unittest.main()
