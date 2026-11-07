import io
import logging
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onioncrawl import cli
from onioncrawl.config import Settings
from tests.test_onion import AHMIA, DUCKDUCKGO, TORPROJECT


class LoggingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = logging.getLogger().handlers[:]

    def tearDown(self):
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if handler not in self.saved:
                root.removeHandler(handler)
                handler.close()
        self.tmp.cleanup()

    def test_library_info_never_reaches_the_log(self):
        path = Path(self.tmp.name) / "crawl.log"
        with mock.patch("sys.stderr", io.StringIO()):
            cli.configure_logging(path)
            logging.getLogger("stem").setLevel(5)
            logging.getLogger("httpx").setLevel(logging.INFO)
            logging.getLogger("httpx").info(f'HTTP Request: GET http://{AHMIA}/secret/path "HTTP/1.1 200 OK"')
            logging.getLogger("stem").info("control message")
            logging.getLogger("stem").warning("stem warning")
            logging.getLogger("onioncrawl.crawler").info(f"{AHMIA} status=200")
        text = path.read_text()
        self.assertNotIn("secret", text)
        self.assertNotIn("control message", text)
        self.assertIn("stem warning", text)
        self.assertIn(f"{AHMIA} status=200", text)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "data").mkdir()
        (self.root / "pw").write_text("pw")
        (self.root / "pw").chmod(0o600)
        self.settings_path = self.root / "settings.toml"
        (self.root / "exclusions.txt").write_text(f"{TORPROJECT}\n")
        (self.root / "patterns.txt").write_text("child_exploitation x\ncredential_dump y\ncard_number z\n")
        self.settings_path.write_text(
            f'control_password_file = "{self.root / "pw"}"\ndata_dir = "{self.root / "data"}"\n'
            f'exclusions_file = "{self.root / "exclusions.txt"}"\nsafety_patterns_file = "{self.root / "patterns.txt"}"\n'
        )
        umask = os.umask(0o022)
        self.addCleanup(os.umask, umask)
        real_load = Settings.load
        patcher = mock.patch.object(Settings, "load", side_effect=lambda path: real_load(path, port_check=lambda port: True))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_root(self):
        with mock.patch("os.geteuid", return_value=0), self.assertRaisesRegex(SystemExit, "root"):
            cli.main(["--settings", str(self.settings_path), "seed", "x"])

    def test_refuses_data_dir_owned_by_someone_else(self):
        with mock.patch("os.geteuid", return_value=4242), self.assertRaisesRegex(SystemExit, "not owned"):
            cli.main(["--settings", str(self.settings_path), "seed", "x"])

    def test_seed_accepts_urls_and_bare_hosts(self):
        seeds = self.root / "seeds.txt"
        seeds.write_text(f"# comment\n\n{AHMIA}\nhttp://{DUCKDUCKGO}/x\nexample.com\n")
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(["--settings", str(self.settings_path), "seed", str(seeds)])
        self.assertEqual(out.getvalue().strip(), "seeded 2, rejected 1")


if __name__ == "__main__":
    unittest.main()
