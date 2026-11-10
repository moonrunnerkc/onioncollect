"""tools/settings_check.py, make deploy's preflight: each user's settings load as that user's commands load them, and
any refusal, an empty exclusion list or a stale patterns file above all, fails with a non-zero exit."""
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from onioncollect.config import Settings
from tests.test_onion import AHMIA

TOOL = Path(__file__).resolve().parent.parent / "tools" / "settings_check.py"
spec = importlib.util.spec_from_file_location("settings_check", TOOL)
settings_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings_check)

REAL_LOAD = Settings.load
PATTERN = "child_exploitation \\bforbiddenterm\\b\n"
RETIRED = "credential_dump (?<![\\w.-])[\\w.-]{3,64}+:[a-f0-9]{32,128}+\n"


class SettingsCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.files = {"control_password_file": "correct horse battery staple\n", "redaction_salt_file": "s" * 40,
                      "exclusions_file": f"# listed\n{AHMIA}\n", "safety_patterns_file": PATTERN}
        self.listening = True

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, *flags: str, **files: str) -> str:
        lines = []
        for key, text in (self.files | files).items():
            path = self.dir / key
            path.write_text(text)
            path.chmod(0o600)
            lines.append(f'{key} = "{path}"')
        settings = self.dir / "settings.toml"
        settings.write_text("\n".join(lines) + "\n")
        out = io.StringIO()
        with mock.patch.object(settings_check.Settings, "load", side_effect=lambda path, crawl: REAL_LOAD(
                path, crawl, port_check=lambda port: self.listening)), redirect_stdout(out):
            settings_check.main([str(settings), *flags])
        return out.getvalue()

    def refusal(self, *flags: str, **files: str) -> str:
        with self.assertRaises(SystemExit) as caught:
            self.run_check(*flags, **files)
        self.assertNotEqual(caught.exception.code, 0)
        return str(caught.exception.code)

    def test_the_crawlers_settings_load_and_only_counts_are_printed(self):
        out = self.run_check("--crawl")
        self.assertIn("1 excluded hosts, every one a v3 onion: True; 1 safety patterns; Tor ports answering", out)
        self.assertNotIn(AHMIA, out)
        self.assertNotIn("forbiddenterm", out)

    def test_the_analysts_settings_need_only_the_exclusions(self):
        self.listening = False
        out = self.run_check(control_password_file="", redaction_salt_file="", safety_patterns_file="")
        self.assertIn("1 excluded hosts, every one a v3 onion: True\n", out)

    def test_an_empty_exclusion_list_fails_for_both_users(self):
        for flags in (("--crawl",), ()):
            with self.subTest(flags=flags):
                self.assertIn("no entries", self.refusal(*flags, exclusions_file="# none yet\n"))

    def test_an_exclusion_that_is_not_a_v3_onion_fails(self):
        self.assertIn("line 1: not a v3 onion host", self.refusal("--crawl", exclusions_file="example.com\n"))

    def test_a_stale_patterns_file_fails(self):
        why = self.refusal("--crawl", safety_patterns_file=PATTERN + RETIRED)
        self.assertIn("line 2: credential_dump is handled by the redaction gate now", why)

    def test_a_dead_tor_port_fails_the_crawler(self):
        self.listening = False
        self.assertIn("Tor ports not listening", self.refusal("--crawl"))


if __name__ == "__main__":
    unittest.main()
