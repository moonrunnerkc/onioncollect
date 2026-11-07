import tempfile
import unittest
from pathlib import Path

from onioncrawl.safety import body_triggers_exclusion, is_excluded, load_exclusions, load_patterns, luhn_valid
from tests.test_onion import AHMIA, DUCKDUCKGO

# Throwaway patterns. The operator's list is never committed or copied into a fixture.
PATTERNS = r"""
# comment
child_exploitation \bforbiddenterm\b
credential_dump (?:zz\w{1,8}:\w{1,8}\n){3}
card_number \b\d{4}(?:-\d{4}){3}\b
"""
COMBO = "zza:pw1\nzzb:pw2\nzzc:pw3\n"


class TempFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, text: str) -> Path:
        path = Path(self.tmp.name) / "file.txt"
        path.write_text(text)
        return path


class ExclusionsTest(TempFiles):
    def test_load_skips_comments_and_lowercases(self):
        hosts = load_exclusions(self.write(f"# header\n\n{AHMIA.upper()}  # trailing\n  {DUCKDUCKGO}\n"))
        self.assertEqual(hosts, {AHMIA, DUCKDUCKGO})

    def test_invalid_entry_is_an_error_not_a_silent_miss(self):
        with self.assertRaisesRegex(ValueError, ":2:"):
            load_exclusions(self.write(f"{AHMIA}\nexample.com\n"))

    def test_is_excluded(self):
        self.assertTrue(is_excluded(AHMIA.upper(), {AHMIA}))
        self.assertFalse(is_excluded(DUCKDUCKGO, {AHMIA}))


class PatternFileTest(TempFiles):
    def test_categories_sorted_into_check_order(self):
        reordered = "card_number \\d{16}\ncredential_dump x\nchild_exploitation y\n"
        self.assertEqual([c for c, _ in load_patterns(self.write(reordered))],
                         ["child_exploitation", "credential_dump", "card_number"])

    def test_unknown_category(self):
        with self.assertRaisesRegex(ValueError, ":1:"):
            load_patterns(self.write("weapons \\bx\\b\n"))

    def test_every_category_required(self):
        with self.assertRaisesRegex(ValueError, "card_number"):
            load_patterns(self.write("child_exploitation x\ncredential_dump y\n"))


class BodyTest(TempFiles):
    def setUp(self):
        super().setUp()
        self.patterns = load_patterns(self.write(PATTERNS))

    def verdict(self, text: str) -> str | None:
        return body_triggers_exclusion(text, self.patterns)

    def test_clean_body(self):
        self.assertIsNone(self.verdict("<p>A forum about gardening. Contact admin@garden.example</p>"))

    def test_child_exploitation_checked_first(self):
        self.assertEqual(self.verdict(f"{COMBO} 4111-1111-1111-1111 FORBIDDENTERM"), "child_exploitation")

    def test_credential_dump_before_card(self):
        self.assertEqual(self.verdict(f"{COMBO}4111-1111-1111-1111"), "credential_dump")

    def test_card_number_needs_luhn(self):
        self.assertEqual(self.verdict("cc: 4111-1111-1111-1111 exp 12/29"), "card_number")
        self.assertIsNone(self.verdict("cc: 4111-1111-1111-1112"))


class LuhnTest(unittest.TestCase):
    def test_known_numbers(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertTrue(luhn_valid("378282246310005"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("0" * 12))


if __name__ == "__main__":
    unittest.main()
