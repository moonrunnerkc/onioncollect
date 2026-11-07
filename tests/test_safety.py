import unittest

from onioncrawl.safety import (
    body_triggers_exclusion, category_of, is_excluded, luhn_valid, parse_exclusions, parse_patterns,
)
from tests.test_onion import AHMIA, DUCKDUCKGO

# Throwaway patterns. The operator's list is never committed or copied into a fixture.
PATTERNS = r"""
# comment
child_exploitation \bforbiddenterm\b
credential_dump (?:zz\w{1,8}:\w{1,8}\n){3}
card_number \b\d{4}(?:-\d{4}){3}\b
"""
COMBO = "zza:pw1\nzzb:pw2\nzzc:pw3\n"


class ExclusionsTest(unittest.TestCase):
    def test_parse_skips_comments_and_lowercases(self):
        hosts = parse_exclusions(f"# header\n\n{AHMIA.upper()}  # trailing\n  {DUCKDUCKGO}\n")
        self.assertEqual(hosts, frozenset({AHMIA, DUCKDUCKGO}))

    def test_invalid_entry_is_an_error_not_a_silent_miss(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            parse_exclusions(f"{AHMIA}\nexample.com\n")

    def test_comments_only_parse_to_empty(self):
        self.assertEqual(parse_exclusions("# nothing listed\n"), frozenset())

    def test_is_excluded(self):
        self.assertTrue(is_excluded(AHMIA.upper(), frozenset({AHMIA})))
        self.assertFalse(is_excluded(DUCKDUCKGO, frozenset({AHMIA})))


class PatternParseTest(unittest.TestCase):
    def test_categories_sorted_into_check_order(self):
        patterns = parse_patterns("card_number \\d{16}\ncredential_dump x\nchild_exploitation y\n")
        self.assertIsInstance(patterns, tuple)
        self.assertEqual([category_of(p) for p in patterns], ["child_exploitation", "credential_dump", "card_number"])

    def test_category_survives_named_groups_in_the_expression(self):
        patterns = parse_patterns("child_exploitation (?P<word>y)\ncredential_dump (?P<user>x)\ncard_number \\d{16}\n")
        self.assertEqual([category_of(p) for p in patterns], ["child_exploitation", "credential_dump", "card_number"])
        self.assertEqual(body_triggers_exclusion("x", patterns), "credential_dump")

    def test_unknown_category(self):
        with self.assertRaisesRegex(ValueError, "line 1"):
            parse_patterns("weapons \\bx\\b\n")

    def test_bad_regex_names_its_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            parse_patterns("child_exploitation y\ncredential_dump (x\ncard_number z\n")

    def test_every_category_required(self):
        with self.assertRaisesRegex(ValueError, "card_number"):
            parse_patterns("child_exploitation x\ncredential_dump y\n")


class BodyTest(unittest.TestCase):
    patterns = parse_patterns(PATTERNS)

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
