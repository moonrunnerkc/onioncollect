import unittest

from onioncollect.safety import body_triggers_exclusion, is_excluded, parse_exclusions, parse_patterns
from tests.test_onion import AHMIA, DUCKDUCKGO

# Throwaway patterns. The operator's list is never committed or copied into a fixture.
PATTERNS = "# comment\nchild_exploitation \\bforbiddenterm\\b\nchild_exploitation \\bothertermx\\b\n"


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
    def test_parses_each_line(self):
        self.assertEqual(len(parse_patterns(PATTERNS)), 2)

    def test_unknown_category(self):
        with self.assertRaisesRegex(ValueError, "line 1"):
            parse_patterns("weapons \\bx\\b\n")

    def test_old_categories_point_at_the_redaction_gate(self):
        for category in ("credential_dump", "card_number"):
            with self.assertRaisesRegex(ValueError, "line 2: .*redaction gate"):
                parse_patterns(f"child_exploitation y\n{category} x\n")

    def test_bad_regex_names_its_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            parse_patterns("child_exploitation y\nchild_exploitation (x\n")

    def test_empty_expression(self):
        with self.assertRaisesRegex(ValueError, "line 1"):
            parse_patterns("child_exploitation   \n")


class BodyTest(unittest.TestCase):
    patterns = parse_patterns(PATTERNS)

    def test_clean_body(self):
        self.assertIsNone(body_triggers_exclusion("<p>Selling acme.com db, 4111-1111-1111-1111</p>", self.patterns))

    def test_any_pattern_excludes(self):
        self.assertEqual(body_triggers_exclusion("x OTHERTERMX y", self.patterns), "child_exploitation")


if __name__ == "__main__":
    unittest.main()
