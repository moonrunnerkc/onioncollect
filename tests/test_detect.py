import time
import unittest

from onioncollect.detect import contains_secret, find, luhn_valid
from tests.test_onion import AHMIA


def kinds(text: str) -> list[tuple[str, str, str]]:
    return [(span.kind, text[span.start:span.end], text[span.start:span.key_end]) for span in find(text)]


class FindTest(unittest.TestCase):
    def test_email_password_pair_hashes_only_the_address(self):
        self.assertEqual(kinds("x bob@acme.com:hunter2 y"), [("email_password", "bob@acme.com:hunter2", "bob@acme.com")])
        self.assertEqual(kinds("bob@acme.com;pw|x")[0][0], "email_password")

    def test_bare_email(self):
        self.assertEqual(kinds("mail alice.b+tag@mail.acme.co.uk now"),
                         [("email", "alice.b+tag@mail.acme.co.uk", "alice.b+tag@mail.acme.co.uk")])

    def test_user_password_line(self):
        self.assertEqual(kinds("root:toor1234\nadmin|letmein99"), [
            ("user_password", "root:toor1234", "root"), ("user_password", "admin|letmein99", "admin"),
        ])

    def test_url_and_prose_lines_are_not_pairs(self):
        self.assertEqual(kinds(f"http://{AHMIA}/ok\nTitle: a forum\nPrice:abc"), [])

    def test_card_needs_luhn(self):
        self.assertEqual(kinds("cc 4111 1111 1111 1111 exp")[0][:2], ("card", "4111 1111 1111 1111"))
        self.assertEqual(kinds("cc 4111-1111-1111-1112 exp"), [])

    def test_national_ids(self):
        self.assertEqual([k for k, _, _ in kinds("ssn 123-45-6789 nino AB 12 34 56 C")], ["national_id", "national_id"])
        self.assertEqual(kinds("000-12-3456 or 666-12-3456 or 123-00-4567"), [])

    def test_tokens_need_mixed_classes_or_hex(self):
        self.assertEqual(kinds("key sk_live_AbCdEf0123456789XyZaBcD end")[0][0], "token")
        self.assertEqual(kinds("md5 5f4dcc3b5aa765d61d8327deb882cf99")[0][0], "token")
        self.assertEqual(kinds("lowercase_words_joined_together_for_a_while"), [])
        self.assertEqual(kinds(AHMIA), [])

    def test_overlaps_go_to_the_higher_priority_kind(self):
        self.assertEqual([k for k, _, _ in kinds("AbCdEf0123456789XyZaBcDbob@acme.com:pw")], ["email_password"])

    def test_spans_never_cross_lines(self):
        text = "bob@acme.com\nroot:toor1234\n4111111111111111\n"
        for span in find(text):
            self.assertNotIn("\n", text[span.start:span.end])

    def test_contains_secret(self):
        self.assertTrue(contains_secret("x bob@acme.com y"))
        self.assertFalse(contains_secret("[email_password at acme.com] [card] 1.2M records, $400"))

    def test_hostile_bodies_stay_linear(self):
        bodies = ["a" * 2_000_000, "a@" * 1_000_000, ("a" * 63 + "@") * 31_000, "4" * 2_000_000,
                  "ab@cd.ef:pw\n" * 160_000, "Ab1" * 700_000, "1-" * 1_000_000, ":" * 2_000_000]
        for body in bodies:
            started = time.perf_counter()
            find(body)
            self.assertLess(time.perf_counter() - started, 3.0, body[:8])


class LuhnTest(unittest.TestCase):
    def test_known_numbers(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertTrue(luhn_valid("378282246310005"))
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("0" * 12))


if __name__ == "__main__":
    unittest.main()
