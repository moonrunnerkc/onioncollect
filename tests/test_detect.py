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

    def test_email_password_pair_with_a_spaced_separator_ending_its_line(self):
        for text in ("bob@acme.com : hunter22\n", "bob@acme.com :hunter22", "bob@acme.com\t|\thunter22<br>",
                     "bob@acme.com ; hunter22  \r\n"):
            with self.subTest(text=text):
                self.assertEqual([k for k, _, key in kinds(text)], ["email_password"])
                self.assertEqual(kinds(text)[0][2], "bob@acme.com")
                self.assertIn("hunter22", kinds(text)[0][1])

    def test_a_spaced_separator_mid_sentence_stays_a_bare_email(self):
        # Contact lines put prose after a spaced separator; only a dump puts the password last on its line.
        for text in ("Mail bob@acme.com | PGP key below", "write to bob@acme.com; we answer in a day"):
            with self.subTest(text=text):
                self.assertEqual([k for k, _, _ in kinds(text)], ["email"])

    def test_a_password_stops_at_a_br_tag(self):
        self.assertEqual([s for _, s, _ in kinds("a@acme.com:pw1<br>b@acme.com:pw2<BR/>")],
                         ["a@acme.com:pw1", "b@acme.com:pw2"])

    def test_a_partly_overlapping_span_keeps_its_uncovered_part(self):
        # Dropping it whole would leave the part past the first span in the text, unredacted.
        # The first password's 128 characters end at "b@acm", inside the second entry.
        text = "a@acme.com:" + "P" * 120 + "<p>b@acme.com:" + "Q" * 40
        spans = find(text)
        covered = bytearray(len(text))
        for span in spans:
            covered[span.start:span.end] = b"\x01" * (span.end - span.start)
        second = text.index("b@")
        self.assertEqual(covered[second:], b"\x01" * (len(text) - second))
        self.assertEqual([(s.kind, s.key_end == s.start) for s in spans],
                         [("email_password", False), ("email_password", True)])

    def test_bare_email(self):
        self.assertEqual(kinds("mail alice.b+tag@mail.acme.co.uk now"),
                         [("email", "alice.b+tag@mail.acme.co.uk", "alice.b+tag@mail.acme.co.uk")])

    def test_user_password_line(self):
        self.assertEqual(kinds("root:toor1234\nadmin|letmein99"), [
            ("user_password", "root:toor1234", "root"), ("user_password", "admin|letmein99", "admin"),
        ])

    def test_a_redacted_link_is_not_a_pair_and_nothing_wider_is_let_through(self):
        for text in ("http:[token]", "https:[token]?page=2", "HTTP:[token]", "seen\nhttps:[token]#top\nagain"):
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [])
        for text in ("http:hunter2pass", "http:[token]:hunter2pass", "https:[token]|hunter2pass", "admin:[token]",
                     "httpx:[token]", "http:[email]", "http;[token]", "http:x[token]"):
            with self.subTest(text=text):
                self.assertIn("user_password", [kind for kind, _, _ in kinds(text)])

    def test_a_real_pair_inside_a_url_still_trips(self):
        self.assertEqual(kinds("http://alice:s3cretpw@site.example/x"),
                         [("email", "s3cretpw@site.example", "s3cretpw@site.example")])
        self.assertEqual([kind for kind, _, _ in kinds("alice:s3cretpw@site.example")], ["user_password", "email"])
        self.assertTrue(contains_secret("ftp://carol:pw123456@files.example/a"))

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

    def test_an_onion_link_is_judged_without_its_host(self):
        token = "sk_live_AbCdEf0123456789XyZaBcD"
        bad_checksum = AHMIA[:10] + ("b" if AHMIA[10] != "b" else "c") + AHMIA[11:]
        rows = [("short path with a capital", f"see http://{AHMIA}/Press/ now", False),
                ("lowercase path", f"http://{AHMIA}/press/2026/", False),
                ("www form with a capital", f"http://www.{AHMIA}/News", False),
                ("upper case host", f"http://{AHMIA.upper()}/Press/1", False),
                ("token in the path", f"http://{AHMIA}/{token}", True),
                ("token in the query", f"http://{AHMIA}/q?key={token}", True),
                ("token split around the host", f"sk_live_AbCdEf-{AHMIA}/0123456789XyZaBcD", True),
                ("long mixed path", f"http://{AHMIA}/Archive/2026/Reports/Q3summary", True),
                ("the same path, relative", "/Archive/2026/Reports/Q3summary", True),
                ("bad checksum host with a capital", f"http://{bad_checksum}/Press/", True),
                ("host inside a longer base32 run", f"Ab2{AHMIA}/Press/", True),
                ("host run on into more letters", f"http://{AHMIA}X/Press/1", True),
                ("bare token", token, True),
                ("bare md5", "5f4dcc3b5aa765d61d8327deb882cf99", True)]
        for name, text, trips in rows:
            with self.subTest(name):
                self.assertEqual([kind for kind, _, _ in kinds(text)], ["token"] if trips else [])
        text = f"x //{AHMIA}/{token} y"
        self.assertEqual(kinds(text)[0][1], f"//{AHMIA}/{token}", "the span is still the whole run")

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
                  "ab@cd.ef:pw\n" * 160_000, "Ab1" * 700_000, "1-" * 1_000_000, ":" * 2_000_000,
                  ".onion" * 333_000, ("A1" + AHMIA + "/") * 30_000, (AHMIA[:-6] + "a.onion/") * 30_000,
                  "a" * 56 + ".onion" * 300_000]
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
