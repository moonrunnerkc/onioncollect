import re
import unittest

from onioncollect import detect, redact
from tests.fixtures import SALT

PAIRS = "bob.synthetic@example.org:SynthPassw0rd!\nroot:Hunter2Synthetic"


class RedactTest(unittest.TestCase):
    def test_clean_text_passes_through(self):
        done = redact.redact("Tor Browser 15.0 released today.", SALT)
        self.assertEqual((done.text, done.counts, done.hashes, done.events), ("Tor Browser 15.0 released today.", {}, (), 0))

    def test_tags_replace_spans_and_nothing_secret_survives(self):
        done = redact.redact(f"leaked:\n{PAIRS}\ncard 4111 1111 1111 1111", SALT)
        self.assertEqual(done.text, "leaked:\n[email_password]\n[user_password]\ncard [card]")
        self.assertFalse(detect.contains_secret(done.text))
        self.assertEqual(done.counts, {"email_password": 1, "user_password": 1, "card": 1})
        self.assertEqual(done.events, 3)

    def test_passwords_are_never_hashed(self):
        done = redact.redact(PAIRS, SALT)
        self.assertIn(redact.keyed_hash(SALT, "bob.synthetic@example.org"), done.hashes)
        self.assertIn(redact.keyed_hash(SALT, "root"), done.hashes)
        for secret in ("SynthPassw0rd!", "Hunter2Synthetic", "bob.synthetic@example.org:SynthPassw0rd!"):
            self.assertNotIn(redact.keyed_hash(SALT, secret), done.hashes)

    def test_card_hash_ignores_spacing(self):
        spaced = redact.redact("4111 1111 1111 1111", SALT).hashes
        dashed = redact.redact("4111-1111-1111-1111", SALT).hashes
        self.assertEqual(spaced, dashed)

    def test_hashes_depend_on_the_salt(self):
        self.assertNotEqual(redact.redact(PAIRS, SALT).hashes, redact.redact(PAIRS, b"y" * 40).hashes)

    def test_hashes_are_keyed_sha256_hex(self):
        for value in redact.redact(PAIRS, SALT).hashes:
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_lone_email_is_redacted_but_not_an_event(self):
        done = redact.redact("Press inquiries: press@example.org", SALT)
        self.assertEqual(done.text, "Press inquiries: [email]")
        self.assertEqual((done.counts, done.events), ({"email": 1}, 0))

    def test_bulk_email_list_is_an_event(self):
        emails = "\n".join(f"user{n}@example.org" for n in range(redact.BULK_EMAILS))
        done = redact.redact(emails, SALT)
        self.assertEqual(done.counts, {"email": redact.BULK_EMAILS})
        self.assertEqual(done.events, redact.BULK_EMAILS)

    def test_just_under_bulk_is_still_quiet(self):
        emails = " ".join(f"user{n}@example.org" for n in range(redact.BULK_EMAILS - 1))
        self.assertEqual(redact.redact(emails, SALT).events, 0)


class RedactFieldsTest(unittest.TestCase):
    def test_each_field_redacted_and_counts_combined(self):
        fields = {"title": "root:Hunter2Synthetic", "body": "contact a@example.org", "url": "http://x/1"}
        clean, summary = redact.redact_fields(fields, SALT)
        self.assertEqual(clean, {"title": "[user_password]", "body": "contact [email]", "url": "http://x/1"})
        self.assertEqual(summary.counts, {"user_password": 1, "email": 1})
        self.assertEqual(summary.events, 1)
        self.assertEqual(len(summary.hashes), 2)
        self.assertEqual(summary.text, "")

    def test_clean_fields_have_an_empty_summary(self):
        clean, summary = redact.redact_fields({"title": "Debian 14 released"}, SALT)
        self.assertEqual(clean, {"title": "Debian 14 released"})
        self.assertEqual((summary.counts, summary.hashes, summary.events), ({}, (), 0))


# The safety-patterns.txt lines retired by safety.MOVED_TO_REDACTION, verbatim. They used to disable a source
# whose body matched; now the redaction gate must leave nothing of what they matched. Each body below is first
# shown to match its retired line, so the cases are in that line's scope and not a guess at it.
RETIRED_EMAIL_DUMP = re.compile(
    r"(?<![^\s>])(?:[\w.+-]{1,64}+@[\w-]{1,63}+(?:\.[\w-]{1,63}+){1,4}+[ \t]{0,4}+[:;|][ \t]{0,4}+[^\s<]{1,128}+"
    r"[ \t]{0,4}+(?:<br\s{0,2}+/?>[ \t]{0,4}+\r?\n?|\r?\n)){3}", re.IGNORECASE | re.MULTILINE)
RETIRED_HASH_DUMP = re.compile(
    r"(?<![\w.-])(?:[\w.-]{3,64}+[ \t]{0,4}+:[ \t]{0,4}+[a-f0-9]{32,128}+[ \t]{0,4}+"
    r"(?:<br\s{0,2}+/?>[ \t]{0,4}+\r?\n?|\r?\n)){3}", re.IGNORECASE | re.MULTILINE)
RETIRED_CARD = re.compile(
    r"(?<![\d-])(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|6011|65\d{2}|3[47]\d{2})(?:[ -]?\d){9,15}(?![\d-])",
    re.IGNORECASE | re.MULTILINE)
SYNTH_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"
LONG_PASSWORD = "SynthLongPass" * 9  # 117 characters, so a 128-character password span ends inside the next entry


def dump(separator: str, end: str, passwords=("SynthPw1aaa", "SynthPw2bbb", "SynthPw3ccc")) -> tuple[str, list[str]]:
    users = ("a1.synthetic@example.org", "b2.synthetic@example.org", "c3.synthetic@example.org")
    return "".join(f"{user}{separator}{password}{end}" for user, password in zip(users, passwords)), list(passwords)


class RetiredPatternsTest(unittest.TestCase):
    def assert_redacted_clean(self, retired: re.Pattern, body: str, secrets: list[str]) -> None:
        self.assertRegex(body, retired, "the case is outside the retired line's scope")
        done = redact.redact(body, SALT)
        for secret in secrets:
            self.assertNotIn(secret, done.text)
            self.assertNotIn(re.sub(r"[ -]", "", secret), re.sub(r"[ -]", "", done.text))
        self.assertFalse(detect.contains_secret(done.text))
        self.assertGreater(done.events, 0)

    def test_email_password_dump_one_per_line(self):
        self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(":", "\n"))
        self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(";", "\r\n"))

    def test_email_password_dump_with_spaced_separators(self):
        for separator in (" : ", " :", ": ", "\t|\t", " ; "):
            with self.subTest(separator=separator):
                self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(separator, "\n"))

    def test_email_password_dump_joined_by_br_tags(self):
        for end in ("<br>\n", "<br>", "<br/>", "<BR />  \n"):
            with self.subTest(end=end):
                self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(":", end))
                self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(" : ", end))

    def test_email_password_dump_with_long_passwords_on_one_line(self):
        passwords = (LONG_PASSWORD + "A", LONG_PASSWORD + "B", LONG_PASSWORD + "C")
        self.assert_redacted_clean(RETIRED_EMAIL_DUMP, *dump(":", "<br>", passwords))

    def test_user_hash_dump(self):
        for separator in (":", " : "):
            for end in ("\n", "<br>", "<br>\n"):
                with self.subTest(separator=separator, end=end):
                    body = "".join(f"{user}{separator}{SYNTH_HASH}{end}" for user in ("admin", "root", "bob_1"))
                    self.assert_redacted_clean(RETIRED_HASH_DUMP, body, [SYNTH_HASH])

    def test_card_numbers_of_every_retired_prefix(self):
        cards = {
            "visa 13": "4222222222222", "visa 16": "4111 1111 1111 1111", "visa 19": "4111111111111111110",
            "mastercard 51-55": "5555-5555-5555-4444", "mastercard 2-series": "2223003122003222",
            "amex": "3782 822463 10005", "discover 6011": "6011111111111117", "discover 65": "6500000000000002",
        }
        for name, card in cards.items():
            with self.subTest(name):
                self.assert_redacted_clean(RETIRED_CARD, f"cc {card} exp 12/29", [card])

    def test_a_luhn_invalid_number_is_not_a_card(self):
        # The retired line matched any 13 to 19 digits with a card prefix; the gate redacts only real card numbers.
        self.assertRegex("4111 1111 1111 1112", RETIRED_CARD)
        self.assertEqual(redact.redact("order 4111 1111 1111 1112", SALT).counts, {})

    def test_a_trimmed_span_adds_no_hash(self):
        # A span cut by an overlap has no whole key, so it is redacted but hashed by nothing.
        passwords = (LONG_PASSWORD + "A", LONG_PASSWORD + "B", LONG_PASSWORD + "C")
        body, _ = dump(":", "<p>", passwords)
        done = redact.redact(body, SALT)
        self.assertNotIn(redact.keyed_hash(SALT, ""), done.hashes)
        self.assertIn(redact.keyed_hash(SALT, "a1.synthetic@example.org"), done.hashes)


if __name__ == "__main__":
    unittest.main()
