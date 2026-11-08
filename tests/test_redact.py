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


if __name__ == "__main__":
    unittest.main()
