import base64
import hashlib
import unittest

from onioncrawl.onion import find_onions_in_text, host_of, is_v3_onion, normalize

AHMIA = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
DUCKDUCKGO = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
TORPROJECT = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
KNOWN_GOOD = [AHMIA, DUCKDUCKGO, TORPROJECT]


def build_address(pubkey: bytes, version: int) -> str:
    checksum = hashlib.sha3_256(b".onion checksum" + pubkey + bytes([version])).digest()[:2]
    return base64.b32encode(pubkey + checksum + bytes([version])).decode().lower() + ".onion"


def flip_char(host: str, index: int) -> str:
    replacement = "a" if host[index] != "a" else "b"
    return host[:index] + replacement + host[index + 1:]


class IsV3OnionTest(unittest.TestCase):
    def test_known_good_addresses(self):
        for host in KNOWN_GOOD:
            self.assertTrue(is_v3_onion(host), host)

    def test_uppercase_is_accepted(self):
        self.assertTrue(is_v3_onion(AHMIA.upper()))

    def test_constructed_address(self):
        self.assertTrue(is_v3_onion(build_address(bytes(range(32)), 3)))

    def test_typo_breaks_checksum(self):
        for index in (0, 20, 55):
            self.assertFalse(is_v3_onion(flip_char(AHMIA, index)), index)

    def test_wrong_version_with_matching_checksum(self):
        self.assertFalse(is_v3_onion(build_address(bytes(range(32)), 2)))

    def test_v2_address(self):
        self.assertFalse(is_v3_onion("expyuzz4wqqyqhjn.onion"))

    def test_wrong_lengths(self):
        label = AHMIA.removesuffix(".onion")
        self.assertFalse(is_v3_onion(label[:55] + ".onion"))
        self.assertFalse(is_v3_onion(label + "a.onion"))

    def test_missing_or_wrong_suffix(self):
        label = AHMIA.removesuffix(".onion")
        self.assertFalse(is_v3_onion(label))
        self.assertFalse(is_v3_onion(label + ".com"))
        self.assertFalse(is_v3_onion(AHMIA + "."))
        self.assertFalse(is_v3_onion("www." + AHMIA))

    def test_characters_outside_base32(self):
        for bad in "0189-_":
            self.assertFalse(is_v3_onion(bad + AHMIA[1:]), bad)

    def test_unicode_that_lowercases_to_ascii(self):
        kelvin_sign = "K"
        self.assertFalse(is_v3_onion(kelvin_sign + AHMIA[1:]))

    def test_clearnet_and_empty(self):
        for host in ("example.com", "127.0.0.1", "localhost", "", ".onion"):
            self.assertFalse(is_v3_onion(host), host)


class NormalizeTest(unittest.TestCase):
    def test_lowercases_scheme_and_host(self):
        self.assertEqual(normalize(f"HTTP://{AHMIA.upper()}/Search?Q=X"), f"http://{AHMIA}/Search?Q=X")

    def test_root_is_always_slash(self):
        self.assertEqual(normalize(f"http://{AHMIA}/"), f"http://{AHMIA}/")
        self.assertEqual(normalize(f"http://{AHMIA}"), f"http://{AHMIA}/")
        self.assertEqual(normalize(f"http://{AHMIA}?q=1"), f"http://{AHMIA}/?q=1")

    def test_other_trailing_slashes_kept(self):
        self.assertEqual(normalize(f"http://{AHMIA}/forum/"), f"http://{AHMIA}/forum/")

    def test_fragment_dropped_query_kept(self):
        self.assertEqual(normalize(f"http://{AHMIA}/t?id=4&p=2#post-9"), f"http://{AHMIA}/t?id=4&p=2")

    def test_default_ports_dropped(self):
        self.assertEqual(normalize(f"http://{AHMIA}:80/a"), f"http://{AHMIA}/a")
        self.assertEqual(normalize(f"https://{AHMIA}:443/a"), f"https://{AHMIA}/a")

    def test_other_ports_kept(self):
        self.assertEqual(normalize(f"http://{AHMIA}:8080/a"), f"http://{AHMIA}:8080/a")
        self.assertEqual(normalize(f"https://{AHMIA}:80/a"), f"https://{AHMIA}:80/a")

    def test_bad_port_rejected(self):
        self.assertIsNone(normalize(f"http://{AHMIA}:99999/"))
        self.assertIsNone(normalize(f"http://{AHMIA}:abc/"))

    def test_userinfo_dropped(self):
        self.assertEqual(normalize(f"http://user:pw@{AHMIA}/a"), f"http://{AHMIA}/a")
        self.assertEqual(normalize(f"http://user@{AHMIA}"), f"http://{AHMIA}/")

    def test_rejects_other_schemes(self):
        for scheme in ("ftp", "gopher", "file", "javascript", "mailto"):
            self.assertIsNone(normalize(f"{scheme}://{AHMIA}/"), scheme)

    def test_rejects_clearnet_and_bad_hosts(self):
        for url in (
            "https://example.com/",
            "http://127.0.0.1/",
            "http://expyuzz4wqqyqhjn.onion/",
            f"http://{flip_char(AHMIA, 10)}/",
            f"http://{AHMIA}.example.com/",
            f"http://{AHMIA}@example.com/",
            f"//{AHMIA}/",
            "/relative/path",
            "",
            "not a url",
        ):
            self.assertIsNone(normalize(url), url)

    def test_idempotent(self):
        once = normalize(f"HTTPS://{AHMIA}:443/x/?a=1#f")
        self.assertEqual(normalize(once), once)


class HostOfTest(unittest.TestCase):
    def test_lowercase_host(self):
        self.assertEqual(host_of(f"http://{AHMIA.upper()}:8080/path?q=1"), AHMIA)

    def test_userinfo_not_included(self):
        self.assertEqual(host_of(f"http://user@{AHMIA}/"), AHMIA)

    def test_garbage(self):
        self.assertEqual(host_of("no host here"), "")
        self.assertEqual(host_of("http://[::1/"), "")


class FindOnionsInTextTest(unittest.TestCase):
    def test_finds_valid_addresses_in_prose(self):
        text = f"New mirror: {AHMIA} (old one {DUCKDUCKGO.upper()} is down)"
        self.assertEqual(find_onions_in_text(text), {AHMIA, DUCKDUCKGO})

    def test_finds_inside_markup_and_comments(self):
        text = f'<!-- backup http://{TORPROJECT}/ --><script>var u="{AHMIA}";</script>'
        self.assertEqual(find_onions_in_text(text), {TORPROJECT, AHMIA})

    def test_drops_invalid_and_v2(self):
        text = f"{flip_char(AHMIA, 3)} expyuzz4wqqyqhjn.onion {DUCKDUCKGO}"
        self.assertEqual(find_onions_in_text(text), {DUCKDUCKGO})

    def test_deduplicates(self):
        self.assertEqual(find_onions_in_text(f"{AHMIA} {AHMIA} {AHMIA.upper()}"), {AHMIA})

    def test_subdomain_yields_service_host(self):
        self.assertEqual(find_onions_in_text(f"http://www.{AHMIA}/"), {AHMIA})

    def test_address_glued_to_preceding_letters_is_still_found(self):
        self.assertEqual(find_onions_in_text(f"mirror:abc{AHMIA}"), {AHMIA})

    def test_non_ascii_lookalike_is_rejected(self):
        k = AHMIA.index("k")
        self.assertEqual(find_onions_in_text(AHMIA[:k] + "\u212a" + AHMIA[k + 1:]), set())

    def test_suffix_without_a_full_label(self):
        self.assertEqual(find_onions_in_text(".onion abc.onion " + "a" * 100), set())

    def test_nothing_found(self):
        self.assertEqual(find_onions_in_text("plain text with example.com and no onions"), set())


if __name__ == "__main__":
    unittest.main()
