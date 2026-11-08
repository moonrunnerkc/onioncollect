import unittest

from selectolax.lexbor import LexborHTMLParser

from onioncollect import fingerprint, parser
from onioncollect.fingerprint import MIN_WORDS, MIRROR_MAX_BITS, Fingerprint
from tests.fixtures import headlines, listing_page

WORDS = " ".join(f"word{n}" for n in range(80))
PAGE = f"""<html><head><title>Front</title><style>p {{ color: red }}</style></head>
<body class="front" id="top"><nav><a href="/" class="home" id="h">home</a></nav>
<main><article data-n="1"><h2><a href="/a/1">{WORDS}</a></h2><p>first summary</p></article></main>
<script>track("one")</script></body></html>"""


def print_of(html: str | bytes) -> Fingerprint:
    tree = LexborHTMLParser(html.decode() if isinstance(html, bytes) else html)
    return fingerprint.of_page(parser.visible_text(tree), tree)


def flipped(value: int, bits: int) -> int:
    return value ^ ((1 << bits) - 1)


class StabilityTest(unittest.TestCase):
    """Normalization is defined once, in fingerprint.py; none of these differences may reach either hash."""

    def assertSamePrint(self, other: str):
        self.assertEqual(print_of(other), print_of(PAGE))

    def test_whitespace(self):
        self.assertSamePrint(PAGE.replace("\n", "\n\n   \t").replace("> <", ">  \n <").replace(" ", "  "))

    def test_tag_case(self):
        self.assertSamePrint(PAGE.replace("<body", "<BODY").replace("</body>", "</BODY>").replace("<article", "<ARTICLE")
                             .replace("</article>", "</Article>").replace("<h2>", "<H2>"))

    def test_attribute_order_and_values(self):
        self.assertSamePrint(PAGE.replace('class="front" id="top"', 'id="top" class="front"')
                             .replace('href="/" class="home" id="h"', 'id="x" class="other" href="/elsewhere"'))

    def test_scripts_styles_and_comments(self):
        self.assertSamePrint(PAGE.replace('track("one")', 'track("two"); nonce()').replace("color: red", "color: blue")
                             .replace("<main>", "<main><!-- build 4711 -->"))

    def test_shape_skips_invisible_elements_and_comments_on_its_own(self):
        shape = fingerprint.tag_shape(LexborHTMLParser("<body><script>x</script><!-- c --><p>t</p><style>s</style></body>"))
        self.assertEqual(shape, ["html", "head", "/", "body", "p", "/", "/", "/"])

    def test_text_case(self):
        self.assertSamePrint(PAGE.replace("first summary", "FIRST Summary"))

    def test_same_bytes_same_print_every_time(self):
        self.assertEqual(print_of(PAGE), print_of(PAGE))
        self.assertEqual(print_of(PAGE).words, 80 + 3)


class SensitivityTest(unittest.TestCase):
    def test_new_text_moves_content_only(self):
        a, b = print_of(listing_page(*headlines("monday"))), print_of(listing_page(*headlines("tuesday")))
        content, structure = fingerprint.distance(a, b)
        self.assertEqual(structure, 0)
        self.assertGreater(content, MIRROR_MAX_BITS)

    def test_new_markup_moves_structure_only(self):
        other = PAGE.replace("<main>", "<main><section><div><ul><li></li><li></li></ul></div></section>")
        content, structure = fingerprint.distance(print_of(PAGE), print_of(other))
        self.assertEqual(content, 0)
        self.assertGreater(structure, 0)

    def test_short_pages_are_not_comparable(self):
        self.assertFalse(print_of("<p>Under maintenance, back soon</p>").comparable)
        self.assertTrue(print_of(PAGE).comparable)
        self.assertEqual(fingerprint.closest([print_of("<p>Under maintenance</p>")], [print_of("<p>Under maintenance</p>")]),
                         None)

    def test_deep_nesting_does_not_recurse(self):
        self.assertGreater(len(fingerprint.tag_shape(LexborHTMLParser("<div>" * 5_000))), 5_000)

    def test_hostile_length_is_capped(self):
        self.assertEqual(print_of("<p>" + "word " * 100_000 + "</p>").words, fingerprint.MAX_TOKENS)

    def test_empty_page(self):
        self.assertEqual(fingerprint.simhash([]), 0)
        self.assertEqual(print_of("").words, 0)


def page_print(content: int, structure: int = 0, words: int = MIN_WORDS) -> Fingerprint:
    return Fingerprint(content, structure, words)


class ClusterTest(unittest.TestCase):
    def test_at_the_threshold_on_both_hashes_is_a_cluster(self):
        groups = {"news": [page_print(0, 0)], "mirror": [page_print(flipped(0, MIRROR_MAX_BITS), flipped(0, MIRROR_MAX_BITS))]}
        self.assertEqual(fingerprint.clusters(groups), {"mirror": "mirror", "news": "mirror"})

    def test_one_bit_past_on_either_hash_is_not(self):
        past = flipped(0, MIRROR_MAX_BITS + 1)
        for other in (page_print(past, 0), page_print(0, past)):
            self.assertEqual(fingerprint.clusters({"news": [page_print(0)], "other": [other]}), {})

    def test_template_only_match_is_not_a_mirror(self):
        monday, tuesday = print_of(listing_page(*headlines("monday"))), print_of(listing_page(*headlines("tuesday")))
        self.assertEqual(fingerprint.clusters({"a": [monday], "b": [tuesday]}), {})
        self.assertEqual(fingerprint.clusters({"a": [monday], "b": [monday]}), {"a": "a", "b": "a"})

    def test_too_short_to_compare_never_clusters(self):
        self.assertEqual(fingerprint.clusters({"a": [page_print(0, words=MIN_WORDS - 1)], "b": [page_print(0)]}), {})

    def test_any_matching_seed_pair_joins_and_linkage_chains(self):
        far = flipped(0, 2 * MIRROR_MAX_BITS)
        groups = {
            "c": [page_print(flipped(0, MIRROR_MAX_BITS))],
            "a": [page_print(0)],
            "b": [page_print(far), page_print(far ^ (1 << 63))],
            "lone": [page_print((1 << 64) - 1)],
        }
        # a matches c, c matches b's first page; a and b are 2x the threshold apart but share the cluster.
        self.assertEqual(fingerprint.clusters(groups), {"a": "a", "b": "a", "c": "a"})

    def test_matches_are_nearest_first_and_skip_non_matches(self):
        ours = [page_print(0)]
        groups = {"near": [page_print(1)], "nearer": [page_print(0)], "far": [page_print(flipped(0, 30))], "none": []}
        self.assertEqual(fingerprint.matches(ours, groups), [("nearer", (0, 0)), ("near", (1, 0))])

    def test_closest_prefers_a_matching_pair(self):
        lopsided = page_print(0, flipped(0, MIRROR_MAX_BITS + 2))
        balanced = page_print(flipped(0, MIRROR_MAX_BITS), flipped(0, MIRROR_MAX_BITS))
        self.assertEqual(fingerprint.closest([page_print(0)], [lopsided, balanced]), (MIRROR_MAX_BITS, MIRROR_MAX_BITS))


if __name__ == "__main__":
    unittest.main()
