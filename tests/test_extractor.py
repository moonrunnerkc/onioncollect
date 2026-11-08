import unittest

from selectolax.lexbor import LexborHTMLParser

from onioncollect import extractor
from onioncollect.source_config import parse
from tests.fixtures import NEWS, NEWS_CONFIG, NEWS_MIRROR, OFF_SOURCE, detail_page, listing_page, news_config

PAGE_URL = f"http://{NEWS}/articles/"
CONFIG = news_config()


def listing(body: bytes, config=CONFIG, page_url: str = PAGE_URL) -> extractor.Extraction:
    return extractor.listing(LexborHTMLParser(body.decode()), page_url, config)


class ListingTest(unittest.TestCase):
    def test_records_and_hit_rate(self):
        found = listing(listing_page("First", "Second"))
        self.assertEqual(found.records, [
            {"title": "First", "url": f"http://{NEWS}/articles/1", "published": "2026-11-02"},
            {"title": "Second", "url": f"http://{NEWS}/articles/2", "published": "2026-11-03"},
        ])
        self.assertEqual((found.items, found.incomplete, found.fields_resolved, found.fields_declared), (2, 0, 6, 6))
        self.assertEqual(found.hit_rate, 1.0)

    def test_incomplete_records_are_counted_never_returned(self):
        body = listing_page("Kept", extra="<article><h2>No link here</h2></article><article><time datetime='x'></time></article>")
        found = listing(body)
        self.assertEqual([record["title"] for record in found.records], ["Kept"])
        self.assertEqual((found.items, found.incomplete), (3, 2))
        self.assertEqual((found.fields_resolved, found.fields_declared), (3 + 0 + 1, 9))
        self.assertAlmostEqual(found.hit_rate, 4 / 9)

    def test_optional_field_missing_still_complete(self):
        body = b"<article><h2><a href='/articles/9'>No date</a></h2></article>"
        found = listing(body)
        self.assertEqual(found.records, [{"title": "No date", "url": f"http://{NEWS}/articles/9"}])
        self.assertEqual(found.incomplete, 0)

    def test_text_is_whitespace_collapsed(self):
        body = b"<article><h2><a href='/a'>  Spread \n over\t lines </a></h2></article>"
        self.assertEqual(listing(body).records[0]["title"], "Spread over lines")

    def test_next_page_is_absolute(self):
        self.assertEqual(listing(listing_page("A", next_href="?page=2")).next_page, f"http://{NEWS}/articles/?page=2")
        self.assertIsNone(listing(listing_page("A")).next_page)

    def test_next_page_without_a_target_is_none(self):
        self.assertIsNone(listing(listing_page("A") + b"<a class='next'>older</a>").next_page)

    def test_no_pagination_configured(self):
        config = parse(NEWS_CONFIG.replace('[pagination]\nnext = "a.next"\nmax_pages = 3\n', ""), "news")
        self.assertIsNone(listing(listing_page("A", next_href="/p2"), config).next_page)

    def test_follows_come_from_complete_records_only(self):
        body = listing_page("A", extra="<article><h2><a href='/orphan'></a></h2></article>")
        self.assertEqual(listing(body).follows, [f"http://{NEWS}/articles/1"])

    def test_follows_keep_off_source_links_for_the_caller_to_judge(self):
        body = f"<article><h2><a href='http://{OFF_SOURCE}/x'>Elsewhere</a></h2></article>".encode()
        self.assertEqual(listing(body).follows, [f"http://{OFF_SOURCE}/x"])

    def test_empty_page(self):
        found = listing(b"<html><body>nothing</body></html>")
        self.assertEqual((found.records, found.items, found.hit_rate, found.follows), ([], 0, 0.0, []))

    def test_field_values_are_capped(self):
        long = "w" * (extractor.MAX_FIELD_CHARS + 10)
        body = f"<article><h2><a href='/a'>{long}</a></h2></article>".encode()
        self.assertEqual(len(listing(body).records[0]["title"]), extractor.MAX_FIELD_CHARS)


class DetailTest(unittest.TestCase):
    def detail(self, body: bytes) -> extractor.Extraction:
        return extractor.detail(LexborHTMLParser(body.decode()), f"http://{NEWS}/articles/1", CONFIG)

    def test_detail_fields(self):
        found = self.detail(detail_page("The full story."))
        self.assertEqual(found.records, [{"body": "The full story."}])
        self.assertEqual((found.items, found.fields_resolved, found.fields_declared), (1, 1, 1))

    def test_detail_with_nothing_found(self):
        found = self.detail(b"<html><body><p>moved</p></body></html>")
        self.assertEqual((found.records, found.items, found.fields_resolved, found.fields_declared), ([], 0, 0, 1))
        self.assertEqual((dict(found.field_hits), found.field_items), ({"body": 0}, 1), "declared even when missed")


class FieldHitsTest(unittest.TestCase):
    def test_every_declared_field_is_counted_even_at_zero(self):
        body = listing_page("Kept", extra="<article><h2>No link here</h2></article>")
        found = listing(body)
        self.assertEqual(dict(found.field_hits), {"title": 1, "url": 1, "published": 1})
        self.assertEqual(found.field_items, 2)
        empty = listing(b"<html><body></body></html>")
        self.assertEqual((dict(empty.field_hits), empty.field_items), ({"title": 0, "url": 0, "published": 0}, 0))


class TagCapTest(unittest.TestCase):
    def test_counted_before_any_parse(self):
        self.assertFalse(extractor.too_many_tags("<p>" * extractor.MAX_TAGS))
        self.assertTrue(extractor.too_many_tags("<p>" * extractor.MAX_TAGS + "<"))
        self.assertFalse(extractor.too_many_tags("a" * 2_000_000))

    def test_the_1_mb_body_lexbor_stalled_on_is_over_it(self):
        self.assertTrue(extractor.too_many_tags("<div>" * 200_000))


class ContentHashTest(unittest.TestCase):
    def test_stable_and_order_independent(self):
        values = {"title": "A", "url": f"http://{NEWS}/articles/1"}
        self.assertEqual(extractor.content_hash(values, CONFIG),
                         extractor.content_hash(dict(reversed(list(values.items()))), CONFIG))
        self.assertRegex(extractor.content_hash(values, CONFIG), r"^[0-9a-f]{64}$")

    def test_same_record_on_two_mirrors_is_one_hash(self):
        config = parse(NEWS_CONFIG.replace(f'hosts = ["{NEWS}"]', f'hosts = ["{NEWS}", "{NEWS_MIRROR}"]'), "news")
        on_main = {"title": "A", "url": f"http://{NEWS}/articles/1"}
        on_mirror = {"title": "A", "url": f"http://{NEWS_MIRROR}/articles/1"}
        self.assertEqual(extractor.content_hash(on_main, config), extractor.content_hash(on_mirror, config))

    def test_different_content_differs(self):
        self.assertNotEqual(extractor.content_hash({"title": "A"}, CONFIG), extractor.content_hash({"title": "B"}, CONFIG))

    def test_off_source_link_is_hashed_whole(self):
        a = {"title": "A", "url": f"http://{OFF_SOURCE}/articles/1"}
        b = {"title": "A", "url": f"http://{NEWS}/articles/1"}
        self.assertNotEqual(extractor.content_hash(a, CONFIG), extractor.content_hash(b, CONFIG))


if __name__ == "__main__":
    unittest.main()
