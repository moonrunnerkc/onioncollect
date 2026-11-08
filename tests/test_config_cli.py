import unittest

from onioncollect.db import LISTING
from tests.fixtures import NEWS_CONFIG, headlines, listing_page
from tests.test_cli import CliTestCase


class ConfigTest(CliTestCase):
    def test_validate(self):
        self.live_news()
        self.assertIn("news: valid, 1 hosts, 1 seeds, 3 listing fields, 1 detail fields", self.cli("config", "validate", "news"))
        (self.configs / "news.toml").write_text(NEWS_CONFIG.replace('item = "article"', 'item = "//article"'))
        self.assertIn("listing.item", self.refused("config", "validate", "news"))
        self.assertIn("no config file", self.refused("config", "validate", "other"))

    def test_test_runs_the_config_on_the_latest_snapshot_without_fetching(self):
        self.live_news()
        self.assertIn("no snapshot", self.refused("config", "test", "news"))
        page = listing_page("First", "Second", next_href="/articles/?page=2").decode()
        self.store_do(lambda store: store.save_snapshot("news", "/articles/", LISTING, page))
        out = self.cli("config", "test", "news")
        self.assertIn("listing /articles/ at ", out)
        self.assertIn(": 2 items, 2 complete (expect 2), hit rate 1.00, next page found", out)
        self.assertIn("no baseline for this path; golive writes one", out)
        self.assertIn('"title": "First"', out)

    def test_test_sets_the_latest_against_the_golive_baseline(self):
        self.live_news()
        known = listing_page(*headlines("monday")).decode()
        self.store_do(lambda store: store.save_baselines("news", [("/articles/", known)]))
        # The site renamed its headline class: the titles and links are gone, the dates are not.
        drifted = known.replace("<h2>", "<h3>").replace("</h2>", "</h3>")
        self.store_do(lambda store: store.save_snapshot("news", "/articles/", LISTING, drifted))
        lines = self.cli("config", "test", "news").splitlines()
        self.assertIn("5 items, 0 complete (expect 2), hit rate 0.33", lines[0])
        self.assertIn("baseline at", lines[1])
        self.assertIn("5 items, 5 complete (expect 2), hit rate 1.00", lines[1])
        self.assertIn("  title: 5 of 5 items at baseline, 0 of 5 now  LOST", lines)
        self.assertIn("  url: 5 of 5 items at baseline, 0 of 5 now  LOST", lines)
        self.assertFalse(any(line.startswith("  published") for line in lines))
        self.assertTrue(lines[4].startswith("  layout: content 0, structure"))


if __name__ == "__main__":
    unittest.main()
