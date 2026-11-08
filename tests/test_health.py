import unittest

from onioncollect import health, lifecycle, scheduler
from onioncollect.health import RunSummary

REQUIRED = ("title", "url")


def run(**overrides) -> RunSummary:
    healthy = {"pages": 3, "failed_runs": 0, "listing_pages": 2, "items": 10, "incomplete": 0, "parse_refused": 0,
               "field_hits": {"title": 10, "url": 10}}
    return RunSummary(**healthy | overrides)


def assess(summary: RunSummary, category: str = "journalism-publishing", minimum: int = 5):
    return [(found.kind, found.priority) for found in health.assess(summary, minimum, REQUIRED, category)]


class PriorityTest(unittest.TestCase):
    def test_category_weight_times_shortfall(self):
        self.assertEqual(health.priority(health.BELOW_EXPECTATION, "journalism-publishing", 0.5), 50)
        self.assertEqual(health.priority(health.BELOW_EXPECTATION, "directories", 0.5), 20)
        self.assertEqual(health.priority(health.UNREACHABLE, "software-infrastructure", 1.0), 60)
        self.assertEqual(health.priority(health.BELOW_EXPECTATION, "self-hosted", 0.01), 1, "never zero")
        self.assertEqual(health.priority(health.BELOW_EXPECTATION, "journalism-publishing", 7.0), health.MAX_PRIORITY)

    def test_a_redaction_outranks_anything_the_formula_gives(self):
        self.assertEqual(set(health.CATEGORY_WEIGHT), set(lifecycle.CATEGORIES))
        highest = max(health.priority(kind, category, 1.0) for kind in health.KINDS if kind != health.REDACTION
                      for category in lifecycle.CATEGORIES)
        self.assertGreater(health.priority(health.REDACTION, "self-hosted", 0.0), highest)
        self.assertEqual(health.redaction("x"), health.Finding(health.REDACTION, health.REDACTION_PRIORITY, "x"))


class AssessTest(unittest.TestCase):
    def test_a_healthy_run_raises_nothing(self):
        self.assertEqual(assess(run()), [])

    def test_below_min_items_by_how_far(self):
        self.assertEqual(assess(run(items=10, incomplete=5)), [(health.BELOW_EXPECTATION, 50)])
        self.assertEqual(assess(run(items=0, field_hits={})), [(health.BELOW_EXPECTATION, 100)])
        (found,) = health.assess(run(items=7, incomplete=0), 5, REQUIRED, "directories")
        self.assertEqual(found.detail, "7 complete items on 2 listing pages, expected 5 a page")

    def test_a_required_field_lost_is_raised_instead_of_the_shortfall_it_causes(self):
        self.assertEqual(assess(run(incomplete=10, field_hits={"title": 10, "url": 0})),
                         [(health.REQUIRED_FIELD_LOST, 50)])
        self.assertEqual(assess(run(incomplete=10, field_hits={"title": 0, "url": 0})),
                         [(health.REQUIRED_FIELD_LOST, 100)])

    def test_unreachable_only_past_the_quick_retries(self):
        down = {"pages": 0, "listing_pages": 0, "items": 0, "field_hits": {}, "last_error": "timeout"}
        self.assertEqual(assess(run(failed_runs=scheduler.QUICK_RETRY_RUNS, **down)), [])
        (found,) = health.assess(run(failed_runs=scheduler.QUICK_RETRY_RUNS + 1, **down), 5, REQUIRED, "directories")
        self.assertEqual((found.kind, found.priority), (health.UNREACHABLE, 40))
        self.assertEqual(found.detail, "nothing fetched in 4 runs in a row, last error timeout")

    def test_parse_refusals_are_their_own_item_not_unreachability(self):
        refused = run(pages=0, failed_runs=9, listing_pages=0, items=0, parse_refused=2, field_hits={})
        self.assertEqual(assess(refused), [(health.PARSE_REFUSED, 100)])
        self.assertEqual(assess(run(pages=3, parse_refused=1)), [(health.PARSE_REFUSED, 25)])

    def test_detail_only_runs_are_not_judged_on_listing_expectations(self):
        self.assertEqual(assess(run(listing_pages=0, items=0, field_hits={})), [])


if __name__ == "__main__":
    unittest.main()
