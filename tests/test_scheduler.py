import unittest
from datetime import UTC, datetime, timedelta

from onioncollect.scheduler import next_due_for_failure, next_run, retry_cost, should_rotate

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
SIX_HOURS = timedelta(hours=6)


class FakeInstance:
    def __init__(self, rate):
        self.rate = rate

    def success_rate(self):
        return self.rate


class RetryTest(unittest.TestCase):
    def test_flaky_errors_cost_one_others_two(self):
        self.assertEqual(retry_cost("timeout"), 1)
        self.assertEqual(retry_cost("tor_unreachable"), 1)
        self.assertEqual(retry_cost("other:ValueError"), 2)

    def test_backoff_is_exponential(self):
        self.assertEqual(next_due_for_failure(1, "timeout", 3, NOW), NOW + timedelta(minutes=2))
        self.assertEqual(next_due_for_failure(2, "timeout", 3, NOW), NOW + timedelta(minutes=4))

    def test_retries_exhausted(self):
        self.assertIsNone(next_due_for_failure(3, "timeout", 3, NOW))

    def test_permanent_errors_never_retry(self):
        for error in ("redirect", "not_text", "gated", "not_approved", "not_source_host", "excluded", "bad_path"):
            self.assertIsNone(next_due_for_failure(0, error, 3, NOW), error)


class NextRunTest(unittest.TestCase):
    def test_healthy_run_follows_the_cadence(self):
        self.assertEqual(next_run(SIX_HOURS, 0, False, NOW), NOW + SIX_HOURS)
        self.assertEqual(next_run(SIX_HOURS, 5, False, NOW), NOW + SIX_HOURS)

    def test_failed_runs_retry_sooner_for_three_runs(self):
        for before in (0, 1, 2):
            self.assertEqual(next_run(SIX_HOURS, before, True, NOW), NOW + timedelta(hours=1, minutes=30), before)

    def test_quick_retry_has_a_floor(self):
        self.assertEqual(next_run(timedelta(hours=1), 0, True, NOW), NOW + timedelta(minutes=30))

    def test_then_the_source_is_slowed_down(self):
        self.assertEqual(next_run(SIX_HOURS, 3, True, NOW), NOW + timedelta(hours=12))
        self.assertEqual(next_run(SIX_HOURS, 9, True, NOW), NOW + timedelta(hours=12))


class ShouldRotateTest(unittest.TestCase):
    def test_unreachable_on_a_struggling_instance(self):
        self.assertTrue(should_rotate("tor_unreachable", FakeInstance(0.2)))

    def test_unreachable_on_a_healthy_instance_is_the_hosts_fault(self):
        self.assertFalse(should_rotate("tor_unreachable", FakeInstance(0.9)))

    def test_other_errors_never_rotate(self):
        self.assertFalse(should_rotate("timeout", FakeInstance(0.0)))


if __name__ == "__main__":
    unittest.main()
