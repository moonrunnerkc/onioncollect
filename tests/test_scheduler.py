import unittest
from datetime import UTC, datetime, timedelta

from onioncrawl.db import PageInfo, Task
from onioncrawl.scheduler import (
    host_is_dead, next_due_for_failure, next_due_for_url, retest_due, retry_cost, should_rotate,
)
from tests.fixtures import throwaway_settings

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
SETTINGS = throwaway_settings()
HOUR = timedelta(hours=1)


def task(depth=1, retries=0, streak=0) -> Task:
    return Task(url="http://h.onion/x", host="h.onion", depth=depth, retries=retries, last_hash="a", unchanged_streak=streak)


def info(gated=False) -> PageInfo:
    return PageInfo(title="", headings=[], links=set(), text_onions=set(), sha256="b", simhash=0, server=None,
                    gated=gated, word_count=0, http_code=200, size=0)


class FakeInstance:
    def __init__(self, rate):
        self.rate = rate

    def success_rate(self):
        return self.rate


class NextDueForUrlTest(unittest.TestCase):
    def due(self, **kwargs) -> timedelta:
        changed = kwargs.pop("changed", False)
        gated = kwargs.pop("gated", False)
        return next_due_for_url(task(**kwargs), info(gated), changed, SETTINGS, NOW) - NOW

    def test_changed_page(self):
        self.assertEqual(self.due(changed=True), 24 * HOUR)

    def test_unchanged_with_a_short_streak(self):
        self.assertEqual(self.due(streak=0), 48 * HOUR)
        self.assertEqual(self.due(streak=1), 48 * HOUR)

    def test_third_unchanged_visit_in_a_row_goes_quiet(self):
        self.assertEqual(self.due(streak=2), 168 * HOUR)
        self.assertEqual(self.due(streak=9), 168 * HOUR)

    def test_depth_zero_is_capped_at_active(self):
        self.assertEqual(self.due(depth=0, streak=0), 24 * HOUR)
        self.assertEqual(self.due(depth=0, streak=9), 24 * HOUR)
        self.assertEqual(self.due(depth=0, changed=True), 24 * HOUR)

    def test_gated_is_weekly_even_at_depth_zero(self):
        self.assertEqual(self.due(gated=True, changed=True), 168 * HOUR)
        self.assertEqual(self.due(gated=True, depth=0), 168 * HOUR)

    def test_follows_settings(self):
        custom = throwaway_settings(recrawl_active_hours=6, recrawl_quiet_hours=72)
        self.assertEqual(next_due_for_url(task(), info(), True, custom, NOW) - NOW, 6 * HOUR)
        self.assertEqual(next_due_for_url(task(streak=5), info(), False, custom, NOW) - NOW, 72 * HOUR)


class NextDueForFailureTest(unittest.TestCase):
    def due(self, error, retries=0):
        due = next_due_for_failure(task(retries=retries), error, SETTINGS, NOW)
        return None if due is None else due - NOW

    def test_flaky_errors_back_off_exponentially(self):
        for error in ("timeout", "tor_unreachable"):
            self.assertEqual(self.due(error, retries=0), timedelta(minutes=2))
            self.assertEqual(self.due(error, retries=1), timedelta(minutes=4))

    def test_flaky_errors_park_at_max_retries(self):
        self.assertIsNone(self.due("timeout", retries=2))
        longer = throwaway_settings(max_retries=4)
        self.assertEqual(next_due_for_failure(task(retries=2), "timeout", longer, NOW) - NOW, timedelta(minutes=8))

    def test_permanent_errors_park_immediately(self):
        for error in ("redirect_offsite", "redirect_excluded", "not_text", "not_onion"):
            self.assertIsNone(self.due(error))

    def test_other_errors_count_double(self):
        self.assertEqual(retry_cost("other:RemoteProtocolError"), 2)
        self.assertEqual(retry_cost("timeout"), 1)
        self.assertEqual(self.due("other:RemoteProtocolError", retries=0), timedelta(minutes=4))
        self.assertIsNone(self.due("other:RemoteProtocolError", retries=1))


class HostIsDeadTest(unittest.TestCase):
    def test_five_failures_in_five_minutes_is_not_dead(self):
        self.assertFalse(host_is_dead([NOW + timedelta(minutes=n) for n in range(5)], SETTINGS))

    def test_five_failures_spread_over_24_hours_is_dead(self):
        self.assertTrue(host_is_dead([NOW + n * 6 * HOUR for n in range(5)], SETTINGS))

    def test_spread_boundary(self):
        just_short = [NOW, NOW + HOUR, NOW + 2 * HOUR, NOW + 3 * HOUR, NOW + 24 * HOUR - timedelta(seconds=1)]
        self.assertFalse(host_is_dead(just_short, SETTINGS))
        self.assertTrue(host_is_dead(just_short[:-1] + [NOW + 24 * HOUR], SETTINGS))

    def test_too_few_failures_over_a_long_spread(self):
        self.assertFalse(host_is_dead([NOW, NOW + 100 * HOUR], SETTINGS))
        self.assertFalse(host_is_dead([], SETTINGS))

    def test_order_does_not_matter(self):
        self.assertTrue(host_is_dead([NOW + 30 * HOUR, NOW, NOW + HOUR, NOW + 2 * HOUR, NOW + 3 * HOUR], SETTINGS))


class RetestDueTest(unittest.TestCase):
    def test_dead_host_uses_last_down(self):
        self.assertTrue(retest_due({"state": "dead", "last_down": NOW - 168 * HOUR, "last_up": NOW}, SETTINGS, NOW))
        self.assertFalse(retest_due({"state": "dead", "last_down": NOW - 167 * HOUR, "last_up": None}, SETTINGS, NOW))

    def test_gated_host_uses_last_up(self):
        self.assertTrue(retest_due({"state": "gated", "last_down": None, "last_up": NOW - 200 * HOUR}, SETTINGS, NOW))
        self.assertFalse(retest_due({"state": "gated", "last_down": NOW - 999 * HOUR, "last_up": NOW - HOUR}, SETTINGS, NOW))

    def test_other_states_never_retest(self):
        for state in ("up", "unknown", "excluded"):
            self.assertFalse(retest_due({"state": state, "last_down": NOW - 999 * HOUR, "last_up": None}, SETTINGS, NOW))


class ShouldRotateTest(unittest.TestCase):
    def test_unreachable_on_a_struggling_instance(self):
        self.assertTrue(should_rotate("tor_unreachable", FakeInstance(0.4)))

    def test_unreachable_on_a_healthy_instance_is_the_hosts_fault(self):
        self.assertFalse(should_rotate("tor_unreachable", FakeInstance(0.5)))
        self.assertFalse(should_rotate("tor_unreachable", FakeInstance(0.9)))

    def test_other_errors_never_rotate(self):
        self.assertFalse(should_rotate("timeout", FakeInstance(0.0)))


if __name__ == "__main__":
    unittest.main()
