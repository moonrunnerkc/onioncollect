import unittest

from onioncollect import lifecycle


class CheckApprovalTest(unittest.TestCase):
    def test_valid_approval(self):
        lifecycle.check_approval("tor-project-blog", "software-infrastructure", "official blog mirror")

    def test_categories_outside_the_policy_are_refused(self):
        for category in ("leak-site", "market", "forum", ""):
            with self.assertRaises(ValueError, msg=category):
                lifecycle.check_approval("x-source", category, "note")

    def test_note_is_required(self):
        with self.assertRaises(ValueError):
            lifecycle.check_approval("x-source", "directories", "   ")

    def test_source_id_shape(self):
        for bad in ("A", "Upper-case", "-leading", "has space", "under_score", "x" * 64):
            with self.assertRaises(ValueError, msg=bad):
                lifecycle.check_approval(bad, "directories", "note")


class CheckTransitionTest(unittest.TestCase):
    def test_allowed(self):
        for current, target in (("approved", "live"), ("approved", "disabled"), ("live", "degraded"),
                                ("degraded", "live"), ("live", "disabled"), ("disabled", "approved")):
            lifecycle.check_transition(current, target)

    def test_refused(self):
        for current, target in (("approved", "degraded"), ("disabled", "live"), ("live", "approved"),
                                ("candidate", "live"), ("declined", "approved"), ("live", "live")):
            with self.assertRaises(ValueError, msg=(current, target)):
                lifecycle.check_transition(current, target)


class FetchableStatesTest(unittest.TestCase):
    def test_only_collecting_states_are_scheduled_and_only_approved_is_tested(self):
        self.assertEqual(lifecycle.COLLECTING, {"live", "degraded"})
        self.assertEqual(lifecycle.UNDER_TEST, {"approved"})
        for never in ("candidate", "declined", "disabled"):
            self.assertNotIn(never, lifecycle.COLLECTING | lifecycle.UNDER_TEST)


if __name__ == "__main__":
    unittest.main()
