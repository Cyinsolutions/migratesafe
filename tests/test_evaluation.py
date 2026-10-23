import unittest

from evaluation.run import evaluate


class FaultInjectionTest(unittest.TestCase):
    """Regression test: the simulated baseline is clean and every injected fault is caught."""

    @classmethod
    def setUpClass(cls):
        cls.r = evaluate()

    def test_baseline_has_no_false_positives(self):
        self.assertEqual(self.r["baseline_false_positives"], [])

    def test_every_fault_detected_by_expected_check(self):
        missed = [row["fault"] for row in self.r["rows"]
                  if not row["detected"] and not row["reported_only"]]
        self.assertEqual(missed, [])

    def test_only_lookalike_is_info_level(self):
        info_only = [row["fault"] for row in self.r["rows"] if row["reported_only"]]
        self.assertEqual(info_only, ["F28"])


if __name__ == "__main__":
    unittest.main()
