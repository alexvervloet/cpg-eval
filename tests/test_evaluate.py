import unittest

from cpg_eval.evaluate import bootstrap_ci, flagged_sets, outcome, pick, precision, score

PAIR = {"before_file": "s/before/a.c", "after_file": "s/after/a.c", "name": "f"}


class EvaluateTest(unittest.TestCase):
    def test_outcomes(self):
        before, after = ("s/before/a.c", "f"), ("s/after/a.c", "f")
        self.assertEqual(outcome(PAIR, {before}), "correct")
        self.assertEqual(outcome(PAIR, {before, after}), "both")
        self.assertEqual(outcome(PAIR, {after}), "reversed")
        self.assertEqual(outcome(PAIR, set()), "neither")

    def test_flag_everything_scores_chance(self):
        self.assertEqual(precision(["both"] * 10), 0.5)
        self.assertEqual(precision(["correct", "neither"]), 1.0)
        self.assertIsNone(precision(["neither"]))

    def test_score_counts(self):
        flagged = flagged_sets([{"variant": "v", "file": "s/before/a.c", "name": "f"}])
        row = score([PAIR], flagged["v"])
        self.assertEqual((row["tp"], row["fp"], row["correct"]), (1, 0, 1))
        self.assertEqual(flagged["any"], flagged["v"])

    def test_bootstrap_is_deterministic_and_bounded(self):
        outs = ["correct"] * 3 + ["both"] * 5 + ["neither"] * 2
        lo, hi = bootstrap_ci(outs)
        self.assertEqual((lo, hi), bootstrap_ci(outs))
        self.assertTrue(0.5 <= lo <= precision(outs) <= hi <= 1.0)

    def test_pick_skips_undefined_and_breaks_ties_on_tp(self):
        scores = {
            "a": {"precision": 0.6, "tp": 3},
            "b": {"precision": 0.6, "tp": 5},
            "c": {"precision": None, "tp": 0},
        }
        self.assertEqual(pick(scores), "b")


if __name__ == "__main__":
    unittest.main()
