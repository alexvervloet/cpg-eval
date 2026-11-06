import unittest

from cpg_eval.pairs import clean_labels, dedup_and_split, normalise, touched, unique_by_name


def pair(name: str, date: str, before: str, after: str) -> dict:
    return {"name": name, "commit_date": date, "fix_commit": date, "before_hash": before, "after_hash": after}


class PairsTest(unittest.TestCase):
    def test_normalise_ignores_comments_and_whitespace(self):
        self.assertEqual(normalise("int x; // a\n/* b\n c */  int y;"), normalise("int x;int y;"))

    def test_touched_and_ambiguous_names(self):
        methods = [
            {"name": "f", "start": 10, "end": 20},
            {"name": "g", "start": 22, "end": 30},
            {"name": "dup", "start": 40, "end": 45},
            {"name": "dup", "start": 50, "end": 55},
        ]
        by_name = unique_by_name(methods)
        self.assertNotIn("dup", by_name)
        self.assertEqual(touched(by_name, [[20, 22]]), {"f", "g"})
        self.assertEqual(touched(by_name, [[21, 21]]), set())

    def test_clean_labels_prefers_crash_state(self):
        cands = [pair("f", "d", "1", "2"), pair("g", "d", "3", "4")]
        kept = clean_labels(cands, ["g", "caller"])
        self.assertEqual([p["name"] for p in kept], ["g"])
        self.assertEqual(kept[0]["label_reason"], "in crash state")

    def test_clean_labels_single_change_or_drop(self):
        self.assertEqual(clean_labels([pair("f", "d", "1", "2")], [])[0]["label_reason"], "only changed function")
        self.assertEqual(clean_labels([pair("f", "d", "1", "2"), pair("g", "d", "3", "4")], []), [])

    def test_dedup_keeps_earliest(self):
        out = dedup_and_split([pair("late", "2023", "same", "x"), pair("early", "2020", "same", "y")], "2022")
        self.assertEqual([p["name"] for p in out], ["early"])

    def test_split_drops_test_pairs_that_leak_dev_bodies(self):
        out = dedup_and_split([
            pair("dev", "2020", "a", "b"),
            pair("leak", "2023", "c", "b"),   # patched body seen in dev
            pair("ok", "2023", "d", "e"),
        ], "2022")
        self.assertEqual([(p["name"], p["split"]) for p in out], [("dev", "dev"), ("ok", "test")])


if __name__ == "__main__":
    unittest.main()
