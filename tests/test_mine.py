import unittest

from cpg_eval.mine import parse_hunks, safe_rel

DIFF = """\
diff --git a/x.c b/x.c
--- a/x.c
+++ b/x.c
@@ -49 +49 @@ static void f(void)
@@ -104,0 +105,4 @@ static void g(void)
@@ -200,3 +204,0 @@ static void h(void)
"""


class MineTest(unittest.TestCase):
    def test_parse_hunks(self):
        old, new = parse_hunks(DIFF)
        # One-line change, pure insertion after line 104, pure deletion.
        self.assertEqual(old, [[49, 49], [104, 104], [200, 202]])
        self.assertEqual(new, [[49, 49], [105, 108], [204, 204]])

    def test_safe_rel_rejects_escapes(self):
        self.assertEqual(str(safe_rel("src/lib/a.c")), "src/lib/a.c")
        with self.assertRaises(ValueError):
            safe_rel("../etc/passwd")
        with self.assertRaises(ValueError):
            safe_rel("/etc/passwd")


if __name__ == "__main__":
    unittest.main()
