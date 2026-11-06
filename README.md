# cpg-eval

Scores a baseline vulnerability detector's precision on nDPI, using a code
property graph built by Joern and labels from real OSS-Fuzz fixes.

## What it measures

Every label comes from a fix commit that OSV.dev links to an OSS-Fuzz crash
in [nDPI](https://github.com/ntop/nDPI). For each fix, the function that
changed gives one **pair**: its body at the parent commit (vulnerable) and at
the fix commit (patched).

The detector runs over both sides. A flag on the vulnerable side is a true
positive, and a flag on the patched side is a false positive:

    precision = TP / (TP + FP)

A detector that ignores the fix and flags both sides gets exactly 0.5, so 0.5
is the chance line. This is the paired setup from PrimeVul (Ding et al.,
2024). It avoids treating unlabelled functions as safe, which is where
precision numbers usually go wrong.

### Why the split is clean

- **Labels.** A changed function counts as vulnerable only if it's in the
  OSS-Fuzz crash stack, or it's the only function the fix changed. 13 fix
  commits that changed several functions, none in the stack, are dropped.
- **No-op changes.** Pairs whose bodies differ only in whitespace or comments
  are dropped.
- **Duplicates.** Each vulnerable body appears once, at its earliest fix.
- **Time.** Fixes committed before 2022-01-01 form dev, later ones form test.
  Test pairs whose before or after body also appears in dev are dropped.
- **Selection.** The detector variant is picked on dev. Test is scored once
  with that variant.

## Results

89 pairs from 82 fix commits: 48 dev (2019 to 2021), 41 test (2022 to 2026).

| split | variant | pairs | TP | FP | precision | 95% CI | correct | both | neither | reversed |
|---|---|---|---|---|---|---|---|---|---|---|
| dev | any | 48 | 32 | 29 | 0.525 | 0.50-0.56 | 3 | 29 | 16 | 0 |
| dev | risky_copy | 48 | 24 | 24 | 0.500 | 0.50-0.50 | 0 | 24 | 24 | 0 |
| dev | unchecked_index | 48 | 24 | 21 | 0.533 | 0.50-0.58 | 3 | 21 | 24 | 0 |
| test | unchecked_index (chosen) | 41 | 16 | 15 | 0.516 | 0.50-0.56 | 1 | 15 | 25 | 0 |

The pair columns are the four outcomes. "correct" means only the vulnerable
side was flagged, "both" means both sides were, and "reversed" means only the
patched side was.

Test precision is 0.516, and the confidence interval touches 0.5. The
baseline can't tell vulnerable code from its fix in any way the data can
show. Most flagged pairs are "both". The fix rarely removes the pattern a
function-level rule looks for, so the rule fires on the patched code too.

The one test pair the rule gets right is real.
`search_valid_dns` in `src/lib/protocols/dns.c` (fix `21493d5654`) wrote
`rsp_addr[num_rsp_addr]` with no bound check. The fix wrapped it in
`if(num_rsp_addr < MAX_NUM_DNS_RSP_ADDRESSES)`, which is the comparison the
rule looks for.

## The detector

Both variants are CPG queries in `joern/extract.sc`.

- `risky_copy` flags a function that calls `strcpy`, `strcat`, `sprintf`,
  `vsprintf` or `gets`, or that calls `memcpy`, `memmove`, `strncpy`,
  `strncat`, `snprintf` or `vsnprintf` with a size argument that isn't a
  constant.
- `unchecked_index` flags a function with an index expression `a[i]` whose
  index variables never appear in a `<`, `<=`, `>` or `>=` comparison in the
  same function.
- `any` is the union of the two, computed in `evaluate.py`.

The index rule matches on identifiers, so `flow->x[flow->n]` reduces to the
identifier `flow`. Any comparison involving `flow` anywhere in the function
counts as a check. That's crude, and it's on purpose. The point is the harness.

## Running it

Needs git, Python 3.10+, curl, and `joern` / `joern-parse` on `PATH`. No
Python packages, no paid APIs.

    ./run.sh

That clones nDPI into `data/`, downloads the OSV OSS-Fuzz archive, mines the
changed files, builds one CPG over all of them with `joern-parse`, runs the
detector queries and writes `out/report.md`. It takes about a minute after
the first clone.

Unit tests:

    python3 -m unittest discover -s tests -t .

To see unselected variants on test, for exploration only:

    python3 -m cpg_eval.evaluate --show-all-test

## Limits

- A patched function is only known to be safe from *this* bug. A flag on it
  could be a true positive for a different bug, which makes FP an upper bound.
- 41 test pairs is small. Read the confidence interval, not the point estimate.
- OSS-Fuzz finds fix commits by bisection. A commit can be the one that made
  the crash stop without being the actual fix. Crash-stack filtering cuts
  this down but can't remove it.
- Only `src/lib/` is scored. Fixes to the example reader and fuzz harnesses
  are skipped.

## Layout

    cpg_eval/osv.py       OSV records -> fix commits with crash frames
    cpg_eval/mine.py      fix commits -> before/after files and diff hunks
    joern/extract.sc      CPG -> method line ranges and detector findings
    cpg_eval/pairs.py     hunks + methods -> clean labelled pairs, split
    cpg_eval/evaluate.py  pairs + findings -> precision report
    run.sh                all of the above in order
