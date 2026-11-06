# Walkthrough

This follows one run of `./run.sh` from start to finish. For each stage it
says what happens, where the code is, and what can surprise you.

## 0. Before you start

You need `git`, `curl`, Python 3.10+, and Joern's `joern` and `joern-parse`
on `PATH`. Check with `which joern joern-parse`. Nothing gets installed with
pip, and nothing calls a paid API.

The first run also clones nDPI. After that a full run takes about a minute
on an M-series Mac, and `joern-parse` is most of it.

## 1. Clone nDPI (`run.sh:13`)

The clone is blobless (`--filter=blob:none`). It fetches commits and trees
up front and downloads file contents only when `git show` asks for them.
The mining step is slower on the first run because of this, and it needs
network access.

The clone stays in `data/nDPI` across runs. Delete it to start completely
fresh.

## 2. Labels from OSV (`run.sh:19-20`, `cpg_eval/osv.py`)

`curl` downloads OSV's OSS-Fuzz archive (about 3 MB, every OSS-Fuzz
project). `osv.py` reads it in memory and keeps records for package `ndpi`.

- `fixes_for` (`osv.py:41`) groups records by fix commit. 23 nDPI fix
  commits close more than one OSV record. It drops any `fixed` value that
  isn't a 40-character hex SHA (`osv.py:55`). That check keeps strings like
  `--upload-pack=...` out of the git commands later on.
- `crash_frames` (`osv.py:20`) parses the `Crash state:` block. Those
  function names are what the label cleaning in step 5 uses.
- `load_records` (`osv.py:76`) skips any zip member over 1 MiB.

Output: `data/fixes.jsonl`, 133 lines.

Surprise: OSV's `published` field isn't the fix date. All 2020 records share
the backfill date 2020-06-24. The split uses git commit dates for this reason.

## 3. Mine before/after files (`run.sh:23`, `cpg_eval/mine.py`)

`mine_fix` (`mine.py:58`) does this for each fix commit F:

1. Skips merges. A pair needs a single parent `F^`.
2. Lists files under `src/lib/` that F modified (`--diff-filter=M`,
   `mine.py:75`). Skips the commit if there are none or more than 5.
3. Writes the file at `F^` to `data/files/<F>/before/<path>` and the file at
   `F` to `data/files/<F>/after/<path>`. `safe_rel` (`mine.py:51`) rejects
   absolute paths and `..` before anything is written.
4. Runs `git diff -U0` and records the changed line ranges on each side
   with `parse_hunks` (`mine.py:32`).

Output: `data/commits.jsonl` and 238 C files. 95 of 133 commits survive.
The drops are 29 with no library `.c` change, 7 merges, and 2 that touch
too many files. The `skip ...` lines in the output give each reason.

`run.sh` deletes `data/files` before this step, so files left over from an
older run never end up in the CPG.

## 4. Build the CPG and run the detector (`run.sh:27-33`, `joern/extract.sc`)

`joern-parse` builds **one** CPG over all 238 files. It writes
`out/cpg.bin`, about 68 MB, and logs to `out/joern-parse.log`. The
`ReachingDefPass ... has more than 4000 definitions` warnings come from
nDPI's huge protocol-table initialisers. Joern skips data flow for those
methods. Neither detector uses data flow, so they don't matter here.

`extract.sc` runs on that CPG.

- `importCpg` (`extract.sc:65`) copies the graph into a Joern project
  under `workspace/`. If `cpg.bin` already exists there, it makes
  `cpg.bin1`, then `cpg.bin2`, and so on, each a full 68 MB copy.
  `run.sh:32` deletes `workspace/` first so they don't pile up.
- `methods.json` lists every function defined in the files, with filename
  and line range. Methods are keyed by file plus short name. Joern adds
  `<duplicate>N` to full names when the same function shows up in many
  copies of a file.
- `findings.json` has one row per detector hit, tagged with its variant.

The two variants:

- `riskyCopy` (`extract.sc:33`) flags unbounded copies (`strcpy` and
  friends) and bounded copies whose size isn't constant. `isConstant`
  (`extract.sc:25`) counts literals, `sizeof` and operators over constants.
  Macros from headers Joern never saw still parse as identifiers, so
  `memcpy(d, s, MAX_LEN)` counts as variable.
- `uncheckedIndex` (`extract.sc:41`) flags `a[i]` when no identifier in `i`
  appears in a `<`, `<=`, `>` or `>=` comparison in the same function.
  Field accesses reduce to their base identifier, so `flow->x[flow->n]` is
  "checked" if anything compares `flow`.

To add a variant, write a `Method => Iterator[Call]` function and add it to
`variants` (`extract.sc:49`). The harness picks it up by name.

## 5. Build clean pairs (`run.sh:36`, `cpg_eval/pairs.py`)

This is where label quality comes from.

1. `candidate_pairs` (`pairs.py:54`) maps hunks onto methods on both sides.
   A function counts as changed if a hunk overlaps it on either side. It
   becomes a pair only if it exists, with a unique name, in both files.
   Changes that are only whitespace or comments are dropped.
2. `clean_labels` (`pairs.py:86`) keeps changed functions named in the crash
   stack (`pairs.py:88`). If none are named, it keeps the commit only when
   exactly one function changed (`pairs.py:91`). 13 commits get dropped here.

   Example: fix `0c81498a` changed two functions in `l2tp.c`. The crash
   stack names `ndpi_search_l2tp`, where the bounds check went in. The
   other function's change loosened an off-by-one from `>=` to `>`, so it
   correctly isn't labelled vulnerable.
3. `dedup_and_split` (`pairs.py:96`) keeps the earliest pair for each
   vulnerable body hash. It puts fixes before `--cutoff` (default
   2022-01-01, `pairs.py:118`) in dev and the rest in test. Then it drops
   test pairs whose before or after body also appears in dev (`pairs.py:105`).
   On nDPI that removes nothing, but it's there for other projects.

   The cutoff compares ISO date strings, so commit timezones are ignored.
   A fix committed near midnight on 31 December could land on either side.

Output: `out/pairs.jsonl`, 89 pairs. 48 are dev and 41 are test.

## 6. Score (`run.sh:39`, `cpg_eval/evaluate.py`)

A function is flagged if its variant has any finding inside it. Each pair
gets one outcome from `outcome` (`evaluate.py:33`): correct, both,
neither or reversed. A flag on the vulnerable side is a TP, and a flag on
the patched side is an FP.

- `pick` (`evaluate.py:93`) chooses the variant with the best dev
  precision, breaking ties on TP count. Only that variant is scored on test.
  `--show-all-test` prints the rest, but numbers you choose after looking at
  them aren't a held-out result.
- `bootstrap_ci` (`evaluate.py:51`) resamples pairs 2,000 times with a fixed
  seed. The interval is the same on every run.

Output: `out/report.md`, also printed to the terminal.

## 7. Reading the result

Test precision for `unchecked_index` is 0.516, CI 0.50 to 0.56. With paired
labels, 0.5 is what you get from flagging both sides of every pair. So the
detector barely beats a coin flip. That's expected, because the pattern a
function-level rule matches usually survives the fix. The useful output is
the harness. Any detector that can write `(file, function)` findings to
`out/findings.json` can be scored on the same 41 test pairs.

## 8. Tests

    python3 -m unittest discover -s tests -t .

19 tests cover hunk parsing, path safety, SHA validation, zip size capping,
label cleaning, dedup and leak removal, the four outcomes, the precision
maths and variant selection. They don't need Joern or the network.
