"""Copy the files each fix commit changed, before and after, plus diff hunks.

For fix commit F this writes
  data/files/<F>/before/<path>   the file at F^ (first parent)
  data/files/<F>/after/<path>    the file at F
and one line in data/commits.jsonl with the commit date and the changed line
ranges on each side. Joern later parses data/files in a single run.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath

from cpg_eval.osv import SHA_RE

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True, errors="replace",
    ).stdout


def git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def parse_hunks(diff: str) -> tuple[list[list[int]], list[list[int]]]:
    """Return changed [start, end] line ranges for the old and new file.

    A pure insertion has count 0 on the old side. Git then reports the line
    *after which* the insertion happens, so it becomes the one-line range
    [n, n]. Pure deletions get the same treatment on the new side.
    """
    old, new = [], []
    for line in diff.splitlines():
        m = HUNK_RE.match(line)
        if not m:
            continue
        a, b = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
        c, d = int(m.group(3)), int(m.group(4) if m.group(4) is not None else 1)
        old.append([a, a + b - 1] if b else [a, a])
        new.append([c, c + d - 1] if d else [c, c])
    return old, new


def safe_rel(path: str) -> PurePosixPath:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"refusing unsafe path from git: {path!r}")
    return p


def mine_fix(repo: Path, fix: dict, out_dir: Path, prefix: str, max_files: int) -> dict:
    sha = fix["fix_commit"]
    rec = {"fix_commit": sha, "files": []}
    if not SHA_RE.match(sha):
        return {**rec, "skipped": "bad sha"}
    try:
        git(repo, "cat-file", "-e", f"{sha}^{{commit}}")
    except subprocess.CalledProcessError:
        return {**rec, "skipped": "commit not in clone"}

    parents = git(repo, "show", "-s", "--format=%P", sha).split()
    if len(parents) != 1:
        return {**rec, "skipped": f"{len(parents)} parents"}
    parent = parents[0]
    rec["commit_date"] = git(repo, "show", "-s", "--format=%cI", sha).strip()

    changed = [
        p for p in git(repo, "diff", "--name-only", "--diff-filter=M", parent, sha).splitlines()
        if p.startswith(prefix) and p.endswith(".c")
    ]
    if not changed:
        return {**rec, "skipped": f"no modified .c files under {prefix}"}
    if len(changed) > max_files:
        return {**rec, "skipped": f"{len(changed)} files changed (> {max_files})"}

    for path in changed:
        rel = safe_rel(path)
        diff = git(repo, "diff", "-U0", parent, sha, "--", path)
        old, new = parse_hunks(diff)
        for side, rev in (("before", parent), ("after", sha)):
            dest = out_dir / sha / side / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(git_bytes(repo, "show", f"{rev}:{path}"))
        rec["files"].append({"path": path, "old_ranges": old, "new_ranges": new})
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=Path("data/nDPI"))
    ap.add_argument("--fixes", type=Path, default=Path("data/fixes.jsonl"))
    ap.add_argument("--out-dir", type=Path, default=Path("data/files"))
    ap.add_argument("--out", type=Path, default=Path("data/commits.jsonl"))
    ap.add_argument("--prefix", default="src/lib/", help="only library code, not fuzz harnesses")
    ap.add_argument("--max-files", type=int, default=5)
    args = ap.parse_args()

    fixes = [json.loads(line) for line in args.fixes.open()]
    kept = 0
    with args.out.open("w") as fh:
        for fix in fixes:
            rec = mine_fix(args.repo, fix, args.out_dir, args.prefix, args.max_files)
            fh.write(json.dumps(rec) + "\n")
            if "skipped" in rec:
                print(f"skip {fix['fix_commit'][:10]}: {rec['skipped']}")
            else:
                kept += 1
    print(f"{kept}/{len(fixes)} fix commits mined -> {args.out}")


if __name__ == "__main__":
    main()
