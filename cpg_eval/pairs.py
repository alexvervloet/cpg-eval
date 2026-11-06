"""Turn mined fix commits into clean vulnerable/patched function pairs.

Steps, in order:
  1. Map each diff hunk onto the CPG methods it touches, on both sides.
  2. Drop functions whose change is only whitespace or comments.
  3. Label cleaning. Keep changed functions named in the OSS-Fuzz crash state.
     If none are, keep the commit only when it changed exactly one function.
  4. Dedup. Keep the earliest pair for each vulnerable body.
  5. Temporal split on the fix commit date, then drop test pairs whose
     before or after body also appears in dev.
"""

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
SPACE_RE = re.compile(r"\s+")


def normalise(code: str) -> str:
    return SPACE_RE.sub("", COMMENT_RE.sub("", code))


def body_hash(code: str) -> str:
    return hashlib.sha256(normalise(code).encode()).hexdigest()[:16]


def overlaps(start: int, end: int, ranges: list[list[int]]) -> bool:
    return any(a <= end and b >= start for a, b in ranges)


def unique_by_name(methods: list[dict]) -> dict[str, dict]:
    """Methods by name. Names defined twice in one file (usually #ifdef
    variants) are ambiguous and left out."""
    counts = defaultdict(int)
    for m in methods:
        counts[m["name"]] += 1
    return {m["name"]: m for m in methods if counts[m["name"]] == 1}


def touched(methods: dict[str, dict], ranges: list[list[int]]) -> set[str]:
    return {name for name, m in methods.items() if overlaps(m["start"], m["end"], ranges)}


def read_lines(files_dir: Path, rel: str, start: int, end: int) -> str:
    lines = (files_dir / rel).read_text(errors="replace").splitlines()
    return "\n".join(lines[start - 1:end])


def candidate_pairs(commit: dict, by_file: dict[str, list[dict]], files_dir: Path) -> list[dict]:
    sha = commit["fix_commit"]
    out = []
    for f in commit["files"]:
        before_file = f"{sha}/before/{f['path']}"
        after_file = f"{sha}/after/{f['path']}"
        all_before = unique_by_name(by_file.get(before_file, []))
        all_after = unique_by_name(by_file.get(after_file, []))
        # A function counts as changed if a hunk lands in it on either side,
        # but a pair needs it on both sides.
        changed = touched(all_before, f["old_ranges"]) | touched(all_after, f["new_ranges"])
        for name in sorted(changed):
            b, a = all_before.get(name), all_after.get(name)
            if b is None or a is None:
                continue
            before_code = read_lines(files_dir, before_file, b["start"], b["end"])
            after_code = read_lines(files_dir, after_file, a["start"], a["end"])
            if normalise(before_code) == normalise(after_code):
                continue
            out.append({
                "fix_commit": sha,
                "commit_date": commit["commit_date"],
                "path": f["path"],
                "name": name,
                "before_file": before_file,
                "after_file": after_file,
                "before_hash": body_hash(before_code),
                "after_hash": body_hash(after_code),
            })
    return out


def clean_labels(pairs: list[dict], crash_frames: list[str]) -> list[dict]:
    frames = set(crash_frames)
    named = [p for p in pairs if p["name"] in frames]
    if named:
        return [{**p, "label_reason": "in crash state"} for p in named]
    if len(pairs) == 1:
        return [{**pairs[0], "label_reason": "only changed function"}]
    return []


def dedup_and_split(pairs: list[dict], cutoff: str) -> list[dict]:
    pairs = sorted(pairs, key=lambda p: (p["commit_date"], p["fix_commit"], p["name"]))
    seen, unique = set(), []
    for p in pairs:
        if p["before_hash"] in seen:
            continue
        seen.add(p["before_hash"])
        unique.append({**p, "split": "dev" if p["commit_date"] < cutoff else "test"})

    dev_bodies = {h for p in unique if p["split"] == "dev" for h in (p["before_hash"], p["after_hash"])}
    return [
        p for p in unique
        if p["split"] == "dev" or not ({p["before_hash"], p["after_hash"]} & dev_bodies)
    ]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--commits", type=Path, default=Path("data/commits.jsonl"))
    ap.add_argument("--fixes", type=Path, default=Path("data/fixes.jsonl"))
    ap.add_argument("--methods", type=Path, default=Path("out/methods.json"))
    ap.add_argument("--files-dir", type=Path, default=Path("data/files"))
    ap.add_argument("--cutoff", default="2022-01-01", help="fixes before this date go to dev")
    ap.add_argument("--out", type=Path, default=Path("out/pairs.jsonl"))
    args = ap.parse_args()

    frames = {}
    for line in args.fixes.open():
        fix = json.loads(line)
        frames[fix["fix_commit"]] = fix["crash_frames"]

    by_file: dict[str, list[dict]] = defaultdict(list)
    for m in json.loads(args.methods.read_text()):
        by_file[m["file"]].append(m)

    stats = defaultdict(int)
    labelled = []
    for line in args.commits.open():
        commit = json.loads(line)
        if "skipped" in commit:
            continue
        cands = candidate_pairs(commit, by_file, args.files_dir)
        kept = clean_labels(cands, frames.get(commit["fix_commit"], []))
        stats["commits"] += 1
        stats["candidate pairs"] += len(cands)
        stats["commits dropped as ambiguous"] += bool(cands) and not kept
        stats["commits with no changed function"] += not cands
        labelled.extend(kept)

    final = dedup_and_split(labelled, args.cutoff)
    stats["labelled pairs"] = len(labelled)
    stats["dropped as duplicate or leak"] = len(labelled) - len(final)
    stats["dev pairs"] = sum(p["split"] == "dev" for p in final)
    stats["test pairs"] = sum(p["split"] == "test" for p in final)

    with args.out.open("w") as fh:
        for p in final:
            fh.write(json.dumps(p) + "\n")
    for k, v in stats.items():
        print(f"{k:>34}: {v}")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
