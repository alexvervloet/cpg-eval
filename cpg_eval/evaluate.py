"""Score baseline detector findings against the paired dev/test split.

A function is flagged by a variant if the variant reports any finding inside
it. For each pair, a flag on the vulnerable (before) side is a true positive
and a flag on the patched (after) side is a false positive, so

    precision = TP / (TP + FP)

A detector that ignores the fix and flags both sides scores 0.5. That is the
chance line here, not 0.

The variant is chosen on dev only. Test is scored once, with that variant.
"""

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

OUTCOMES = ("correct", "both", "neither", "reversed")


def flagged_sets(findings: list[dict]) -> dict[str, set[tuple[str, str]]]:
    flagged: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for f in findings:
        key = (f["file"], f["name"])
        flagged[f["variant"]].add(key)
        flagged["any"].add(key)
    return flagged


def outcome(pair: dict, flagged: set[tuple[str, str]]) -> str:
    vuln = (pair["before_file"], pair["name"]) in flagged
    patched = (pair["after_file"], pair["name"]) in flagged
    if vuln and not patched:
        return "correct"
    if vuln and patched:
        return "both"
    if patched:
        return "reversed"
    return "neither"


def precision(outcomes: list[str]) -> float | None:
    tp = sum(o in ("correct", "both") for o in outcomes)
    fp = sum(o in ("both", "reversed") for o in outcomes)
    return tp / (tp + fp) if tp + fp else None


def bootstrap_ci(outcomes: list[str], n: int = 2000, seed: int = 0) -> tuple[float, float] | None:
    """95% percentile interval, resampling pairs. Resamples with no flags are
    skipped, since precision is undefined there."""
    rng = random.Random(seed)
    stats = []
    for _ in range(n):
        p = precision(rng.choices(outcomes, k=len(outcomes)))
        if p is not None:
            stats.append(p)
    if not stats:
        return None
    stats.sort()
    return stats[int(0.025 * len(stats))], stats[int(0.975 * len(stats)) - 1]


def score(pairs: list[dict], flagged: set[tuple[str, str]]) -> dict:
    outs = [outcome(p, flagged) for p in pairs]
    tp = sum(o in ("correct", "both") for o in outs)
    fp = sum(o in ("both", "reversed") for o in outs)
    return {
        "pairs": len(pairs),
        "tp": tp,
        "fp": fp,
        "precision": precision(outs),
        "ci95": bootstrap_ci(outs),
        **{o: outs.count(o) for o in OUTCOMES},
    }


def fmt(row: dict) -> str:
    p = "n/a" if row["precision"] is None else f"{row['precision']:.3f}"
    ci = "n/a" if row["ci95"] is None else f"{row['ci95'][0]:.2f}-{row['ci95'][1]:.2f}"
    counts = " | ".join(str(row[o]) for o in OUTCOMES)
    return f"| {row['pairs']} | {row['tp']} | {row['fp']} | {p} | {ci} | {counts} |"


HEADER = (
    "| split | variant | pairs | TP | FP | precision | 95% CI | correct | both | neither | reversed |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|"
)


def pick(dev_scores: dict[str, dict]) -> str:
    """Highest dev precision, then most TPs, then name for a stable tie-break."""
    usable = {v: s for v, s in dev_scores.items() if s["precision"] is not None}
    return max(sorted(usable), key=lambda v: (usable[v]["precision"], usable[v]["tp"]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pairs", type=Path, default=Path("out/pairs.jsonl"))
    ap.add_argument("--findings", type=Path, default=Path("out/findings.json"))
    ap.add_argument("--out", type=Path, default=Path("out/report.md"))
    ap.add_argument("--show-all-test", action="store_true",
                    help="also print unselected variants on test (exploration only, not the result)")
    args = ap.parse_args()

    pairs = [json.loads(line) for line in args.pairs.open()]
    flagged = flagged_sets(json.loads(args.findings.read_text()))
    by_split = {s: [p for p in pairs if p["split"] == s] for s in ("dev", "test")}

    dev_scores = {v: score(by_split["dev"], flagged[v]) for v in sorted(flagged)}
    chosen = pick(dev_scores)
    rows = [f"| dev | {v} {fmt(s)}" for v, s in dev_scores.items()]
    test_variants = sorted(flagged) if args.show_all_test else [chosen]
    for v in test_variants:
        rows.append(f"| test | {v}{' (chosen)' if v == chosen else ''} {fmt(score(by_split['test'], flagged[v]))}")

    report = "\n".join([
        f"Variant chosen on dev: `{chosen}`",
        "",
        HEADER,
        *rows,
        "",
        "Chance line: 0.5. A variant that flags both sides of every pair scores exactly that.",
    ])
    args.out.write_text(report + "\n")
    print(report)


if __name__ == "__main__":
    main()
