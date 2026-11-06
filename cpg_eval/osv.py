"""Download OSV's OSS-Fuzz records and keep the fix commits for one project.

Several OSV records can share a fix commit, so the output has one line per
fix commit with the union of the crash frames from every record that names it.
"""

import argparse
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_MEMBER_BYTES = 1 << 20  # real records are a few KB


def crash_frames(details: str) -> list[str]:
    """Pull the 'Crash state:' frames out of an OSS-Fuzz details block."""
    lines = details.splitlines()
    try:
        start = lines.index("Crash state:") + 1
    except ValueError:
        return []
    frames = []
    for line in lines[start:]:
        line = line.strip()
        if not line or line.startswith("```"):
            break
        frames.append(line)
    return frames


def crash_type(details: str) -> str:
    m = re.search(r"^Crash type: (.+)$", details, re.MULTILINE)
    return m.group(1).strip() if m else ""


def fixes_for(records: list[dict], package: str) -> list[dict]:
    by_sha: dict[str, dict] = {}
    for rec in records:
        details = rec.get("details", "")
        for affected in rec.get("affected", []):
            if affected.get("package", {}).get("name") != package:
                continue
            for rng in affected.get("ranges", []):
                if rng.get("type") != "GIT":
                    continue
                for event in rng.get("events", []):
                    sha = event.get("fixed", "")
                    # The SHA goes into git commands later, so reject anything
                    # that isn't a plain 40-char hex commit id.
                    if not SHA_RE.match(sha):
                        continue
                    fix = by_sha.setdefault(sha, {
                        "fix_commit": sha,
                        "repo": rng.get("repo", ""),
                        "osv_ids": [],
                        "published": rec.get("published", ""),
                        "crash_types": [],
                        "crash_frames": [],
                    })
                    fix["osv_ids"].append(rec["id"])
                    fix["published"] = min(fix["published"], rec.get("published", ""))
                    ctype = crash_type(details)
                    if ctype and ctype not in fix["crash_types"]:
                        fix["crash_types"].append(ctype)
                    for frame in crash_frames(details):
                        if frame not in fix["crash_frames"]:
                            fix["crash_frames"].append(frame)
    return sorted(by_sha.values(), key=lambda f: f["published"])


def load_records(zip_bytes: bytes, max_member: int = MAX_MEMBER_BYTES) -> list[dict]:
    # Read members in memory instead of extracting, so archive paths never
    # touch the filesystem. Reading at most max_member + 1 bytes caps memory
    # even if a member's header understates its size.
    records = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            with zf.open(name) as fh:
                data = fh.read(max_member + 1)
            if len(data) > max_member:
                print(f"skip oversized zip member {name!r}")
                continue
            records.append(json.loads(data))
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", default="ndpi")
    ap.add_argument("--zip", type=Path, help="use a local copy of all.zip instead of downloading")
    ap.add_argument("--out", type=Path, default=Path("data/fixes.jsonl"))
    args = ap.parse_args()

    if args.zip:
        zip_bytes = args.zip.read_bytes()
    else:
        with urllib.request.urlopen(OSV_URL, timeout=120) as resp:
            zip_bytes = resp.read()

    fixes = fixes_for(load_records(zip_bytes), args.package)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for fix in fixes:
            fh.write(json.dumps(fix) + "\n")
    print(f"{len(fixes)} fix commits for {args.package} -> {args.out}")


if __name__ == "__main__":
    main()
