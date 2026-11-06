import io
import json
import unittest
import zipfile
from contextlib import redirect_stdout

from cpg_eval.osv import crash_frames, crash_type, fixes_for, load_records

DETAILS = (
    "OSS-Fuzz report: https://example.invalid/1\n\n```\n"
    "Crash type: Heap-buffer-overflow READ 1\n"
    "Crash state:\nndpi_search_dns\ncheck_ndpi_udp_flow_func\nndpi_detection_process_packet\n```\n"
)
SHA = "a" * 40


def record(osv_id: str, sha: str, published: str = "2021-01-01T00:00:00Z") -> dict:
    return {
        "id": osv_id,
        "published": published,
        "details": DETAILS,
        "affected": [{
            "package": {"name": "ndpi"},
            "ranges": [{"type": "GIT", "repo": "https://x.invalid/r.git", "events": [{"fixed": sha}]}],
        }],
    }


class OsvTest(unittest.TestCase):
    def test_crash_frames_stop_at_fence(self):
        self.assertEqual(
            crash_frames(DETAILS),
            ["ndpi_search_dns", "check_ndpi_udp_flow_func", "ndpi_detection_process_packet"],
        )
        self.assertEqual(crash_type(DETAILS), "Heap-buffer-overflow READ 1")

    def test_missing_crash_state(self):
        self.assertEqual(crash_frames("no stack here"), [])

    def test_records_sharing_a_fix_merge(self):
        fixes = fixes_for([record("A", SHA, "2021-05-01"), record("B", SHA, "2021-02-01")], "ndpi")
        self.assertEqual(len(fixes), 1)
        self.assertEqual(fixes[0]["osv_ids"], ["A", "B"])
        self.assertEqual(fixes[0]["published"], "2021-02-01")

    def test_rejects_non_sha_fixed_values(self):
        self.assertEqual(fixes_for([record("A", "--upload-pack=evil")], "ndpi"), [])
        self.assertEqual(fixes_for([record("A", "v1.2.3")], "ndpi"), [])

    def test_other_packages_ignored(self):
        self.assertEqual(fixes_for([record("A", SHA)], "libxml2"), [])

    def test_load_records_skips_oversized_members(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("small.json", json.dumps(record("A", SHA)))
            zf.writestr("big.json", json.dumps({"pad": "x" * 5000}))
            zf.writestr("readme.txt", "not json")
        with redirect_stdout(io.StringIO()):
            records = load_records(buf.getvalue(), max_member=1000)
        self.assertEqual([r["id"] for r in records], ["A"])


if __name__ == "__main__":
    unittest.main()
