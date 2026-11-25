"""Regression coverage for the CLI report contract and local consistency."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "cli"), str(ROOT / "runtime")]
from candidate import public_handoff
from pgopcore import cli


class Reports(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = self.root / "Informes ñ"
        self.source = self.root / "catalog"
        shutil.copytree(ROOT / "runtime/public_profile", self.source)

    def invoke(self, *args, store=None, factory=None):
        arguments = cli.parser().parse_args(["--json", "report", *args, "--store",
                                             str(self.store if store is None else store)])
        def profile(package_root, output_root):
            return public_handoff.PublicProfile(self.source, output_root)
        return cli.backend_result(arguments, public_handoff, factory or profile)

    def create(self, key="demo"):
        return self.invoke("create", "RUN012_PUBLIC", "--request-key", key)

    def test_repeat_and_page_verified_bytes(self):
        result, code = self.create()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.create(), (result, code))
        metadata = result["data"]
        self.assertEqual(metadata["generation"], "REPORT_GENERATED")
        self.assertEqual(metadata["verification"]["status"], "PASS")
        report_id = metadata["report_id"]
        shown, code = self.invoke("show", report_id)
        self.assertEqual(code, 0)
        self.assertIsNone(shown["native_status"])
        for artifact in shown["data"]["artifacts"]:
            actual = (self.store / report_id / artifact).read_bytes()
            offset, pages = 0, []
            while offset is not None:
                page, code = self.invoke("read", report_id, "--artifact", artifact,
                                         "--offset", str(offset), "--limit", "251")
                self.assertEqual(code, 0)
                page = page["data"]
                self.assertEqual(page["sha256"], public_handoff.sha(actual))
                self.assertEqual(page["offset"], offset)
                pages.append(page["content"])
                offset = page["next_offset"]
            self.assertEqual("".join(pages).encode(), actual)

    def test_current_receipt_is_required_and_conflict_preserves_original(self):
        report, _ = self.create()
        report_id = report["data"]["report_id"]
        source = self.source / "run012/HISTORICAL_MANIFEST.json"
        source.write_bytes(source.read_bytes() + b" ")
        conflict, code = self.create()
        self.assertEqual((code, conflict["native_code"]), (4, "REQUEST_KEY_CONFLICT"))
        generated, code = self.create("fresh")
        self.assertEqual((code, generated["native_status"]), (3, "FAIL"))
        self.assertEqual(generated["data"]["generation"], "REPORT_GENERATED")
        self.assertEqual(self.invoke("show", report_id)[1], 0)

    def test_missing_completion_and_corruption_fail_closed(self):
        report, _ = self.create()
        report_id = report["data"]["report_id"]
        root = self.store / report_id
        marker = root / "COMPLETE.json"
        marker_body = marker.read_bytes()
        marker.unlink()
        result, code = self.invoke("read", report_id)
        self.assertEqual((code, result["native_code"]), (4, "ATTEMPT_IN_PROGRESS_OR_INTERRUPTED"))
        self.assertEqual(self.create()[0]["native_code"], "ATTEMPT_IN_PROGRESS_OR_INTERRUPTED")
        self.assertFalse(marker.exists())
        marker.write_bytes(marker_body + b" ")
        self.assertEqual(self.create()[0]["native_code"], "ARTIFACT_INTEGRITY_ERROR")
        marker.write_bytes(b"{")
        for member in ("COMPLETE.json", "FINAL_HANDOFF.md", "REQUEST.json", "MANIFEST.json"):
            with self.subTest(member=member):
                path = root / member
                old = marker_body if path == marker else path.read_bytes()
                path.write_bytes(b"{")
                result, code = self.invoke("read", report_id)
                self.assertEqual((code, result["native_code"]), (3, "ARTIFACT_INTEGRITY_ERROR"))
                self.assertNotIn("content", result["data"])
                path.write_bytes(old)
        request = root / "REQUEST.json"
        request.unlink()
        self.assertEqual(self.create()[0]["native_code"], "ARTIFACT_INTEGRITY_ERROR")
        request.write_bytes(public_handoff.encoded({
            "package_id": "RUN012_PUBLIC", "request_key": "demo", "profile": cli.PROFILE,
            "receipt_id": report["data"]["verification"]["receipt_id"],
        }))
        copy = self.store / ("report-" + "b" * 40)
        shutil.copytree(root, copy)
        self.assertEqual(self.invoke("show", copy.name)[1], 3)

    def test_report_read_does_not_reopen_a_verified_body(self):
        result, _ = self.create()
        report_id = result["data"]["report_id"]
        file = self.store / report_id / "FINAL_HANDOFF.md"
        expected = file.read_bytes()
        actual_reader = public_handoff.report_bytes

        def capture(path):
            body = actual_reader(path)
            if path == file:
                path.write_bytes(b"changed after capture")
            return body

        with patch.object(public_handoff, "report_bytes", side_effect=capture) as opens:
            page, code = self.invoke("read", report_id)
        self.assertEqual(code, 0)
        self.assertEqual(page["data"]["content"].encode(), expected)
        self.assertEqual(sum(c.args == (file,) for c in opens.call_args_list), 1)
        self.assertEqual(self.invoke("read", report_id)[1], 3)

    def test_invalid_paths_are_refused_before_access(self):
        for raw in ("relative", r"\\host\share\reports", str(self.root) + "/../escape",
                    self.root.anchor, ROOT / "outside-data-but-in-checkout"):
            with self.subTest(raw=raw):
                request, code = self.invoke("create", "RUN012_PUBLIC", "--request-key", "key", store=raw,
                                            factory=lambda **_: self.fail("opened profile"))
                self.assertEqual(code, 4)
                self.assertIn(request["native_code"], {"UNSAFE_PATH", "OUTPUT_OVERLAP"})

    def test_create_never_dispatches_with_a_stale_receipt(self):
        source = self.source / "run012/HISTORICAL_MANIFEST.json"
        original = public_handoff.PublicProfile.verify

        def change_after_verify(service, package_id):
            current = original(service, package_id)
            source.write_bytes(source.read_bytes() + b" ")
            return current

        with patch.object(public_handoff.PublicProfile, "verify", change_after_verify):
            payload, code = self.create()
        self.assertEqual((code, payload["native_code"]), (4, "STALE_RECEIPT"))
        self.assertFalse(self.store.exists())


if __name__ == "__main__":
    unittest.main()
