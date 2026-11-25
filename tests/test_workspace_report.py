"""Independent-process retrieval and integrity controls for workspace exports."""

import ctypes as c
from ctypes import wintypes as w
from hashlib import sha256
import json
from pathlib import Path
import os
import subprocess

import test_workspace_registry as fixtures


class WorkspaceReport(fixtures.WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.source = self.put("guide/first note.md", b"line one\nsource integrity\n")
        self.put("record.txt", b"source integrity twice, source integrity")
        self.put("readme.exe", b"sample unsupported data")
        self.put(".env.txt", b"private-ish synthetic name")
        self.run_pgop("init", ".")
        self.run_pgop("scan")

    def test_w13_w17_report_binds_search_bytes_and_citations(self):
        found = self.run_pgop("search", "source integrity")["data"]
        self.assertEqual(self.run_pgop("verify")["outcome"], "PASS")
        saved = self.run_pgop("report", "create", "--query", "source integrity")["data"]
        actual = Path(saved["artifact_path"]).read_bytes()
        report_id = saved["report_id"]
        self.assertEqual(report_id, "ws-report-" + sha256(actual).hexdigest())
        show = self.run_pgop("report", "show", report_id)["data"]
        fresh = show["report"]
        self.assertEqual(fresh, json.loads(actual))
        self.assertEqual(fresh["schema"], "pgop.workspace-search-report.v2")
        self.assertEqual(fresh["evidence"]["results"], found["results"])
        exclusions = fresh["evidence"]["registered_scan"]
        self.assertEqual(exclusions["excluded_paths"], [{"path": "readme.exe", "reason": "UNSUPPORTED_FORMAT"}])
        self.assertNotIn(".env.txt", actual.decode("ascii"))
        self.assertEqual(fresh["source_currentness"], "AT_CAPTURE_ONLY")
        self.assertFalse(show["current_sources_verified_by_this_receipt"])
        self.source.write_bytes(b"new body")
        self.assertEqual(self.run_pgop("verify", expected=3)["outcome"], "PARTIAL")
        self.run_pgop("scan", "--refresh")
        self.assertEqual(self.run_pgop("report", "show", report_id)["data"]["report"], fresh)
        parts, offset = [], 0
        while offset is not None:
            page = self.run_pgop("report", "read", report_id, "--artifact", "REPORT.json",
                                 "--offset", str(offset), "--limit", "701")["data"]
            parts.append(page["content"])
            offset = page["next_offset"]
        self.assertEqual("".join(parts).encode("ascii"), actual)

    def test_w14_partial_report_and_tampering_detected(self):
        self.source.unlink()
        receipt = self.run_pgop("report", "create", "--query", "source integrity", expected=3)["data"]
        report_id = receipt["report_id"]
        payload = self.run_pgop("report", "show", report_id)["data"]["report"]
        self.assertEqual(payload["status"], "PARTIAL")
        self.assertEqual(len(payload["evidence"]["results"]), 1)
        self.assertEqual(payload["evidence"]["unavailable"][0]["path"], "guide/first note.md")
        path = Path(receipt["artifact_path"])
        old = path.read_bytes()
        path.write_bytes(old + b" ")
        self.assertEqual(self.run_pgop("report", "show", report_id, expected=3)["native_code"],
                         "REPORT_INTEGRITY")
        path.write_bytes(old)
        wrong = self.run_pgop("report", "read", "../workspace.json", expected=2)
        self.assertEqual(wrong["native_code"], "INVALID_REPORT_ID")
        unrelated = self.project.with_name(self.project.name + "-extra")
        unrelated.mkdir()
        self.run_pgop("init", ".", cwd=unrelated)
        self.assertEqual(self.run_pgop("report", "show", report_id, cwd=unrelated, expected=4)["native_code"],
                         "REPORT_NOT_FOUND")

    def test_w14_malformed_report_with_consistent_id_is_rejected(self):
        receipt = self.run_pgop("report", "create", "--query", "source integrity")["data"]
        artifact = Path(receipt["artifact_path"])
        report = json.loads(artifact.read_bytes())
        report["evidence"]["results"][0].pop("sha256")
        body = json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        report_id = "ws-report-" + sha256(body).hexdigest()
        artifact.with_name(report_id + ".json").write_bytes(body)
        verdict = self.run_pgop("report", "show", report_id, expected=3)
        self.assertEqual(verdict["native_code"], "REPORT_INTEGRITY")

    def test_w14_hardlink_report_refused(self):
        receipt = self.run_pgop("report", "create", "--query", "source integrity")["data"]
        os.link(receipt["artifact_path"], self.project / "alias.json")
        result = self.run_pgop("report", "read", receipt["report_id"], expected=2)
        self.assertEqual(result["native_code"], "UNSAFE_PATH_HARDLINK")

    def test_w14_read_preserves_report_when_registry_unavailable(self):
        receipt = self.run_pgop("report", "create", "--query", "source integrity")["data"]
        for draft in self.journal.glob("draft-*"):
            draft.rename(self.project / ".archived-draft")
        self.assertEqual(self.run_pgop("catalog", expected=3)["native_code"], "INVALID_WORKSPACE_STATE")
        self.assertEqual(self.run_pgop("report", "show", receipt["report_id"])["outcome"], "VERIFIED_REPORT")

    def test_w15_controls_and_redirected_codepage(self):
        guide = self.put("print.txt", "é 漢\u202e\tmarker".encode())
        self.run_pgop("scan")
        env = dict(os.environ, PYTHONIOENCODING="cp1252:strict")
        p = subprocess.run([fixtures.EXE, "search", "漢\u202e\tmarker"], cwd=self.project,
                           env=env, capture_output=True, check=False)
        self.transcript.append({"mode": "CP1252 redirect", "exit": p.returncode,
                                "stdout_hex": p.stdout.hex(), "stderr_hex": p.stderr.hex()})
        self.assertEqual((p.returncode, p.stderr), (0, b""))
        self.assertIn("漢\\u202e\\tmarker", p.stdout.decode("utf-8", errors="strict"))
        hit = self.run_pgop("search", "漢\u202e\tmarker")["data"]["results"][0]
        self.assertEqual(hit["sha256"], sha256(guide.read_bytes()).hexdigest())

    def test_doctor_is_informational_from_venv_parent(self):
        parent = Path(fixtures.EXE).parents[2]
        doctor = self.run_pgop("doctor", cwd=parent)
        self.assertEqual((doctor["data"]["installation"], doctor["data"]["workspace"]),
                         ("AVAILABLE", "NOT_CONFIGURED"))
        self.assertEqual(doctor["native_code"], "WORKSPACE_LOCATION_OVERLAPS_INSTALLATION")

    def test_registry_writes_require_native_lock(self):
        k = c.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = w.HANDLE
        k.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        k.CloseHandle.argtypes = (w.HANDLE,)
        handle = k.CreateFileW(str(self.project / ".pgopcore/lock"), 0x80000000, 1, None, 3, 128, None)
        self.assertNotEqual(handle, c.c_void_p(-1).value)
        try:
            self.assertEqual(self.run_pgop("scan", expected=4)["native_code"], "WORKSPACE_BUSY")
            self.assertEqual(self.run_pgop("catalog")["data"]["revision"], 1)
        finally:
            k.CloseHandle(handle)
        self.assertEqual(self.run_pgop("scan")["data"]["revision"], 2)
