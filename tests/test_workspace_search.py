"""Workspace search and verification on a non-editable Windows wheel."""

import ctypes as c
from ctypes import wintypes as w
from hashlib import sha256
import json
from pathlib import Path
import subprocess

import test_workspace_registry as fixtures


class WorkspaceSearch(fixtures.WorkspaceCase):
    def prepare(self, sources):
        for path, raw in sources.items():
            self.put(path, raw)
        self.run_pgop("init", ".")
        self.run_pgop("scan")

    def test_w07_multi_source_exact_citations(self):
        expected = {"guide a.txt": "préface\r\nsource integrity\r\nsource integrity".encode(),
                    "guide/sample.md": b"header\nsource integrity\nsource integrity\n",
                    "record.json": b'{"message":"source integrity"}'}
        self.prepare(expected)
        search = self.run_pgop("search", "source integrity")
        self.assertEqual((search["schema"], search["outcome"]), ("pgop.workspace.v1", "FOUND"))
        data = search["data"]
        self.assertEqual(data["successful_native_captured_bytes"], sum(map(len, expected.values())) * 2)
        self.assertEqual([hit["path"] for hit in data["results"]], sorted(expected))
        for hit in data["results"]:
            raw = expected[hit["path"]]
            self.assertEqual(raw[hit["byte_start"]:hit["byte_end"]], b"source integrity")
            self.assertEqual(hit["sha256"], sha256(raw).hexdigest())
            self.assertEqual(hit["line_start"], 1 if hit["path"] == "record.json" else 2)
        self.assertEqual(data["results"][0]["additional_occurrences_in_source"], 1)
        truncated = self.run_pgop("search", "source integrity", "--limit", "2", expected=3)
        self.assertEqual((truncated["outcome"], truncated["data"]["omitted_matching_sources"]), ("TRUNCATED", 1))
        self.assertFalse(truncated["data"]["partial"])
        self.assertEqual((truncated["data"]["verified_occurrences"], truncated["data"]["omitted_occurrences"]), (5, 3))
        self.assertEqual(self.run_pgop("verify")["outcome"], "PASS")
        legacy = self.run_pgop("search", "source integrity", "--file", str(self.project / "guide a.txt"))
        self.assertEqual((legacy["schema_version"], legacy["status"]), ("pgop.search.v1", "FOUND"))

    def test_w08_absence_uses_only_admitted_complete_scope(self):
        self.prepare({"first.txt": b"in scope"})
        self.put("unregistered.md", b"unregistered")
        absent = self.run_pgop("search", "unregistered")
        self.assertEqual((absent["outcome"], absent["data"]["scope"]), ("NO_MATCH", "ACTIVE_REGISTERED_SOURCES"))
        self.put("oversize.txt", b"x" * 262145)
        self.run_pgop("scan", expected=3)
        partial = self.run_pgop("search", "missing text", expected=3)
        self.assertEqual((partial["outcome"], partial["data"]["results"]), ("PARTIAL", []))
        self.assertEqual(partial["data"]["registered_scan"]["reasons"], {"SOURCE_LIMIT": 1})

    def test_w09_mutation_same_bytes_replacement_and_missing(self):
        original = b"source integrity"
        self.prepare({name: original for name in ("a.txt", "b.txt", "c.txt", "d.txt")})
        self.put("a.txt", b"another revision")
        self.put(".replacement", original).replace(self.project / "b.txt")
        (self.project / "c.txt").unlink()
        result = self.run_pgop("search", "source integrity", expected=3)["data"]
        self.assertEqual([row["path"] for row in result["results"]], ["d.txt"])
        unavailable = {row["path"]: row for row in result["unavailable"]}
        self.assertEqual(unavailable["b.txt"]["code"], "SOURCE_IDENTITY_CHANGED")
        self.assertTrue(all(row["status"] == "STALE" for row in unavailable.values()))
        self.assertEqual(self.run_pgop("verify", expected=3)["outcome"], "PARTIAL")
        self.run_pgop("scan", "--refresh")
        refreshed = self.run_pgop("search", "another revision", expected=3)["data"]
        self.assertEqual([row["path"] for row in refreshed["results"]], ["a.txt"])
        self.assertEqual([row["path"] for row in refreshed["unavailable"]], ["c.txt"])

    def test_w09_second_pass_suppresses_first_pass_hit(self):
        self.prepare({"changes.txt": b"needle", "stable.txt": b"needle"})
        python = Path(fixtures.EXE).with_name("python.exe")
        script = """
from pathlib import Path
from pgopcore import cli, workspace_search as ws
capture = ws.capture
def change_after_read(root, row, on_read):
    result = capture(root, row, on_read)
    if row["path"] == "changes.txt":
        Path("changes.txt").write_bytes(b"edited")
    return result
ws.capture = change_after_read
raise SystemExit(cli.main(["--json", "search", "needle"]))
"""
        run = subprocess.run([python, "-I", "-B", "-c", script], cwd=self.project, capture_output=True, check=False)
        self.transcript.append({"mode": "installed Python, mutation after first per-source capture",
                                "exit": run.returncode, "stdout": run.stdout.decode("ascii"),
                                "stderr": run.stderr.decode("ascii", errors="backslashreplace")})
        self.assertEqual(run.returncode, 3, self.transcript[-1])
        data = json.loads(run.stdout)["data"]
        self.assertEqual([row["path"] for row in data["results"]], ["stable.txt"])
        self.assertEqual(data["unavailable"][0]["path"], "changes.txt")

    def test_w09_effective_read_sharing_denial(self):
        self.prepare({"held.txt": b"needle", "usable.txt": b"needle"})
        k = c.WinDLL("kernel32", use_last_error=True)
        k.CreateFileW.restype = w.HANDLE
        k.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        k.CloseHandle.argtypes = (w.HANDLE,)
        path = self.project / "held.txt"
        handle = k.CreateFileW(str(path), 0x80000000, 0, None, 3, 128, None)
        self.assertNotEqual(handle, c.c_void_p(-1).value)
        try:
            result = self.run_pgop("search", "needle", expected=3)["data"]
            denied, = result["unavailable"]
            self.assertEqual((denied["path"], denied["winerror"]), (path.name, 32))
            self.assertEqual([row["path"] for row in result["results"]], ["usable.txt"])
        finally:
            k.CloseHandle(handle)
        self.assertEqual(self.run_pgop("verify")["outcome"], "PASS")

    def test_w09_hidden_ancestor_rejected_without_reusing_citations(self):
        self.prepare({"parent/inside.md": b"needle", "outside.md": b"needle"})
        subprocess.run(["attrib.exe", "+H", str(self.project / "parent")],
                       check=True, capture_output=True)
        result = self.run_pgop("search", "needle", expected=3)["data"]
        self.assertEqual([row["path"] for row in result["results"]], ["outside.md"])
        self.assertEqual(result["successful_native_captured_bytes"], 2 * len(b"needle"))
        self.assertEqual(result["unavailable"][0]["code"], "UNSAFE_PATH_ATTRIBUTES")

    def test_w11_requires_scan_and_honors_exact_case(self):
        self.run_pgop("search", "needle", expected=2)
        self.assertEqual(self.run_pgop("verify", "--bad-option", expected=2)["schema"], "pgop.workspace.v1")
        path = self.put("lower.txt", b"needle")
        self.run_pgop("init", ".")
        self.assertEqual(self.run_pgop("verify", expected=2)["native_code"], "SCAN_REQUIRED")
        self.run_pgop("scan")
        middle = path.with_name("middle.txt")
        path.rename(middle)
        middle.rename(path.with_name("LOWER.txt"))
        self.assertEqual(self.run_pgop("verify", expected=3)["outcome"], "PARTIAL")

    def test_w12_python_admitted_as_text_and_invalid_utf8_not_registered(self):
        self.put("python-text.py", b"raise RuntimeError('needle')")
        self.put("text.txt", b"\xff")
        self.put("binary.txt", b"needle\0disabled")
        self.put("safe.json", b'{"help":"needle"}')
        self.run_pgop("init", ".")
        scan = self.run_pgop("scan", expected=3)["data"]
        self.assertEqual([row["path"] for row in scan["candidates"]], ["python-text.py", "safe.json"])
        self.assertEqual(scan["reasons"], {"NUL_REJECTED": 1, "UTF8_INVALID": 1})
        result = self.run_pgop("search", "needle", expected=3)["data"]
        self.assertEqual([row["path"] for row in result["results"]], ["python-text.py", "safe.json"])
