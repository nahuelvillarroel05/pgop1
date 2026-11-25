"""Acceptance matrix run explicitly from the non-editable Windows wheel."""

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("PGOP_SEARCH_RECEIPTS"), "Run with the isolated installed wheel")
class InstalledSearch(unittest.TestCase):
    def setUp(self):
        from pgopcore import search

        self.search = search
        self.assertTrue(Path(search.__file__).is_relative_to(Path(sys.prefix)))
        self.assertFalse(ctypes.windll.shell32.IsUserAnAdmin())
        temporary = tempfile.TemporaryDirectory(prefix="file-", dir=Path.cwd())
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.source = self.folder / "source.txt"

    def lookup(self, phrase="needle", paths=None):
        return self.search.search(phrase, [str(self.source)] if paths is None else paths)

    def refusal(self, result, status, exit_code):
        out, code = result
        self.assertEqual((out["status"], code), (status, exit_code), out)
        self.assertEqual(out["results"], [])
        self.assertIsNone(out["source"])
        self.assertIsNotNone(out["error"])
        return out["error"]["code"]

    def test_01_exact_literal_lines_and_independent_hash(self):
        raw = "ignored\r\ncafé needle\r\nlast needle".encode()
        self.source.write_bytes(raw)
        out, code = self.lookup("needle\r\nlast")
        self.assertEqual((out["status"], code), ("FOUND", 0))
        hit, = out["results"]
        self.assertEqual((hit["line_start"], hit["line_end"]), (2, 3))
        self.assertEqual(hit["excerpt"], "needle\r\nlast")
        self.assertEqual(raw[hit["byte_start"]:hit["byte_end"]], b"needle\r\nlast")
        self.assertEqual(out["source"]["bytes"], len(raw))
        self.assertEqual(out["source"]["path"], str(self.source))
        with self.source.open("rb") as file:
            self.assertEqual(out["source"]["sha256"], hashlib.file_digest(file, "sha256").hexdigest())
        out, _ = self.lookup("needle\r\n")
        self.assertEqual(out["results"][0]["line_end"], 2)
        out, _ = self.lookup("last needle")
        self.assertEqual(out["results"][0]["line_start"], 3)

    def test_02_no_match_and_case_sensitivity(self):
        self.source.write_bytes(b"NEEDLE\n")
        out, code = self.lookup()
        self.assertEqual((out["status"], code), ("NO_MATCH", 0))
        self.assertEqual(out["results"], [])
        self.assertIsNone(out["error"])
        self.assertEqual(out["source"]["sha256"], hashlib.sha256(b"NEEDLE\n").hexdigest())

    def test_03_unicode_text_and_unsupported_path(self):
        self.source.write_bytes("éclair\r中文 needle\n".encode())
        out, code = self.lookup("中文")
        self.assertEqual((out["status"], code), ("FOUND", 0))
        self.assertEqual(out["results"][0]["excerpt"], "中文")
        self.assertEqual(out["results"][0]["line_start"], 2)
        self.refusal(self.lookup(paths=[str(self.folder / "café.txt")]), "UNSUPPORTED_PATH", 2)
        protected = self.folder / ".git" / self.source.name
        self.assertEqual(self.refusal(self.lookup(paths=[str(protected)]), "UNSUPPORTED_PATH", 2),
                         "SENSITIVE_PATH")
        self.refusal(self.lookup(paths=[str(Path(sys.prefix, self.source.name))]), "UNSUPPORTED_PATH", 2)

    def test_04_no_file_duplicate_and_no_neighbor_discovery(self):
        self.source.write_bytes(b"blank\n")
        (self.folder / "neighbor.txt").write_bytes(b"needle\n")
        with patch.object(self.search, "admit", wraps=self.search.admit) as admit:
            self.refusal(self.lookup(paths=[]), "INVALID_SOURCE", 2)
            self.refusal(self.lookup(paths=[str(self.source)] * 2), "INVALID_SOURCE", 2)
            self.assertEqual(admit.call_count, 0)
        self.assertEqual(self.lookup()[0]["status"], "NO_MATCH")
        source = self.search.admit(str(self.source))
        policy = json.loads(source.policy_raw)
        self.assertEqual(policy["allow_exact"], [self.source.name])
        self.assertEqual(len(json.loads(source.catalog_raw)["sources"]), 1)

    def test_05_file_missing(self):
        self.refusal(self.lookup(), "FILE_NOT_FOUND", 4)

    def test_06_mutation_replacement_and_disappearance(self):
        admit = self.search.admit
        acquire = self.search.text.acquire
        for change in ("same-size edit", "same-byte replacement", "removed between reads", "no-match stale"):
            with self.subTest(change=change):
                before = b"nothing\n" if change == "no-match stale" else b"needle\n"
                self.source.write_bytes(before)
                if change in ("same-size edit", "same-byte replacement"):
                    def change_after_admission(path):
                        binding = admit(path)
                        if change == "same-size edit":
                            self.source.write_bytes(b"editen\n")
                        else:
                            replacement = self.folder / "replacement.txt"
                            replacement.write_bytes(before)
                            replacement.replace(self.source)
                        return binding
                    with patch.object(self.search, "admit", side_effect=change_after_admission):
                        self.refusal(self.lookup(), "STALE", 3)
                else:
                    calls = 0
                    def remove_after_first_capture(*args, **kwargs):
                        nonlocal calls
                        result = acquire(*args, **kwargs)
                        calls += 1
                        if calls == 1:
                            self.source.unlink()
                        return result
                    with patch.object(self.search.text, "acquire", side_effect=remove_after_first_capture):
                        self.refusal(self.lookup(), "STALE", 3)
                    self.assertEqual(calls, 1)

    def test_07_effective_read_denial_and_io_error(self):
        self.source.write_bytes(b"needle\n")
        capture = self.search.native_capture.capture
        for fail_on, error, status, code in (
            (1, PermissionError(errno.EACCES, "fixture access denied"), "PERMISSION_DENIED", 4),
            (2, self.search.native_io.SafeIOError("SOURCE_UNAVAILABLE_OR_UNSAFE", winerror=5),
             "PERMISSION_DENIED", 4),
            (3, OSError(errno.EIO, "fixture read error"), "INTERNAL_ERROR", 1),
        ):
            with self.subTest(fail_on=fail_on):
                calls = 0
                def effective_read(*args):
                    nonlocal calls
                    calls += 1
                    if calls == fail_on:
                        raise error
                    return capture(*args)
                with patch.object(self.search.native_capture, "capture", side_effect=effective_read):
                    self.refusal(self.lookup(), status, code)
                self.assertEqual(calls, fail_on)
        self.assertEqual(self.lookup()[0]["status"], "FOUND")
        safe_read = self.search.native_io.safe_read
        code_reads = 0
        def lose_installed_code(*args):
            nonlocal code_reads
            code_reads += 1
            if code_reads == len(self.search.text.CODE_FILES) + 1:
                raise self.search.native_io.SafeIOError("SOURCE_UNAVAILABLE_OR_UNSAFE", winerror=5)
            return safe_read(*args)
        with patch.object(self.search.native_io, "safe_read", side_effect=lose_installed_code):
            self.assertEqual(self.refusal(self.lookup(), "INTERNAL_ERROR", 1), "INSTALLED_CODE_UNAVAILABLE")

    def test_08_no_junction_symlink_or_hardlink(self):
        self.source.write_bytes(b"needle\n")
        hard = self.folder / "hard.txt"
        os.link(self.source, hard)
        try:
            self.refusal(self.lookup(paths=[str(hard)]), "UNSUPPORTED_PATH", 2)
        finally:
            hard.unlink()
        actual = self.folder / "target"
        actual.mkdir()
        (actual / self.source.name).write_bytes(b"needle\n")
        junction = self.folder / "junction"
        shell = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
        subprocess.run([str(shell), "/d", "/c", "mklink", "/J", str(junction), str(actual)],
                       check=True, capture_output=True)
        try:
            self.refusal(self.lookup(paths=[str(junction / self.source.name)]), "UNSUPPORTED_PATH", 2)
        finally:
            junction.rmdir()
        linked = self.folder / "linked.txt"
        try:
            linked.symlink_to(self.source)
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (5, 1314):
                raise
            self.skipTest(f"Junction and hardlink checked; file symlink creation denied by Windows ({exc.winerror})")
        try:
            self.refusal(self.lookup(paths=[str(linked)]), "UNSUPPORTED_PATH", 2)
        finally:
            linked.unlink()

    def test_09_unsafe_windows_spellings(self):
        for path in (r"\\server\share\source.txt", r"C:source.txt", str(self.source) + ":stream",
                     str(self.folder) + r"\..\source.txt", str(self.folder) + r"\source.txt.",
                     str(self.folder) + r"\\source.txt", str(self.folder) + r"\NUL.txt",
                     r"\\?\C:\source.txt", r"\source.txt", "COM1 .txt", "source*.txt", "source.txt "):
            with self.subTest(path=path):
                self.refusal(self.lookup(paths=[path]), "UNSUPPORTED_PATH", 2)
        self.source.write_bytes(b"needle")
        out, code = self.lookup(paths=[str(self.source.with_name("Source.txt"))])
        self.assertIn((out["status"], code), {("UNSUPPORTED_PATH", 2), ("FILE_NOT_FOUND", 4)})
        self.assertEqual(out["results"], [])

    def test_10_invalid_utf8_and_binary(self):
        for body, native in ((b"needle\xff", "UTF8_INVALID"),
                             (b"needle\0binary", "NUL_REJECTED"),
                             (b"needle\x01\x02", "BINARY_CONTROLS"),
                             (b"\xef\xbb\xbfneedle", "BOM_REJECTED")):
            self.source.write_bytes(body)
            self.assertEqual(self.refusal(self.lookup(), "INVALID_SOURCE", 2), native)
        markdown = self.folder / "source.md"
        markdown.write_bytes(b"# needle\n")
        self.assertEqual(self.lookup(paths=[str(markdown)])[0]["status"], "FOUND")
        data = self.folder / "source.json"
        data.write_bytes(b'{"needle": true}\n')
        self.assertEqual(self.lookup(paths=[str(data)])[0]["status"], "FOUND")
        data.write_bytes(b'{"needle": ')
        self.assertEqual(self.refusal(self.lookup(paths=[str(data)]), "INVALID_SOURCE", 2), "JSON_INVALID")

    def test_11_source_line_literal_and_result_limits(self):
        self.source.write_bytes(b"x" * (self.search.MAX_BYTES + 1))
        self.assertEqual(self.refusal(self.lookup(), "INVALID_SOURCE", 2), "SOURCE_LIMIT")
        self.source.write_bytes(b"\n" * (self.search.MAX_LINES + 1))
        self.assertEqual(self.refusal(self.lookup(), "INVALID_SOURCE", 2), "LINE_LIMIT")
        self.source.write_bytes(b"\n" * (self.search.MAX_LINES - 1) + b"needle needle\n")
        out, code = self.lookup()
        self.assertEqual((out["status"], code, out["truncated"]), ("FOUND", 0, True))
        self.assertEqual(out["remaining_occurrences"], 1)
        self.assertEqual(out["results"][0]["line_start"], self.search.MAX_LINES)
        self.refusal(self.lookup("x" * 257), "INVALID_SOURCE", 2)

    def test_12_installed_entrypoint_in_cmd_and_powershell(self):
        self.source.write_bytes(b"test\r\nneedle\r\n")
        launcher = Path(sys.executable).with_name("pgop.exe")
        shells = Path(os.environ["SystemRoot"]) / "System32"
        logs = Path(os.environ["PGOP_SEARCH_RECEIPTS"])
        evidence = []
        for shell in ("CMD", "PowerShell"):
            for case, args, expected, status in (
                ("found", ["search", "needle", "--file", str(self.source), "--json"], 0, "FOUND"),
                ("absent", ["--json", "search", "absent", "--file", str(self.source)], 0, "NO_MATCH"),
                ("missing", ["--json", "search", "needle", "--file", str(self.folder / "absent.txt")],
                 4, "FILE_NOT_FOUND"),
                ("workspace-needs-init", ["search", "needle", "--json"], 2, "INIT_REQUIRED"),
                ("invalid-syntax", ["search", "--json", "--file"], 2, "INVALID_SOURCE"),
            ):
                if shell == "CMD":
                    cmd = [str(shells / "cmd.exe"), "/d", "/c", str(launcher), *args]
                else:
                    script = "& " + " ".join("'" + value.replace("'", "''") + "'"
                                             for value in (str(launcher), *args))
                    cmd = [str(shells / "WindowsPowerShell/v1.0/powershell.exe"), "-NoProfile",
                           "-Command", script + "; exit $LASTEXITCODE"]
                start = time.perf_counter()
                run = subprocess.run(cmd, capture_output=True, timeout=30)
                stem = f"{shell}-{case}"
                (logs / (stem + ".stdout")).write_bytes(run.stdout)
                (logs / (stem + ".stderr")).write_bytes(run.stderr)
                evidence.append({"test": self._testMethodName, "label": stem, "argv": cmd,
                                 "ms": (time.perf_counter() - start) * 1000, "exit": run.returncode})
                (logs / "SHELL_COMMANDS.json").write_text(json.dumps(evidence, indent=2) + "\n",
                                                          encoding="utf-8")
                self.assertEqual(run.returncode, expected, run.stderr)
                self.assertEqual(run.stderr, b"")
                self.assertEqual(len(run.stdout.splitlines()), 1)
                response = json.loads(run.stdout)
                if case == "workspace-needs-init":
                    self.assertEqual((response["schema"], response["native_code"]),
                                     ("pgop.workspace.v1", status))
                    continue
                self.assertEqual(response["schema_version"], "pgop.search.v1")
                self.assertEqual(response["status"], status)
                if status == "FOUND":
                    self.assertEqual(response["source"]["sha256"],
                                     hashlib.sha256(self.source.read_bytes()).hexdigest())
                    self.assertEqual(response["results"][0]["line_start"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
