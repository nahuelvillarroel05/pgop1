"""Physical Windows registry tests against an explicitly selected, installed wheel."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

EXE = os.environ.get("PGOP_WORKSPACE_EXE")
HOME = os.environ.get("PGOP_WORKSPACE_TEST_ROOT")


@unittest.skipUnless(os.name == "nt" and EXE and HOME, "set explicit installed CLI and disposable Windows test root")
class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.project = Path(tempfile.mkdtemp(prefix="new project ", dir=HOME))
        self.transcript = []
        self.addCleanup(self.save_transcript)

    def save_transcript(self):
        (self.project / ".test-transcript.json").write_text(
            json.dumps(self.transcript, indent=2, ensure_ascii=True), encoding="utf-8"
        )

    def run_pgop(self, *args, expected=0, cwd=None, env=None):
        p = subprocess.run([EXE, "--json", *args], cwd=cwd or self.project, env=env,
                           capture_output=True, timeout=45, check=False)
        self.transcript.append({"argv": args, "exit": p.returncode,
                                "stdout": p.stdout.decode("ascii", errors="backslashreplace"),
                                "stderr": p.stderr.decode("ascii", errors="backslashreplace")})
        self.assertEqual(p.returncode, expected, self.transcript[-1])
        self.assertEqual(p.stderr, b"", self.transcript[-1])
        return json.loads(p.stdout)

    def put(self, path, raw=b"note integrity"):
        target = self.project / path
        target.parent.mkdir(exist_ok=True, parents=True)
        target.write_bytes(raw)
        return target

    @property
    def journal(self):
        return self.project / ".pgopcore/registry"

class WorkspaceRegistry(WorkspaceCase):
    def test_w02_w03_init_preserves_inputs_and_rejects_foreign_state(self):
        source = self.put("note with spaces.txt")
        self.assertEqual(self.run_pgop("init", ".")["outcome"], "CREATED")
        self.assertEqual(self.run_pgop("init", ".")["outcome"], "ALREADY_INITIALIZED")
        self.assertEqual(source.read_bytes(), b"note integrity")
        self.assertEqual(list(self.journal.iterdir()), [])
        foreign = self.project / "other"
        foreign.mkdir()
        shutil.copytree(self.project / ".pgopcore", foreign / ".pgopcore")
        self.assertEqual(self.run_pgop("init", ".", cwd=foreign, expected=3)["native_code"],
                         "INVALID_WORKSPACE_STATE")

    def test_w04_preview_does_not_decode_and_scan_pins_sources(self):
        self.put("manual.txt", b"fresh")
        self.put("guide/intro.md", b"nested")
        self.put("guide/broken.txt", b"\xff")
        self.run_pgop("init", ".")
        preview = self.run_pgop("scan", "--preview")["data"]
        self.assertEqual([x["path"] for x in preview["candidates"]],
                         ["guide/broken.txt", "guide/intro.md", "manual.txt"])
        self.assertEqual((preview["captured_valid_bytes"], preview["revision"]), (0, 0))
        self.assertEqual(list(self.journal.iterdir()), [])
        scan = self.run_pgop("scan", expected=3)["data"]
        self.assertEqual((scan["registered_sources"], scan["reasons"]), (2, {"UTF8_INVALID": 1}))
        catalog = self.run_pgop("catalog", "--limit", "1")["data"]
        self.assertEqual(catalog["source_verification"], "NOT_PERFORMED")
        self.assertEqual(catalog["next_offset"], 1)
        self.assertEqual(catalog["items"][0]["sha256"], sha256(b"nested").hexdigest())

    def test_w05_policy_and_physical_exclusions(self):
        allowed = self.put("manual.txt")
        for name in (".env.txt", ".ssh/inside.txt", "node_modules/pkg.md",
                     "credential.txt", "build/archive.md", "code.exe"):
            self.put(name, b"\xff forbidden")
        self.put("hidden/skip.txt", b"\xff forbidden")
        subprocess.run(["attrib.exe", "+H", str(self.project / "hidden")], check=True, capture_output=True)
        os.link(allowed, self.project / "alias.txt")
        self.put("visible.md", b"one body")
        outside = self.project.with_name(self.project.name + "-outside")
        outside.mkdir()
        (outside / "outside.txt").write_bytes(b"\xff not allowed")
        proc = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(self.project / "alias-dir"),
                               str(outside)], capture_output=True, check=True)
        self.transcript.append({"control": "NTFS junction created", "exit": proc.returncode})
        self.run_pgop("init", ".")
        scan = self.run_pgop("scan")["data"]
        self.assertEqual([row["path"] for row in scan["candidates"]], ["visible.md"])
        self.assertEqual(scan["excluded"]["HARDLINK"], 2)
        self.assertGreaterEqual(scan["excluded"]["ATTRIBUTES_OR_REPARSE"], 2)
        self.assertEqual(scan["captured_valid_bytes"], len(b"one body"))

    def test_w05_source_file_byte_and_depth_budgets(self):
        self.put("large.txt", b"x" * 262145)
        self.put("a/b/c/d/e/f/really deep.txt")
        for i in range(102):
            self.put(f"small/a{i:03}.md", b"one")
        self.run_pgop("init", ".")
        scan = self.run_pgop("scan", expected=3)["data"]
        self.assertEqual(scan["registered_sources"], 100)
        self.assertEqual(scan["reasons"], {"DEPTH_LIMIT": 1, "SOURCE_LIMIT": 1, "REGISTRY_LIMIT": 2})

    def test_w05_corpus_byte_budget(self):
        for i in range(33):
            self.put(f"a{i:03}.txt", b"x" * 262144)
        self.run_pgop("init", ".")
        preview = self.run_pgop("scan", "--preview", expected=3)["data"]
        self.assertEqual((preview["candidate_bytes"], preview["captured_valid_bytes"]), (8388608, 0))
        self.assertEqual(len(preview["candidates"]), 32)
        self.assertEqual(preview["reasons"], {"CORPUS_BYTE_LIMIT": 1})

    def test_w05_entry_budget_includes_excluded_names(self):
        for i in range(1003):
            self.put(f"file{i:04}.bin", b"")
        self.run_pgop("init", ".")
        preview = self.run_pgop("scan", "--preview", expected=3)["data"]
        self.assertEqual(preview["examined_entries"], 1000)
        self.assertGreater(preview["native_decoded_entries"], 1000)
        self.assertEqual(preview["candidates"], [])
        self.assertEqual(preview["reasons"], {"DIRECTORY_ENTRY_BUDGET": 1})

    def test_w06_deny_ambiguous_roots_and_skip_unsupported_names(self):
        for path in (self.project.anchor, "..", "relative", r"D:\p:alternate", r"\\server\share",
                     str(self.project).replace("new project", "NEW PROJECT"),
                     str(self.project / "café")):
            with self.subTest(path=path):
                self.run_pgop("init", path, expected=2)
        home = os.environ.get("USERPROFILE")
        if home:
            altered = dict(os.environ, USERPROFILE=str(self.project))
            self.assertEqual(self.run_pgop("init", home, env=altered, expected=2)["native_code"],
                             "ROOT_NOT_ALLOWED")
        self.put("café.txt", b"\xff")
        self.put("new.txt", b"admitted")
        self.run_pgop("init", ".")
        scan = self.run_pgop("scan", expected=3)["data"]
        self.assertEqual([item["path"] for item in scan["candidates"]], ["new.txt"])
        self.assertEqual(scan["reasons"], {"UNSAFE_PATH": 1})

    def test_journal_ignores_interrupted_draft_and_rejects_missing_published_draft(self):
        self.put("fresh.txt")
        self.run_pgop("init", ".")
        (self.journal / ("draft-" + "a" * 32 + ".json")).write_bytes(b"orphan")
        self.assertEqual(self.run_pgop("scan")["data"]["revision"], 1)
        self.assertEqual(self.run_pgop("scan")["data"]["revision"], 2)
        old = next(self.journal.glob("commit-0001-*"))
        draft = self.journal / f'draft-{old.name.split("-")[2]}.json'
        draft.rename(self.project / ".old-draft-backup")
        self.assertEqual(self.run_pgop("catalog", expected=3)["native_code"], "INVALID_WORKSPACE_STATE")

    def test_w09_removal_survives_refresh(self):
        self.put("withdraw.txt")
        self.run_pgop("init", ".")
        self.run_pgop("scan")
        source_id = self.run_pgop("catalog")["data"]["items"][0]["id"]
        self.run_pgop("catalog", "remove", source_id)
        repeated = self.run_pgop("catalog", "remove", source_id)
        self.assertEqual(self.run_pgop("scan", "--refresh")["data"]["removed_sources"], 1)
        self.assertEqual(repeated["data"]["revision"], 2)
