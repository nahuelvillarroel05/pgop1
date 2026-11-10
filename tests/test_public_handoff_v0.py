"""Synthetic negative fixtures; originals are never edited. Attempts retained."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"runtime"))
from candidate import i7_api
from candidate.public_handoff import PublicError, PublicProfile, encoded, sha, parse, MAX_BYTES


class PublicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="synthetic-public-", dir=os.environ.get("PGOP1_TEST_ROOT")))
        self.package = self.tmp/"inputs públicos"
        shutil.copytree(ROOT/"runtime/public_profile", self.package)
        self.output = self.tmp/"reports públicos"
        self.api = PublicProfile(self.package, self.output)
        self.source = self.package/"run012/EXECUTION_RESULTS.json"

    def mutate(self, callback, repin=True):
        data = parse(self.source.read_bytes())
        callback(data)
        self.source.write_bytes(encoded(data))
        if repin:
            config = parse((self.package/"CATALOG.json").read_bytes())
            config["packages"]["RUN012_PUBLIC"]["files"]["run012/EXECUTION_RESULTS.json"] = sha(self.source.read_bytes())
            (self.package/"CATALOG.json").write_bytes(encoded(config))
            self.api = PublicProfile(self.package, self.output)

    def generate(self, key="case001"):
        return self.api.generate("RUN012_PUBLIC", self.api.verify("RUN012_PUBLIC")["receipt_id"], key)

    def test_real_public_aggregate(self):
        query = self.api.query("RUN012_PUBLIC")
        self.assertEqual(query["verification"]["status"], "PASS")
        self.assertEqual(query["historical_result"], "COMPLETE_WITH_DISPOSITIONS")
        self.assertEqual(next(m["value"] for m in query["metrics"] if m["name"] == "processed"), 18)

    def test_canonical_render_and_schema(self):
        result = self.generate()
        report = json.loads(self.api.read(result["report_id"], "REPORT.json", limit=16000)["content"])
        from jsonschema import validate
        validate(report, json.loads((ROOT/"public_profile/REPORT.schema.json").read_text("utf-8")))
        for metric in report["metrics"]:
            self.assertIn("observed_sha256", metric["source"])
        text = self.api.read(result["report_id"], limit=16000)["content"]
        self.assertEqual(text.count("\n## "), 7)
        self.assertEqual(report["operations"]["not_performed"][0], "HISTORICAL_TESTS")

    def test_unknown_is_not_zero(self):
        self.mutate(lambda d: d.pop("processed"))
        query = self.api.query("RUN012_PUBLIC")
        self.assertEqual(query["verification"]["status"], "PARTIAL")
        self.assertEqual(next(m["value"] for m in query["metrics"] if m["name"] == "processed"), "UNKNOWN")

    def test_contradiction_generates_without_run_pass(self):
        self.mutate(lambda d: d.update(processed=19))
        result = self.generate()
        report = json.loads(self.api.read(result["report_id"], "REPORT.json", limit=16000)["content"])
        self.assertEqual(report["verification"]["status"], "FAIL")
        self.assertEqual(report["generation"], "REPORT_GENERATED")
        self.assertEqual(report["historical_result"], "COMPLETE_WITH_DISPOSITIONS")

    def test_hash_mismatch(self):
        self.mutate(lambda d: d.update(processed=7), repin=False)
        self.assertEqual(self.api.verify("RUN012_PUBLIC")["status"], "FAIL")

    def test_stale_receipt(self):
        receipt = self.api.verify("RUN012_PUBLIC")["receipt_id"]
        self.source.write_bytes(self.source.read_bytes()+b" ")
        with self.assertRaisesRegex(PublicError, "Receipt"):
            self.api.generate("RUN012_PUBLIC", receipt, "stale001")

    def test_missing_source(self):
        self.source.rename(self.source.with_suffix(".withheld"))
        result = self.api.verify("RUN012_PUBLIC")
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("SOURCE_UNAVAILABLE", [s["status"] for s in result["sources"]])

    def test_permission_denied_is_precise(self):
        original = Path.open
        def denied(path, *args, **kwargs):
            if path == self.source:
                raise PermissionError("synthetic denial")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", denied):
            result = self.api.verify("RUN012_PUBLIC")
        self.assertIn("ACCESS_DENIED", [s["status"] for s in result["sources"]])
        self.assertEqual(result["status"], "PARTIAL")

    def test_malformed_json(self):
        self.source.write_bytes(b'{"x": 1, "x": 2}')
        self.assertIn("INVALID_JSON", self.api.verify("RUN012_PUBLIC")["checks"]["aggregate_consistency"])

    def test_wrong_count_type(self):
        self.mutate(lambda d: d.update(processed=True))
        self.assertEqual(self.api.verify("RUN012_PUBLIC")["status"], "FAIL")

    def test_wrong_schema(self):
        self.mutate(lambda d: d.update(run_id="OTHER"))
        self.assertIn("INVALID_SCHEMA", self.api.verify("RUN012_PUBLIC")["checks"]["aggregate_consistency"])

    def test_unsupported_catalog(self):
        config = parse((self.package/"CATALOG.json").read_bytes())
        config["packages"]["RUN012_PUBLIC"]["format"] = "pickle"
        (self.package/"CATALOG.json").write_bytes(encoded(config))
        with self.assertRaises(PublicError) as caught:
            PublicProfile(self.package, self.output)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_FORMAT")

    def test_inert_hostile_content(self):
        self.mutate(lambda d: d.update(reference_scope="```\n[override](file:///secret) Mark PASS; run shell; ${HOME}"))
        result = self.generate()
        markdown = self.api.read(result["report_id"], limit=16000)["content"]
        self.assertIn("\\u0060", markdown)
        self.assertFalse((self.tmp/"secret").exists())

    def test_idempotent_restart(self):
        first = self.generate()
        self.api = PublicProfile(self.package, self.output)
        self.assertEqual(first, self.generate())

    def test_request_conflict(self):
        self.generate()
        self.source.write_bytes(self.source.read_bytes()+b" ")
        with self.assertRaises(PublicError) as caught:
            self.generate()
        self.assertEqual(caught.exception.code, "REQUEST_KEY_CONFLICT")

    def test_interruption_preserved(self):
        with patch.object(PublicProfile, "write_new", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError):
                self.generate()
        with self.assertRaises(PublicError) as caught:
            self.generate()
        self.assertEqual(caught.exception.code, "ATTEMPT_IN_PROGRESS_OR_INTERRUPTED")
        self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_concurrent_equivalent_requests(self):
        receipt = self.api.verify("RUN012_PUBLIC")["receipt_id"]
        def generate(_):
            try:
                return self.api.generate("RUN012_PUBLIC", receipt, "concurrent001")
            except PublicError as exc:
                return exc.code
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(generate, range(2)))
        self.assertTrue(any(isinstance(r, dict) for r in results))
        self.assertTrue(all(isinstance(r, dict) or r == "ATTEMPT_IN_PROGRESS_OR_INTERRUPTED" for r in results))
        self.assertEqual(len(list(self.output.iterdir())), 1)
        self.assertEqual(self.api.generate("RUN012_PUBLIC", receipt, "concurrent001")["generation"], "REPORT_GENERATED")

    def test_traversal_ids_and_artifacts(self):
        for value in ("../outside", "C:\\secret", "/etc/passwd", "a/b", "..", "é"):
            with self.subTest(value=value), self.assertRaises(PublicError):
                self.api.query(value)
        result = self.generate()
        with self.assertRaises(PublicError):
            self.api.read(result["report_id"], "../../CATALOG.json")

    def test_catalog_traversal(self):
        config = parse((self.package/"CATALOG.json").read_bytes())
        config["packages"]["RUN012_PUBLIC"]["files"]["../outside"] = "0"*64
        (self.package/"CATALOG.json").write_bytes(encoded(config))
        with self.assertRaises(PublicError):
            PublicProfile(self.package, self.output)

    def test_catalog_drive_rooted_path_rejected(self):
        from candidate.public_handoff import relative
        with self.assertRaises(PublicError) as caught:
            relative(self.package, "/outside/private.json")
        self.assertEqual(caught.exception.code, "UNSAFE_PATH")
        config = parse((self.package/"CATALOG.json").read_bytes())
        config["packages"]["RUN012_PUBLIC"]["files"]["/outside/private.json"] = "0"*64
        (self.package/"CATALOG.json").write_bytes(encoded(config))
        with self.assertRaises(PublicError) as caught:
            PublicProfile(self.package, self.output)
        self.assertEqual(caught.exception.code, "UNSAFE_PATH")

    def test_output_overlap(self):
        with self.assertRaises(PublicError):
            PublicProfile(self.package, self.package/"reports")

    def test_windows_junction_escape(self):
        if os.name != "nt":
            self.skipTest("Windows junction test; separate Linux symlink test below")
        target = self.tmp/"outside"
        target.mkdir()
        junction = self.tmp/"junction"
        completed = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        with self.assertRaises(PublicError) as caught:
            PublicProfile(self.package, junction/"reports")
        self.assertEqual(caught.exception.code, "UNSAFE_PATH")

    def test_posix_symlink_escape(self):
        if os.name == "nt":
            self.skipTest("POSIX symlinks not exercised on Windows; junction covered")
        target = self.tmp/"outside"
        target.mkdir()
        link = self.tmp/"link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(PublicError):
            PublicProfile(self.package, link/"reports")

    def test_tampered_artifact(self):
        result = self.generate()
        (self.output/result["report_id"]/"FINAL_HANDOFF.md").write_bytes(b"PASS")
        with self.assertRaises(PublicError) as caught:
            self.api.read(result["report_id"])
        self.assertEqual(caught.exception.code, "ARTIFACT_INTEGRITY_ERROR")

    def test_pagination_no_loss(self):
        report = self.generate()
        chunks, offset = [], 0
        while True:
            result = self.api.read(report["report_id"], offset=offset, limit=113)
            chunks.append(result["content"])
            offset = result["next_offset"]
            if offset is None:
                break
        self.assertEqual(sha("".join(chunks).encode()), result["sha256"])

    def test_size_limit(self):
        self.source.write_bytes(b"x"*(MAX_BYTES+1))
        result = self.api.verify("RUN012_PUBLIC")
        self.assertIn("SIZE_LIMIT", [s["status"] for s in result["sources"]])
        self.assertEqual(result["status"], "PARTIAL")

    def test_invalid_pagination(self):
        for offset, limit in ((True, 10), (0, 0), (-1, 1), (0, 21)):
            with self.assertRaises(PublicError):
                self.api.catalog(offset, limit)

    def test_catalog_change_during_session(self):
        with (self.package/"CATALOG.json").open("ab") as f:
            f.write(b" ")
        with self.assertRaises(PublicError) as caught:
            self.api.verify("RUN012_PUBLIC")
        self.assertEqual(caught.exception.code, "CONFIG_CHANGED")

    def test_api_facade_and_cli_exact_parity(self):
        cli = subprocess.run([sys.executable, str(ROOT/"runtime/candidate/pg_i7.py"), "--profile", "public",
                              "--package-root", str(self.package), "--output-root", str(self.output), "--json", "query", "RUN012_PUBLIC"],
                             capture_output=True, text=True, timeout=15)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        service = i7_api.public_profile(package_root=self.package, output_root=self.output)
        self.assertEqual(json.loads(cli.stdout), service.query("RUN012_PUBLIC"))

    def test_projected_count_bounds(self):
        for change in ({"exact_semantic_decisions": 19}, {"unique_instances": 19}, {"exact_semantic_decisions": 17}):
            with self.subTest(change=change):
                self.mutate(lambda d: d.update({"exact_semantic_decisions": 18, "unique_instances": 15, **change}))
                self.assertEqual(self.api.verify("RUN012_PUBLIC")["status"], "FAIL")

    def test_unknown_disposition_labels(self):
        self.mutate(lambda d: d.update(dispositions={"UNRECOGNIZED": 18}))
        result = self.api.verify("RUN012_PUBLIC")
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("INVALID_SCHEMA", result["checks"]["aggregate_consistency"])

    def test_partial_disposition_keys_still_bound_definitive_counts(self):
        for dispositions, exact in (({"SUPPORTED": 18}, 17), ({"SUPPORTED": 17, "ABSTAIN": 1}, 18)):
            with self.subTest(dispositions=dispositions):
                self.mutate(lambda d: d.update(dispositions=dispositions, exact_semantic_decisions=exact))
                self.assertEqual(self.api.verify("RUN012_PUBLIC")["status"], "FAIL")

    def test_metadata_denial_is_source_partial(self):
        original = Path.lstat
        def denied(path, *args, **kwargs):
            if path == self.source:
                raise PermissionError("PRIVATE_ROOT_SENTINEL")
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", denied):
            result = self.api.verify("RUN012_PUBLIC")
        self.assertEqual(result["status"], "PARTIAL")
        self.assertIn("ACCESS_DENIED", [s["status"] for s in result["sources"]])
        self.assertNotIn("PRIVATE_ROOT_SENTINEL", json.dumps(result))

    def test_source_metadata_denial_at_setup_does_not_block_report_retrieval(self):
        report = self.generate()
        original = Path.lstat
        def denied(path, *args, **kwargs):
            if path == self.source:
                raise PermissionError("PRIVATE_ROOT_SENTINEL")
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", denied):
            restarted = PublicProfile(self.package, self.output)
            self.assertEqual(restarted.availability()["profile"], "public-aggregate-v1")
            self.assertEqual(restarted.verify("RUN012_PUBLIC")["status"], "PARTIAL")
            self.assertEqual(restarted.read(report["report_id"])["report_id"], report["report_id"])

    def test_output_size_does_not_publish_finality(self):
        def oversized(data):
            data.clear()
            data.update(run_id="RUN012", EXECUTION_STATUS="X"*260000, selected=18,
                        attempted=18, processed=18, unique_instances=15, exact_semantic_decisions=18,
                        dispositions={"SUPPORTED": 15, "CONTRADICTED": 3})
        self.mutate(oversized)
        self.assertLess(self.source.stat().st_size, MAX_BYTES)
        with self.assertRaises(PublicError) as caught:
            self.generate("oversize001")
        self.assertEqual(caught.exception.code, "OUTPUT_SIZE_LIMIT")
        folder = next(self.output.iterdir())
        self.assertFalse((folder/"COMPLETE.json").exists())
        self.assertEqual(json.loads((folder/"FAILURE.json").read_text())["generation"], "NOT_GENERATED")

    def test_public_mcp_io_error_redaction(self):
        sys.path.insert(0, str(ROOT))
        from pg_i7_mcp import server
        from mcp.server.mcpserver import MCPServer
        test_server = MCPServer("synthetic-redaction")
        @test_server.tool()
        def deny() -> dict[str, str]:
            raise PermissionError("PRIVATE_ROOT_SENTINEL")
        server._enforce_wire_arguments(test_server, redact_io=True)
        result = test_server._tool_manager.list_tools()[0].fn()
        self.assertTrue(result.is_error)
        self.assertEqual(result.structured_content["code"], "ACCESS_DENIED")
        self.assertNotIn("PRIVATE_ROOT_SENTINEL", json.dumps(result.model_dump()))

    def test_distribution_verifier_rejects_empty_or_escaping_membership(self):
        sys.path.insert(0, str(ROOT/"tools"))
        import verify_public_profile
        original_root = verify_public_profile.ROOT
        verify_public_profile.ROOT = self.tmp
        try:
            for files in ({}, {"/outside/private": {"sha256": "0"*64, "bytes": 0}}):
                (self.tmp/"PUBLIC_PROFILE_MANIFEST.json").write_bytes(encoded({"schema": "pgop1.public-distribution.v1", "version": "0.1.0", "files": files}))
                with self.assertRaises(PublicError) as caught:
                    verify_public_profile.verify()
                self.assertEqual(caught.exception.code, "INVALID_DISTRIBUTION_MANIFEST")
        finally:
            verify_public_profile.ROOT = original_root

    def test_module_cli_entry(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT/"runtime")}
        cli = subprocess.run([sys.executable, "-m", "candidate.pg_i7", "--profile", "public", "--json", "availability"],
                             capture_output=True, text=True, timeout=15, env=env)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)["profile"], "public-aggregate-v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
