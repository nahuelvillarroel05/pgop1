"""Focused contract tests for the terminal adapter and real public fixture."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "cli"), str(ROOT / "runtime")]
from candidate import i7_api, public_handoff
from pgopcore import cli


class PgopCliContract(unittest.TestCase):
    def test_evidence_and_verify_use_the_same_public_backend(self):
        source = ROOT / "runtime" / "public_profile"
        legacy = i7_api.public_profile(package_root=source, output_root=ROOT / "public-handoffs")
        with patch.object(cli, "__file__", str(source.with_name("unpacked") / "cli.py")):
            def factory(*, package_root, output_root):
                self.assertEqual(package_root, source.with_name("unpacked") / "_data")
                self.assertEqual(output_root, package_root.with_name("_reports_disabled"))
                return legacy

            for command, expected in (("evidence", legacy.query("RUN012_PUBLIC")),
                                      ("verify", legacy.verify("RUN012_PUBLIC"))):
                with self.subTest(command=command):
                    args = argparse.Namespace(command=command, package_id="RUN012_PUBLIC")
                    result, code = cli.backend_result(args, public_handoff, factory)
                    self.assertEqual(result["data"], expected)
                    self.assertEqual(result["native_status"], "PASS")
                    self.assertEqual(code, 0)

    def test_status_does_not_verify_and_exposes_only_alpha_commands(self):
        class CatalogOnly:
            def availability(self):
                return {"version": "0.1.0", "scope": cli.SCOPE,
                        "registered_packages": ["RUN012_PUBLIC"],
                        "capabilities": ["generate", "read"]}

        args = argparse.Namespace(command="status")
        data, status = cli.execute(args, CatalogOnly())
        self.assertEqual(data["source_verification"], "NOT_VERIFIED")
        self.assertEqual(data["commands"], list(cli.COMMANDS))
        self.assertIsNone(status)

    def test_packaged_catalog_setup_errors_are_not_user_errors(self):
        def invalid_catalog(**_):
            raise public_handoff.PublicError("INVALID_ID", "Malformed catalog key")

        args = argparse.Namespace(command="status")
        result, code = cli.backend_result(args, public_handoff, invalid_catalog)
        self.assertEqual((code, result["native_code"]), (4, "INVALID_ID"))

    def test_unknown_package_for_doctor_is_an_installation_issue(self):
        class OtherCatalog:
            def verify(self, package_id):
                raise public_handoff.PublicError("UNKNOWN_PACKAGE", "Missing package")

        for command, expected in (("doctor", 4), ("verify", 2)):
            args = argparse.Namespace(command=command, package_id="RUN012_PUBLIC")
            result, code = cli.backend_result(args, public_handoff, lambda **_: OtherCatalog())
            self.assertEqual((code, result["native_code"]), (expected, "UNKNOWN_PACKAGE"))

    def test_invalid_argument_is_not_echoed(self):
        for args in (["--json"], ["--json", "\x1b[31mPRIVATE_ARGUMENT"]):
            with self.subTest(args=args):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(cli.main(args), 2)
                self.assertEqual(json.loads(out.getvalue())["outcome"], "USAGE_ERROR")
                self.assertNotIn("PRIVATE_ARGUMENT", out.getvalue() + err.getvalue())

    def test_terminal_control_characters_are_escaped(self):
        self.assertEqual(cli.safe("cita\x1b\n\u202eá"), r"cita\x1b\n\u202e" + "á")

    def test_human_output_preserves_exit_for_strict_redirected_encoding(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="\n")
        payload = cli.result("evidence", "VERIFICATION_INCOMPLETE", {})
        with patch.object(cli, "human_lines", return_value=["Estado \u6f22\x1b"]), contextlib.redirect_stdout(stream):
            self.assertEqual(cli.emit(payload, False, 3), 3)
        stream.flush()
        self.assertEqual(raw.getvalue(),
                         (cli.HISTORICAL_LABEL + "\n").encode("cp1252") + b"Estado \\u6f22\\x1b\n")


if __name__ == "__main__":
    unittest.main()
