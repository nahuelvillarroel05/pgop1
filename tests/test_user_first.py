"""Product commands remain usable with the historical profile quarantined."""

import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "cli"))

from pgopcore import cli


class UserFirstContract(unittest.TestCase):
    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch.object(
            cli, "open_profile", side_effect=AssertionError("historical profile opened")
        ):
            try:
                code = cli.main(args)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_product_commands_use_a_separate_schema(self):
        fake_distribution = SimpleNamespace(version="0.1.0a5", entry_points=[
            SimpleNamespace(group="console_scripts", name="pgop", value="pgopcore.cli:main"),
        ])
        with (
            patch("pgopcore.product.distribution", return_value=fake_distribution),
            patch("pgopcore.product.literal_capability", return_value=("READY", None)),
        ):
            for command in ("doctor", "status", "catalog"):
                with self.subTest(command=command):
                    code, out, err = self.invoke("--json", command)
                    response = json.loads(out)
                    self.assertEqual((code, err), (0, ""))
                    self.assertEqual(response["schema"], "pgop.product.v1")
                    self.assertEqual(response["command"], command)
                    self.assertNotIn("RUN012_PUBLIC", out)
                    self.assertNotIn("verification", response["data"])

    def test_catalog_is_empty_and_validates_legacy_pagination_bounds(self):
        code, out, _ = self.invoke("--json", "catalog", "--offset", "100000", "--limit", "1")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["data"], {
            "registry": "NOT_CONFIGURED", "items": [], "total": 0, "next_offset": None,
            "offset": 100000, "limit": 1,
        })
        for flag, value in (("--limit", "0"), ("--offset", "100001"), ("--limit", "PRIVATE")):
            code, out, err = self.invoke("--json", "catalog", flag, value)
            response = json.loads(out)
            self.assertEqual((code, response["schema"], response["command"]),
                             (2, "pgop.product.v1", "catalog"))
            self.assertNotIn("PRIVATE", out + err)

    def test_help_starts_with_explicit_user_file(self):
        for argv in ((), ("--help",), ("search", "--help")):
            with self.subTest(argv=argv):
                status, out, err = self.invoke(*argv)
                self.assertEqual((status, err), (0, ""))
                self.assertIn("search", out)
                self.assertIn("--file", out)
                self.assertNotIn("RUN012_PUBLIC", out)


if __name__ == "__main__":
    unittest.main()
