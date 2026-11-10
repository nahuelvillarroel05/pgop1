"""Build explicit portable snapshot; never walks private evidence or Git history."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ["LICENSE", "runtime/candidate/pg_i7.py", "runtime/candidate/i7_api.py",
         "runtime/candidate/public_handoff.py", "pg_i7_mcp/__init__.py", "pg_i7_mcp/server.py",
         "pg_i7_mcp/public_tools.py", "runtime/public_profile/CATALOG.json",
         "runtime/public_profile/run012/EXECUTION_RESULTS.json",
         "runtime/public_profile/run012/HISTORICAL_MANIFEST.json",
         "public_profile/README.md", "public_profile/requirements.lock",
         "public_profile/config.example.toml", "public_profile/launch.cmd", "public_profile/launch.ps1",
         "public_profile/launch.sh", "public_profile/REPORT.schema.json", "tools/verify_public_profile.py",
         "tools/test_public_mcp.py", "tests/test_public_handoff_v0.py", "tools/build_public_profile.py"]


def build(destination):
    destination = Path(destination)
    bodies = {name: (ROOT/name).read_bytes() for name in FILES}
    manifest = {"schema": "pgop1.public-distribution.v1", "version": "0.1.0",
                "base_commit": "36e17fbfc2b49a4db8b60d313a1492097d0f347b",
                "base_tree": "04bf55db2ca809127a1e395d7d5963ba1cddfac3",
                "identity_scope": "Local byte identity only; no external custody/authenticity claim",
                "files": {name: {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)} for name, body in bodies.items()}}
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, body in bodies.items():
            bundle.writestr(name, body)
        bundle.writestr("PUBLIC_PROFILE_MANIFEST.json", json.dumps(manifest, indent=2)+"\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    print(json.dumps(build(parser.parse_args().destination), indent=2))
