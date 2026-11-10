"""Public distribution verifier only. Does not replace the historical verifier."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"runtime"))
from candidate import i7_api
from candidate.public_handoff import PublicError, checked, relative, read_bytes, parse
from build_public_profile import FILES


def verify():
    root = checked(ROOT)
    manifest = parse(read_bytes(root/"PUBLIC_PROFILE_MANIFEST.json"))
    if (manifest.get("schema") != "pgop1.public-distribution.v1"
            or manifest.get("version") != "0.1.0"
            or not isinstance(manifest.get("files"), dict)
            or set(manifest["files"]) != set(FILES)):
        raise PublicError("INVALID_DISTRIBUTION_MANIFEST", "Manifest must enumerate the exact public distribution membership")
    checks = []
    for name, expected in manifest["files"].items():
        body = read_bytes(relative(root, name))
        checks.append({"path": name, "pass": expected == {"sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}})
    receipt = i7_api.public_profile(output_root=ROOT/"verification-output").verify("RUN012_PUBLIC")
    return {"scope": "PUBLIC_DISTRIBUTION_ONLY", "status": "PASS" if all(x["pass"] for x in checks) and receipt["status"] == "PASS" else "FAIL",
            "checks": checks, "receipt": receipt, "historical_global_integrity": "NOT_CHECKED"}


if __name__ == "__main__":
    try:
        result = verify()
    except (PublicError, OSError, ValueError) as exc:
        result = {"scope": "PUBLIC_DISTRIBUTION_ONLY", "status": "FAIL", "code": getattr(exc, "code", "IO_OR_SCHEMA_ERROR")}
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["status"] == "PASS" else 1)
