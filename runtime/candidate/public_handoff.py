"""Public aggregate profile v1. No producer, semantic auditor or LLM is invoked."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

VERSION = "0.1.0"
PROFILE = "public-aggregate-v1"
MAX_BYTES = 262144
MAX_FILES = 16
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
DEFAULT_PACKAGE = Path(__file__).absolute().parents[1] / "public_profile"
OPERATIONS = ("availability", "catalog", "query", "verify", "generate", "read")


class PublicError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise PublicError("INVALID_ID", "Expected an opaque ASCII identifier, maximum 80 characters")
    return value


def checked(path):
    """Reject every existing symlink/reparse component, including root ancestors."""
    path = Path(os.path.abspath(path))
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        except PermissionError as exc:
            raise PublicError("ACCESS_DENIED", "Path metadata access denied") from exc
        except OSError as exc:
            raise PublicError("IO_ERROR", "Path metadata inspection failed") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PublicError("UNSAFE_PATH", "Links and reparse points are not supported")
    return path


def relative(root, value):
    if not isinstance(value, str) or "\\" in value or ":" in value:
        raise PublicError("UNSAFE_PATH", "Expected a portable relative path")
    p = Path(value)
    if p.anchor or p.is_absolute() or not p.parts or any(x in ("..", ".") for x in value.split("/")):
        raise PublicError("UNSAFE_PATH", "Path escapes the registered root")
    path = checked(root / p)
    if not path.is_relative_to(checked(root)):
        raise PublicError("UNSAFE_PATH", "Path escapes the registered root")
    return path


def read_bytes(path):
    try:
        checked(path)
        with path.open("rb") as f:
            body = f.read(MAX_BYTES + 1)
    except FileNotFoundError as exc:
        raise PublicError("SOURCE_UNAVAILABLE", "Registered source is unavailable") from exc
    except PermissionError as exc:
        raise PublicError("ACCESS_DENIED", "Registered source access denied") from exc
    except OSError as exc:
        raise PublicError("IO_ERROR", "Registered source read failed") from exc
    if len(body) > MAX_BYTES:
        raise PublicError("SIZE_LIMIT", "File exceeds 262144 bytes; not silently truncated")
    return body


def parse(body):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate key")
            result[k] = v
        return result
    def invalid(value):
        raise ValueError("nonfinite number")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite number")
        return number
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite_float)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PublicError("INVALID_JSON", "Expected a finite UTF-8 JSON object with unique keys") from exc


def bounded(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise PublicError("INVALID_ARGUMENT", f"Integer must be in {low}..{high}")
    return value


class PublicProfile:
    profile = PROFILE
    version = VERSION

    def project_report(self, report):
        return report

    def render_report(self, report):
        return render(report)

    def __init__(self, package_root=None, output_root=None):
        self.root = checked(package_root or DEFAULT_PACKAGE)
        self.out = checked(output_root or Path.cwd() / "public-handoffs")
        # Output must be disjoint from registered inputs in both directions.
        if self.out == self.root or self.root in self.out.parents or self.out in self.root.parents:
            raise PublicError("OUTPUT_OVERLAP", "Output and package roots must be disjoint")
        self.catalog_path = self.root / "CATALOG.json"
        self.catalog_bytes = read_bytes(self.catalog_path)
        self.config = parse(self.catalog_bytes)
        if self.config.get("profile") != PROFILE or self.config.get("schema") != "pgop1.catalog.v1":
            raise PublicError("UNSUPPORTED_FORMAT", "Unsupported catalog schema/profile")
        self.entries = self.config.get("packages")
        if not isinstance(self.entries, dict) or not 1 <= len(self.entries) <= 20:
            raise PublicError("INVALID_SCHEMA", "Expected 1..20 registered packages")
        for name, entry in self.entries.items():
            identifier(name)
            if not isinstance(entry, dict) or entry.get("format") != "run012-aggregate-v1":
                raise PublicError("UNSUPPORTED_FORMAT", "Only RUN012 aggregate v1 is supported")
            files = entry.get("files")
            if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
                raise PublicError("INVALID_SCHEMA", "Invalid registered file count")
            for path, digest in files.items():
                try:
                    relative(self.root, path)
                except PublicError as exc:
                    # Unavailable source metadata must not disable catalog/report reads.
                    # Lexical escapes/reparse points still fail closed; every actual
                    # source read checks the path again and records its exact state.
                    if exc.code not in {"ACCESS_DENIED", "IO_ERROR"}:
                        raise
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise PublicError("INVALID_SCHEMA", "Expected SHA-256 pin")
            if entry.get("summary") not in files:
                raise PublicError("INVALID_SCHEMA", "Summary must be a registered file")

    def entry(self, package_id):
        identifier(package_id)
        if package_id not in self.entries:
            raise PublicError("UNKNOWN_PACKAGE", "Package is not registered")
        return self.entries[package_id]

    def availability(self):
        return {"schema": "pgop1.public.v1", "version": VERSION, "profile": self.profile,
                "capabilities": list(OPERATIONS), "registered_packages": list(self.entries),
                "limits": {"file_bytes": MAX_BYTES, "files": MAX_FILES, "page_chars": 16000},
                "scope": "PUBLIC_AGGREGATES_ONLY", "historical_execution": "NOT_PERFORMED",
                "authority_effect": "NONE", "identity": self.config.get("identity", "UNKNOWN")}

    def catalog(self, offset=0, limit=10):
        bounded(offset, 0, 100000)
        bounded(limit, 1, 20)
        items = [{"package_id": k, "format": v["format"], "evidence_scope": "PUBLIC_AGGREGATES_ONLY"}
                 for k, v in sorted(self.entries.items())]
        return {"items": items[offset:offset+limit], "total": len(items),
                "next_offset": offset+limit if offset+limit < len(items) else None}

    def snapshot(self, package_id):
        if read_bytes(self.catalog_path) != self.catalog_bytes:
            raise PublicError("CONFIG_CHANGED", "Catalog changed after setup; restart with reviewed configuration")
        entry = self.entry(package_id)
        observations, bodies = [], {}
        for name, expected in sorted(entry["files"].items()):
            record = {"source_id": name, "expected_sha256": expected, "operation": "READ_SHA256"}
            try:
                body = read_bytes(relative(self.root, name))
                bodies[name] = body
                record.update(observed_sha256=sha(body), bytes=len(body),
                              status="PASS" if sha(body) == expected else "HASH_MISMATCH")
            except PublicError as exc:
                record.update(observed_sha256=None, status=exc.code)
            observations.append(record)
        binding = {"catalog_sha256": sha(self.catalog_bytes), "package_id": package_id, "sources": observations}
        return entry, observations, bodies, sha(encoded(binding))

    def analyze(self, package_id):
        entry, sources, bodies, snapshot = self.snapshot(package_id)
        summary = bodies.get(entry["summary"])
        metrics, errors = [], []
        historical = "UNKNOWN"
        if summary is not None:
            try:
                data = parse(summary)
                if data.get("run_id") != "RUN012" or not isinstance(data.get("EXECUTION_STATUS"), str):
                    raise PublicError("INVALID_SCHEMA", "Expected RUN012 aggregate identity and historical status")
                historical = data["EXECUTION_STATUS"]
                # Missing values remain UNKNOWN; there are no implied zeros.
                specs = [("selected", "selected occurrences"), ("attempted", "attempted occurrences"),
                         ("processed", "processed occurrences"), ("unique_instances", "instances"),
                         ("exact_semantic_decisions", "selected occurrences"), ("independent_labels", "labels")]
                for key, denominator_scope in specs:
                    value = data.get(key, "UNKNOWN")
                    if value != "UNKNOWN" and (type(value) is not int or value < 0):
                        raise PublicError("INVALID_SCHEMA", "Counts must be nonnegative integers or absent")
                    metrics.append({"name": key, "value": value,
                                    "denominator": data.get("selected", "UNKNOWN") if denominator_scope == "selected occurrences" else "NOT_APPLICABLE",
                                    "denominator_scope": denominator_scope,
                                    "source": {"source_id": entry["summary"], "observed_sha256": sha(summary),
                                               "selector": "/"+key, "operation": "READ_AGGREGATE"}})
                for key in ("INDEPENDENT_PRECISION", "INDEPENDENT_RECALL", "GATE_11", "reference_scope"):
                    value = data.get(key, "UNKNOWN")
                    if not isinstance(value, str):
                        raise PublicError("INVALID_SCHEMA", "Declared states must be strings")
                    metrics.append({"name": key, "value": value, "denominator": "NOT_APPLICABLE",
                                    "denominator_scope": "declared state",
                                    "source": {"source_id": entry["summary"], "observed_sha256": sha(summary),
                                               "selector": "/"+key, "operation": "READ_AGGREGATE"}})
                dispositions = data.get("dispositions")
                if dispositions is None:
                    errors.append("MISSING_DISPOSITIONS")
                elif not isinstance(dispositions, dict) or any(type(v) is not int or v < 0 for v in dispositions.values()):
                    raise PublicError("INVALID_SCHEMA", "Invalid disposition counts")
                elif set(dispositions) - {"SUPPORTED", "CONTRADICTED", "ABSTAIN", "VERIFICATION_ERROR", "NOT_EVALUABLE"}:
                    raise PublicError("INVALID_SCHEMA", "Unsupported disposition label")
                elif type(data.get("processed")) is int and sum(dispositions.values()) != data["processed"]:
                    errors.append("CONTRADICTORY_TOTALS")
                if isinstance(dispositions, dict):
                    for key, value in sorted(dispositions.items()):
                        metrics.append({"name": "dispositions/"+key, "value": value,
                                        "denominator": data.get("processed", "UNKNOWN"),
                                        "denominator_scope": "processed occurrences",
                                        "source": {"source_id": entry["summary"], "observed_sha256": sha(summary),
                                                   "selector": "/dispositions/"+key.replace("~", "~0").replace("/", "~1"), "operation": "READ_AGGREGATE"}})
                for key in ("selected", "attempted", "processed", "unique_instances", "exact_semantic_decisions"):
                    if key not in data:
                        errors.append("MISSING_"+key.upper())
                if all(type(data.get(k)) is int for k in ("selected", "attempted", "processed")):
                    if not data["processed"] <= data["attempted"] <= data["selected"]:
                        errors.append("CONTRADICTORY_COUNTS")
                for lower, upper in (("exact_semantic_decisions", "processed"), ("unique_instances", "selected")):
                    if all(type(data.get(k)) is int for k in (lower, upper)) and data[lower] > data[upper]:
                        errors.append("CONTRADICTORY_"+lower.upper())
                if isinstance(dispositions, dict) and type(data.get("exact_semantic_decisions")) is int:
                    known_definitive = sum(value for key, value in dispositions.items() if key in {"SUPPORTED", "CONTRADICTED"})
                    known_nondefinitive = sum(value for key, value in dispositions.items() if key in {"ABSTAIN", "VERIFICATION_ERROR", "NOT_EVALUABLE"})
                    if data["exact_semantic_decisions"] < known_definitive:
                        errors.append("CONTRADICTORY_KNOWN_DEFINITIVE_BOUND")
                    if type(data.get("processed")) is int and data["exact_semantic_decisions"] > data["processed"] - known_nondefinitive:
                        errors.append("CONTRADICTORY_KNOWN_NONDEFINITIVE_BOUND")
                if (isinstance(dispositions, dict) and {"SUPPORTED", "CONTRADICTED"} <= set(dispositions)
                        and type(data.get("exact_semantic_decisions")) is int
                        and data["exact_semantic_decisions"] != dispositions["SUPPORTED"] + dispositions["CONTRADICTED"]):
                    errors.append("CONTRADICTORY_DEFINITIVE_TOTAL")
            except PublicError as exc:
                errors.append(exc.code)
                metrics = []
        else:
            errors.append("SUMMARY_UNAVAILABLE")
        failed = any(s["status"] == "HASH_MISMATCH" for s in sources) or any(x.startswith("CONTRADICTORY") or x in ("INVALID_SCHEMA", "INVALID_JSON") for x in errors)
        status = "FAIL" if failed else "PARTIAL" if errors or any(s["status"] != "PASS" for s in sources) else "PASS"
        receipt = {"schema": "pgop1.verification.v1", "profile": self.profile, "package_id": package_id,
                   "snapshot_id": snapshot, "status": status, "sources": sources,
                   "checks": {"registered_bytes": "PERFORMED", "aggregate_consistency": errors or ["PASS"],
                              "aggregate_consistency_scope": "PROJECTED_TOP_LEVEL_COUNTS_ONLY",
                              "semantic_reference": "NOT_AVAILABLE_IN_PUBLIC_PROFILE",
                              "original_tests": "NOT_PERFORMED", "semantic_regrade": "NOT_PERFORMED"},
                   "coverage": {"passed": sum(s["status"] == "PASS" for s in sources), "registered": len(sources),
                                "original_bodies": "NOT_VERIFIED"}}
        receipt["receipt_id"] = sha(encoded(receipt))
        return receipt, metrics, historical

    def query(self, package_id):
        receipt, metrics, historical = self.analyze(package_id)
        return {"package_id": package_id, "snapshot_id": receipt["snapshot_id"],
                "historical_result": historical, "metrics": metrics, "verification": receipt,
                "limitations": ["Aggregate declarations only; original bodies and per-unit outcomes not verified.",
                                "No historical tests, semantic regrade, model, training or RUN executed."]}

    def verify(self, package_id):
        return self.analyze(package_id)[0]

    def generate(self, package_id, receipt_id, request_key):
        identifier(request_key)
        current, metrics, historical = self.analyze(package_id)
        if receipt_id != current["receipt_id"]:
            raise PublicError("STALE_RECEIPT", "Receipt is not compatible with the current input snapshot")
        binding = {"package_id": package_id, "receipt_id": receipt_id, "request_key": request_key, "profile": self.profile}
        report_id = "report-"+sha(request_key.encode())[:40]
        folder = checked(self.out / report_id)
        self.out.mkdir(parents=True, exist_ok=True)
        checked(self.out)
        try:
            folder.mkdir()
        except FileExistsError:
            try:
                prior = parse(read_bytes(folder / "REQUEST.json"))
            except PublicError:
                raise PublicError("ATTEMPT_IN_PROGRESS_OR_INTERRUPTED", "Attempt retained; final artifact is not published")
            if prior != binding:
                raise PublicError("REQUEST_KEY_CONFLICT", "Request key was already used with different parameters")
            return self.completed(report_id)
        # Exclusive directory claim supports concurrent clients; incomplete attempts remain visible.
        self.write_new(folder / "REQUEST.json", encoded(binding))
        report = {"schema": "pgop1.report.v1", "generator_version": self.version, "template_version": "1",
                  "profile": self.profile, "report_id": report_id, "package_id": package_id,
                  "generation": "REPORT_GENERATED", "historical_result": historical,
                  "historical_source": {"source_id": self.entry(package_id)["summary"],
                                        "selector": "/EXECUTION_STATUS", "operation": "READ_AGGREGATE",
                                        "observed_sha256": next(s["observed_sha256"] for s in current["sources"] if s["source_id"] == self.entry(package_id)["summary"])},
                  "verification": current, "metrics": metrics,
                  "operations": {"performed": ["READ_AGGREGATE", "READ_SHA256", "CHECK_AGGREGATE_CONSISTENCY", "RENDER_HANDOFF"],
                                 "not_performed": ["HISTORICAL_TESTS", "SEMANTIC_REGRADE", "NEW_RUN", "TRAINING", "MODEL_INFERENCE"]},
                  "limitations": ["Public aggregates only; original bodies and per-unit outcomes NOT_VERIFIED.",
                                  "Hash consistency is not external authenticity, custody or semantic truth.",
                                  "Report generation does not imply RUN_PASS or new authority."],
                  "continuity": {"status": "NO_NEW_AUTHORIZATION", "documented_pending": "UNKNOWN"}}
        report = self.project_report(report)
        bodies = {"REPORT.json": encoded(report), "FINAL_HANDOFF.md": self.render_report(report).encode("utf-8")}
        if any(len(body) > MAX_BYTES for body in bodies.values()):
            self.write_new(folder / "FAILURE.json", encoded({"code": "OUTPUT_SIZE_LIMIT", "generation": "NOT_GENERATED"}))
            raise PublicError("OUTPUT_SIZE_LIMIT", "Generated report exceeds retrieval limit; attempt retained without final publication")
        for name, body in bodies.items():
            self.write_new(folder / name, body)
        manifest = {"schema": "pgop1.report-manifest.v1", "report_id": report_id,
                    "files": {k: {"sha256": sha(v), "bytes": len(v)} for k, v in bodies.items()}}
        self.write_new(folder / "MANIFEST.json", encoded(manifest))
        # Same-directory rename of final marker; no cross-filesystem/durability claim.
        self.write_new(folder / "COMPLETE.pending", encoded({"manifest_sha256": sha(encoded(manifest))}))
        os.replace(folder / "COMPLETE.pending", folder / "COMPLETE.json")
        return self.completed(report_id)

    @staticmethod
    def write_new(path, body):
        checked(path)
        with path.open("xb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())

    def completed(self, report_id):
        identifier(report_id)
        folder = checked(self.out / report_id)
        if not (folder / "COMPLETE.json").exists():
            raise PublicError("ATTEMPT_IN_PROGRESS_OR_INTERRUPTED", "Attempt retained without final publication")
        complete = parse(read_bytes(folder / "COMPLETE.json"))
        manifest_bytes = read_bytes(folder / "MANIFEST.json")
        if sha(manifest_bytes) != complete.get("manifest_sha256"):
            raise PublicError("ARTIFACT_INTEGRITY_ERROR", "Manifest differs from completion receipt")
        manifest = parse(manifest_bytes)
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != {"REPORT.json", "FINAL_HANDOFF.md"}:
            raise PublicError("ARTIFACT_INTEGRITY_ERROR", "Unexpected artifact membership")
        for name, item in files.items():
            body = read_bytes(folder / name)
            if item != {"sha256": sha(body), "bytes": len(body)}:
                raise PublicError("ARTIFACT_INTEGRITY_ERROR", "Final artifact bytes changed")
        # Prospective scoped reports cannot be retrieved through a legacy reader
        # pointed at the same directory. Existing unscoped artifacts are unchanged.
        report = parse(read_bytes(folder / "REPORT.json"))
        if "report_scope" in report:
            scope = getattr(self, "report_scope", None)
            if not callable(scope) or report["report_scope"] != scope():
                raise PublicError("REPORT_SCOPE_MISMATCH", "Report belongs to another configured scope")
        return {"report_id": report_id, "generation": "REPORT_GENERATED",
                "manifest_sha256": sha(manifest_bytes), "artifacts": list(files)+["MANIFEST.json"]}

    def read(self, report_id, artifact="FINAL_HANDOFF.md", offset=0, limit=8000):
        bounded(offset, 0, MAX_BYTES)
        bounded(limit, 1, 16000)
        if artifact not in ("REPORT.json", "FINAL_HANDOFF.md", "MANIFEST.json"):
            raise PublicError("UNKNOWN_ARTIFACT", "Only report artifacts are readable")
        self.completed(report_id)
        body = read_bytes(checked(self.out / identifier(report_id) / artifact))
        value = body.decode("utf-8")
        return {"report_id": report_id, "artifact": artifact, "sha256": sha(body), "total_chars": len(value),
                "offset": offset, "content": value[offset:offset+limit],
                "next_offset": offset+limit if offset+limit < len(value) else None}


def render(report):
    # All source values are inert JSON in fenced blocks. No executable Markdown links.
    sections = [("1. Identidad y alcance", {k: report[k] for k in ("schema", "generator_version", "template_version", "profile", "report_id", "package_id", "generation", "historical_result", "historical_source")}),
                ("2. Operaciones realizadas y no realizadas", report["operations"]),
                ("3. Resultados con denominadores", report["metrics"]),
                ("4. Comprobaciones y cobertura de evidencia", report["verification"]),
                ("5. Fallos, contradicciones y limitaciones", report["limitations"]),
                ("6. Artefactos y referencias", {"canonical": "REPORT.json", "binding": "MANIFEST.json", "references": "See metric source selectors and observed SHA-256 values."}),
                ("7. Continuidad documentada", report["continuity"])]
    if 'report_scope' in report:
        sections[0][1]['report_scope'] = report['report_scope']
    return "# FINAL_HANDOFF\n\n" + "\n".join("## "+title+"\n\n```json\n"+json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2).replace("`", "\\u0060")+"\n```\n" for title, value in sections)


def main(argv=None, *, service_class=PublicProfile):
    parser = argparse.ArgumentParser(description="PGOP1 public aggregate profile; no historical execution")
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--json", action="store_true", help="All operation output is JSON")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("availability")
    catalog = commands.add_parser("catalog")
    catalog.add_argument("--offset", type=int, default=0)
    catalog.add_argument("--limit", type=int, default=10)
    for operation in ("query", "verify", "generate"):
        sub = commands.add_parser(operation)
        sub.add_argument("package_id")
        if operation == "generate":
            sub.add_argument("receipt_id")
            sub.add_argument("request_key")
    read = commands.add_parser("read")
    read.add_argument("report_id")
    read.add_argument("--artifact", default="FINAL_HANDOFF.md")
    read.add_argument("--offset", type=int, default=0)
    read.add_argument("--limit", type=int, default=8000)
    args = vars(parser.parse_args(argv))
    operation = args.pop("operation")
    args.pop("json")
    package_root, output_root = args.pop("package_root"), args.pop("output_root")
    try:
        result = getattr(service_class(package_root, output_root), operation)(**args)
        print(encoded(result).decode(), end="")
        return 0  # Domain FAIL/PARTIAL is structured output, not a transport failure.
    except (PublicError, OSError) as exc:
        print(encoded({"status": "ERROR", "code": getattr(exc, "code", "IO_ERROR"),
                       "message": str(exc) if isinstance(exc, PublicError) else "Filesystem operation failed"}).decode(), end="")
        return 2


if __name__ == "__main__":
    sys.exit(main())
