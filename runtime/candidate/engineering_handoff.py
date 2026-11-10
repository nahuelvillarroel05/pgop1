"""Trusted, declarative scalar projection adapter. Sources are inert and never exposed raw."""
from pathlib import Path
import os
import re

try:
    from .public_handoff import PublicProfile, PublicError, checked, relative, read_bytes, parse, encoded, sha, identifier, MAX_BYTES, OPERATIONS
except ImportError:  # existing direct-file CLI entry
    from public_handoff import PublicProfile, PublicError, checked, relative, read_bytes, parse, encoded, sha, identifier, MAX_BYTES, OPERATIONS

PROFILE = "engineering-local-v1"
FORMAT = "json-scalar-projection-v1"
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
PATH = re.compile(r"[A-Za-z0-9_./-]{1,160}\Z")


def require(condition, code="INVALID_SCHEMA"):
    if not condition:
        raise PublicError(code, "Invalid trusted engineering manifest or unsupported projection contract")


def disjoint(a, b):
    require(a != b and a not in b.parents and b not in a.parents, "OUTPUT_OVERLAP")


def pointer(data, selector):
    for part in selector[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(data, dict) or part not in data:
            return None
        data = data[part]
    return data


class EngineeringProfile(PublicProfile):
    profile = PROFILE
    version = "0.2.0"

    def __init__(self, package_root=None, output_root=None):
        require(package_root is not None and output_root is not None)
        config_root = checked(package_root)
        self.catalog_path = config_root / "CATALOG.json"
        self.catalog_bytes = read_bytes(self.catalog_path)
        self.config = parse(self.catalog_bytes)
        require(set(self.config) == {"schema", "profile", "source_root", "packages"})
        require(self.config["schema"] == "pgop1.engineering-catalog.v1" and self.config["profile"] == PROFILE, "UNSUPPORTED_FORMAT")
        source_root = self.config["source_root"]
        require(isinstance(source_root, str) and Path(source_root).is_absolute() and not source_root.startswith(("//", "\\\\")), "UNSAFE_PATH")
        # A registered source root may be inaccessible while config/output remain
        # readable. Defer only access/I/O metadata failures; every source read
        # still checks all components. Unsafe links remain a setup error.
        self.root = Path(os.path.abspath(source_root))
        try:
            checked(self.root)
        except PublicError as exc:
            if exc.code not in {"ACCESS_DENIED", "IO_ERROR"}:
                raise
        self.out = checked(output_root)
        disjoint(self.out, self.root)
        disjoint(self.out, config_root)
        self.entries = self.config["packages"]
        require(isinstance(self.entries, dict) and 1 <= len(self.entries) <= 20)
        for name, entry in self.entries.items():
            identifier(name)
            require(isinstance(entry, dict) and entry.get("format") == FORMAT, "UNSUPPORTED_FORMAT")
            require(set(entry) == {"format", "synthetic", "files", "sources", "summary", "projections", "checks"})
            require(type(entry["synthetic"]) is bool)
            files, sources = entry["files"], entry["sources"]
            require(isinstance(files, dict) and 1 <= len(files) <= 8 and isinstance(sources, dict) and set(files) == set(sources))
            for path, digest in files.items():
                require(isinstance(path, str) and PATH.fullmatch(path) and all(path.split("/")), "UNSAFE_PATH")
                try:
                    relative(self.root, path)
                except PublicError as exc:
                    if exc.code not in {"ACCESS_DENIED", "IO_ERROR"}:
                        raise
                require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest))
                spec = sources[path]
                require(isinstance(spec, dict) and set(spec) == {"bytes", "role", "schema"})
                require(type(spec["bytes"]) is int and 0 <= spec["bytes"] <= MAX_BYTES)
                require(isinstance(spec["role"], str) and spec["role"] in {"results", "complement", "inert-context"})
                require(isinstance(spec["schema"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", spec["schema"]))
            require(isinstance(entry["summary"], str) and entry["summary"] in files and sources[entry["summary"]]["role"] == "results")
            projections = entry["projections"]
            require(isinstance(projections, dict) and 1 <= len(projections) <= 40)
            for key, spec in projections.items():
                identifier(key)
                require(isinstance(spec, dict) and set(spec) == {"source", "pointer", "kind", "allowed", "denominator", "scope"})
                require(isinstance(spec["source"], str) and spec["source"] in files and sources[spec["source"]]["role"] != "inert-context")
                require(isinstance(spec["pointer"], str) and 1 < len(spec["pointer"]) <= 180 and spec["pointer"].startswith("/") and spec["pointer"].count("/") <= 12)
                require(not re.search(r"~(?![01])", spec["pointer"]))
                # Selectors are setup metadata. Forbid links/markup/credential-like free text.
                require(re.fullmatch(r"/[A-Za-z0-9_~/.-]+", spec["pointer"]) is not None)
                require(isinstance(spec["kind"], str) and spec["kind"] in {"count", "state", "boolean"})
                require(isinstance(spec["allowed"], list) and len(spec["allowed"]) <= 20)
                require(all(isinstance(v, str) and TOKEN.fullmatch(v) for v in spec["allowed"]))
                require(bool(spec["allowed"]) if spec["kind"] == "state" else not spec["allowed"])
                require(spec["denominator"] is None or (isinstance(spec["denominator"], str) and spec["denominator"] in projections))
                require(isinstance(spec["scope"], str) and spec["scope"] in {"claims", "instances", "task_claims", "tests_claims", "labels", "receipts", "checkpoints", "files", "declared_state", "recovered_units"})
            require("execution_status" in projections and projections["execution_status"]["kind"] == "state")
            for spec in projections.values():
                if spec["denominator"] is not None:
                    require(projections[spec["denominator"]]["kind"] == "count")
            require(isinstance(entry["checks"], dict) and len(entry["checks"]) <= 24)
            for key, spec in entry["checks"].items():
                identifier(key)
                require(isinstance(spec, dict) and set(spec) == {"operation", "left", "right"})
                require(isinstance(spec["operation"], str) and spec["operation"] in {"eq", "le", "sum_eq"})
                require(isinstance(spec["left"], list) and 1 <= len(spec["left"]) <= 16)
                require(all(isinstance(k, str) and k in projections and projections[k]["kind"] == "count" for k in spec["left"]))
                require(isinstance(spec["right"], str) and spec["right"] in projections and projections[spec["right"]]["kind"] == "count")
                require(spec["operation"] == "sum_eq" or len(spec["left"]) == 1)

    def availability(self):
        return {"schema": "pgop1.engineering.v1", "version": self.version, "profile": self.profile,
                "capabilities": list(OPERATIONS), "registered_packages": list(self.entries),
                "limits": {"file_bytes": MAX_BYTES, "files": 8, "page_chars": 16000, "projections": 40, "checks": 24},
                "scope": "APPROVED_SCALAR_PROJECTIONS_ONLY", "historical_execution": "NOT_PERFORMED",
                "authority_effect": "NONE", "os_sandbox": "NOT_PROVEN"}

    def catalog(self, offset=0, limit=10):
        result = super().catalog(offset, limit)
        for item in result["items"]:
            item["evidence_scope"] = "APPROVED_SCALAR_PROJECTIONS_ONLY"
            item["synthetic"] = self.entry(item["package_id"])["synthetic"]
        return result

    def analyze(self, package_id):
        entry, sources, bodies, snapshot = self.snapshot(package_id)
        documents, issues = {}, []
        for source in sources:
            name = source["source_id"]
            source["category"] = "SOURCE_BYTE_IDENTITY"
            source["expected_bytes"] = entry["sources"][name]["bytes"]
            if source["status"] == "PASS" and source["bytes"] != source["expected_bytes"]:
                source["status"] = "SIZE_MISMATCH"
            if entry["sources"][name]["role"] == "inert-context" or name not in bodies:
                continue
            try:
                data = parse(bodies[name])
                if data.get("schema") != entry["sources"][name]["schema"]:
                    raise PublicError("UNSUPPORTED_FORMAT", "Source schema is not the registered version")
                documents[name] = data
            except PublicError as exc:
                issues.append({"source_id": name, "code": exc.code})
        metrics, values = [], {}
        for name, spec in entry["projections"].items():
            value = pointer(documents.get(spec["source"], {}), spec["pointer"])
            state = "DECLARED_RESULT"
            if value is None:
                value, state = "UNKNOWN", "NOT_VERIFIED"
            elif ((spec["kind"] == "count" and not (type(value) is int and 0 <= value <= 2**53-1))
                  or (spec["kind"] == "boolean" and type(value) is not bool)
                  or (spec["kind"] == "state" and (not isinstance(value, str) or value not in spec["allowed"]))):
                value, state = "WITHHELD", "NOT_VERIFIED"
                issues.append({"projection": name, "code": "INVALID_PROJECTED_VALUE"})
            values[name] = value
            body = bodies.get(spec["source"])
            metrics.append({"name": name, "value": value, "category": state,
                            "denominator": spec["denominator"], "denominator_scope": spec["scope"],
                            "source": {"source_id": spec["source"], "observed_sha256": sha(body) if body is not None else None,
                                       "selector": spec["pointer"], "operation": "READ_REGISTERED_SCALAR"}})
        for metric in metrics:
            metric["denominator"] = values.get(metric["denominator"], "NOT_APPLICABLE")
        checks = []
        for name, spec in entry["checks"].items():
            operands = [values[k] for k in spec["left"]] + [values[spec["right"]]]
            if any(type(x) is not int for x in operands):
                status = "UNKNOWN"
            else:
                left, right = sum(operands[:-1]), operands[-1]
                status = "PASS" if (left <= right if spec["operation"] == "le" else left == right) else "FAIL"
            checks.append({"name": name, "category": "CURRENT_CONSISTENCY", **spec, "status": status})
        failed = any(x["status"] in {"HASH_MISMATCH", "SIZE_MISMATCH"} for x in sources) or any(x["status"] == "FAIL" for x in checks)
        failed |= any(x["code"] in {"INVALID_JSON", "UNSUPPORTED_FORMAT", "INVALID_PROJECTED_VALUE"} for x in issues)
        partial = bool(issues) or any(x["status"] != "PASS" for x in sources + checks) or any(x["category"] == "NOT_VERIFIED" for x in metrics)
        receipt = {"schema": "pgop1.verification.v1", "profile": self.profile, "package_id": package_id,
                   "snapshot_id": snapshot, "status": "FAIL" if failed else "PARTIAL" if partial else "PASS", "sources": sources,
                   "checks": {"registered_bytes": "PERFORMED", "aggregate_consistency": checks,
                              "projection_issues": issues, "aggregate_consistency_scope": "EXPLICIT_REGISTERED_RELATIONS_ONLY",
                              "original_tests": "NOT_PERFORMED", "semantic_regrade": "NOT_PERFORMED"},
                   "coverage": {"passed": sum(x["status"] == "PASS" for x in sources), "registered": len(sources), "original_bodies": "NOT_VERIFIED"}}
        receipt["receipt_id"] = sha(encoded(receipt))
        return receipt, metrics, values["execution_status"]

    def query(self, package_id):
        result = super().query(package_id)
        result["limitations"] = self.limits()
        return result

    @staticmethod
    def limits():
        return ["Historical declarations only; historical execution NOT_PERFORMED in this intervention.",
                "Explicit scalar relations only; per-unit outcomes and independent semantic truth NOT_VERIFIED.",
                "Unregistered fields and private bodies WITHHELD; no independent custody or OS sandbox established.",
                "Hash consistency does not authenticate the original execution. REPORT_GENERATED is not RUN_PASS."]

    def project_report(self, report):
        entry = self.entry(report["package_id"])
        status = next(x for x in report["metrics"] if x["name"] == "execution_status")
        report.update(template_version="engineering-1", synthetic=entry["synthetic"],
                      historical_source=status["source"], limitations=self.limits(),
                      continuity={"status": "NO_NEW_AUTHORIZATION", "documented_pending": "SEE_EXPLICIT_DECLARED_STATE_METRICS_ONLY"})
        report["operations"]["performed"] = ["READ_SHA256", "READ_REGISTERED_SCALAR", "CHECK_REGISTERED_RELATIONS", "RENDER_HANDOFF"]
        return report

    def render_report(self, report):
        lines = ["# FINAL_HANDOFF — " + report["package_id"], "", "## 1. Identidad, version y alcance", "",
                 f'Perfil `{self.profile}`; generador `{self.version}`; plantilla `engineering-1`.',
                 f'Informe `{report["report_id"]}`; `REPORT_GENERATED`; verificacion actual `{report["verification"]["status"]}`.',
                 f'Instancia sintetica: `{report["synthetic"]}`. Estado historico declarado: `{report["historical_result"]}`.',
                 "", "## 2. Fuentes observadas y cobertura", "", "Fuente relativa | SHA-256 observado | Bytes | Estado", "--- | --- | ---: | ---"]
        for src in report["verification"]["sources"]:
            lines.append(f'{src["source_id"]} | `{src["observed_sha256"]}` | {src.get("bytes", "UNKNOWN")} | {src["status"]}')
        lines += ["", "## 3. Resultados declarados con denominadores", "",
                  "Valores leidos del JSON historico; no son pruebas repetidas ni precision independiente.", "",
                  "Campo | Valor | Denominador | Ambito | Estado | Fuente y selector", "--- | --- | --- | --- | --- | ---"]
        for m in report["metrics"]:
            lines.append(f'{m["name"]} | {m["value"]} | {m["denominator"]} | {m["denominator_scope"]} | {m["category"]} | {m["source"]["source_id"]} `{m["source"]["selector"]}`')
        lines += ["", "Cada selector corresponde al hash observado de la tabla de fuentes; REPORT.json conserva cada enlace completo.",
                  "", "## 4. Comprobaciones actuales y resultados", "", "Relacion registrada | Operacion | Operandos | Resultado", "--- | --- | --- | ---"]
        for c in report["verification"]["checks"]["aggregate_consistency"]:
            lines.append(f'{c["name"]} | {c["operation"]} | {", ".join(c["left"])} : {c["right"]} | {c["status"]}')
        for issue in report["verification"]["checks"]["projection_issues"]:
            lines.append("Incidencia: " + issue["code"] + "; campo/fuente: " + issue.get("projection", issue.get("source_id", "UNKNOWN")))
        lines += ["", "PGOP1 comprobo ahora identidad de bytes y relaciones declaradas. No volvio a ejecutar las pruebas historicas.",
                  "", "## 5. Comparabilidad, limites y pendientes", ""] + ["- " + x for x in report["limitations"]]
        lines += ["", "## 6. Artefactos y enlaces verificables", "", "[REPORT.json](REPORT.json) es canonico; [MANIFEST.json](MANIFEST.json) vincula sus hashes con este Markdown.",
                  f'Recibo actual: `{report["verification"]["receipt_id"]}`.',
                  "", "## 7. Continuidad sin autorizacion nueva", "",
                  "NO_NEW_AUTHORIZATION. Los estados proyectados son declaraciones historicas con selector; los demas permanecen UNKNOWN.",
                  "No se inicio ningun RUN, entrenamiento, regrade, promocion, merge ni publicacion.", ""]
        return "\n".join(lines)
