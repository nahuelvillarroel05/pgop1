"""Content-bound Markdown/JSON pairs with atomic completion in an NTFS directory."""

from contextlib import ExitStack
import json
from pathlib import PureWindowsPath
import re

from . import workspace as ws, workspace_report
from .panel_views import safe_text


LEGACY_SCHEMA = "pgop.panel-report.v1"
PREVIOUS_SCHEMA = "pgop.panel-report.v2"
SCHEMA = "pgop.panel-report.v3"
MANIFEST_SCHEMA = "pgop.panel-report-manifest.v1"
REPORT_ID = re.compile(r"pgop-panel-([a-f0-9]{64})")
JSON = "INFORME.json"
MARKDOWN = "INFORME.md"
MANIFEST = "MANIFEST.json"
MAX_BYTES = workspace_report.MAX_BYTES
LIMITATIONS = (
    "Las referencias identifican los bytes capturados en el momento indicado.",
    "La lectura se limita a las fuentes y opciones indicadas. El estado actual requiere otra verificación.",
    "Validez semántica y ejecución sin evaluar. Los controles se escapan en la vista Markdown.",
)
V3_LIMITATIONS = (
    "Las citas corresponden a los bytes y al alcance observados durante la captura.",
    "La vigencia de la fuente se comprueba al volver a capturarla.",
    "La observación describe contenido y estructura. La ejecución y la validez semántica quedan fuera de su alcance.",
)


def citation_id(entry):
    binding = [entry["source"], entry["selector"], entry.get("context"), entry.get("literal_match"), entry["text"]]
    return "ev-" + ws.contract.digest(ws.contract.canonical(binding))


def build(kind, root, revision, version, observed_at, parameters, entries, coverage=None, *, result=None):
    if result is None:
        if kind == "Búsqueda literal":
            count = coverage["verified_occurrences"]
            displayed = len(entries)
            result = (f"Se encontraron {count} coincidencias. El informe incluye {displayed} citas."
                      if count else "La búsqueda no encontró coincidencias en las fuentes comprobadas.")
        else:
            if not entries:
                result = "No hay una selección de contenido registrada."
            else:
                selector = entries[0]["selector"]
                if selector.get("kind") in ("python_declaration", "markdown_section"):
                    result = (f'Se recuperó {selection_label(selector)} completa '
                              f'entre las líneas {selector["line_start"]} y {selector["line_end"]}.')
                else:
                    result = f'Se capturó {selection_label(selector)} de {entries[0]["source"]["path"]}.'
    return {"schema": SCHEMA, "operation": kind, "project": root, "registry_revision": revision,
            "distribution_version": version, "observed_at": observed_at,
            "source_currentness": "AT_CAPTURE_ONLY", "parameters": parameters,
            "entries": [{**entry, "evidence_id": citation_id(entry)} for entry in entries],
            "result": result, "coverage": coverage, "limitations": list(V3_LIMITATIONS)}


def code_block(text):
    # Indented data cannot activate untrusted Markdown links, images, or HTML.
    return "\n".join("    " + line for line in safe_text(text).split("\n"))


def legacy_markdown(report):
    lines = ["# PGOPCore · Informe local", "", "## Observación", ""]
    details = {
        "Operación": report["operation"], "Proyecto": report["project"],
        "Revisión del registro": report["registry_revision"], "Captura UTC": report["observed_at"],
        "Versión": report["distribution_version"],
    }
    lines.extend(code_block(f"{key}: {value}") for key, value in details.items())
    for key, value in (("Parámetros", report["parameters"]), ("Cobertura", report["coverage"])):
        if value is not None:
            body = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False, sort_keys=True)
            lines.extend(["", "## " + key, "", code_block(body)])
    for entry in report["entries"]:
        lines.extend(["", "## Referencia", "", code_block(
            json.dumps({k: v for k, v in entry.items() if k != "text"}, ensure_ascii=False, indent=2,
                       allow_nan=False, sort_keys=True)), "", code_block(entry["text"])])
    lines.extend(["", "## Alcance", "", *report["limitations"], ""])
    return "\n".join(lines).encode("utf-8")


def inline(value):
    # Escape every Markdown punctuation mark after making control characters inert.
    return re.sub(r"([\\`*{}\[\]()#!_<>|~&$:@])", r"\\\1", " ".join(safe_text(str(value)).split("\n")))


def selection_label(selector):
    if "title" in selector:
        return selector["title"]
    if selector.get("kind") == "json_pointer":
        return "Valor JSON " + (selector["pointer"] or "en la raíz")
    if selector.get("kind") == "csv_record":
        return f'Registro CSV {selector["record"]}' + (
            f' · columna {selector["column"]}' if "column" in selector else "")
    return "Texto seleccionado"


def readable_coverage(coverage):
    if coverage is None:
        return []
    lines = ["- Cobertura parcial." if coverage.get("partial") else "- Alcance completado durante la comprobación."]
    if "read_paths" in coverage:
        paths = coverage["read_paths"]
        lines.append(f'- {len(paths)} fuentes leídas y {coverage["unread_count"]} candidatas sin leer.')
        if paths:
            lines.append("- Fuentes leídas · " + ", ".join(map(inline, paths)))
        if areas := coverage.get("root_areas"):
            lines.append("- Carpetas observadas · " + ", ".join(map(inline, areas)))
        if possible := coverage.get("entry_candidates"):
            lines.append("- Posibles entradas por nombre · " + ", ".join(map(inline, possible)))
        if python := coverage.get("static_python"):
            lines.append(f'- AST V2 en {inline(python["path"])} · {inline(python["status"])} · '
                         f'{python["navigable_units"]} unidades navegables.')
    elif "checked_sources" in coverage:
        lines.append(f'- {coverage["checked_sources"]} de {coverage["started_with_active_sources"]} fuentes comprobadas.')
        lines.append(f'- {coverage["omitted_occurrences"]} coincidencias adicionales sin cita.')
    if unavailable := coverage.get("unavailable"):
        lines.append(f"- {len(unavailable)} fuentes no se pudieron comprobar.")
    return lines


def human_markdown(report):
    entries = report["entries"]
    operation = report["operation"]
    title = selection_label(entries[0]["selector"]) if operation == "Lectura" and entries else operation
    if operation == "Búsqueda literal":
        objective = f'Localizar el texto {inline(report["parameters"]["literal"])} en el alcance elegido.'
    elif operation == "Comprender proyecto":
        objective = "Identificar el propósito documentado y observar la estructura de una muestra del proyecto."
    elif entries:
        objective = f'Consultar {inline(title)} en {inline(entries[0]["source"]["path"])}.'
    else:
        objective = "Conservar el resultado de la observación local."
    lines = [f"# {inline(title)}", "", f"**Objetivo** · {objective}", "", "## Resultado", "", inline(report["result"])]
    for index, entry in enumerate(entries, 1):
        selector = entry["selector"]
        path = entry["source"]["path"]
        scope = (f' · líneas {selector["line_start"]}–{selector["line_end"]}'
                 if "line_start" in selector else "")
        lines.extend(["", f'### {index}. {inline(path)} · {inline(selection_label(selector))}{scope}', ""])
        if description := selector.get("documented_description"):
            lines.extend(["Docstring declarado", "", code_block(description), ""])
        if "literal_match" in entry:
            lines.extend(["Coincidencia", "", code_block(entry["literal_match"]), "", "Contexto", ""])
        lines.append(code_block(entry["text"]))
    lines.extend(["", "## Cobertura y límites", "", *readable_coverage(report["coverage"])])
    lines.extend("- " + line for line in report["limitations"])
    revision = report["registry_revision"] if report["registry_revision"] is not None else "sin revisión del registro"
    lines.extend(["", "## Referencia técnica", "", f'- Captura UTC {inline(report["observed_at"])} · '
                  f'PGOPCore {inline(report["distribution_version"])} · {inline(revision)}.',
                  f'- Proyecto {inline(report["project"])}.'])
    for index, entry in enumerate(entries, 1):
        source, selector = entry["source"], entry["selector"]
        offsets = (f' · bytes [{selector["byte_start"]}, {selector["byte_end"]})'
                   if "byte_start" in selector else "")
        lines.append(f'- Evidencia {index} · SHA-256 {source.get("sha256", "sin SHA")} · {entry["evidence_id"]}{offsets}')
    return ("\n".join(lines) + "\n").encode("utf-8")


def markdown(report):
    return human_markdown(report) if report["schema"] == SCHEMA else legacy_markdown(report)


def unit_markdown(markdown, report):
    """Select the source heading and excerpt from a verified V3 unit report."""
    if report["schema"] != SCHEMA or report["operation"] != "Lectura" or len(report["entries"]) != 1:
        return None
    entry = report["entries"][0]
    if entry["selector"].get("kind") not in {
        "python_declaration", "markdown_section", "markdown_front_matter", "text_paragraph",
    }:
        return None
    _, heading_marker, evidence = markdown.partition("\n### 1. ")
    heading, _, rest = evidence.partition("\n")
    body, limits_marker, _ = rest.partition("\n\n## Cobertura y límites")
    expected = code_block(entry["text"])
    if not heading_marker or not limits_marker or not body.endswith(expected):
        return None
    return heading_marker.lstrip() + heading + "\n\n" + body[-len(expected):]


def prepare(report):
    encoded = ws.contract.canonical(report)
    bodies = {JSON: encoded, MARKDOWN: markdown(report)}
    if any(len(raw) > MAX_BYTES for raw in bodies.values()):
        raise ws.WorkspaceError("PANEL_REPORT_LIMIT", "Guardá un fragmento o reducí el contexto del informe.", 3)
    name = "pgop-panel-" + ws.contract.digest(encoded)
    manifest = {"schema": MANIFEST_SCHEMA, "id": name, "files": {
        file: {"bytes": len(body), "sha256": ws.contract.digest(body)} for file, body in bodies.items()
    }}
    return name, {**bodies, MANIFEST: ws.contract.canonical(manifest)}


def save(parent, name, bodies):
    try:
        with ws.child(parent, name, create=True) as directory, ExitStack() as artifacts:
            for file, raw in bodies.items():
                artifacts.enter_context(ws.io.created_file(directory, file, raw))
            # A failure keeps its partial directory; only verified bytes get a completion marker.
            marker = "complete-" + ws.contract.digest(bodies[MANIFEST])
            with ws.child(directory, marker, create=True):
                pass
    except FileExistsError as exc:
        raise ws.WorkspaceError("PANEL_REPORT_EXISTS",
                                "Ya existe un informe o intento con ese ID. Elegí otra carpeta.", 4) from exc
    return str(PureWindowsPath(parent.path, name))


def verify_projection(report, encoded, body):
    ws.contract.need(type(report) is dict and report.get("schema") in (LEGACY_SCHEMA, PREVIOUS_SCHEMA, SCHEMA)
                     and type(report.get("entries")) is list
                     and len(report["entries"]) <= ws.LIMITS["results"], "PANEL_REPORT_SCHEMA")
    current = report["schema"] == SCHEMA
    ws.contract.need(report.get("limitations") == list(V3_LIMITATIONS if current else LIMITATIONS),
                     "PANEL_REPORT_SCHEMA")
    pending = [(report, 0)]
    while pending:
        value, depth = pending.pop()
        ws.contract.need(depth <= 12, "PANEL_REPORT_DEPTH")
        if type(value) is dict:
            pending.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            pending.extend((item, depth + 1) for item in value)
    ws.contract.need(ws.contract.canonical(report) == encoded, "PANEL_REPORT_CANONICAL")
    if current:
        ws.contract.need(type(report.get("result")) is str and report.get("source_currentness") == "AT_CAPTURE_ONLY"
                         and all(type(entry) is dict and entry.get("evidence_id") == citation_id(entry)
                                 for entry in report["entries"]),
                         "PANEL_REPORT_SCHEMA")
    projection = markdown(report)
    historical = report["schema"] == LEGACY_SCHEMA
    ws.contract.need(len(projection) <= MAX_BYTES and (historical or body == projection), "PANEL_REPORT_PROJECTION")
    return projection.decode("utf-8"), encoded.decode("ascii"), historical


def read(parent, name):
    if not REPORT_ID.fullmatch(name):
        raise ws.WorkspaceError("PANEL_REPORT_ID", "Indicá la carpeta exacta del informe pgop-panel.")
    try:
        with ws.child(parent, name, source=True) as directory:
            raw = ws.read_bytes(directory, MANIFEST, 4096)
            marker = "complete-" + ws.contract.digest(raw)
            with ws.child(directory, marker, source=True):
                manifest = ws.contract.strict(raw)
                encoded = ws.read_bytes(directory, JSON, MAX_BYTES)
                body = ws.read_bytes(directory, MARKDOWN, MAX_BYTES)
                actual = {file: {"bytes": len(data), "sha256": ws.contract.digest(data)}
                          for file, data in ((JSON, encoded), (MARKDOWN, body))}
                ws.contract.need(manifest == {"schema": MANIFEST_SCHEMA, "id": name, "files": actual},
                                 "PANEL_REPORT_MANIFEST")
                ws.contract.need(name == "pgop-panel-" + actual[JSON]["sha256"], "PANEL_REPORT_HASH")
                return verify_projection(ws.contract.strict(encoded), encoded, body)
    except (ValueError, RecursionError, OSError, KeyError, TypeError) as exc:
        if getattr(exc, "winerror", None) in (5, 32, 33):
            raise
        raise ws.WorkspaceError("PANEL_REPORT_INCOMPLETE",
                                "El informe falta, está incompleto o no coincide con sus datos y hashes.", 3) from exc
