"""Current source admission and evidence packets for the local context profile."""
from pathlib import Path, PureWindowsPath

from . import context_local_store as store
from . import panel_views as views, workspace as ws, workspace_search as search
from .literal_projection import citation
from .panel import guarded_project
from .text_bytes import content_start, decode

MAX_SELECTIONS = 8
MAX_FRAGMENT_BYTES = 8192


def context_error(code, message):
    return ws.WorkspaceError(code, message, 3)


def check_code():
    if not ws.search.code_matches():
        raise context_error("CODE_CHANGED", "Reinstalá PGOPCore antes de leer fuentes.")


def project_binding(root):
    return {"path": root.path, "identity": list(root.ids[-1])}


def text_label(value, limit):
    value = value.strip()
    if not value or len(value) > limit or not value.isprintable():
        raise context_error("INVALID_CONTEXT_LABEL", f"Escribí entre 1 y {limit} caracteres visibles.")
    views.guard(value.encode("utf-8"), "context.txt")
    return value


def json_value(raw, pointer):
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ValueError("pointer")
    value = views.json_value(raw)
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        if views.json_pointer([key]) != "/" + part:
            raise ValueError("pointer")
        if isinstance(value, list):
            index = int(key)
            if str(index) != key or index < 0:
                raise ValueError("index")
            value = value[index]
        else:
            value = value[key]
    return views.render_json(value)


def project_fragment(raw, breaks, path, selector):
    try:
        kind = selector["kind"]
        if kind == "json_pointer" and path.endswith(".json"):
            pointer = selector["pointer"]
            return {"kind": kind, "pointer": pointer}, json_value(raw, pointer)
        if kind == "csv_record" and path.endswith(".csv"):
            delimiter, number = selector["delimiter"], selector["record"]
            if delimiter not in views.DELIMITERS or type(number) is not int or number < 1:
                raise ValueError("record")
            record = views.csv_rows(decode(raw), delimiter)[number - 1]
            exact = {"kind": kind, "delimiter": delimiter, "record": number,
                     "line_start": record.first_line, "line_end": record.last_line}
            if "column" in selector:
                column = selector["column"]
                if type(column) is not int or column < 1:
                    raise ValueError("column")
                return {**exact, "column": column}, record.fields[column - 1]
            import json
            return exact, json.dumps(record.fields, ensure_ascii=False, indent=2)
        if kind == "lines":
            offsets = views.line_offsets(raw, breaks)
            first, last = selector["line_start"], selector["line_end"]
            if not 1 <= first <= last < len(offsets):
                raise ValueError("lines")
            start, end = offsets[first - 1], offsets[last]
            kind = "utf8_bytes"
        elif kind in {"utf8_bytes", "markdown_section", "markdown_front_matter", "python_declaration", "paragraph"}:
            start, end = selector["byte_start"], selector["byte_end"]
        else:
            raise ValueError("kind")
        if not content_start(raw) <= start < end <= len(raw):
            raise ValueError("range")
        exact = citation(raw, breaks, start, end)
        return {"kind": kind, **{key: exact[key] for key in ("byte_start", "byte_end", "line_start", "line_end")}}, exact["excerpt"]
    except (TypeError, ValueError, KeyError, IndexError, AttributeError, OverflowError) as exc:
        raise context_error("INVALID_SELECTOR", "Elegí una sección, valor o rango disponible.") from exc


def source_problem(exc):
    code = getattr(exc, "code", str(exc))
    winerror = getattr(exc, "winerror", None)
    if winerror == 5 or isinstance(exc, PermissionError):
        return context_error("ACCESS_DENIED", "Windows denegó la lectura de una fuente.")
    if (code.startswith("SOURCE_") and any(word in code for word in ("CHANGED", "MISMATCH"))):
        return context_error("STALE_SOURCE_CHANGED", "Cambió una fuente. Volvé a capturarla.")
    if code == "PANEL_SENSITIVE_CONTENT":
        return context_error("ACCESS_DENIED", "La política actual de contenido impide abrir una fuente.")
    return context_error("SOURCE_UNAVAILABLE", "Una fuente ya no está disponible para verificarla.")


def admit_source(root, path, selector, expected=None):
    try:
        row, raw, breaks = search.capture_file(root, path)
        views.guard(raw, path)
    except (ws.io.SafeIOError, OSError, ValueError) as exc:
        raise source_problem(exc) from exc
    keys = ("path", "bytes", "sha256", "identity", "times", "policy")
    reference = {key: row[key] for key in keys}
    if expected and any(reference[key] != expected[key] for key in keys if key in expected):
        raise context_error("STALE_SOURCE_CHANGED", "Cambió una fuente. Volvé a capturarla.")
    exact, text = project_fragment(raw, breaks, path, selector)
    body = text.encode("utf-8")
    if len(body) > MAX_FRAGMENT_BYTES:
        raise context_error("FRAGMENT_LIMIT", "Elegí un fragmento de hasta 8 KiB.")
    return {"source": reference, "selector": exact, "text": text,
            "projection_sha256": store.sha256_bytes(body), "checked_at": row["captured_at"]}


def approval(plan):
    entries = [{key: value for key, value in item.items() if key != "checked_at"} for item in plan["entries"]]
    return store.sha256_bytes(store.canonical_json({**plan, "entries": entries}))


def prepare(project, parent, name, purpose, selections, identity=None):
    check_code()
    if not 1 <= len(selections) <= MAX_SELECTIONS:
        raise context_error("CONTEXT_LIMIT", "Elegí entre una y ocho referencias.")
    parent = store.store_parent(parent)
    destination = store.destination_identity(parent)
    name, purpose = text_label(name, 80), text_label(purpose, 240)
    with guarded_project(project, identity) as (root, _):
        entries, seen = [], set()
        for selection in selections:
            path, selector, expected = selection
            entry = admit_source(root, path, selector, expected)
            key = store.canonical_json([path, entry["selector"]])
            if key not in seen:
                entries.append(entry)
                seen.add(key)
        root.validate()
        return {"project": project_binding(root), "destination_parent": parent, "destination_identity": destination,
                "name": name, "purpose": purpose, "entries": entries}


def save(plan, confirmed_approval):
    if approval(plan) != confirmed_approval:
        raise context_error("CONSENT_REQUIRED", "Volvé a revisar la selección y el destino.")
    project = plan["project"]
    selections = [(entry["source"]["path"], entry["selector"], entry["source"]) for entry in plan["entries"]]
    current = prepare(project["path"], plan["destination_parent"], plan["name"], plan["purpose"],
                      selections, tuple(project["identity"]))
    if current["destination_identity"] != plan["destination_identity"]:
        raise store.changed_destination()
    if approval(current) != confirmed_approval:
        raise context_error("STALE_SOURCE_CHANGED", "Cambió una selección antes de guardar.")
    with guarded_project(project["path"], tuple(project["identity"])) as (root, _):
        with store.open_store(plan["destination_parent"], root, write=True, create=True,
                              expected=plan["destination_identity"]) as engine:
            root.validate()
            fingerprint = store.sha256_bytes(Path(__file__).read_bytes())
            return engine.ingest(current, fingerprint)


def catalog(project, parent, *, identity=None, fragment=""):
    with guarded_project(project, identity) as (root, _):
        with store.open_store(parent, root) as engine:
            return engine.query(project_binding(root), fragment)


def packet(project, parent, key, *, identity=None):
    check_code()
    with guarded_project(project, identity) as (root, _):
        with store.open_store(parent, root) as engine:
            record = engine.observation(project_binding(root), key)
            if key in engine.revoked:
                raise context_error("REVOKED", "Se quitó el acceso local a esta versión.")
            entries = []
            for saved in record["entries"]:
                source = saved["source"]
                try:
                    current = admit_source(root, source["path"], saved["selector"], source)
                except ws.WorkspaceError as exc:
                    if exc.code == "STALE_SOURCE_CHANGED":
                        raise context_error(exc.code, f'Cambió {source["path"]}. Volvé a capturar la referencia.') from exc
                    raise
                if current["selector"] != saved["selector"] or current["projection_sha256"] != saved["projection_sha256"]:
                    raise store.corrupt()
                entries.append(current)
            root.validate()
            fields = ("id", "project", "name", "purpose", "stored_at", "supersedes", "consent_receipt",
                      "authority_scope", "independent_custody", "extractor_code_sha256")
            return {"state": "CURRENT_AT_READ", **{field: record[field] for field in fields},
                    "entries": entries, "coverage": "EXPLICIT_SELECTIONS",
                    "limits": {"selections": MAX_SELECTIONS, "fragment_bytes": MAX_FRAGMENT_BYTES,
                               "atomic_multi_source_snapshot": False}}


def revoke(project, parent, key, *, identity=None):
    with guarded_project(project, identity) as (root, _):
        with store.open_store(parent, root, write=True) as engine:
            return engine.revoke(project_binding(root), key)


def destination(parent):
    return str(PureWindowsPath(store.store_parent(parent), store.DIRECTORY))


def dispatch(args):
    action = args.context_action
    root, parent = args.project, args.store_parent
    try:
        if not args.allow_local:
            raise context_error("CONSENT_REQUIRED", "Confirmá el alcance con --allow-local.")
        if action in {"preview", "save"}:
            selections = []
            for path, first, last in args.lines:
                if not first.isascii() or not last.isascii() or not first.isdecimal() or not last.isdecimal():
                    raise context_error("INVALID_SELECTOR", "Usá números de línea positivos.")
                if max(len(first), len(last)) > 6:
                    raise context_error("INVALID_SELECTOR", "El rango supera el límite de líneas.")
                selections.append((path, {"kind": "lines", "line_start": int(first), "line_end": int(last)}, None))
            selections.extend((path, {"kind": "json_pointer", "pointer": pointer}, None)
                              for path, pointer in args.json_value)
            plan = prepare(root, parent, args.name, args.purpose, selections)
            data = ({"preview": plan, "confirm": approval(plan), "destination": destination(parent),
                     "message": "Selecciones verificadas. Revisá el contenido y destino antes de guardar."}
                    if action == "preview" else
                    {**save(plan, args.confirm), "message": "Contexto guardado en el almacén local."})
        elif action == "list":
            records = catalog(root, parent, fragment=args.name)
            data = {"contexts": records, "message": "\n".join(
                f'{row["name"]} · {row["state"]} · {row["id"]}' for row in records) or "No hay contextos para este proyecto."}
        elif action == "get":
            data = packet(root, parent, args.id)
        else:
            data = {**revoke(root, parent, args.id), "message": "Acceso local revocado."}
        return {"schema": store.SCHEMA, "command": f"context {action}", "outcome": "OK", "data": data}, 0
    except (ws.WorkspaceError, ws.io.SafeIOError, OSError, ValueError) as exc:
        payload, code = ws.error_result(f"context {action}", exc)
        return {**payload, "schema": store.SCHEMA}, code


def human(payload):
    data = payload["data"]
    if "preview" in data:
        preview = data["preview"]
        return "\n\n".join((preview["name"], preview["purpose"], data["destination"],
                            *(f'{item["source"]["path"]}\n{item["text"]}' for item in preview["entries"]),
                            "Confirmación · " + data["confirm"]))
    if "entries" in data:
        return "\n\n".join((data["name"], data["purpose"],
                            *(f'{item["source"]["path"]}\n{item["text"]}' for item in data["entries"])))
    return data.get("message", payload["outcome"])


