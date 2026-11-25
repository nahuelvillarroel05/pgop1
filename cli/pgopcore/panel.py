"""PGOPCore's local, numbered terminal panel."""

from contextlib import contextmanager
from dataclasses import dataclass
from importlib.metadata import version
import json
import os
from pathlib import PureWindowsPath
import sys

from . import product, workspace as ws, workspace_report, workspace_search
from . import panel_project, panel_python, panel_report as reports, panel_views as views
from .cli import safe, write_legacy_text
from .source_paths import canonical, excluded_name, path_parts
from .text_bytes import content_start, decode


PAGE = 8
REPORT_EVIDENCE_PAGE = 16
SUFFIXES = tuple(sorted(ws.text.FORMATS))
ERRORS = (ws.WorkspaceError, ws.io.SafeIOError, OSError, ValueError)
FORMAT = {".md": "Markdown", ".txt": "Texto", ".py": "Python", ".json": "JSON", ".csv": "CSV"}
PREVIEW_CODES = {
    "SOURCE_LIMIT": "archivos mayores a 256 KiB", "REGISTRY_LIMIT": "límite de 100 fuentes",
    "CORPUS_BYTE_LIMIT": "límite de 8 MiB", "ENTRY_OR_PAGE_LIMIT": "límite de exploración",
    "DEPTH_LIMIT": "más de cinco niveles", "NAME_POLICY": "nombres ocultos o protegidos",
    "UNSUPPORTED_FORMAT": "formatos sin soporte", "ATTRIBUTES_OR_REPARSE": "atributos o enlaces excluidos",
    "USER_SELECTED_SCOPE": "selección acotada", "HARDLINK": "enlaces duros excluidos",
    "NEW_SINCE_PREVIEW": "nuevos archivos fuera de la conformidad", "REMOVED": "retirados del registro",
    "PREVIEW_FILES_UNAVAILABLE": "candidatas de la vista previa que no se pudieron registrar",
}


@dataclass
class Source:
    row: dict
    raw: bytes
    breaks: list
    revision: int | None
    observed: str
    root: str
    root_identity: tuple


def pathname(value):
    value = value.strip()
    return value[1:-1] if len(value) > 1 and value[0] == value[-1] == '"' else value


def overlap(path, protected):
    protected = PureWindowsPath(protected)
    return protected.is_absolute() and (path.is_relative_to(protected) or protected.is_relative_to(path))


@contextmanager
def guarded_project(raw, identity=None):
    path = ws.configured_root(raw)
    normalized = PureWindowsPath(path)
    protected = (sys.prefix, sys.base_prefix, os.environ.get("PGOP_PANEL_INSTALL_DIR"),
                 os.environ.get("SystemRoot"), os.environ.get("PUBLIC"))
    if any(item and overlap(normalized, item) for item in protected):
        raise ws.root_error()
    for name in ("HOME", "HOMEDRIVE"):
        home = os.environ.get(name, "")
        if name == "HOMEDRIVE":
            home += os.environ.get("HOMEPATH", "")
        if home and PureWindowsPath(home).is_absolute() and PureWindowsPath(home).is_relative_to(normalized):
            raise ws.root_error()
    with ws.project(path) as (root, installed):
        if identity is not None and root.ids[-1] != identity:
            raise ws.WorkspaceError("ROOT_IDENTITY_CHANGED", "La carpeta cambió. Volvé a seleccionarla.", 3)
        yield root, installed


def source_problem(status, code, winerror):
    if winerror in (2, 3):
        return "Archivo ausente. Si lo moviste, elegí la carpeta nueva o actualizá el registro."
    if code == "PANEL_SENSITIVE_CONTENT":
        return "Contenido reservado por indicadores de credenciales. Elegí otra fuente."
    if code.startswith("JSON_"):
        return f"JSON inválido o fuera de límite ({code}). Revisá el archivo original."
    return {
        "STALE": "Archivo cambiado. Revisá y actualizá el registro si querés capturar la versión nueva.",
        "PERMISSION_DENIED": "Sin permiso de lectura. Revisá el acceso con tu cuenta.",
        "UNSUPPORTED_PATH": "Ruta no admitida. Elegí un archivo local regular con ruta compatible.",
        "INVALID_SOURCE": f"Contenido no admitido ({code}). Verificá UTF-8 y los límites del formato.",
        "NOT_VERIFIED": "Verificación incompleta por el límite de tiempo. Acotá el alcance.",
    }.get(status, f"No se pudo leer ({code}). Revisá el acceso y probá con otro archivo.")


def summarize(counts):
    return ", ".join(f"{PREVIEW_CODES.get(name, name)} · {count}" for name, count in sorted(counts.items()))


class Panel:
    def __init__(self, input_stream=None, output=None):
        self.input = input_stream
        self.output = output if output is not None else sys.stdout
        self.version = version("pgopcore")
        self.path = self.identity = self.observation = self.last_path = None

    def say(self, message=""):
        write_legacy_text(self.output, safe(message) + "\n")

    def ask(self, prompt):
        if self.input is None:
            answer = input(prompt + " ")
        else:
            write_legacy_text(self.output, prompt + " ")
            self.output.flush()
            answer = self.input.readline()
            if not answer:
                raise EOFError
            answer = answer.rstrip("\r\n")
        return "0" if answer == "\x1b" else answer

    def choose(self, options, prompt="Elegí una opción:", default=None):
        for key, label in options.items():
            self.say(f"  {key}. {label}")
        while True:
            reply = self.ask(prompt).strip().lower()
            if not reply and default is not None:
                return default
            if reply in options:
                return reply
            self.say("Elegí una de las opciones que aparecen en el menú.")

    def error(self, exc):
        if isinstance(exc, ValueError) and not isinstance(exc, ws.io.SafeIOError):
            self.say("No se pudo interpretar la selección. Revisá el formato o usá otra ubicación.")
            return
        result, _ = ws.error_result("panel", exc)
        self.say(result["data"]["message"])

    def confirm(self, label, cancel="Volver"):
        return self.choose({"1": label, "0": cancel}, default="0") == "1"

    def run(self):
        actions = {"1": self.open_project, "2": self.explore, "3": self.search,
                   "4": self.verify, "5": self.report_menu, "6": self.help,
                   "7": self.about, "8": self.understand_project}
        menu = {"7": "¿Qué es PGOPCore?", "1": "Abrir proyecto o archivo", "8": "Comprender el proyecto",
                "2": "Explorar archivos", "3": "Buscar información y evidencia",
                "4": "Verificar archivos y cambios", "5": "Ver o guardar informes",
                "6": "Configuración y ayuda", "0": "Salir"}
        try:
            while True:
                self.say()
                self.say(f"PGOPCore {self.version}   Proyecto: {self.path or 'ninguno'}")
                if self.path is None:
                    self.say("Enter elige la carpeta actual si es compatible.")
                choice = self.choose(menu, default="current" if self.path is None else None)
                if choice == "0":
                    return 0
                try:
                    if choice == "current":
                        self.open_project(current=True)
                        continue
                    if choice == "8" and self.path is None:
                        self.open_project(overview=True)
                        if self.path is None:
                            continue
                    if choice in {"2", "3", "4"} and self.path is None:
                        self.say("Elegí qué carpeta querés usar para esta operación.")
                        self.open_project()
                        if self.path is None:
                            continue
                    actions[choice]()
                except ERRORS as exc:
                    self.error(exc)
        except EOFError:
            self.say("Fin de entrada. El panel se cerró.")
            return 0
        except KeyboardInterrupt:
            self.say("Panel interrumpido.")
            return 130

    def browse(self, rows, label, title, actions=None):
        offset = 0
        while True:
            page = rows[offset:offset + PAGE]
            self.say()
            self.say(f"{title} · {offset + 1 if rows else 0}–{offset + len(page)} de {len(rows)}")
            options = {str(i): label(item) for i, item in enumerate(page, 1)}
            if offset + PAGE < len(rows):
                options["n"] = "Página siguiente"
            if offset:
                options["p"] = "Página anterior"
            options.update(actions or {})
            choice = self.choose({**options, "0": "Volver"}, default="0")
            if choice == "n":
                offset += PAGE
            elif choice == "p":
                offset -= PAGE
            elif choice.isdecimal() and choice != "0":
                return page[int(choice) - 1]
            else:
                return choice

    def pick_suffix(self):
        types = {str(i): suffix for i, suffix in enumerate(SUFFIXES, 1)}
        chosen = self.choose({**{key: f"{name} · {FORMAT[name]}" for key, name in types.items()},
                              "0": "Todos los formatos"}, default="0")
        return types.get(chosen, "")

    def set_project(self, path, identity):
        if (path, identity) != (self.path, self.identity):
            self.observation = self.last_path = None
        self.path, self.identity = path, identity

    def open_project(self, *, current=False, overview=False):
        cwd = None
        try:
            with guarded_project(".") as (root, _):
                cwd = root.path
        except ERRORS:
            pass
        if cwd:
            self.say(f"Carpeta actual: {cwd}")
            raw = cwd if current else (pathname(self.ask(
                "Enter elige la carpeta actual, o indicá la ruta de un proyecto o archivo (0 vuelve):")) or cwd)
        else:
            raw = pathname(self.ask("Indicá una carpeta de proyecto local específica o la ruta de un archivo (0 vuelve):"))
        if raw in ("", "0"):
            return
        if not overview and PureWindowsPath(raw).suffix in SUFFIXES:
            drive, parts = path_parts(raw)
            self.open_individual(canonical(drive, parts[:-1]), None, parts[-1])
            return
        with guarded_project(raw) as (root, installed):
            path, identity = root.path, root.ids[-1]
            if overview:
                self.set_project(path, identity)
                return
            with ws.open_registry(root, optional=True) as registry:
                existing = registry is not None
                if existing:
                    summary = ws.reviewable_registry(registry)
                else:
                    ws.reject_initialized_ancestor(root, installed)
        self.say(f"Carpeta elegida: {path}")
        if existing:
            self.say(f'Hay un espacio de trabajo con {summary["registered_sources"]} fuentes registradas '
                     f'y {summary["removed_sources"]} retiradas.')
            choice = self.choose({"8": "Comprender el proyecto · propósito y documentación",
                                  "1": "Usar el registro existente", "2": "Revisar y actualizar archivos",
                                  "0": "Volver"}, default="1")
            if choice == "8":
                self.set_project(path, identity)
                self.understand_project()
                return
            if choice == "1":
                self.set_project(path, identity)
                return
            if choice == "0":
                return
        if self.register(path, identity, refresh=existing):
            self.set_project(path, identity)

    def pick_scan_scope(self):
        raw = pathname(self.ask("Subcarpeta relativa dentro del proyecto (Enter para toda la carpeta):"))
        parts = tuple(ws.io.relative(raw.replace("\\", "/"))) if raw else ()
        if len(parts) > ws.LIMITS["directories_deep"] or any(excluded_name(part) for part in parts):
            raise ws.WorkspaceError("SCAN_FOLDER_NOT_ALLOWED", "Elegí una subcarpeta visible, de hasta cinco niveles.")
        suffix = self.pick_suffix()
        name = self.ask("Texto en el nombre de archivo (Enter deja todos):").strip()
        return {"folder": parts, "suffix": suffix, "name": name[:255]}

    def scan_preview(self, path, identity, refresh, scope):
        with guarded_project(path, identity) as (root, _):
            with ws.open_registry(root, optional=True) as registry:
                if (registry is not None) != refresh:
                    raise self.changed_preview()
                scanner = ws.Scan(registry or ws.Registry(root, None, None), True, refresh, **scope)
                preview = scanner.run()
                return preview, scanner.candidate_metadata

    @staticmethod
    def changed_preview():
        return ws.WorkspaceError("PREVIEW_CHANGED", "El estado del proyecto cambió. Volvé a abrir y revisá de nuevo.", 3)

    def register(self, path, identity, *, refresh):
        scope = {}
        while True:
            preview, approved = self.scan_preview(path, identity, refresh, scope)
            candidates = preview["candidates"]
            types = sorted({PureWindowsPath(row["path"]).suffix for row in candidates})
            self.say()
            self.say(f"Vista previa de {path}")
            self.say(f'{len(candidates)} archivos elegibles · {", ".join(types) or "ningún formato"} · '
                     f'{preview["registered_sources"]} ya registrados.')
            self.say("Solo metadatos. Podés comprender el proyecto con una muestra o registrar los archivos de esta vista.")
            self.say("Topes: 100 fuentes, 8 MiB en total, 256 KiB por archivo, cinco niveles y 1.000 entradas.")
            if preview["excluded"]:
                self.say("Exclusiones · " + summarize(preview["excluded"]))
            if preview["partial"]:
                self.say("Cobertura parcial · " + summarize(preview["reasons"]))
                self.say("Acotá por subcarpeta, formato o nombre, o registrá solo los candidatos de esta vista.")
            options = {"2": "Ver candidatas y problemas de acceso", "3": "Acotar la selección", "0": "Volver"}
            if not refresh:
                options = {"4": "Abrir el proyecto sin registrar archivos", **options}
            if candidates:
                options = {"1": "Confirmar lectura y actualización del registro" if refresh else
                           "Confirmar lectura, creación de .pgopcore y registro", **options}
            choice = self.choose({"8": "Comprender el proyecto · propósito y secciones de documentación",
                                  **options}, default="0")
            if choice == "0":
                return False
            if choice == "2":
                picked = self.browse(candidates + preview["failures"], self.preview_row, "Vista por archivo",
                                     {"c": "Comprender el proyecto · propósito y documentación"})
                if picked == "c":
                    choice = "8"
                elif picked != "0" and "bytes" in picked:
                    self.open_individual(path, identity, picked["path"], expected=approved[picked["path"]])
                if choice != "8":
                    continue
            if choice == "8":
                self.set_project(path, identity)
                self.understand_project()
                return True
            if choice == "3":
                scope = self.pick_scan_scope()
                continue
            if choice == "4":
                return True
            data = self.capture_preview(path, identity, refresh, scope, preview["revision"], approved)
            self.say(f'Registro guardado · {data["registered_sources"]} fuentes activas · '
                     f'{len(data["candidates"])} altas o actualizaciones en esta operación.')
            if data["partial"]:
                self.say("Cobertura parcial · " + summarize(data["reasons"]))
            for row in data["failures"][:PAGE]:
                self.say(self.preview_row(row))
            if len(data["failures"]) > PAGE:
                self.browse(data["failures"], self.preview_row, "Problemas durante el registro")
            return True

    @staticmethod
    def preview_row(row):
        if "bytes" in row:
            return f'{row["path"]} · {row["bytes"]} bytes · elegible por metadatos'
        return row["path"] + " · " + source_problem(row["status"], row["code"], row.get("winerror"))

    def capture_preview(self, path, identity, refresh, scope, revision, approved):
        if not ws.search.code_matches():
            raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)
        with guarded_project(path, identity) as (root, installed):
            if not refresh:
                ws.reject_initialized_ancestor(root, installed)
                if not ws.create(root):
                    raise self.changed_preview()
            with ws.open_registry(root, write=True) as registry:
                if registry.revision != revision:
                    raise self.changed_preview()
                return ws.Scan(registry, False, refresh, approved=approved, **scope).run()

    @contextmanager
    def registry(self, *, load_journal=True, optional=False):
        with guarded_project(self.path, self.identity) as (root, _):
            with ws.open_registry(root, load_journal=load_journal, optional=optional) as registry:
                yield registry

    def explore(self):
        name = suffix = ""
        while True:
            with self.registry(optional=True) as registry:
                rows = registry.value["rows"] if registry else []
            filtered = [row for row in rows if name.lower() in row["path"].lower()
                        and (not suffix or row["path"].endswith(suffix))]
            picked = self.browse(filtered, self.registered_row, "Archivos registrados", {
                "u": "Abrir un archivo por ruta relativa al proyecto",
                "f": "Filtrar por nombre y extensión",
            })
            if picked == "0":
                return
            if picked == "f":
                name = self.ask("Texto en el nombre o la ruta (Enter deja todos):").strip()
                suffix = self.pick_suffix()
            elif picked == "u":
                path = pathname(self.ask("Ruta relativa exacta dentro del proyecto (Enter vuelve):"))
                if path:
                    try:
                        self.open_individual(self.path, self.identity, path.replace("\\", "/"))
                    except ERRORS as exc:
                        self.error(exc)
            elif picked["status"] == "REMOVED":
                self.say("La fuente fue retirada del registro. Elegí otro archivo para leer.")
            else:
                try:
                    self.open_source(picked)
                except ERRORS as exc:
                    self.error(exc)

    @staticmethod
    def registered_row(row):
        status = "retirado" if row["status"] == "REMOVED" else "registrado · vigencia por comprobar"
        return f'{row["path"]} · {row["bytes"]} bytes · {status}'

    def open_individual(self, path, identity, relative, *, expected=None):
        """Read a confirmed file; return False when its initial metadata is unavailable."""
        ws.supported_path(path, relative)
        if expected is None:
            with guarded_project(path, identity) as (root, _):
                try:
                    expected = workspace_search.preview_file(root, relative)
                except ERRORS as exc:
                    self.show_source_problem(relative, exc)
                    return False
                identity = root.ids[-1]
        self.say(f"Archivo elegido: {PureWindowsPath(path, relative)}")
        if not self.confirm("Leer solo este archivo"):
            return
        if not ws.search.code_matches():
            raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)
        with guarded_project(path, identity) as (root, _):
            try:
                row, raw, breaks = workspace_search.capture_file(root, relative, expected=expected)
                views.guard(raw, relative)
            except ERRORS as exc:
                self.show_source_problem(relative, exc)
                return
            source = Source(row, raw, breaks, None, row["captured_at"], root.path, root.ids[-1])
        self.set_project(source.root, source.root_identity)
        self.say("Captura individual para esta sesión.")
        self.view_source(source)

    def show_source_problem(self, path, exc):
        detail = ws.classify(exc)
        self.say(f'{path} · ' + source_problem(detail["status"], detail["code"], detail["winerror"]))

    def open_source(self, row, *, line=None):
        if not ws.search.code_matches():
            raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)
        with self.registry() as registry:
            if row not in registry.value["rows"]:
                self.say("El registro cambió. Volvé a elegir el archivo.")
                return
            try:
                raw, breaks = workspace_search.capture(registry.root, row, lambda _: None)
                views.guard(raw, row["path"])
            except ERRORS as exc:
                self.show_source_problem(row["path"], exc)
                return
            source = Source(row, raw, breaks, registry.revision, ws.now(), registry.root.path, registry.root.ids[-1])
        self.view_source(source, line=line)

    def view_source(self, source, *, line=None):
        path = source.row["path"]
        suffix = PureWindowsPath(path).suffix
        self.say(f'{path} · {FORMAT[suffix]} · {source.row["bytes"]} bytes capturados')
        if suffix == ".py":
            self.python_view(source, line=line)
        elif suffix == ".md" and line:
            sections = [unit for unit in views.markdown_units(source.raw, source.breaks)
                        if unit.start_line <= line <= unit.end_line]
            if sections:
                self.unit_view(source, sections[-1])
            else:
                self.text_view(source, line=line)
        elif suffix == ".json":
            self.say("Las cadenas se muestran con sus comillas y escapes JSON. Los números conservan su escritura original.")
            self.json_view(source, views.json_value(source.raw))
        elif suffix == ".csv":
            self.csv_view(source, line=line)
        else:
            self.text_view(source, line=line)

    def source_entry(self, source, selector, text):
        row = source.row
        location = {"registered_at": row["captured_at"]} if row["status"] == "REGISTERED" else {
            "observed_at": row["captured_at"], "identity": row["identity"], "times": row["times"],
            "root_identity": list(source.root_identity), "acquisition_scope": "EXPLICIT_FILE",
        }
        return {"source": {**workspace_search.observed_source(row), "policy": row["policy"], **location},
                "selector": selector, "text": text}

    def note_view(self, source, selector, text):
        entry = self.source_entry(source, selector, text)
        self.observation = reports.build("Lectura", source.root, source.revision, self.version,
                                         source.observed, {"format": PureWindowsPath(source.row["path"]).suffix}, [entry])

    def details(self, source, *, reference=False):
        self.say(f'Archivo: {source.row["path"]} · {source.row["bytes"]} bytes')
        if reference and self.observation and self.observation["operation"] == "Lectura":
            selector = self.observation["entries"][0]["selector"]
            self.say("Referencia · " + json.dumps(selector, ensure_ascii=False))
        self.say(f'SHA-256 de los bytes capturados: {source.row["sha256"]}')
        scope = f"Revisión {source.revision}" if source.revision is not None else "captura individual"
        self.say(f'Captura UTC: {source.observed} · {scope} · PGOPCore {self.version}')

    def text_view(self, source, *, line=None):
        rows = list(views.segments(source.raw, source.breaks))
        is_md = source.row["path"].endswith(".md")
        sections = views.markdown_units(source.raw, source.breaks) if is_md else []
        is_txt = source.row["path"].endswith(".txt")
        offset = next((index for index, row in enumerate(rows) if row.line == line), 0) if line else 0
        previous_offset = None
        while True:
            page = rows[offset:offset + PAGE]
            if page:
                first, last = page[0], page[-1]
                self.say()
                self.say(f'{source.row["path"]} · líneas {first.line}–{last.line}')
                for item in page:
                    self.say(f"{item.line:>5} | {item.text}")
                selector = {"kind": "utf8_bytes", "line_start": first.line, "line_end": last.line,
                            "byte_start": first.start, "byte_end": last.end}
                text = source.raw[first.start:last.end].decode("utf-8")
            else:
                self.say("Archivo vacío.")
                start = content_start(source.raw)
                selector, text = {"kind": "utf8_bytes", "byte_start": start, "byte_end": start}, ""
            if previous_offset != offset:
                self.note_view(source, selector, text)
                previous_offset = offset
            options = {"3": "Buscar dentro del archivo", "4": "Ver referencia del fragmento",
                       "5": "Detalles de la fuente", "6": "Guardar informe del fragmento", "0": "Volver"}
            if offset + PAGE < len(rows):
                options = {"1": "Ver más", **options}
            if offset:
                options["2"] = "Página anterior"
            if rows:
                options["7"] = "Ir a una línea"
            if is_md:
                options["8"] = "Leer una sección Markdown completa"
            elif is_txt and rows:
                options["8"] = "Leer por párrafos"
            options["q"] = "¿Qué es este archivo?"
            if self.last_path:
                options["9"] = "Reabrir el último informe guardado"
            choice = self.choose(dict(sorted(options.items(), key=lambda pair: pair[0] == "0")), default="0")
            if choice == "0":
                return
            if choice == "1":
                offset += PAGE
            elif choice == "2":
                offset = max(0, offset - PAGE)
            elif choice == "3":
                self.search(source=source)
            elif choice in ("4", "5"):
                if choice == "4":
                    self.note_view(source, selector, text)
                self.details(source, reference=choice == "4")
            elif choice == "6":
                self.note_view(source, selector, text)
                self.save_report()
            elif choice == "9":
                self.open_saved(self.last_path)
            elif choice == "q":
                self.file_summary(source, sections)
            elif choice == "8":
                if is_md:
                    self.browse_units(source, sections, "Secciones Markdown")
                else:
                    self.browse_units(source, list(views.paragraphs(source.raw, source.breaks)), "Párrafos")
            elif choice == "7":
                requested = self.ask(f"Número de línea de 1 a {rows[-1].line}:").strip()
                target = int(requested) if requested.isascii() and requested.isdecimal() and len(requested) <= 5 else None
                found = next((i for i, row in enumerate(rows) if row.line == target), None)
                if found is None:
                    self.say("Esa línea queda fuera del archivo.")
                else:
                    offset = found

    def file_summary(self, source, sections=()):
        suffix = PureWindowsPath(source.row["path"]).suffix
        self.say(f'¿Qué es este archivo? · {source.row["path"]} · {FORMAT[suffix]}')
        self.say(f'{source.row["bytes"]} bytes capturados como UTF-8.')
        if suffix == ".md":
            self.browse_units(source, sections, "Secciones Markdown disponibles para leer")
        elif suffix == ".py":
            self.python_view(source, fallback=False)
        else:
            self.say("El propósito no se puede determinar con la estructura observada.")

    @staticmethod
    def unit_label(unit):
        return f"{views.short(unit.title)} · líneas {unit.start_line}–{unit.end_line}"

    def browse_units(self, source, units, title, *, original=False):
        actions = {"t": "Leer el archivo por líneas"} if original else None
        while True:
            picked = self.browse(units, self.unit_label, title, actions)
            if picked == "0":
                return
            if picked == "t":
                self.text_view(source)
            else:
                self.unit_view(source, picked)

    def unit_view(self, source, unit):
        text = source.raw[unit.start:unit.end].decode("utf-8")
        self.note_view(source, unit.selector(), text)
        description = (unit.facts or {}).get("documented_description")
        if unit.kind == "python_declaration":
            self.say("Docstring declarado · " + views.short(description, 240) if description else
                     "La declaración no aporta un docstring disponible.")
            self.say("Rango sintáctico observado estáticamente.")

        def search_file():
            with self.preserve_observation():
                self.search(source=source)

        self.show_text(f'{source.row["path"]} · {self.unit_label(unit)}', text, {
            "r": ("Ver referencia de la unidad", lambda: self.details(source, reference=True)),
            "g": ("Guardar y abrir el informe de la unidad completa", self.save_unit_report),
            "b": ("Buscar dentro del archivo", search_file),
            **self.context_option(),
        }, unit=True)

    def context_option(self, entry=None):
        return {}

    def python_view(self, source, *, line=None, fallback=True):
        report, units, description = panel_python.analyze(source)
        self.say(f'¿Qué es este archivo? · Python · AST V2 · {report["status"]}')
        if report["status"] not in ("COMPLETE", "PARTIAL"):
            self.say(f'Análisis sintáctico no disponible ({report.get("reason", report["status"])}). Podés leer el texto.')
        elif len(units) != report["returned"] or report["status"] == "PARTIAL":
            self.say(f'Cobertura parcial · {len(units)} unidades navegables de {report["total_detected"]} detectadas.')
        else:
            self.say(f"{len(units)} funciones y clases detectadas. Análisis estático sin ejecución.")
        if description:
            self.say("Docstring del módulo · " + views.short(description, 240))
        else:
            self.say("Propósito del módulo sin determinar por docstring.")
        if line:
            picked = [unit for unit in units if unit.start_line <= line <= unit.end_line]
            if picked:
                self.unit_view(source, picked[-1])
            else:
                self.text_view(source, line=line)
            return
        if not units:
            if report["status"] in ("COMPLETE", "PARTIAL"):
                first_import = next(panel_python.imports(report), None)
                if first_import:
                    self.say("Primer import declarado · " + first_import)
            if fallback:
                self.text_view(source, line=line)
            return
        while True:
            picked = self.browse(units, self.unit_label, "Funciones y clases por ámbito", {
                "i": "Ver imports declarados", "t": "Ver código completo", "b": "Buscar dentro del archivo",
                "d": "Detalles de la fuente",
            })
            if picked == "0":
                return
            if picked == "i":
                imports = "\n".join(panel_python.imports(report))
                self.show_text("Imports declarados · resolución sin comprobar", imports or "Sin imports observados.")
            elif picked == "t":
                self.text_view(source)
            elif picked == "b":
                self.search(source=source)
            elif picked == "d":
                self.details(source)
            else:
                self.unit_view(source, picked)

    def show_text(self, title, text, actions=None, *, unit=False, page_size=PAGE):
        lines = views.safe_text(text).split("\n")
        rows = [line[i:i + views.LINE_WIDTH] for line in lines
                for i in range(0, max(len(line), 1), views.LINE_WIDTH)]
        offset = 0
        while True:
            self.say()
            self.say(title)
            if unit and len(rows) > page_size:
                self.say(f"Unidad completa · página {offset // page_size + 1} de "
                         f"{(len(rows) + page_size - 1) // page_size}")
            for row in rows[offset:offset + page_size]:
                self.say("  " + row)
            options = {key: label for key, (label, _) in (actions or {}).items()}
            if offset + page_size < len(rows):
                options["n"] = "Ver más"
            if offset:
                options["p"] = "Página anterior"
            choice = self.choose({**options, "0": "Volver"}, default="0")
            if choice == "n":
                offset += page_size
            elif choice == "p":
                offset -= page_size
            elif actions and choice in actions:
                actions[choice][1]()
            else:
                return

    @contextmanager
    def preserve_observation(self):
        previous = self.observation
        try:
            yield
        finally:
            self.observation = previous

    def structured_value(self, source, selector, text, title):
        self.note_view(source, selector, text)

        def search_current_file():
            with self.preserve_observation():
                self.search(source=source)

        actions = {"r": ("Ver referencia", lambda: self.details(source, reference=True)),
                   "g": ("Guardar informe", self.save_report),
                   "b": ("Buscar dentro del archivo", search_current_file),
                   "a": ("Reabrir el último informe guardado", self.reopen_last), **self.context_option()}
        self.show_text(title, text, actions)

    def json_view(self, source, value, route=()):
        pointer = views.json_pointer(route)
        selector = {"kind": "json_pointer", "pointer": pointer}
        title = f'JSON · {views.json_kind(value)} · {views.short(pointer or "raíz", 120)}'
        children = list(value.items()) if isinstance(value, dict) else (
            list(enumerate(value)) if isinstance(value, list) else [])
        if not children:
            self.structured_value(source, selector, views.render_json(value), title)
            return
        while True:
            selected = self.browse(children, self.json_row, title, {
                "v": "Ver el contenido de este elemento", "t": "Leer archivo por líneas",
                "b": "Buscar dentro del archivo", "d": "Detalles de la fuente",
            })
            if selected == "0":
                return
            if selected == "v":
                self.structured_value(source, selector, views.render_json(value), title)
            elif selected == "t":
                self.text_view(source)
            elif selected == "b":
                self.search(source=source)
            elif selected == "d":
                self.details(source)
            else:
                key, item = selected
                self.json_view(source, item, (*route, key))

    @staticmethod
    def json_row(item):
        key, value = item
        label = f"Índice {key}" if isinstance(key, int) else f"Campo {views.short(key)!r}"
        description = views.json_kind(value)
        if not isinstance(value, (dict, list)):
            description += " · " + views.short(views.render_json(value), 63)
        return f"{label} · {description}"

    def csv_view(self, source, *, line=None):
        text = decode(source.raw)
        try:
            delimiter, records = views.detect_csv(text)
        except views.CSVError:
            self.say("No se pudo determinar un delimitador único con filas consistentes.")
            delimiters = dict(zip("1234", views.DELIMITERS))
            selected = self.choose({**{k: views.DELIMITERS[v] for k, v in delimiters.items()},
                                    "t": "Leer como texto", "0": "Volver"}, default="0")
            if selected in ("0", "t"):
                if selected == "t":
                    self.text_view(source)
                return
            delimiter = delimiters[selected]
            try:
                records = views.csv_rows(text, delimiter)
            except views.CSVError as exc:
                self.say(f"Estructura CSV no disponible ({exc}). Se puede leer el texto original.")
                self.text_view(source)
                return
        header, *body = records
        if line:
            for number, record in enumerate(records):
                if record.first_line <= line <= record.last_line:
                    self.csv_fields(source, delimiter, number, record, header)
                    return
        numbered = list(enumerate(body, 1))
        matching = numbered
        heading = f'CSV · {views.DELIMITERS[delimiter]} · {len(header.fields)} columnas · {len(body)} filas'
        self.say("Primera fila como encabezados · " + views.short(" | ".join(header.fields), 140))
        while True:
            selected = self.browse(matching, self.csv_row_label, heading, {
                "e": "Ver encabezados", "b": "Buscar texto en las celdas", "t": "Leer archivo por líneas",
                "d": "Detalles de la fuente",
            })
            if selected == "0":
                return
            if selected == "e":
                self.csv_fields(source, delimiter, 0, header, header)
            elif selected == "d":
                self.details(source)
            elif selected == "t":
                self.text_view(source)
            elif selected == "b":
                query = self.ask("Texto literal en celdas (Enter restaura todas las filas):")
                if query == "":
                    matching = numbered
                else:
                    workspace_search.needle_for(query)
                    matching = [row for row in numbered if any(query in field for field in row[1].fields)]
                    self.say(f"{len(matching)} filas con coincidencias. La búsqueda distingue mayúsculas.")
            else:
                number, row = selected
                self.csv_fields(source, delimiter, number, row, header)

    @staticmethod
    def csv_row_label(item):
        number, row = item
        return f"Fila {number} · líneas {row.first_line}–{row.last_line} · " + views.short(" | ".join(row.fields), 96)

    def csv_fields(self, source, delimiter, number, row, header):
        selector = {"kind": "csv_record", "delimiter": delimiter, "record": number + 1,
                    "line_start": row.first_line, "line_end": row.last_line}
        title = f"Fila {number}" if number else "Encabezados"
        while True:
            selection = self.browse(list(enumerate(row.fields, 1)),
                                    lambda item: f"Columna {item[0]} · {views.short(header.fields[item[0] - 1])} "
                                                 f"= {views.short(item[1])}", title, {"v": "Ver todos los campos"})
            if selection == "0":
                return
            if selection == "v":
                text = json.dumps(row.fields, ensure_ascii=False, indent=2)
                self.structured_value(source, selector, text, title)
            else:
                field, value = selection
                self.structured_value(source, {**selector, "column": field}, value, f"{title} · Campo {field}")

    def ask_query(self):
        return self.ask("Texto literal para buscar (sin interpretar escapes, Enter vuelve):")

    def search(self, *, source=None):
        query = self.ask_query()
        if not query:
            return
        needle = workspace_search.needle_for(query)
        try:
            views.guard(needle, "")
        except ValueError:
            self.say("Elegí una consulta que no incluya indicadores de credenciales.")
            return
        path = source.row["path"] if source else ""
        suffix = ""
        ignore_case, context, all_matches = False, 1, source is not None
        default_scope = path or "todas las fuentes registradas"
        self.say(f"Alcance: {default_scope} · distingue mayúsculas · una línea de contexto.")
        choice = self.choose({"1": "Buscar con estas opciones", "2": "Ajustar opciones", "0": "Volver"}, default="1")
        if choice == "0":
            return
        if choice == "2":
            if source is None:
                raw = pathname(self.ask("Ruta relativa a una carpeta o archivo (Enter deja todas):"))
                if raw:
                    path = "/".join(ws.io.relative(raw.replace("\\", "/")))
                suffix = self.pick_suffix()
            ignore_case = self.choose({"1": "Distinguir mayúsculas", "2": "Ignorar mayúsculas ASCII"}, default="1") == "2"
            context = int(self.choose({"1": "Una línea alrededor", "3": "Tres líneas alrededor",
                                      "0": "Solo la línea de la coincidencia"}, default="1"))
            all_matches = self.choose({"1": "Una cita por archivo", "2": "Varias citas por archivo"},
                                      default="2" if source else "1") == "2"
        individual = source if source and source.revision is None else None
        if individual:
            if not ws.search.code_matches():
                raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)
            with guarded_project(source.root, source.root_identity) as (root, _):
                try:
                    result = workspace_search.observe_file(root, source.row, query, ignore_case=ignore_case,
                                                           all_matches=all_matches, context_lines=context,
                                                           source_guard=views.guard)
                except ERRORS as exc:
                    self.show_source_problem(path, exc)
                    return
        else:
            with self.registry(optional=True) as registry:
                if not registry:
                    self.say("La búsqueda del proyecto necesita un registro. También podés abrir y buscar en un solo archivo.")
                    return
                if source and source.row not in registry.value["rows"]:
                    self.say("El registro cambió. Volvé a elegir el archivo para buscar.")
                    return
                selected = None
                if path or suffix:
                    selected = {row["id"] for row in registry.value["rows"]
                                if (not path or row["path"] == path or row["path"].startswith(path + "/"))
                                and (not suffix or row["path"].endswith(suffix))}
                    if not selected:
                        self.say("No hay archivos registrados para esa ruta y ese formato. Revisá la selección.")
                        return
                result, _ = workspace_search.observe(registry, query=query, ignore_case=ignore_case,
                                                     all_matches=all_matches, selected=selected,
                                                     context_lines=context, source_guard=views.guard, diverse=True)
        parameters = {"literal": query, "ruta_relativa": path or None, "formato": suffix or None,
                      "mayúsculas": "plegado ASCII" if ignore_case else "coincidencia exacta",
                      "citas_por_archivo": "varias" if all_matches else "una", "líneas_de_contexto": context,
                      "selection_order": "FIRST_MATCH_PER_SOURCE_BEFORE_REPEATS"}
        self.search_results(result, parameters, individual)

    def search_results(self, result, parameters, individual=None):
        data = result["data"]
        hits = data["results"]
        self.say(f'{data["verified_occurrences"]} coincidencias · {data["matched_sources"]} archivos con resultados · '
                 f'{data["checked_sources"]}/{data["started_with_active_sources"]} fuentes comprobadas.')
        if not hits:
            self.say("No se encontró el texto en las fuentes que se pudieron comprobar.")
            self.say("Probá el texto tal como aparece en el documento, con su idioma y ortografía.")
        if data["partial"]:
            self.say("Búsqueda incompleta. Revisá el acceso, el registro y los límites antes de concluir.")
        if data["omitted_occurrences"]:
            self.say(f'{data["omitted_occurrences"]} coincidencias adicionales sin cita. '
                     'Acotá la ruta o elegí varias citas por archivo.')
        if data["truncated"]:
            self.say("Resultados truncados por el tope de diez citas.")
        if data["matched_sources"] > 1:
            self.say("Se ofrece una cita por archivo antes de repetir archivos.")
        for row in data["unavailable"][:PAGE]:
            self.say(row["path"] + " · " + source_problem(row["status"], row["code"], row["winerror"] if "winerror" in row else None))
        entries = []
        for hit in hits:
            context = hit["context"]
            source = {key: hit[key] for key in ("id", "path", "bytes", "sha256")}
            selector = {"kind": "utf8_bytes", **{k: hit[k] for k in ("line_start", "line_end", "byte_start", "byte_end")}}
            entry = self.source_entry(individual, selector, context["excerpt"]) if individual else {
                "source": source, "selector": selector, "text": context["excerpt"],
            }
            entries.append({**entry, "literal_match": hit["excerpt"],
                            "context": {k: v for k, v in context.items() if k != "excerpt"}})
        coverage_fields = ("limits", "registered_scan", "partial", "truncated", "started_with_active_sources",
                           "checked_sources", "verified", "unavailable", "removed", "verified_occurrences",
                           "omitted_occurrences", "omitted_matching_sources")
        coverage = {"outcome": result["outcome"], "scope": data["scope"],
                    **{key: data[key] for key in coverage_fields}}
        self.observation = reports.build("Búsqueda literal", self.path, data["revision"], self.version,
                                         data["observed_at"], parameters, entries, coverage)
        groups = {}
        for hit in hits:
            groups.setdefault(hit["path"], []).append(hit)
        actions = {"g": "Guardar informe de esta búsqueda", "a": "Reabrir el último informe guardado"}
        if not hits:
            actions = {"e": "Explorar archivos", **actions}
        if len(hits) == 1:
            self.hit_view(hits[0], individual)
            return
        while True:
            selected = self.browse(list(groups.items()), self.search_group, "Coincidencias por archivo", actions)
            if selected == "0":
                return
            if selected == "g":
                self.save_report()
            elif selected == "a":
                self.reopen_last()
            elif selected == "e":
                with self.preserve_observation():
                    self.explore()
            else:
                path, matches = selected
                if len(matches) == 1:
                    self.hit_view(matches[0], individual)
                    continue
                while True:
                    hit = self.browse(matches, self.hit_label, path)
                    if hit == "0":
                        break
                    self.hit_view(hit, individual)

    @staticmethod
    def search_group(item):
        path, hits = item
        return f'{path} · {len(hits)} citas · {Panel.hit_label(hits[0])}'

    @staticmethod
    def hit_label(hit):
        excerpt = " ".join(hit["context"]["excerpt"].split())
        position = excerpt.find(" ".join(hit["excerpt"].split()))
        start = max(0, position - 18)
        return f'Línea {hit["line_start"]} · ' + ("…" if start else "") + views.short(excerpt[start:], 76)

    def open_hit(self, hit, individual=None):
        if individual:
            with guarded_project(individual.root, individual.root_identity) as (root, _):
                try:
                    raw, breaks = workspace_search.capture(root, individual.row, lambda _: None)
                    views.guard(raw, individual.row["path"])
                except ERRORS as exc:
                    self.show_source_problem(hit["path"], exc)
                    return
            with self.preserve_observation():
                self.view_source(Source(individual.row, raw, breaks, None, ws.now(), individual.root,
                                        individual.root_identity), line=hit["line_start"])
            return
        with self.registry() as registry:
            row = next((item for item in registry.value["rows"] if item["id"] == hit["id"]
                        and item["sha256"] == hit["sha256"] and item["status"] == "REGISTERED"), None)
        if row is None:
            self.say("La versión citada cambió o fue retirada. Volvé a buscar o elegí el archivo en Explorar.")
            return
        with self.preserve_observation():
            self.open_source(row, line=hit["line_start"])

    def hit_view(self, hit, individual=None):
        context = hit["context"]
        title = f'{hit["path"]} · contexto líneas {context["line_start"]}–{context["line_end"]}'
        if context["shortened"]:
            self.say("Contexto acotado a 500 caracteres antes y después de la coincidencia.")
        labels = {".md": "Abrir la sección Markdown", ".py": "Abrir la función o clase",
                  ".csv": "Abrir la fila CSV"}
        label = labels.get(PureWindowsPath(hit["path"]).suffix, "Abrir el archivo")
        entry = next((item for item in (self.observation or {}).get("entries", ())
                      if item["source"]["path"] == hit["path"]
                      and item["selector"]["byte_start"] == hit["byte_start"]), None)
        self.show_text(title, context["excerpt"], {
            "1": (label, lambda: self.open_hit(hit, individual)),
            "g": ("Guardar informe de esta búsqueda", self.save_report),
            "a": ("Reabrir el último informe guardado", self.reopen_last),
            **(self.context_option(entry) if entry else {}),
        })

    def verify(self):
        while True:
            with self.registry(optional=True) as registry:
                initialized = registry is not None
                if not initialized or registry.value["scanned_at"] is None:
                    result = None
                else:
                    result, _ = workspace_search.observe(registry)
            checks = []
            if result is None:
                self.say("El espacio todavía no tiene un registro de fuentes.")
            else:
                data = result["data"]
                self.say(f'{data["checked_sources"]}/{data["started_with_active_sources"]} fuentes activas vigentes '
                         f'durante la comprobación · {len(data["removed"])} retiradas.')
                if data["partial"]:
                    self.say("Verificación parcial. Hay límites de cobertura o archivos que requieren revisión.")
                checks = [dict(row, explanation="coincidió durante la comprobación") for row in data["verified"]]
                checks.extend(dict(row, explanation=source_problem(row["status"], row["code"], row.get("winerror")))
                              for row in data["unavailable"])
                checks.extend(dict(row, explanation="retirado del registro activo") for row in data["removed"])
                for row in data["unavailable"][:PAGE]:
                    self.say(row["path"] + " · " + source_problem(row["status"], row["code"], row.get("winerror")))
            options = {"1": "Revisar y actualizar el registro", "0": "Volver"}
            if checks:
                options = {"2": "Ver estados y detalles por archivo", **options}
            choice = self.choose(options, default="0")
            if choice == "0":
                return
            if choice == "1":
                self.register(self.path, self.identity, refresh=initialized)
                return
            picked = self.browse(checks, lambda row: f'{row["path"]} · {row["explanation"]}', "Estado por archivo")
            if picked != "0":
                self.say(f'{picked["path"]} · {picked["explanation"]}')
                self.say(f'SHA-256 registrado: {picked["sha256"]}')

    def report_menu(self):
        while True:
            options = {"1": "Ver o guardar la última observación", "2": "Reabrir un informe guardado",
                       "3": "Leer un informe de búsqueda del CLI (v1 o v2)", "0": "Volver"}
            choice = self.choose(options, default="0")
            if choice == "0":
                return
            try:
                if choice == "1":
                    if not self.observation:
                        self.say("Primero leé una fuente o hacé una búsqueda en este proyecto.")
                    else:
                        self.show_text("Última observación · Markdown", reports.markdown(self.observation).decode("utf-8"),
                                       {"g": ("Guardar informe en Markdown y JSON", self.save_report)})
                elif choice == "2":
                    self.reopen_report()
                else:
                    self.read_workspace_report()
            except ERRORS as exc:
                self.error(exc)

    def save_unit_report(self):
        if self.save_report():
            self.reopen_last()

    def save_report(self):
        if not self.observation:
            self.say("Primero leé una fuente o hacé una búsqueda.")
            return
        try:
            name, bodies = reports.prepare(self.observation)
            with self.registry(load_journal=False, optional=True) as registry:
                registered = registry is not None
            self.say(f'Vista previa · {self.observation["operation"]} · {self.observation["result"]}')
            self.say(f'{len(self.observation["entries"])} evidencias · {len(bodies[reports.MARKDOWN])} bytes en Markdown.')
            self.say("El informe conserva la observación de la captura.")
            path, raw = self.save_at_destination(name, bodies, registered)
            if path:
                self.last_path = path if raw else name
                self.say(f"Informe guardado en {path}")
                self.say("Archivos: INFORME.md y INFORME.json. Podés reabrirlos desde este panel.")
                return True
        except ERRORS as exc:
            self.error(exc)

    def save_at_destination(self, name, bodies, registered):
        prompt = ("Carpeta de destino existente (Enter usa .pgopcore/reports, 0 cancela):" if registered else
                  "Carpeta de destino existente, fuera del proyecto (Enter cancela):")
        raw = pathname(self.ask(prompt))
        if raw == "0" or (not raw and not registered):
            return None, raw
        with guarded_project(self.path, self.identity) as (root, _):
            if raw:
                with guarded_project(raw) as (directory, _):
                    ws.io.reject_membership(directory, root)
                    ws.io.reject_membership(root, directory)
                    path = self.save_in(directory, name, bodies)
            else:
                with ws.open_registry(root, load_journal=False) as registry:
                    path = self.save_in(registry.reports, name, bodies)
        return path, raw

    def save_in(self, directory, name, bodies):
        self.say(f"Destino: {PureWindowsPath(directory.path, name)}")
        if not self.confirm("Guardar Markdown y JSON", "Cancelar"):
            return None
        return reports.save(directory, name, bodies)

    def reopen_report(self):
        names = []
        try:
            if self.path:
                with self.registry(load_journal=False, optional=True) as registry:
                    if registry:
                        entries = ws.native.enumerate_directory(registry.reports.handle, {"max_entries": ws.LIMITS["entries"]})
                        names = sorted(item["name"] for item in entries if reports.REPORT_ID.fullmatch(item["name"])
                                       and item["attributes"] & 16 and not item["attributes"] & ws.EXCLUDED_ATTRIBUTES
                                       and not item["tag"])
        except ws.io.SafeIOError:
            self.say("No se pudo listar el almacén completo. Podés abrir un informe por ruta o ID.")
            names = []
        actions = {"u": "Indicar ubicación o ID"}
        if self.last_path:
            actions["a"] = "Reabrir el último informe guardado"
        raw = self.browse(names, lambda name: name, "Informes del proyecto", actions)
        if raw == "a":
            raw = self.last_path
        elif raw == "u":
            raw = pathname(self.ask("Ruta de la carpeta del informe o su ID en este proyecto (0 vuelve):"))
        self.open_saved(raw)

    def reopen_last(self):
        if self.last_path:
            self.open_saved(self.last_path)
        else:
            self.say("Todavía no guardaste un informe en esta sesión.")

    def about(self):
        self.say("PGOPCore organiza la lectura y verificación de archivos locales.")
        self.say("Podés leer un archivo, recorrer sus secciones o funciones, buscar texto y guardar citas con su referencia.")
        self.say("Por ejemplo, abrí el README de un proyecto para consultar qué hace y guardar la sección que lo explica.")
        self.say("El acceso depende de los permisos de tu cuenta. Tus archivos de origen se mantienen de solo lectura.")
        self.say("Confirmás el destino de los registros y los informes.")
        self.say("El análisis de Python describe su sintaxis. La ejecución y la validez semántica quedan fuera del panel.")
        self.choose({"0": "Volver a la pantalla principal"}, default="0")

    def understand_project(self):
        with guarded_project(self.path, self.identity) as (root, _):
            selection, paths, types, areas, skipped = panel_project.preview(root)
        self.say(f"Comprender el proyecto · {self.path}")
        self.say("Muestra acotada de la raíz y de carpetas habituales de código y documentación.")
        if selection:
            self.say("Archivos que se leerán si confirmás:")
            for path, _ in selection:
                self.say("  " + path)
            if not self.confirm("Leer estas fuentes para comprender el proyecto"):
                return
            if not ws.search.code_matches():
                raise ws.WorkspaceError("CODE_CHANGED", "Reinstalá la wheel antes de leer fuentes.", 1)
        captures, failures = [], []
        with guarded_project(self.path, self.identity) as (root, _):
            for path, listed in selection:
                try:
                    row, raw, breaks = workspace_search.capture_file(root, path, listed=listed)
                    views.guard(raw, path)
                except ERRORS as exc:
                    failures.append({"path": path, **ws.classify(exc)})
                    continue
                captures.append(Source(row, raw, breaks, None, row["captured_at"], root.path, root.ids[-1]))
        entries = []
        purpose = purpose_source = None
        for source in captures:
            unit = panel_project.documented_purpose(source)
            if unit:
                purpose = source.raw[unit.start:unit.end].decode("utf-8")
                purpose_source = source
                entries.append(self.source_entry(source, unit.selector(), purpose))
                break
            if source.row["path"].endswith(".json") and panel_project.priority(source.row["path"]) == 3:
                value = views.json_value(source.raw)
                if isinstance(value, dict) and isinstance(value.get("description"), str) and value["description"].strip():
                    purpose = value["description"]
                    purpose_source = source
                    entries.append(self.source_entry(source, {"kind": "json_pointer", "pointer": "/description",
                                                              "title": "Descripción documentada"}, views.render_json(purpose)))
                    break
        result = "Se encontró un propósito documentado." if purpose else (
            "No pude determinar el propósito; estas son las estructuras observadas.")
        self.say(result)
        documentation = []
        if purpose:
            path = purpose_source.row["path"]
            selector = entries[0]["selector"]
            self.say(f'Fuente del propósito · {path} · {selector["title"]}')
            if path.endswith(".md"):
                documentation = views.markdown_units(purpose_source.raw, purpose_source.breaks)
                section = next((unit for unit in reversed(documentation)
                                if unit.start_line <= selector["line_start"] <= unit.end_line), None)
                if section:
                    self.say("Sección · " + self.unit_label(section))
            for line in views.safe_text(purpose[:700]).splitlines():
                self.say("  " + line)
            if len(purpose) > 700:
                self.say("Vista previa acotada. Podés abrir la fuente o guardar el resultado completo.")
        types_label = ", ".join(f"{suffix} ({count})" for suffix, count in sorted(types.items())) or "ninguno"
        areas_label = ", ".join(areas[:PAGE]) or "ninguna observada"
        self.say("Formatos observados · " + types_label)
        self.say("Carpetas principales observadas · " + areas_label)
        candidates = [source.row["path"] for source in captures
                      if PureWindowsPath(source.row["path"]).name.lower() in panel_project.ENTRIES]
        if candidates:
            self.say("Posibles archivos de entrada por nombre · " + ", ".join(candidates))
        python = next((source for source in captures if source.row["path"].endswith(".py")), None)
        if python:
            report, units, _ = panel_python.analyze(python)
            self.say(f'Python estático · {python.row["path"]} · AST V2 {report["status"]} · {len(units)} unidades navegables.')
        read_paths = [source.row["path"] for source in captures]
        unread = [path for path in paths if path not in read_paths]
        self.say(f"Cobertura parcial · {len(captures)} fuentes leídas · {len(unread)} candidatas sin leer.")
        if read_paths:
            self.say("Fuentes leídas · " + ", ".join(read_paths))
        if unread:
            self.say("Sin leer · " + ", ".join(unread[:PAGE]) + (" · y más" if len(unread) > PAGE else ""))
        for row in failures:
            self.say(row["path"] + " · " + source_problem(row["status"], row["code"], row["winerror"]))
        if skipped:
            self.say("Exclusiones y límites · " + summarize(skipped))
        coverage = {"partial": True, "read_paths": read_paths, "unread_count": len(unread),
                    "unread_examples": unread[:PAGE], "file_types": dict(types), "root_areas": areas[:PAGE],
                    "entry_candidates": candidates, "unavailable": failures, "discovery_limits": dict(skipped)}
        if python:
            coverage["static_python"] = {"path": python.row["path"], "schema": report["schema"],
                                         "status": report["status"], "snapshot": report["snapshot_id"],
                                         "navigable_units": len(units), "source": self.source_entry(python, {}, "")["source"]}
        self.observation = reports.build("Comprender proyecto", self.path, None, self.version, ws.now(),
                                         {}, entries, coverage, result=result)
        other_sources = [source for source in captures if not documentation or source is not purpose_source]
        options = {}
        if documentation:
            options["1"] = f'Explorar secciones completas de {purpose_source.row["path"]}'
        if other_sources:
            options["2" if documentation else "1"] = "Abrir una fuente de la muestra"
        options.update({"g": "Guardar informe del proyecto", "0": "Volver"})
        while True:
            choice = self.choose(options, default="0")
            if choice == "0":
                return
            if choice == "g":
                self.save_report()
            elif choice == "1" and documentation:
                with self.preserve_observation():
                    self.browse_units(purpose_source, documentation, f'Secciones de {purpose_source.row["path"]}',
                                      original=True)
            else:
                picked = self.browse(other_sources, lambda source: source.row["path"], "Fuentes leídas")
                if picked != "0":
                    with self.preserve_observation():
                        path = picked.row["path"]
                        if path.endswith(".md"):
                            sections = views.markdown_units(picked.raw, picked.breaks)
                            self.browse_units(picked, sections, f"Secciones de {path}", original=True)
                        else:
                            self.view_source(picked)

    def open_saved(self, raw):
        if not raw or raw == "0":
            return
        try:
            self.show_saved(raw)
        except ERRORS as exc:
            self.error(exc)

    def load_saved(self, raw):
        if reports.REPORT_ID.fullmatch(raw):
            if not self.path:
                self.say("Indicá la ruta completa del informe o elegí su proyecto.")
                return
            with self.registry(load_journal=False) as registry:
                markdown, json_text, historical = reports.read(registry.reports, raw)
        else:
            drive, parts = path_parts(raw)
            if not parts:
                raise ws.root_error()
            parent_path = canonical(drive, parts[:-1])
            if self.path and PureWindowsPath(parent_path) == PureWindowsPath(self.path, ws.STATE, "reports"):
                with self.registry(load_journal=False) as registry:
                    markdown, json_text, historical = reports.read(registry.reports, parts[-1])
            else:
                with guarded_project(parent_path) as (parent, _):
                    markdown, json_text, historical = reports.read(parent, parts[-1])
        try:
            views.guard(json_text.encode("utf-8"), ".json")
            views.guard(markdown.encode("utf-8"), ".md")
        except ValueError:
            self.say("Contenido reservado por indicadores de credenciales. El informe no se muestra.")
            return
        return markdown, json_text, historical

    def show_saved(self, raw):
        document = self.load_saved(raw)
        if document is None:
            return
        markdown, json_text, historical = document
        if historical:
            self.say("Informe del panel a9. Se comprobó el JSON ligado a su ID y se regeneró el Markdown en pantalla.")
        else:
            self.say("Integridad de los artefactos comprobada. La observación conserva la fecha de captura.")
        json_view = lambda: self.show_text("Informe guardado · JSON", json_text)
        actions = {"j": ("Leer JSON", json_view)}
        evidence = reports.unit_markdown(markdown, json.loads(json_text))
        if evidence is None:
            self.show_text("Informe guardado · Markdown", markdown, actions)
        else:
            full = lambda: self.show_text("Informe guardado · Markdown completo", markdown, actions)
            self.show_text("Informe guardado · Markdown · evidencia de la unidad", evidence,
                           {"m": ("Leer Markdown completo desde el comienzo", full), **actions},
                           unit=True, page_size=REPORT_EVIDENCE_PAGE)

    def read_workspace_report(self):
        if self.path is None:
            self.say("Primero elegí el proyecto del informe.")
            return
        report_id = self.ask("ID completo ws-report-… (Enter vuelve):").strip()
        if report_id:
            with self.registry(load_journal=False) as registry:
                result, _ = workspace_report.read(registry, report_id, show=True)
            text = json.dumps(result["data"]["report"], ensure_ascii=False, indent=2, allow_nan=False)
            try:
                views.guard(text.encode("utf-8"), ".json")
            except ValueError:
                self.say("Contenido reservado por indicadores de credenciales. El informe no se muestra.")
                return
            self.show_text("Informe del workspace · integridad comprobada", text)

    def help(self):
        self.say("Elegí una carpeta local NTFS. El panel conserva la carpeta de inicio de la consola.")
        self.say("Las opciones numeradas funcionan en PowerShell y CMD. En listas, n avanza y p vuelve una página.")
        self.say("En los menús, 0 vuelve o sale. Esc también vuelve si se envía como entrada.")
        self.say("El panel admite UTF-8 con o sin BOM. JSON y CSV tienen vistas de datos acotadas.")
        self.say("Markdown se puede leer por secciones. Python se analiza estáticamente con AST V2.")
        self.say(f"Vista CSV: hasta {views.CSV_ROWS} registros, {views.CSV_COLUMNS} columnas y {views.CSV_CELLS} celdas.")
        self.say("Ruta compatible: ASCII, nombre exacto en disco, sin enlaces ni directorios sensibles.")
        self.say("El contenido se trata como dato local. Revisá qué documentos autorizás y a dónde exportás.")
        choice = self.choose({"1": "Comprobar esta instalación", "0": "Volver"}, default="0")
        if choice == "1":
            from argparse import Namespace

            response, _ = product.execute(Namespace(command="doctor"))
            for line in product.human_lines(response):
                self.say(line)


def run():
    return Panel().run()
