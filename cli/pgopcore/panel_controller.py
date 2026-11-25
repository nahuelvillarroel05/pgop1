"""Present existing local panel workflows without re-running them on tab changes."""

from contextlib import ExitStack
import json
import os
from pathlib import PureWindowsPath
from threading import Event

from .panel import ERRORS, Panel, guarded_project, pathname, reports, summarize, views
from .panel_messages import Page, Prompt, StopFlow
from .source_paths import canonical, excluded_name, path_parts
from .text_bytes import content_start, decode
from . import workspace as ws


def references_label(entry):
    selector = entry["selector"]
    location = []
    if "line_start" in selector:
        location.append(f'Líneas {selector["line_start"]}–{selector["line_end"]}')
    if selector.get("pointer"):
        location.append(selector["pointer"])
    if selector.get("column"):
        location.append(str(selector["column"]))
    return " · ".join((entry["source"]["path"], *location))


def report_preview(report):
    """Project verified report data to the screen; leave stored formats intact."""
    entries = report["entries"]
    blocks = []
    for entry in entries:
        excerpt = entry["text"]
        if match := entry.get("literal_match"):
            excerpt = match + ("\n\n" + excerpt if match != excerpt else "")
        blocks.append(excerpt.rstrip("\r\n") + "\n\nFuente · " + references_label(entry))
    if not blocks:
        blocks.append(report.get("result", "El informe no contiene evidencias de una fuente."))
    coverage = reports.readable_coverage(report.get("coverage"))
    blocks.append("Cobertura y límites\n" + "\n".join(coverage + [
        "La evidencia corresponde a su captura. La vigencia actual se comprueba en Verificar.",
    ]))
    return "\n\n".join(blocks)


class PanelController(Panel):
    def __init__(self, bridge, tab, path=None, identity=None, query=""):
        super().__init__()
        self.bridge = bridge
        self.tab = tab
        self.path, self.identity = path, identity
        self.query = query
        self.notes = []
        self.feedback = ""
        self.file_filters = {}
        self.context_draft = []
        self.context_home = [""]
        self.scan_cancel = None

    def say(self, message=""):
        self.notes.append(views.safe_text(message))

    def take_notes(self):
        note = "\n".join(self.notes).strip("\n")
        self.notes.clear()
        return note

    def set_project(self, path, identity):
        previous = self.path, self.identity
        super().set_project(path, identity)
        if previous != (path, identity):
            self.query = ""
            self.bridge.project_changed(self)

    def ask(self, prompt):
        return self.bridge.exchange(self, Prompt(
            prompt.replace(" (0 vuelve)", "").replace(", 0 cancela", ""),
            self.take_notes(), field=True,
        ))

    def ask_query(self):
        answer = self.bridge.exchange(self, Prompt(
            "Texto literal para buscar",
            self.take_notes() + "\nEjemplos: get_metrics, total_trades, configuración. Buscá el texto tal como aparece.",
            field=True, value=self.query,
        ))
        if answer:
            self.query = answer
        return answer

    def confirm(self, label, cancel="Volver"):
        if self.bridge.exchange(self, Prompt(label, self.take_notes())) == "yes":
            return True
        self.feedback = "Operación cancelada."
        return False

    def file_location(self, raw, base=None, identity=None):
        if PureWindowsPath(raw).anchor:
            drive, parts = path_parts(raw)
            if not parts:
                raise ws.root_error()
            return canonical(drive, parts[:-1]), None, parts[-1], None
        return base or self.path or ".", identity, raw.replace("\\", "/"), None

    def open_file_prompt(self):
        self.say("Una ruta relativa se toma desde el proyecto actual o la carpeta de inicio.")
        raw = pathname(self.ask("Ruta exacta del archivo"))
        if not raw:
            self.feedback = "Apertura cancelada."
            return
        try:
            path, identity, relative, _ = self.file_location(raw, self.path, self.identity)
        except ERRORS as exc:
            self.error(exc)
            location = self.recover_file(self.path, self.identity)
            if location is None:
                return
            path, identity, relative, expected = location
            self.open_individual(path, identity, relative, expected=expected)
        else:
            self.open_individual(path, identity, relative)

    def open_individual(self, path, identity, relative, *, expected=None):
        while True:
            try:
                opened = super().open_individual(path, identity, relative, expected=expected)
            except ERRORS as exc:
                self.error(exc)
                opened = False
            if opened is not False:
                return
            location = self.recover_file(path, identity)
            if location is None:
                return
            path, identity, relative, expected = location

    def recover_file(self, base, identity):
        while True:
            choice = self.choose({"r": "Reintentar ruta de archivo", "l": "Listar archivos de una carpeta sin registrar",
                                  "0": "Volver"}, prompt="Archivo sin abrir")
            if choice == "0":
                return None
            try:
                if choice == "l":
                    found = self.pick_unregistered_file(base, identity)
                    if found is not None:
                        return found
                else:
                    raw = pathname(self.ask("Otra ruta de archivo"))
                    if raw:
                        return self.file_location(raw, base, identity)
            except ERRORS as exc:
                self.error(exc)

    def pick_unregistered_file(self, base=None, identity=None):
        current = base or self.path or "."
        self.say(f"Carpeta propuesta: {current}")
        raw = pathname(self.ask("Carpeta para listar archivos · Enter usa la propuesta"))
        current_identity = identity if base else self.identity
        with guarded_project(raw or current, None if raw else current_identity) as (root, _):
            path, identity = root.path, root.ids[-1]
            scan = ws.Scan(ws.Registry(root, None, None), preview=True, refresh=False)
            preview = scan.run()
        self.say(f"Carpeta · {path}")
        self.say("Solo metadatos. Elegí un archivo para pedir su lectura individual.")
        if not preview["candidates"]:
            self.say("No se encontraron archivos elegibles.")
        if preview["partial"]:
            self.say("Cobertura parcial · " + summarize(preview["reasons"]))
        if preview["excluded"]:
            self.say("Exclusiones · " + summarize(preview["excluded"]))
        selection = self.browse(preview["candidates"] + preview["failures"], self.preview_row,
                                "Archivos de la carpeta")
        if selection != "0" and "bytes" in selection:
            relative = selection["path"]
            return path, identity, relative, scan.candidate_metadata[relative]
        return None

    def list_unregistered_files(self):
        if location := self.pick_unregistered_file():
            path, identity, relative, expected = location
            self.open_individual(path, identity, relative, expected=expected)
    def find_files(self):
        scope = self.path or "."
        self.say(f"Carpeta: {self.path or os.getcwd()} · solo nombres y metadatos.")
        self.say("Ejemplos: readme, analyzer, .md. Enter sin texto lista los archivos elegibles.")
        name = self.bridge.exchange(self, Prompt("Buscar por nombre o parte del nombre",
                                                   self.take_notes(), field=True, value=self.file_filters.get("name", "")))
        name = name.strip()
        if len(name) > 100 or not (not name or name.isprintable()):
            raise ws.WorkspaceError("INVALID_NAME_FILTER", "Escribí hasta 100 caracteres visibles.")
        with guarded_project(scope, self.identity) as (root, _):
            path, identity = root.path, root.ids[-1]
        self.set_project(path, identity)
        self.file_filters["name"] = name
        folder = self.file_filters.get("folder", ())
        suffix = self.file_filters.get("suffix", "")
        while True:
            cancel = Event()
            self.scan_cancel = cancel
            try:
                self.bridge.discovery(self, "Buscando nombres… 0/Esc cancela.")
                with guarded_project(path, identity) as (root, _):
                    scan = ws.Scan(ws.Registry(root, None, None), preview=True, refresh=False,
                                   folder=folder, suffix=suffix, name=name, cancel=cancel)
                    preview = scan.run()
            finally:
                self.scan_cancel = None
            if cancel.is_set():
                self.feedback = "Búsqueda cancelada."
                return

            while True:
                self.say(f"Nombre: {name or 'todos'} · extensión: {(suffix or 'todas').upper()}")
                self.say(f"Carpeta: {'/'.join(folder) or '.'} · coincidencia sin distinguir mayúsculas.")
                reasons = {key: value for key, value in preview["reasons"].items() if key != "USER_SELECTED_SCOPE"}
                if reasons:
                    self.say("Cobertura parcial · " + summarize(reasons) + ". Acotá la carpeta o el filtro.")
                if not preview["candidates"]:
                    self.say("Sin coincidencias en el alcance recorrido. Cambiá el filtro o elegí una carpeta.")
                selected = self.browse(preview["candidates"], self.preview_row, "Archivos encontrados", {
                    "n": "Cambiar fragmento de nombre", "f": "Extensión · Todos / MD / PY / JSON / CSV / TXT",
                    "d": "Explorar subcarpetas", "r": "Actualizar resultados",
                })
                if isinstance(selected, dict):
                    relative = selected["path"]
                    self.open_individual(path, identity, relative, expected=scan.candidate_metadata[relative])
                else:
                    break
            if selected == "0":
                return
            if selected == "f":
                suffix = self.pick_suffix()
            elif selected == "d":
                folder = self.choose_folder(path, identity, folder)
            elif selected == "n":
                try:
                    name = self.bridge.exchange(self, Prompt("Buscar por nombre o parte del nombre",
                                                            "Ejemplos: readme, analyzer, .md.", field=True, value=name)).strip()
                except StopFlow:
                    self.feedback = "Filtro conservado."
                if len(name) > 100 or (name and not name.isprintable()):
                    raise ws.WorkspaceError("INVALID_NAME_FILTER", "Escribí hasta 100 caracteres visibles.")
            self.file_filters.update(name=name, folder=folder, suffix=suffix)

    def choose_folder(self, path, identity, folder):
        proposed = folder
        while True:
            with guarded_project(path, identity) as (root, _), ExitStack() as stack:
                directory = root
                for part in proposed:
                    directory = stack.enter_context(ws.child(directory, part, source=True))
                rows = ws.native.enumerate_directory(directory.handle, {
                    "max_entries": ws.LIMITS["entries"], "max_pages": ws.LIMITS["pages"],
                }, allow_unsupported_names=True)
                names = []
                if len(proposed) < ws.LIMITS["directories_deep"]:
                    for row in rows:
                        name = row["name"]
                        if not row["attributes"] & 16 or row["attributes"] & ws.EXCLUDED_ATTRIBUTES or row["tag"]:
                            continue
                        if excluded_name(name):
                            continue
                        try:
                            ws.io.component(name)
                        except ws.io.SafeIOError:
                            continue
                        names.append(name)
                root.validate()
            self.say(f"Carpeta elegida: {'/'.join(proposed) or '.'}")
            options = {"u": "Buscar en esta carpeta"}
            if proposed:
                options["p"] = "Subir una carpeta"
            rows = [{"name": name} for name in sorted(names, key=str.casefold)]
            choice = self.browse(rows, lambda row: row["name"], "Subcarpetas", options)
            if choice == "0":
                return folder
            if choice == "u":
                return proposed
            if choice == "p" and proposed:
                proposed = proposed[:-1]
            elif isinstance(choice, dict):
                proposed = (*proposed, choice["name"])

    def context_option(self, entry=None):
        if entry is None:
            entries = (self.observation or {}).get("entries", ())
            if len(entries) != 1:
                return {}
            entry = entries[0]
        return {"x": ("Añadir esta referencia al contexto", lambda: self.add_context_reference(entry))}

    def add_context_reference(self, entry):
        from .context_local import MAX_SELECTIONS

        selection = (entry["source"]["path"], entry.get("context", entry["selector"]), entry["source"])
        if "context" in entry:
            selection = (selection[0], {"kind": "utf8_bytes", **selection[1]}, selection[2])
        if selection not in self.context_draft:
            if len(self.context_draft) >= MAX_SELECTIONS:
                self.say("El borrador admite hasta ocho referencias. Quitá una desde Informes.")
                return
            self.context_draft.append(selection)
        self.say(f"Referencias en el borrador: {len(self.context_draft)}. Para guardarlo, abrí Informes.")

    def context_parent(self):
        raw = self.bridge.exchange(self, Prompt("Carpeta del almacén de contextos",
            "Elegí una carpeta local existente fuera del proyecto. PGOPCore usa .pgop-context-v1 dentro de ella.",
            field=True, value=self.context_home[0]))
        parent = pathname(raw)
        if not parent:
            raise StopFlow
        return parent

    def save_context(self):
        from . import context_local as context

        while self.context_draft:
            selected = self.browse(self.context_draft, lambda item: item[0], "Referencias elegidas", {
                "g": "Preparar guardado", "d": "Vaciar borrador",
            })
            if selected == "0":
                return
            if selected == "g":
                break
            if selected == "d":
                if self.confirm("Vaciar borrador de contexto"):
                    self.context_draft.clear()
            elif self.confirm(f"Quitar referencia de {selected[0]}"):
                self.context_draft.remove(selected)
        else:
            self.say("Abrí una sección, función o valor y elegí «Añadir esta referencia al contexto».")
            return
        name = self.ask("Nombre del contexto")
        purpose = self.ask("Propósito breve del contexto")
        parent = self.context_parent()
        plan = context.prepare(self.path, parent, name, purpose, list(self.context_draft), self.identity)
        preview = {"data": {"preview": plan, "destination": context.destination(parent),
                            "confirm": "Guardar contexto"}}
        if self.bridge.exchange(self, Page("Vista previa del contexto",
            context.human(preview).rsplit("\n\n", 1)[0] + "\n\nRevisá las referencias con Tab y flechas.",
            (("g", "Guardar contexto"),))) == "0":
            return
        self.say(f'{len(plan["entries"])} referencias · {context.destination(parent)}')
        if self.confirm("Confirmar escritura del contexto"):
            result = context.save(plan, context.approval(plan))
            self.context_home[0] = parent
            self.context_draft.clear()
            self.say("El contexto ya existe." if result["duplicate"] else "Contexto guardado.")
            self.say(f'{plan["name"]} · Abrí «Contextos guardados» para recuperarlo.')

    def saved_contexts(self):
        from . import context_local as context

        parent = self.context_parent()
        self.say(f"Proyecto: {self.path} · Almacén: {context.destination(parent)}")
        if not self.confirm("Consultar el almacén local"):
            return
        self.context_home[0] = parent
        while True:
            records = context.catalog(self.path, parent, identity=self.identity)
            if not records:
                self.say("Todavía no hay contextos guardados para este proyecto.")
                return
            result = self.browse(records, lambda row: f'{row["name"]} · {row["stored_at"]}' +
                                 (" · revocado" if row["state"] == "REVOKED" else ""), "Contextos guardados")
            if result == "0":
                return
            key = result["id"]

            def revoke():
                if self.confirm("Quitar acceso local a esta versión"):
                    context.revoke(self.path, parent, key, identity=self.identity)
                    self.say("Acceso local revocado.")

            actions = (("r", "Quitar acceso local a esta versión"),) if result["state"] != "REVOKED" else ()
            def recover():
                return context.packet(self.path, parent, key, identity=self.identity)

            try:
                packet = recover()
                name, purpose = packet["name"], packet["purpose"]
                entries = [{field: item[field] for field in ("source", "selector")} for item in packet["entries"]]
                del packet
                choice = self.browse_context_packet(name, purpose, entries, dict(actions), recover)
            except ws.WorkspaceError as exc:
                body = f"{exc}\n\nSin referencias vigentes."
                choice = self.bridge.exchange(self, Page(result["name"], body, actions))
            if choice == "r":
                revoke()

    def browse_context_packet(self, name, purpose, entries, actions, recover):
        while True:
            self.say(purpose)
            self.say("Elegí una referencia con las flechas y Enter. Se vuelven a comprobar las fuentes.")
            selected = self.browse(entries, references_label, name + " · Referencias", actions)
            if isinstance(selected, str):
                return selected
            packet = recover()
            reference = packet["entries"][entries.index(selected)]
            self.show_text(references_label(reference), reference["text"])
            del packet, reference


    def choose(self, options, prompt="Elegí una opción:", default=None):
        body = self.take_notes()
        back = "0" if options.get("0", "").startswith(("Volver", "Cancelar")) else ""
        items = tuple((key, label) for key, label in options.items() if key != back)
        return self.bridge.exchange(self, Page(prompt, body, items, back))

    def browse(self, rows, label, title, actions=None):
        body = self.take_notes()
        options = {str(index): label(item) for index, item in enumerate(rows, 1)}
        options.update(actions or {})
        chosen = self.bridge.exchange(self, Page(
            f"{title} · {len(rows)}", body, tuple(options.items()),
        ))
        return rows[int(chosen) - 1] if chosen != "0" and chosen.isdecimal() else chosen

    def show_text(self, title, text, actions=None, *, unit=False, page_size=None, markdown=False):
        if unit and self.observation and self.observation["entries"]:
            kind = self.observation["entries"][0]["selector"].get("kind")
            markdown = kind == "markdown_section"
        actions = actions or {}
        summary = self.take_notes()
        items = tuple((key, label) for key, (label, _) in actions.items())
        while True:
            body = text + ("\n\n" + summary if summary else "")
            key = self.bridge.exchange(self, Page(title, body, items, markdown=markdown))
            if key == "0":
                return
            actions[key][1]()
            extra = self.take_notes()
            if extra:
                self.bridge.exchange(self, Page("Detalles técnicos", extra))

    def text_view(self, source, *, line=None):
        path = source.row["path"]
        suffix = PureWindowsPath(path).suffix
        rows = list(views.segments(source.raw, source.breaks))
        options = {"b": ("Buscar dentro del archivo", lambda: self.search(source=source)),
                   "r": ("Ver referencia", lambda: self.details(source, reference=True)),
                   "g": ("Guardar informe", self.save_report)}
        if suffix == ".md":
            sections = views.markdown_units(source.raw, source.breaks)
            options = {"m": ("Leer secciones Markdown", lambda: self.browse_units(source, sections, "Secciones Markdown")),
                       **options}
        elif suffix == ".txt":
            paragraphs = list(views.paragraphs(source.raw, source.breaks))
            options = {"p": ("Leer párrafos", lambda: self.browse_units(source, paragraphs, "Párrafos")), **options}
        options["q"] = ("¿Qué es este archivo?", lambda: self.file_summary(source, sections if suffix == ".md" else ()))
        if self.last_path:
            options["a"] = ("Reabrir el último informe guardado", self.reopen_last)
        if rows:
            first = next((row for row in rows if row.line == line), rows[0])
            last = rows[-1]
            title = f"{path} · líneas {first.line}–{last.line}"
            text = decode(source.raw) if not line else source.raw[first.start:last.end].decode("utf-8")
            selector = {"kind": "utf8_bytes", "line_start": first.line, "line_end": last.line,
                        "byte_start": first.start, "byte_end": last.end}
            options["i"] = ("Ir a una línea", lambda: self.goto_line(source, last.line))
        else:
            title, text = path, "Archivo vacío."
            start = content_start(source.raw)
            selector = {"kind": "utf8_bytes", "byte_start": start, "byte_end": start}
        self.note_view(source, selector, text if rows else "")
        prior = self.observation
        if text and rows and len(text.encode("utf-8")) <= 8192:
            options.update(self.context_option())

        def restore(action):
            def run():
                with self.preserve_observation():
                    self.observation = prior
                    action()
            return run

        self.show_text(title, text, {key: (label, restore(action)) for key, (label, action) in options.items()},
                       markdown=suffix == ".md")

    def goto_line(self, source, maximum):
        raw = self.ask(f"Número de línea de 1 a {maximum}").strip()
        if raw.isascii() and raw.isdecimal() and len(raw) <= 5 and 1 <= int(raw) <= maximum:
            self.text_view(source, line=int(raw))
        else:
            self.say("Esa línea queda fuera del archivo.")

    def show_saved(self, raw):
        document = self.load_saved(raw)
        if document is None:
            return
        original, encoded, historical = document
        report = json.loads(encoded)
        status = ("JSON comprobado · Markdown de a9 regenerado." if historical
                  else "Markdown, JSON y manifiesto comprobados.")
        self.show_text("Informe guardado · " + report["operation"],
                       report_preview(report) + "\n\n" + status, {
            "m": ("Markdown completo", lambda: self.show_text("Informe guardado · Markdown", original, markdown=True)),
            "j": ("Detalles técnicos · JSON", lambda: self.show_text("Informe guardado · JSON", encoded)),
        })

    def save_unit_report(self):
        self.save_report()

    def save_at_destination(self, name, bodies, registered):
        if registered:
            with self.registry(load_journal=False) as registry:
                parent = registry.reports
                self.say(f"Destino: {PureWindowsPath(parent.path, name)}")
                choice = self.bridge.exchange(self, Prompt(
                    "Guardar Markdown y JSON", self.take_notes(), alternative="Otra carpeta",
                ))
                if choice == "yes":
                    return reports.save(parent, name, bodies), ""
                if choice != "alternative":
                    self.feedback = "Guardado cancelado."
                    return None, ""
        path, raw = super().save_at_destination(name, bodies, registered=False)
        if not path and not raw:
            self.feedback = "Guardado cancelado."
        return path, raw

    def save_report(self):
        if super().save_report():
            self.bridge.report_saved(self, self.last_path)
            if self.tab == "reports":
                self.open_saved(self.last_path)
            else:
                self.take_notes()
            return True
        return False
