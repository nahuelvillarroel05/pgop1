"""Fixed-screen presentation for the local PGOPCore panel."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
import os
from pathlib import PureWindowsPath
from queue import Queue
import sys
from threading import Thread
from typing import TYPE_CHECKING

from markdown_it import MarkdownIt
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, ContentSwitcher, Input, Markdown, OptionList, Static, Tab, Tabs
from textual.widgets.option_list import Option

from .panel_messages import Page, Prompt, StopFlow
from .panel_views import safe_text

if TYPE_CHECKING:
    from .panel_controller import PanelController


TABS = ("home", "files", "search", "reports", "verify")
LABELS = ("Inicio", "Archivos", "Buscar", "Informes", "Verificar")
ABANDON = object()
SHORTCUTS = "abcdefgijlmnpqrstuvwx"

HELP = {
    "home": "C usa la carpeta de inicio. A elige otro proyecto o un archivo local.",
    "files": "N busca nombres sin registrar archivos. Probá readme o .md. F filtra la extensión. D explora subcarpetas.",
    "search": "N busca nombres. B busca texto dentro de fuentes registradas. Ejemplo: total_trades.",
    "reports": "A abre un informe. M guarda el borrador de referencias. C recupera un contexto y comprueba su vigencia.",
    "verify": "V comprueba cambios de identidad y contenido en las fuentes registradas.",
}


def supports_terminal():
    if os.name != "nt" or os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        columns, rows = os.get_terminal_size(sys.stdout.fileno())
    except (AttributeError, OSError, ValueError):
        return False
    return columns >= 50 and rows >= 16


def inert_markdown():
    return MarkdownIt("commonmark", {"html": False}).disable(["autolink", "image", "link"])


class ScrollBody(VerticalScroll, can_focus=True):
    def compose(self):
        yield Static(markup=False, classes="literal")
        yield Markdown(parser_factory=inert_markdown, open_links=False)

    def render_body(self, body, markdown):
        literal = self.query_one(Static)
        document = self.query_one(Markdown)
        literal.display = not markdown
        document.display = markdown
        if markdown:
            document.update(safe_text(body))
        else:
            literal.update(Text(safe_text(body), overflow="fold", no_wrap=self.has_class("unwrapped")))

    def toggle_wrap(self, page):
        if page and page.body and not page.markdown:
            self.toggle_class("unwrapped")
            self.render_body(page.body, False)


class MenuList(OptionList):
    def __init__(self):
        super().__init__(classes="choices")
        self.labels = ()
        self.marked = None

    def set_menu(self, items):
        self.labels = tuple((f"{key}  " if key.isalpha() and len(key) == 1 else "") + safe_text(label)
                            for key, label in items)
        self.marked = None
        self.set_options([Option(Text("  " + label), id=key) for (key, _), label in zip(items, self.labels)])

    def mark_selection(self):
        index = self.highlighted
        if index == self.marked:
            return
        if self.marked is not None:
            self.replace_option_prompt_at_index(self.marked, Text("  " + self.labels[self.marked]))
        self.marked = index
        if index is not None:
            self.replace_option_prompt_at_index(index, Text("> " + self.labels[index]))

    def on_option_list_option_highlighted(self, event):
        if event.option_index == self.highlighted:
            self.mark_selection()


class WorkPane(Vertical):
    def __init__(self):
        super().__init__(classes="work-pane")
        self.page = None
        self.locations = OrderedDict()
        self.focus_area = None

    def compose(self):
        yield Static(markup=False, classes="page-title")
        with Horizontal(classes="page-split"):
            yield ScrollBody(classes="result-body")
            yield MenuList()

    @staticmethod
    def signature(page):
        return (page.title, len(page.options), page.options[:1], page.options[-1:])

    def save_location(self):
        if self.page is not None:
            signature = self.signature(self.page)
            choices = self.query_one(OptionList)
            result = self.query_one(ScrollBody)
            self.locations[signature] = (choices.highlighted, result.scroll_offset)
            self.locations.move_to_end(signature)
            if len(self.locations) > 16:
                self.locations.popitem(last=False)

    def show_page(self, page, *, save=True):
        if save:
            self.save_location()
        if self.page and self.signature(page) == self.signature(self.page) and not page.body:
            page = replace(page, body=self.page.body, markdown=self.page.markdown)
        previous = self.locations.get(self.signature(page))
        self.page = page
        self.query_one(".page-title", Static).update(safe_text(page.title))
        result = self.query_one(ScrollBody)
        choices = self.query_one(MenuList)
        result.display = bool(page.body) or not page.options
        choices.display = bool(page.options)
        self.set_class(result.display and choices.display, "with-body")
        result.render_body(page.body, page.markdown)
        choices.set_menu(page.options)
        if page.options:
            choices.highlighted = min((previous[0] if previous else None) or 0, len(page.options) - 1)
        choices.mark_selection()
        if previous:
            result.scroll_to(*previous[1], animate=False, force=True)
        else:
            result.scroll_home(animate=False, force=True)
        self.focus_area = result if page.body and not any(key.isdecimal() for key, _ in page.options) else choices

    def restore_focus(self):
        preferred = self.focus_area
        if preferred is not None and preferred.display:
            preferred.focus()
        else:
            selector = OptionList if self.page and self.page.options else ScrollBody
            self.query_one(selector).focus()

    def reset(self):
        self.page = None
        self.locations.clear()


class Question(ModalScreen):
    BINDINGS = [Binding("ctrl+a", "select_field", show=False, priority=True)]

    def __init__(self, prompt, *, help_view=False):
        super().__init__()
        self.prompt = prompt
        self.help_view = help_view

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(safe_text(self.prompt.title), markup=False, classes="dialog-title")
            if self.prompt.body:
                with ScrollBody(classes="dialog-notes"):
                    pass
            if self.prompt.field:
                yield Input(value=self.prompt.value, id="answer", max_length=4096)
            with Horizontal(classes="dialog-actions"):
                yield Button(self.buttons()["no"], id="no")
                if not self.help_view:
                    yield Button(self.buttons()["yes"], id="yes", variant="primary")
                if self.prompt.alternative:
                    yield Button(self.buttons()["alternative"], id="alternative")

    def buttons(self):
        labels = {"no": "Volver" if self.help_view else "Cancelar"}
        if not self.help_view:
            labels["yes"] = "Aceptar" if self.prompt.field else "c Confirmar"
        if self.prompt.alternative:
            labels["alternative"] = "o " + self.prompt.alternative
        return labels

    def on_mount(self):
        if self.prompt.body:
            self.query_one(ScrollBody).render_body(self.prompt.body, False)
        if self.prompt.field:
            self.query_one(Input).focus()
        else:
            self.query_one("#no", Button).focus()

    def on_descendant_focus(self, event):
        for button in self.query(Button):
            label = self.buttons()[button.id]
            button.label = ("> " if button is event.widget else "  ") + label

    def cancel(self):
        self.dismiss(ABANDON if self.prompt.field else "no")

    def accept(self):
        self.dismiss(self.query_one(Input).value if self.prompt.field else "yes")

    def on_key(self, event):
        if event.key == "f1" and self.prompt.field:
            event.stop()
            self.app.push_screen(Question(Prompt("Ayuda · " + self.prompt.title,
                f"{self.prompt.body}\nEnter acepta la entrada. Esc vuelve sin aplicarla."), help_view=True))
        elif event.key == "escape" or (not self.prompt.field and event.character == "0"):
            event.stop()
            self.cancel()
        elif not self.prompt.field and not self.help_view:
            if event.character in ("c", "C"):
                event.stop()
                self.accept()
            elif self.prompt.alternative and event.character in ("o", "O"):
                event.stop()
                self.dismiss("alternative")

    def action_select_field(self):
        if self.prompt.field:
            self.query_one(Input).action_select_all()

    def on_input_submitted(self, event):
        event.stop()
        self.accept()

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "yes":
            self.accept()
        elif event.button.id == "alternative":
            self.dismiss("alternative")
        else:
            self.cancel()


@dataclass
class Work:
    panel: PanelController
    reply: Queue | None = None


class FixedPanel(App):
    TITLE = "PGOPCore"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        *(Binding(str(number), f"select_tab({number})", show=False, priority=True) for number in range(1, 6)),
        Binding("0,escape", "panel_back", show=False, priority=True),
        Binding("f1", "panel_help", show=False, priority=True),
        *(Binding(f"{letter},{letter.upper()},shift+{letter}", f"shortcut('{letter}')", show=False, priority=True)
          for letter in SHORTCUTS),
    ]
    CSS = """
    Screen { background: #0d1725; color: #ecf2f9; }
    #project { height: 1; padding: 0 1; color: #9ad3ff; background: #14283f; text-overflow: ellipsis; }
    #tabs { height: 2; }
    #views { height: 1fr; }
    .tab-pane { height: 1fr; padding: 0 1; }
    Tab { padding: 0 1; color: #cddbeb; }
    Tab.-active { text-style: bold reverse; color: #b2dcff; }
    WorkPane, .page-split { height: 1fr; }
    .page-title { color: #d1e8ff; text-style: bold; height: auto; max-height: 2; padding: 0 1; }
    .result-body, .choices { height: 1fr; width: 1fr; color: #ecf2f9; }
    ScrollBody { border: round #465c73; padding: 0 1; overflow-y: auto; overflow-x: hidden; }
    ScrollBody:focus, .choices:focus { border: round #7fd1ff; }
    ScrollBody.unwrapped { overflow-x: auto; }
    ScrollBody.unwrapped .literal { width: auto; }
    .choices { border: round #465c73; padding: 0; background: #112034; }
    .with-body .result-body { width: 3fr; }
    .with-body .choices { width: 2fr; }
    .compact .with-body .page-split { layout: vertical; }
    .compact .with-body .result-body, .compact .with-body .choices { width: 100%; }
    .compact .with-body .choices { height: auto; max-height: 6; }
    #keybar { height: 1; background: #14283f; color: #e0effe; }
    #back { border: none; height: 1; min-width: 9; width: 9; padding: 0; }
    #keys { height: 1; width: 1fr; text-overflow: clip; }
    #state { height: 1; padding: 0 1; color: #ffd18b; }
    Question { align: center middle; }
    .dialog { background: #152943; border: round #80cbff;
              padding: 0 1; width: 90%; max-width: 85; height: auto; }
    .dialog-title { height: auto; text-style: bold; margin: 1 0; }
    .dialog-notes { height: auto; max-height: 8; }
    .dialog-actions { align: right middle; height: 3; }
    .dialog-actions Button { margin-left: 1; }
    """

    def __init__(self):
        super().__init__()
        self.path = self.identity = self.observation = self.last_report = None
        self.work = {}
        self.queries = {}
        self.file_filters = {}
        self.context_draft = []
        self.context_home = [os.environ.get("PGOP_CONTEXT_HOME") or os.environ.get("LOCALAPPDATA", "")]
        self.active_tab = "home"
        self.queued_report = None
        self.main_screen = None

    def compose(self) -> ComposeResult:
        yield Static(markup=False, id="project")
        yield Tabs(*(Tab(f"[{number} {label}]" if tab == "home" else f"{number} {label}", id=f"tab-{tab}")
                     for number, (tab, label) in enumerate(zip(TABS, LABELS), 1)),
                   active="tab-home", id="tabs")
        with ContentSwitcher(initial="home", id="views"):
            for tab in TABS:
                with Vertical(id=tab, classes="tab-pane"):
                    yield WorkPane()
        yield Static("", markup=False, id="state")
        with Horizontal(id="keybar"):
            yield Button("0 Volver", id="back")
            yield Static("Tab Foco  ↑↓ Mover  Enter Elegir  F1 Ayuda", markup=False, id="keys")

    def on_mount(self):
        self.main_screen = self.screen
        self.main_screen.set_class(self.size.width < 78, "compact")
        self.header()
        self.show_root("home")
        self.pane("home").restore_focus()

    def on_resize(self, event):
        if self.main_screen is not None:
            self.main_screen.set_class(event.size.width < 78, "compact")

    def pane(self, tab):
        return self.main_screen.query_one(f"#{tab}", Vertical).query_one(WorkPane)

    def header(self):
        name = PureWindowsPath(self.path).name if self.path else ""
        path = name or self.path or "ninguno"
        self.main_screen.query_one("#project", Static).update(safe_text(f"PGOPCore  ·  Proyecto {path}"))

    def status(self, text):
        self.main_screen.query_one("#state", Static).update(text)

    def root_page(self, tab):
        if tab == "home":
            return Page("Inicio", "Elegí un proyecto local o abrí un solo archivo.", (
                ("a", "Abrir proyecto o archivo"), ("c", "Usar carpeta actual"), ("p", "Comprender el proyecto"),
                ("q", "¿Qué es PGOPCore?"), ("s", "Salir"),
            ))
        if tab == "files":
            return Page("Archivos", "Encontrá un archivo. Ejemplos: readme, analyzer, .md.", (
                ("n", "Buscar por nombre o parte del nombre"),
                ("e", "Explorar archivos registrados"), ("a", "Abrir un archivo por ruta (avanzado)"),
                ("l", "Listar archivos de una carpeta sin registrar"),
            ))
        if tab == "search":
            query = self.queries.get(tab, "")
            return Page("Buscar", "Última consulta · " + query if query else
                        "Dentro de los archivos: texto literal. Ejemplos: get_metrics, total_trades, configuración.",
                        (("b", "Escribir consulta · Dentro de los archivos"), ("n", "Por nombre de archivo")))
        if tab == "reports":
            actions = (("g", "Guardar el resultado actual"), ("v", "Ver el resultado actual")) if self.observation else ()
            return Page("Informes", "Consultá observaciones y sus referencias.", actions + (
                ("a", "Abrir informe guardado"), ("j", "Leer informe de búsqueda del CLI"),
                ("m", f"Guardar contexto · {len(self.context_draft)} referencias"),
                ("c", "Contextos guardados"),
            ))
        return Page("Verificar", "Comprobá cambios y alcance de las fuentes registradas.",
                    (("v", "Verificar las fuentes"),))

    def show_root(self, tab, notes=""):
        page = self.root_page(tab)
        if notes:
            page = replace(page, body=notes)
        pane = self.pane(tab)
        pane.show_page(page)
        pane.focus_area = pane.query_one(OptionList)

    def busy(self):
        return any(work.reply is None for work in self.work.values())

    def switch(self, tab):
        if self.busy() or tab == self.active_tab:
            return
        self.remember_focus()
        tabs = self.main_screen.query_one(Tabs)
        old = TABS.index(self.active_tab)
        new = TABS.index(tab)
        tabs.query_one(f"#tab-{self.active_tab}", Tab).label = f"{old + 1} {LABELS[old]}"
        tabs.query_one(f"#tab-{tab}", Tab).label = f"[{new + 1} {LABELS[new]}]"
        self.active_tab = tab
        self.main_screen.query_one(ContentSwitcher).current = tab
        tabs.active = f"tab-{tab}"
        if self.pane(tab).page is None:
            self.show_root(tab)
        self.pane(tab).restore_focus()

    def remember_focus(self):
        current = self.pane(self.active_tab)
        focused = self.main_screen.focused
        if focused in (current.query_one(OptionList), current.query_one(ScrollBody)):
            current.focus_area = focused

    def on_tabs_tab_activated(self, event):
        if self.main_screen is None or event.tabs.active != event.tab.id:
            return
        tab = event.tab.id.removeprefix("tab-")
        if self.busy():
            event.tabs.active = f"tab-{self.active_tab}"
            return
        self.switch(tab)

    def check_action(self, action, parameters):
        if action in {"select_tab", "panel_back", "panel_help", "shortcut"}:
            if self.screen is not self.main_screen:
                return False
            if action == "shortcut":
                page = self.pane(self.active_tab).page
                return parameters[0] == "w" or bool(page and parameters[0] in dict(page.options))
        return super().check_action(action, parameters)

    def action_select_tab(self, number):
        self.switch(TABS[number - 1])

    def action_panel_back(self):
        self.go_back()

    def action_panel_help(self):
        self.show_help()

    def action_shortcut(self, key):
        if key == "w":
            pane = self.pane(self.active_tab)
            pane.query_one(ScrollBody).toggle_wrap(pane.page)
        else:
            self.select(key)

    def on_option_list_option_selected(self, event):
        if self.screen is self.main_screen:
            self.select(event.option_id)

    def on_button_pressed(self, event):
        if event.button.id == "back":
            self.go_back()

    def go_back(self):
        if self.busy():
            work = self.work.get(self.active_tab)
            if work and (cancel := work.panel.scan_cancel) is not None:
                cancel.set()
                self.status("Cancelando búsqueda…")
            return
        if work := self.work.get(self.active_tab):
            self.resolve(work, self.pane(self.active_tab).page.back or ABANDON)
        elif self.active_tab != "home":
            self.switch("home")
        else:
            self.exit_dialog()

    def select(self, key):
        if self.busy():
            return
        tab = self.active_tab
        if work := self.work.get(tab):
            self.resolve(work, key)
        elif tab == "home" and key == "s":
            self.exit_dialog()
        else:
            self.start(tab, key)

    def exit_dialog(self):
        self.push_screen(Question(Prompt("¿Salir de PGOPCore?", "Se cerrará la sesión del panel.")),
                         lambda response: self.finish() if response == "yes" else self.status("Salida cancelada."))

    def finish(self):
        for work in tuple(self.work.values()):
            self.resolve(work, ABANDON)
        self.exit()

    def show_help(self):
        if not self.busy():
            self.push_screen(Question(Prompt(
                "Ayuda y presentación",
                HELP[self.active_tab] + "\n\n1–5 cambian de pestaña. 0 o Esc vuelven.\n"
                "Tab y Shift+Tab cambian el foco; las flechas mueven y Enter elige.\n"
                "W cambia el ajuste visual en texto o código.\n"
                "Windows Terminal: Ctrl+rueda o Ctrl+signo más/menos.\n"
                "Consola clásica: Propiedades > Fuente, si está disponible.\n"
                "Modo lineal accesible: pgop --plain.",
            ), help_view=True))

    def start(self, tab, key, raw=None):
        from .panel_controller import ERRORS, PanelController

        panel = PanelController(self, tab, self.path, self.identity, self.queries.get(tab, ""))
        panel.last_path = self.last_report
        panel.file_filters = self.file_filters
        panel.context_draft = self.context_draft
        panel.context_home = self.context_home
        if tab == "reports":
            panel.observation = self.observation
        self.work[tab] = Work(panel)
        self.status("Procesando…")

        def run():
            try:
                self.perform(panel, key, raw)
            except StopFlow:
                panel.take_notes()
            except ERRORS as exc:
                panel.error(exc)
            except Exception:
                panel.say("El panel no pudo completar la operación. Podés volver a intentarlo en modo lineal.")
            finally:
                try:
                    self.call_from_thread(self.completed, panel)
                except RuntimeError:
                    pass

        Thread(target=run, name=f"pgop-{tab}", daemon=True).start()

    @staticmethod
    def need_project(panel):
        if not panel.path:
            panel.say("Elegí primero una carpeta para esta operación.")
            panel.open_project()
        return bool(panel.path)

    def perform(self, panel, key, raw):
        if raw:
            panel.open_saved(raw)
        elif panel.tab == "home":
            if key == "a":
                panel.open_project()
            elif key == "c":
                panel.open_project(current=True)
            elif key == "p":
                if not panel.path:
                    panel.open_project(overview=True)
                if panel.path:
                    panel.understand_project()
            elif key == "q":
                panel.about()
        elif panel.tab == "files":
            if key == "a":
                panel.open_file_prompt()
            elif key == "n":
                panel.find_files()
            elif key == "l":
                panel.list_unregistered_files()
            elif self.need_project(panel):
                panel.explore()
        elif panel.tab == "search":
            if key == "n":
                panel.find_files()
            elif self.need_project(panel):
                panel.search()
        elif panel.tab == "reports":
            if key == "a":
                panel.reopen_report()
            elif key == "j":
                panel.read_workspace_report()
            elif key == "g":
                panel.save_report()
            elif key == "m":
                if self.need_project(panel):
                    panel.save_context()
            elif key == "c":
                if self.need_project(panel):
                    panel.saved_contexts()
            elif panel.observation:
                from .panel_controller import report_preview

                panel.show_text("Vista previa del informe", report_preview(panel.observation),
                                {"g": ("Guardar este resultado", panel.save_report)})
        elif self.need_project(panel):
            panel.verify()

    def exchange(self, panel, content):
        reply = Queue(maxsize=1)
        self.call_from_thread(self.present, panel, content, reply)
        answer = reply.get()
        if answer is ABANDON:
            if isinstance(content, Prompt) and content.field:
                panel.feedback = "Edición cancelada."
            raise StopFlow
        return answer

    def publish(self, panel):
        self.queries[panel.tab] = panel.query
        if panel.observation and panel.path == self.path and panel.identity == self.identity and panel.tab != "reports":
            self.observation = panel.observation
            if "reports" not in self.work:
                self.show_root("reports")

    def discovery(self, panel, message):
        def update():
            work = self.work.get(panel.tab)
            if work and work.panel is panel:
                self.status(message)
        self.call_from_thread(update)

    def present(self, panel, content, reply):
        work = self.work.get(panel.tab)
        if work is None or work.panel is not panel:
            reply.put(ABANDON)
            return
        work.reply = reply
        self.status(panel.feedback)
        panel.feedback = ""
        self.publish(panel)
        if isinstance(content, Prompt):
            self.push_screen(Question(content), lambda value: self.resolve(work, value))
        else:
            pane = self.pane(panel.tab)
            pane.show_page(content)
            if panel.tab == self.active_tab:
                pane.restore_focus()
            self.open_queued_report()

    def resolve(self, work, value):
        if work.reply is not None:
            reply, work.reply = work.reply, None
            self.status("Procesando…")
            reply.put(value)

    def completed(self, panel):
        work = self.work.get(panel.tab)
        if work is None or work.panel is not panel:
            return
        del self.work[panel.tab]
        self.publish(panel)
        self.show_root(panel.tab, panel.take_notes())
        if panel.tab == self.active_tab:
            self.pane(panel.tab).restore_focus()
        self.status(panel.feedback)
        self.open_queued_report()

    def project_changed(self, panel):
        self.call_from_thread(self.invalidate_project, panel)

    def invalidate_project(self, panel):
        self.path, self.identity = panel.path, panel.identity
        self.observation = self.last_report = self.queued_report = None
        self.queries.clear()
        self.file_filters.clear()
        self.context_draft.clear()
        for tab in TABS:
            if tab != panel.tab:
                if work := self.work.pop(tab, None):
                    self.resolve(work, ABANDON)
            self.pane(tab).reset()
            self.show_root(tab)
        self.header()

    def report_saved(self, panel, raw):
        self.call_from_thread(self.record_report, panel, raw)

    def record_report(self, panel, raw):
        if (panel.path, panel.identity) == (self.path, self.identity):
            self.last_report = raw
            if panel.tab != "reports":
                self.queued_report = raw

    def open_queued_report(self):
        if self.queued_report and not self.busy():
            raw, self.queued_report = self.queued_report, None
            if work := self.work.pop("reports", None):
                self.resolve(work, ABANDON)
            self.switch("reports")
            self.start("reports", None, raw)


def run_tui():
    app = FixedPanel()
    app.run()
    return app.return_code or 0
