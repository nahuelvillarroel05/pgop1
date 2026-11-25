"""Numbered panel controls and bounded views using developer-created inputs."""

from hashlib import sha256
from codecs import BOM_UTF8
from io import StringIO
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pgopcore import cli, panel, panel_report, panel_views, workspace
from pgopcore import workspace_search


class ProjectionTests(unittest.TestCase):
    def test_recognizes_only_checkable_flat_front_matter(self):
        text = (
            "---\nname: tool-reader\ndescription: \"Tool: overview\"\n"
            "tags: [docs, 'public', \"local\"]\n---\n\nSection\n=======\n~~~md\n# example\n~~~\n"
        )
        raw = text.encode()
        units = panel_views.markdown_units(raw, workspace.search.line_breaks(raw))
        self.assertEqual([unit.kind for unit in units], ["markdown_front_matter", "markdown_section"])
        self.assertEqual(list(panel_views.markdown_sections(text)), [(7, 1, "Section")])
        self.assertEqual(raw[units[0].start:units[0].end].decode(), "\n".join(text.splitlines()[:5]) + "\n")

    def test_unrecognized_front_matter_is_literal_and_does_not_create_heading(self):
        for metadata in ("title: [", 'title: "open', "title: {a: b}", "title: [one, [two]]",
                         "title: [one, , two]", "title: >\n  folded", "title: first\ntitle: second"):
            with self.subTest(metadata=metadata):
                preamble = f"---\n{metadata}\n---\n"
                text = preamble + "\n## Actual\nBody\n"
                raw = text.encode()
                units = panel_views.markdown_units(raw, workspace.search.line_breaks(raw))
                self.assertEqual([unit.kind for unit in units], ["markdown_section", "markdown_section"])
                self.assertEqual(units[0].title, "Introducción")
                self.assertEqual(raw[units[0].start:units[0].end].decode(), preamble + "\n")
                self.assertEqual(list(panel_views.markdown_sections(text)),
                                 [(preamble.count("\n") + 2, 2, "Actual")])
        self.assertEqual(list(panel_views.markdown_sections("---\nMy title\n---\n")), [(2, 2, "My title")])

    def test_markdown_fences_and_exact_multibyte_text_offsets(self):
        raw = ("# Vista\r\n```md\n# ejemplo\n```\nSubtítulo\n---------\n" + "ñ" * 220).encode()
        headings = list(panel_views.markdown_sections(raw.decode()))
        self.assertEqual(headings, [(1, 1, "Vista"), (5, 2, "Subtítulo")])
        rows = list(panel_views.segments(raw, workspace.search.line_breaks(raw)))
        self.assertEqual(b"".join(raw[row.start:row.end] for row in rows), raw)
        self.assertTrue(all(len(row.text) <= panel_views.LINE_WIDTH for row in rows))

    def test_csv_quoted_delimiters_multiline_cells_and_ambiguity(self):
        delim, rows = panel_views.detect_csv('zona;observacion\r\nsur;"dos; valores\r\n=2+2"\r\n')
        self.assertEqual(delim, ";")
        self.assertEqual(rows[1].fields, ("sur", "dos; valores\r\n=2+2"))
        self.assertEqual((rows[1].first_line, rows[1].last_line), (2, 3))
        with self.assertRaisesRegex(panel_views.CSVError, "CSV_DELIMITER_UNCERTAIN"):
            panel_views.detect_csv("a,b;c\nx,y;z\n")
        with self.assertRaisesRegex(panel_views.CSVError, "CSV_INVALID"):
            panel_views.csv_rows('a,b\nx,"sin cierre', ",")

    def test_guarded_content_and_control_rendering(self):
        with self.assertRaisesRegex(ValueError, "PANEL_SENSITIVE_CONTENT"):
            panel_views.guard(b'{"api_key": "un valor local"}', "sample.json")
        with self.assertRaisesRegex(ValueError, "PANEL_SENSITIVE_CONTENT"):
            panel_views.guard(br'{"\u0070assword": "un valor local"}', "sample.json")
        with self.assertRaisesRegex(ValueError, "PANEL_SENSITIVE_CONTENT"):
            panel_views.guard(b'"Password";usuario\nprueba;alfa', "sample.csv")
        self.assertEqual(panel_views.safe_text("uno\r\ndos\u009b3\u202e"), "uno\ndos\\x9b3\\u202e")
        self.assertEqual(panel_views.json_pointer(("a/b", "c~d", 0)), "/a~1b/c~0d/0")

    def test_stdout_and_stdin_must_both_be_interactive(self):
        stdin, stdout, stderr = StringIO(), StringIO(), StringIO()
        with patch.multiple(sys, stdin=stdin, stdout=stdout, stderr=stderr), patch.object(panel, "run") as run:
            self.assertEqual(cli.main([]), 0)
            self.assertIn("usage:", stdout.getvalue())
            self.assertEqual(cli.main(["--json"]), 2)
            run.assert_not_called()
            with patch.object(stdin, "isatty", return_value=True), patch.object(stdout, "isatty", return_value=True):
                run.return_value = 0
                self.assertEqual(cli.main([]), 0)
            run.assert_called_once_with()

    def test_json_number_lexemes_survive_container_rendering(self):
        raw = b'{"n":[1e-400,1.00000000000000001,-0,2.50E+04],"s":"1e-400","ok":true}'
        workspace.validated_text(raw, ".json")
        value = panel_views.json_value(raw)
        rendered = panel_views.render_json(value)
        self.assertEqual(panel_views.json_kind(value["n"][0]), "número")
        self.assertEqual(rendered, '''{
  "n": [
    1e-400,
    1.00000000000000001,
    -0,
    2.50E+04
  ],
  "s": "1e-400",
  "ok": true
}''')


@unittest.skipUnless(os.name == "nt", "Windows and the a7 native contract are required")
class NativePanelTests(unittest.TestCase):
    def setUp(self):
        try:
            workspace.io.api()
        except workspace.io.SafeIOError as exc:
            self.skipTest(exc.code)
        fixture_root = os.environ.get("PGOP_PANEL_DEV_TEST_ROOT")
        if not fixture_root:
            self.skipTest("set PGOP_PANEL_DEV_TEST_ROOT to a disposable NTFS fixture root")
        self.tmp = TemporaryDirectory(prefix="panel fixture ", dir=fixture_root)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.root)
        patcher = patch.object(panel, "version", return_value="0.1.0a9.post1")
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, name, body):
        f = self.root / name
        f.parent.mkdir(exist_ok=True)
        f.write_bytes(body)

    def drive(self, script):
        output = StringIO()
        app = panel.Panel(StringIO(script), output)
        self.assertEqual(app.run(), 0, output.getvalue())
        return app, output.getvalue()

    def test_metadata_preview_then_cancel_does_not_create_state(self):
        self.put("malformado.json", b'{ "unclosed": [')
        app, output = self.drive("\n0\n0\n")
        self.assertIn("1 archivos elegibles", output)
        self.assertIn("Solo metadatos", output)
        self.assertIsNone(app.path)
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_refuses_launcher_location_before_scan(self):
        self.put("installer-note.txt", b"not a selected project")
        with patch.dict(os.environ, {"PGOP_PANEL_INSTALL_DIR": str(self.root) + "\\"}):
            with patch.object(workspace.Scan, "run", side_effect=AssertionError("protected root reached scan")):
                app, output = self.drive(f"1\n{self.root}\n0\n")
        self.assertIsNone(app.path)
        self.assertIn("carpeta de proyecto local específica", output)
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_markdown_read_save_and_reopen_with_persistent_registry(self):
        body = "# Manual\r\nEnvío por la tarde.\r\n".encode()
        self.put("guide.md", body)
        app, output = self.drive("1\n\n1\n2\n1\n6\n\n1\n9\nj\n0\n0\n0\n0\n0\n")
        self.assertIn("Envío por la tarde.", output)
        self.assertIn("Integridad de los artefactos comprobada", output)
        self.assertIn("Informe guardado · JSON", output)
        export = self.root / ".pgopcore" / "reports" / app.last_path
        report = json.loads((export / panel_report.JSON).read_bytes())
        entry, = report["entries"]
        self.assertEqual(entry["source"]["sha256"], sha256(body).hexdigest())
        self.assertEqual(entry["selector"]["byte_end"], len(body))
        self.assertEqual((self.root / "guide.md").read_bytes(), body)
        _, reopened = self.drive("1\n\n1\n5\n2\n1\n0\n0\n0\n")
        self.assertIn("Integridad de los artefactos comprobada", reopened)
        self.assertIn("Hay un espacio de trabajo con 1 fuentes registradas", reopened)

    def test_confirmation_cannot_capture_new_or_replaced_candidate(self):
        self.put("change.txt", b"before")
        self.put("stable.txt", b"accepted")
        app = panel.Panel(output=StringIO())
        with panel.guarded_project(".") as (root, _):
            path, identity = root.path, root.ids[-1]
        preview, approved = app.scan_preview(path, identity, False, {})
        self.put("change.txt", b"after changes")
        self.put("new.txt", b"unexpected")
        result = app.capture_preview(path, identity, False, {}, preview["revision"], approved)
        self.assertEqual([row["path"] for row in result["candidates"]], ["stable.txt"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["reasons"]["NEW_SINCE_PREVIEW"], 1)
        self.assertEqual(result["failures"][0]["code"], "SOURCE_CHANGED")

    def test_quick_literal_search_has_context_and_omits_protected_body(self):
        self.put("journal.txt", "Línea previa\r\nclave pública\r\nLínea posterior\r\n".encode())
        self.put("settings.json", b'{"password": "clave que no debe verse"}')
        app, output = self.drive("1\n\n1\n3\nclave\n\n0\n0\n")
        self.assertIn("Línea previa", output)
        self.assertIn("Línea posterior", output)
        self.assertIn("Búsqueda incompleta", output)
        self.assertNotIn("no debe verse", output)
        hit, = app.observation["entries"]
        self.assertEqual(hit["source"]["path"], "journal.txt")
        self.assertEqual(hit["selector"]["line_start"], 2)
        self.assertEqual((hit["context"]["line_start"], hit["context"]["line_end"]), (1, 3))

    def test_reads_json_csv_python_and_plain_text_from_the_registry(self):
        inputs = {
            "data.json": b'{"ready":false}',
            "ledger.csv": b'area;formula\nmedicion;"=SUM(1;2)"\n',
            "script.py": b'raise RuntimeError("texto original")\n',
            "words.txt": "Línea de texto común.\n".encode(),
        }
        for name, body in inputs.items():
            self.put(name, body)
        _, output = self.drive("1\n\n1\n2\n1\n1\n0\n0\n2\n1\n2\n0\n0\n0\n3\n0\n4\n0\n0\n0\n")
        for expected in ("JSON · booleano · /ready", "false", "Primera fila como encabezados",
                         "Fila 1 · Campo 2", "=SUM(1;2)", "Python · AST V2 · COMPLETE",
                         'raise RuntimeError("texto original")', "Línea de texto común."):
            self.assertIn(expected, output)
        for name, body in inputs.items():
            self.assertEqual((self.root / name).read_bytes(), body)

    def test_verification_distinguishes_change_and_absence(self):
        for name in ("changed.txt", "missing.txt", "stable.txt"):
            self.put(name, b"initial")
        self.drive("1\n\n1\n0\n")
        self.put("changed.txt", b"different bytes")
        (self.root / "missing.txt").unlink()
        _, output = self.drive("1\n\n1\n4\n0\n0\n")
        self.assertIn("1/3 fuentes activas vigentes", output)
        self.assertIn("changed.txt · Archivo cambiado", output)
        self.assertIn("missing.txt · Archivo ausente", output)
        self.assertNotIn("SHA-256", output)

    def test_cold_search_opens_revalidated_source_at_hit(self):
        raw = b"start\n" + b"between\n" * 6 + b"needle here\nafter\nfarther\n"
        self.put("notes.txt", raw)
        app, output = self.drive("3\n\n1\nneedle\n\n1\n4\n0\n0\n0\n")
        self.assertIn("Elegí qué carpeta querés usar para esta operación.", output)
        self.assertIn("Abrir el archivo", output)
        self.assertIn("notes.txt · líneas 8–10", output)
        self.assertIn("farther", output)
        self.assertIn(sha256(raw).hexdigest(), output)
        self.assertEqual(app.observation["operation"], "Búsqueda literal")

    def test_no_match_cue_and_direct_exploration(self):
        self.put("notes.txt", "Fecha de la revisión\n".encode())
        _, output = self.drive("3\n\n1\nreview date\n\ne\n1\n0\n0\n0\n0\n")
        self.assertIn("con su idioma y ortografía", output)
        self.assertIn("e. Explorar archivos", output)
        self.assertIn("Fecha de la revisión", output)

    def test_json_value_reference_and_exact_export_survive_nested_hit(self):
        self.put("numbers.json", b'{"mass":1.00000000000000001,"small":1e-400}')
        app, output = self.drive("\n1\n2\n1\n1\nb\n1e-400\n\n0\nr\ng\n\n1\n0\n0\n0\n0\n")
        self.assertIn("Referencia · {\"kind\": \"json_pointer\", \"pointer\": \"/mass\"}", output)
        self.assertIn("1.00000000000000001", output)
        export = self.root / ".pgopcore" / "reports" / app.last_path
        report = json.loads((export / panel_report.JSON).read_bytes())
        self.assertEqual(report["operation"], "Lectura")
        entry, = report["entries"]
        self.assertEqual(entry["text"], "1.00000000000000001")
        self.assertIn(entry["text"], (export / panel_report.MARKDOWN).read_text(encoding="utf-8"))

    def test_csv_value_reference_and_export_survive_nested_no_match(self):
        self.put("table.csv", b'area;lectura\nmedicion;"2; detalle"\n')
        app, output = self.drive("\n1\n2\n1\n1\n2\nb\nmissing\n\n0\nr\ng\n\n1\n0\n0\n0\n0\n0\n")
        self.assertIn("No se encontró el texto", output)
        self.assertIn('"column": 2', output)
        export = self.root / ".pgopcore" / "reports" / app.last_path
        report = json.loads((export / panel_report.JSON).read_bytes())
        self.assertEqual(report["operation"], "Lectura")
        entry, = report["entries"]
        self.assertEqual(entry["text"], "2; detalle")
        self.assertEqual(entry["selector"]["column"], 2)

    def test_export_incomplete_fails_read_and_repeated_save_preserves_bytes(self):
        project = panel.Panel(output=StringIO())
        body = panel_report.build("Lectura", str(self.root), 1, project.version, workspace.now(), {}, [])
        name, contents = panel_report.prepare(body)
        with panel.guarded_project(".") as (destination, _):
            panel_report.save(destination, name, contents)
            with self.assertRaisesRegex(workspace.WorkspaceError, "Ya existe"):
                panel_report.save(destination, name, contents)
            self.assertEqual(json.loads(panel_report.read(destination, name)[1]), body)
        (self.root / name / (
            "complete-" + sha256(contents[panel_report.MANIFEST]).hexdigest())).rmdir()
        with panel.guarded_project(".") as (destination, _):
            with self.assertRaisesRegex(workspace.WorkspaceError, "incompleto"):
                panel_report.read(destination, name)

    def test_new_report_rejects_independently_pinned_divergent_markdown(self):
        report = panel_report.build("Lectura", str(self.root), 1, "0.1.0a9.post1", workspace.now(), {}, [])
        with panel.guarded_project(".") as (destination, _):
            name = self.save_divergent_markdown(destination, report)
            with self.assertRaisesRegex(workspace.WorkspaceError, "no coincide con sus datos"):
                panel_report.read(destination, name)

    def test_a9_panel_report_renders_from_bound_json_and_withholds_old_markdown(self):
        report = self.a9_report(panel_report.LEGACY_SCHEMA)
        with panel.guarded_project(".") as (destination, _):
            name = self.save_divergent_markdown(destination, report)
            markdown, encoded, historical = panel_report.read(destination, name)
        self.assertTrue(historical)
        self.assertEqual(json.loads(encoded), report)
        self.assertIn("PGOPCore · Informe local", markdown)
        self.assertNotIn("divergent fixture", markdown)

    def a9_report(self, schema):
        return {"schema": schema, "operation": "Lectura", "project": str(self.root),
                "registry_revision": 1, "distribution_version": "0.1.0a9.post1",
                "observed_at": workspace.now(), "source_currentness": "AT_CAPTURE_ONLY",
                "parameters": {}, "entries": [], "coverage": None, "limitations": list(panel_report.LIMITATIONS)}

    def test_a9_post1_panel_report_requires_original_markdown_projection(self):
        report = self.a9_report(panel_report.PREVIOUS_SCHEMA)
        name, bodies = panel_report.prepare(report)
        with panel.guarded_project(".") as (destination, _):
            panel_report.save(destination, name, bodies)
            markdown, encoded, historical = panel_report.read(destination, name)
        self.assertFalse(historical)
        self.assertEqual(markdown.encode(), bodies[panel_report.MARKDOWN])
        self.assertEqual(encoded.encode("ascii"), bodies[panel_report.JSON])

    def test_direct_open_pins_root_and_file_before_consent(self):
        self.put("manual.txt", b"previous")

        class ChangedDuringPrompt(StringIO):
            def readline(stream):
                reply = super().readline()
                if reply == "confirm\n":
                    self.put("manual.txt", b"changed")
                    return "1\n"
                return reply

        output = StringIO()
        app = panel.Panel(ChangedDuringPrompt("1\nmanual.txt\nconfirm\n0\n"), output)
        self.assertEqual(app.run(), 0)
        self.assertIn("Archivo cambiado", output.getvalue())
        self.assertIsNone(app.observation)
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_preview_can_open_one_bom_markdown_section_without_registration(self):
        body = BOM_UTF8 + ("---\r\ntitle: Manual\r\n---\r\n# Arranque\r\n"
                          "Explicación.\r\n## Detalle\r\nContenido interno.\r\n# Arranque\r\n"
                          "Otra sección.\r\n").encode()
        self.put("manual.md", body)
        self.put("other.txt", b"not in the selected file")
        app, output = self.drive("\n2\n1\n1\n8\n2\n0\n0\n0\n0\n0\n")
        self.assertIn("Captura individual", output)
        self.assertIn("Metadatos (YAML) · líneas 1–3", output)
        self.assertIn("Arranque · líneas 4–7", output)
        self.assertIn("Arranque · líneas 8–9", output)
        self.assertNotIn("not in the selected file", output)
        source, = app.observation["entries"]
        selector = source["selector"]
        self.assertEqual(body[selector["byte_start"]:selector["byte_end"]], source["text"].encode())
        self.assertEqual(selector["byte_start"], body.index(b"# Arranque"))
        self.assertNotIn("Otra sección", source["text"])
        self.assertEqual(source["source"]["sha256"], sha256(body).hexdigest())
        self.assertEqual(source["source"]["acquisition_scope"], "EXPLICIT_FILE")
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_real_ast_worker_and_complete_decorated_unit_saved_from_first_page(self):
        whole = ('    @property\r\n    def measure(self):\r\n        """Métrica literal."""\r\n'
                 + "".join(f"        value_{index} = {index}\r\n" for index in range(12))
                 + "        return 'último resultado'")
        body = BOM_UTF8 + ('"""Módulo de prueba."""\r\nimport math\r\n'
                          "raise RuntimeError('must never execute')\r\n"
                          "class Sample:\r\n" + whole + "\r\n\r\n"
                          "def another():\r\n    return 'ajeno'\r\n").encode()
        self.put("sample.py", body)
        with TemporaryDirectory(prefix="export fixture ", dir=self.root.parent) as destination:
            app, output = self.drive(f"1\nsample.py\n1\n2\ng\n{destination}\n1\n0\n0\n0\n")
            report_dir = Path(app.last_path)
            markdown = (report_dir / panel_report.MARKDOWN).read_text("utf-8")
            report = json.loads((report_dir / panel_report.JSON).read_bytes())
        self.assertIn("Python · AST V2 · COMPLETE", output)
        self.assertIn("Módulo de prueba.", output)
        self.assertIn("Unidad completa · página 1 de 2", output)
        self.assertEqual(report["schema"], "pgop.panel-report.v3")
        entry, = report["entries"]
        selector = entry["selector"]
        self.assertEqual(selector["ast_schema"], "pgop1.static-ast.v2")
        self.assertEqual(selector["scope"], ["Sample"])
        self.assertEqual(selector["documented_description"], "Métrica literal.")
        self.assertEqual(entry["text"], whole)
        self.assertEqual(body[selector["byte_start"]:selector["byte_end"]], whole.encode())
        self.assertIn("último resultado", markdown)
        self.assertNotIn("return 'ajeno'", markdown)
        self.assertNotIn("## Parámetros", markdown)
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_save_and_cold_reopen_show_short_unit_evidence_first_in_markdown(self):
        raw = ('def next_slot():\n    """Horario publicado."""\n'
               + "    current = 1\n" * 8
               + '    return "viernes a las quince"\n').encode()
        self.put("schedule.py", raw)
        with TemporaryDirectory(prefix="export fixture ", dir=self.root.parent) as destination:
            app, output = self.drive(f"1\nschedule.py\n1\n1\ng\n{destination}\n1\n0\n0\n0\n0\n")
            exported = Path(app.last_path)
            before = (exported / panel_report.MARKDOWN).read_bytes()
            self.assertIn(b"**Objetivo**", before)
            with patch.object(workspace_search, "capture", side_effect=AssertionError("source reread")):
                _, cold = self.drive(f"5\n2\nu\n{exported}\n0\n0\n0\n")
            self.assertEqual((exported / panel_report.MARKDOWN).read_bytes(), before)
        for transcript in (output, cold):
            initial = transcript.split("Informe guardado · Markdown · evidencia de la unidad", 1)[1]
            first_screen = initial.split("Elegí una opción:", 1)[0]
            self.assertIn("schedule.py · next\\_slot · líneas 1–11", first_screen)
            self.assertIn('return "viernes a las quince"', first_screen)
            self.assertIn("Leer Markdown completo desde el comienzo", first_screen)
            self.assertNotIn("## Cobertura y límites", first_screen)

    def test_project_summary_uses_documented_purpose_and_bounded_sample(self):
        self.put("README.md", BOM_UTF8 + b"# Manual\r\n\r\nEste proyecto convierte horarios.\r\n")
        self.put("src/main.py", b'def start():\n    return "ready"\n')
        for number in range(12):
            self.put(f"file{number}.txt", b"uncited")
        app, output = self.drive("8\n\n1\n0\n0\n")
        self.assertIn("Este proyecto convierte horarios.", output)
        self.assertIn("src/main.py · AST V2 COMPLETE", output)
        self.assertIn("6 fuentes leídas · 8 candidatas sin leer", output)
        self.assertEqual(app.observation["entries"][0]["source"]["path"], "README.md")
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_folder_preview_offers_direct_read_only_project_documentation(self):
        self.put("README.md", b"# Agenda\n\nOrganiza horarios.\n\n## Reglas\nLa apertura es manana.\n")
        app, output = self.drive("1\n\n8\n1\n1\n2\n0\n0\n0\n0\n")
        self.assertLess(output.index("8. Comprender el proyecto · propósito y secciones"),
                        output.index("1. Confirmar lectura, creación de .pgopcore"))
        self.assertIn("Archivos que se leerán si confirmás:", output)
        self.assertIn("Fuente del propósito · README.md", output)
        self.assertIn("Sección · Agenda · líneas 1–6", output)
        self.assertIn("Explorar secciones completas de README.md", output)
        self.assertIn("Secciones de README.md", output)
        self.assertIn("README.md · Reglas · líneas 5–6", output)
        self.assertIn("La apertura es manana.", output)
        self.assertEqual(app.observation["operation"], "Comprender proyecto")
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_cancel_project_sample_before_reading_any_file(self):
        self.put("README.md", b"# Open only with confirmation\n")
        with patch.object(workspace.native, "capture", side_effect=AssertionError("unconfirmed capture")):
            app, output = self.drive("1\n\n8\n0\n0\n")
        self.assertIn("Archivos que se leerán si confirmás:", output)
        self.assertNotIn("Open only with confirmation", output)
        self.assertIsNone(app.observation)
        self.assertFalse((self.root / ".pgopcore").exists())

    def test_panel_search_diversifies_citations_with_original_bom_offsets(self):
        self.put("a.txt", b"fecha alfa\n" * 25)
        body = BOM_UTF8 + "fecha bíblica\r\n".encode()
        self.put("b.md", body)
        app, output = self.drive("\n1\n3\nfecha\n2\n\n0\n1\n1\n2\n0\n0\n")
        results = app.observation["entries"]
        self.assertEqual([entry["source"]["path"] for entry in results[:2]], ["a.txt", "b.md"])
        entry = results[1]
        self.assertEqual(entry["selector"]["byte_start"], len(BOM_UTF8))
        self.assertEqual(entry["source"]["sha256"], sha256(body).hexdigest())
        self.assertEqual(app.observation["coverage"]["verified_occurrences"], 26)
        self.assertEqual(app.observation["coverage"]["omitted_occurrences"], 16)
        self.assertIn("una cita por archivo antes de repetir", output)
        with app.registry() as registry:
            self.assertEqual(registry.value["rows"][1]["policy"], workspace.BOM_POLICY)

    def test_saved_output_guard_blocks_visible_report_content(self):
        self.put("notes.txt", b"public fixture")
        app, _ = self.drive("\n1\n0\n")
        blocked = "password = local fixture value"
        report = panel_report.build("Lectura", str(self.root), 1, app.version, workspace.now(), {},
                                    [{"source": {"path": "notes.txt"}, "selector": {}, "text": blocked}])
        name, bodies = panel_report.prepare(report)
        with app.registry(load_journal=False) as registry:
            panel_report.save(registry.reports, name, bodies)
        _, output = self.drive("\n1\n5\n2\n1\n0\n0\n")
        self.assertIn("indicadores de credenciales", output)
        self.assertNotIn(blocked, output)

    @staticmethod
    def save_divergent_markdown(destination, report):
        name, contents = panel_report.prepare(report)
        contents[panel_report.MARKDOWN] = b"divergent fixture\n"
        manifest = json.loads(contents[panel_report.MANIFEST])
        body = contents[panel_report.MARKDOWN]
        manifest["files"][panel_report.MARKDOWN] = {"bytes": len(body), "sha256": sha256(body).hexdigest()}
        contents[panel_report.MANIFEST] = workspace.contract.canonical(manifest)
        panel_report.save(destination, name, contents)
        return name


if __name__ == "__main__":
    unittest.main()
