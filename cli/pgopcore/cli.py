"""Dispatch local product commands and explicitly selected historical operations."""

import argparse
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import platform
import sys
import unicodedata

from . import product, report
from .search_contract import add_search_options, failure as search_failure

PROFILE = "public-aggregate-v1"
SCOPE = "PUBLIC_AGGREGATES_ONLY"
LIMITS = (
    "Agregados públicos registrados. No se repiten las pruebas históricas.",
    "La integridad de los bytes y la consistencia de conteos no acreditan respaldo semántico.",
)
HISTORICAL_LABEL = "Demostración histórica congelada. Sin adjudicación semántica independiente."
SEARCH_EXAMPLE = r'pgop search "texto exacto" --file "D:\Mis fuentes\notas.txt"'
COMMANDS = ("doctor", "status", "catalog", "evidence", "verify", "report")
PACKAGE = "RUN012_PUBLIC"


class UsageError(Exception):
    pass


def write_text(stream, text):
    binary = getattr(stream, "buffer", None)
    if binary is None:
        stream.write(text)
    else:
        binary.write(text.encode("utf-8", errors="strict"))


def write_legacy_text(stream, text):
    encoding = getattr(stream, "encoding", None)
    if encoding:
        text = text.encode(encoding, errors="backslashreplace").decode(encoding)
    stream.write(text)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse may include arbitrary arguments (paths, secrets or controls).
        raise UsageError

    def _print_message(self, message, file=None):
        if message:
            write_text(sys.stderr if file is None else file, message)


def parser():
    root = Parser(
        prog="pgop",
        description="Registrá y consultá archivos en tu espacio de trabajo local.",
        epilog=f"En una terminal interactiva, pgop abre el panel. También podés buscar en un archivo: {SEARCH_EXAMPLE}. "
               "Para comprobar la instalación, usá pgop doctor.",
        allow_abbrev=False,
    )
    root.add_argument("--json", action="store_true", help="Un objeto JSON. Va antes del subcomando.")
    root.add_argument("--plain", action="store_true", help="Abrí el panel lineal, también con entrada redirigida.")
    root.add_argument("--version", action="store_true", help="Mostrá la versión instalada y salí.")
    commands = root.add_subparsers(dest="command", metavar="comando")
    init = commands.add_parser("init", help="Creá un espacio de trabajo local.", allow_abbrev=False)
    init.add_argument("root", nargs="?", default=".", metavar="RAÍZ",
                      help="Carpeta actual si se omite. También admite rutas relativas y absolutas NTFS.")
    scan = commands.add_parser("scan", help="Registrá archivos elegibles de la raíz elegida.", allow_abbrev=False)
    scan.add_argument("--preview", action="store_true", help="Mostrá candidatas sin leer cuerpos ni registrar.")
    scan.add_argument("--refresh", action="store_true", help="Registrá nuevas versiones de fuentes activas.")
    for name, summary in (
        ("doctor", "Comprobá la instalación y las capacidades locales."),
        ("status", "Mostrá el estado de la instalación y del espacio de trabajo."),
        ("catalog", "Listá las fuentes registradas en tu espacio de trabajo."),
        ("evidence", "Consultá métricas de un paquete histórico por ID."),
        ("verify", "Comprobá la identidad y los bytes de las fuentes registradas."),
    ):
        sub = commands.add_parser(name, help=summary, description=summary, allow_abbrev=False)
        if name in ("evidence", "verify"):
            sub.add_argument("package_id", nargs="?" if name == "verify" else None, metavar="ID",
                             help="Indicá un ID solo para verificar un paquete histórico.")
        if name in product.COMMANDS:
            sub.add_argument("--examples", action="store_true",
                             help="Usá el perfil histórico y su salida anterior.")
        if name == "catalog":
            actions = sub.add_subparsers(dest="catalog_action", metavar="acción")
            remove = actions.add_parser("remove", help="Retirá una fuente de futuras búsquedas.", allow_abbrev=False)
            remove.add_argument("source_id", metavar="ID")
            sub.add_argument("--offset", type=int, default=0, metavar="N",
                             help="Posición inicial, entre 0 y 100000. Predeterminado: 0.")
            sub.add_argument("--limit", type=int, default=10, metavar="N",
                             help="Tamaño de página, entre 1 y 20. Predeterminado: 10.")
    report.add_commands(commands)
    search = commands.add_parser("search", help="Buscá texto literal en fuentes registradas.",
                                 description="Buscá texto literal en el workspace. "
                                             "Devuelve la primera cita por fuente, hasta diez. "
                                             "Con --file, consultá un archivo explícito sin init.",
                                 epilog=f"Ejemplo: {SEARCH_EXAMPLE}.",
                                 allow_abbrev=False)
    search.add_argument("literal", help="Texto exacto entre comillas (1–256 caracteres).")
    add_search_options(search, "Tope de fuentes con citas o de citas en modo múltiple (1–10).")
    search.add_argument("--file", action="append", metavar="RUTA",
                        help="Una ruta ASCII relativa o absoluta en NTFS. "
                             "Admite .txt, .md, .json, .py y .csv de hasta 256 KiB.")
    search.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="Salida JSON para automatización.")
    context = commands.add_parser("context", help="Guardá y recuperá contexto local.", allow_abbrev=False)
    actions = context.add_subparsers(dest="context_action", required=True)
    for action, help_text in (
        ("preview", "Previsualizá selecciones y el destino sin escribir."),
        ("save", "Guardá las selecciones con la confirmación de preview."),
        ("list", "Listá contextos del proyecto seleccionado."),
        ("get", "Recuperá un contexto y revalidá sus fuentes."),
        ("revoke", "Quitá el acceso local a una versión."),
    ):
        sub = actions.add_parser(action, help=help_text, allow_abbrev=False)
        sub.add_argument("--project", required=True, metavar="CARPETA")
        sub.add_argument("--store-parent", required=True, metavar="CARPETA",
                         help="Carpeta existente y separada del proyecto para .pgop-context-v1.")
        sub.add_argument("--allow-local", action="store_true",
                         help="Confirmá esta operación local con tu cuenta y el alcance indicado.")
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if action in {"preview", "save"}:
            sub.add_argument("--name", required=True)
            sub.add_argument("--purpose", required=True)
            sub.add_argument("--lines", nargs=3, action="append", default=[], metavar=("RUTA", "DESDE", "HASTA"))
            sub.add_argument("--json-value", nargs=2, action="append", default=[], metavar=("RUTA", "PUNTERO"))
        if action == "save":
            sub.add_argument("--confirm", required=True, metavar="CONFIRMACIÓN")
        if action in {"get", "revoke"}:
            sub.add_argument("id")
        if action == "list":
            sub.add_argument("--name", default="", help="Filtrá por parte del nombre.")
    return root


def open_profile(factory, store=None):
    root = Path(__file__).absolute().parent / "_data"
    return factory(package_root=root, output_root=store if store is not None else root.with_name("_reports_disabled"))


def execute(args, service):
    match args.command:
        case "doctor":
            verification = service.verify(PACKAGE)
            return {
                "distribution_version": version("pgopcore"),
                "python_version": platform.python_version(),
                "catalog": "READABLE",
                "verification": verification,
            }, verification["status"]
        case "status":
            state = service.availability()
            return {
                "profile_version": state["version"],
                "scope": state["scope"],
                "registered_packages": state["registered_packages"],
                "commands": list(COMMANDS),
                "source_verification": "NOT_VERIFIED",
            }, None
        case "catalog":
            return service.catalog(offset=args.offset, limit=args.limit), None
        case "evidence":
            data = service.query(args.package_id)
            return data, data["verification"]["status"]
        case "verify":
            data = service.verify(args.package_id)
            return data, data["status"]
        case "report":
            return report.execute(args, service)
    raise RuntimeError("Unsupported dispatch")


def result(command, outcome, data, status=None, code=None):
    return {
        "schema": "pgop.result.v1",
        "command": command,
        "profile": PROFILE,
        "outcome": outcome,
        "native_status": status,
        "native_code": code,
        "scope": SCOPE,
        "data": data,
        "limitations": [*LIMITS, HISTORICAL_LABEL],
    }


def safe(value):
    return "".join(
        ascii(char)[1:-1] if unicodedata.category(char)[0] == "C"
        or unicodedata.category(char) in ("Zl", "Zp") else char
        for char in str(value)
    )


def verification_lines(data):
    coverage = data["coverage"]
    lines = [f'{data["package_id"]} · Integridad y consistencia: {data["status"]}',
             f'Fuentes con hash coincidente: {coverage["passed"]}/{coverage["registered"]}']
    lines.extend(f'  {source["source_id"]}: {source["status"]}'
                 for source in data["sources"])
    checks = data["checks"]["aggregate_consistency"]
    lines.append("Conteos del agregado: " + ", ".join(checks))
    lines.append(f'Snapshot: {data["snapshot_id"]}')
    lines.append(f'Recibo: {data["receipt_id"]}')
    lines.append(LIMITS[1])
    return lines


def human_lines(command, data):
    match command:
        case "doctor":
            verification = data["verification"]
            lines = [f'pgopcore {data["distribution_version"]} · Python {data["python_version"]}',
                     "Catálogo instalado legible.", *verification_lines(verification)]
            if verification["status"] != "PASS":
                lines.append("Revisá los permisos de lectura o reinstalá la wheel.")
            return lines
        case "status":
            return [f'Perfil de agregados públicos · versión {data["profile_version"]}',
                    f'Paquetes registrados: {len(data["registered_packages"])}',
                    "Fuentes sin verificar en este comando. Consultá pgop catalog."]
        case "catalog":
            lines = [f'Paquetes registrados: {data["total"]}']
            lines.extend(item["package_id"] for item in data["items"])
            if not data["items"]:
                lines.append("Sin paquetes en esta página.")
            if data["next_offset"] is not None:
                lines.append(f'Página siguiente: pgop catalog --examples --offset {data["next_offset"]}')
            return lines
        case "verify":
            return verification_lines(data)
        case "evidence":
            lines = verification_lines(data["verification"])
            lines.append(f'Estado histórico declarado: {data["historical_result"]}')
            for metric in data["metrics"]:
                source = metric["source"]
                lines.append(
                    f'  {metric["name"]}: {metric["value"]} '
                    f'(denominador: {metric["denominator"]}, {metric["denominator_scope"]})'
                    f' · {source["source_id"]}#{source["selector"]}'
                )
            return lines
        case "report":
            if "content" in data:
                lines = data["content"].split("\n")
                if lines[-1] == "":
                    lines.pop()
                if data["next_offset"] is not None:
                    lines.append(f'Página siguiente: --offset {data["next_offset"]}')
                return lines
            lines = [f'{data["generation"]} · {data["report_id"]}',
                     f'Manifiesto SHA-256: {data["manifest_sha256"]}',
                     "Artefactos: " + ", ".join(data["artifacts"])]
            if "verification" in data:
                lines.extend(verification_lines(data["verification"]))
            return lines
    raise RuntimeError("Unsupported presentation")


def write_json(payload):
    text = json.dumps(payload, ensure_ascii=True, allow_nan=False) + "\n"
    binary = getattr(sys.stdout, "buffer", None)
    if binary is None:
        sys.stdout.write(text)
    else:
        binary.write(text.encode("utf-8"))


def emit(payload, as_json, exit_code):
    if as_json:
        write_json(payload)
    elif "message" not in payload["data"]:
        if "content" not in payload["data"]:
            write_legacy_text(sys.stdout, HISTORICAL_LABEL + "\n")
        for line in human_lines(payload["command"], payload["data"]):
            write_legacy_text(sys.stdout, safe(line) + "\n")
    if "message" in payload["data"]:
        write_legacy_text(sys.stderr, payload["data"]["message"] + "\n")
    return exit_code


def emit_product(payload, as_json, exit_code):
    if as_json:
        write_json(payload)
    elif "message" in payload["data"]:
        write_text(sys.stderr, payload["data"]["message"] + "\n")
    else:
        for line in product.human_lines(payload):
            write_text(sys.stdout, safe(line) + "\n")
    return exit_code


def emit_search(payload, as_json, exit_code):
    if as_json:
        write_json(payload)
    elif payload["error"]:
        error = payload["error"]
        hint = {
            "FILE_NOT_FOUND": "Comprobá que la ruta exista y coincida con las mayúsculas del nombre.",
            "PERMISSION_DENIED": "Elegí un archivo que puedas leer con tu cuenta.",
        }.get(payload["status"], error["message"])
        if error["code"] in {"USAGE_ERROR", "EXACTLY_ONE_EXPLICIT_FILE_REQUIRED"}:
            hint = "Indicá el texto y una sola ruta con --file. Consultá pgop search --help."
        write_text(sys.stderr, f'{payload["status"]} ({error["code"]}). {hint}\n')
    else:
        source = payload["source"]
        lines = [f'{payload["status"]} · {source["path"]}',
                 f'SHA-256 {source["sha256"]} · {source["bytes"]} bytes']
        if payload["status"] == "NO_MATCH":
            lines.append("El texto no apareció en este archivo con las opciones elegidas.")
        for hit in payload["results"]:
            lines.append(f'Líneas {hit["line_start"]}–{hit["line_end"]} · {hit["excerpt"]}')
        if payload["truncated"]:
            lines.append(f'Coincidencias adicionales omitidas: {payload["remaining_occurrences"]}')
        lines.append("El SHA-256 identifica los bytes leídos. La validez semántica queda sin evaluar.")
        for line in lines:
            write_text(sys.stdout, safe(line) + "\n")
    return exit_code


def emit_workspace(payload, as_json, exit_code):
    if as_json:
        write_json(payload)
    elif "message" in payload["data"]:
        message = payload["data"]["message"]
        write_text(sys.stderr, f'{payload["native_code"] or payload["outcome"]}. {message}\n')
    else:
        from . import workspace_cli

        for line in workspace_cli.human_lines(payload):
            write_text(sys.stdout, safe(line) + "\n")
    return exit_code


def workspace_envelope(command, outcome, data, code):
    return {"schema": "pgop.workspace.v1", "command": command, "outcome": outcome,
            "native_code": code, "data": data}


def dispatch_workspace_error(command, as_json):
    payload = workspace_envelope(command, "USAGE_ERROR",
                                 {"message": f"Consultá pgop {command} --help."}, "INVALID_ARGUMENT")
    return emit_workspace(payload, as_json, 2)


def dispatch_workspace(args, as_json):
    try:
        from . import workspace_cli
        from . import workspace as ws
    except (ImportError, OSError):
        envelope = product.response if args.command in product.COMMANDS else workspace_envelope
        response = envelope(args.command, "FAILED", {
            "message": "Reinstalá la wheel en tu entorno virtual.",
        }, "INSTALLED_CODE_UNAVAILABLE")
        return emit_workspace(response, as_json, 1)
    try:
        payload, code = workspace_cli.execute(args)
    except (ws.WorkspaceError, ws.io.SafeIOError, OSError) as exc:
        payload, code = ws.error_result(args.command, exc)
    except Exception:
        payload, code = ws.payload(args.command, "ERROR", {
            "message": "No se pudo completar la operación local. Ejecutá pgop doctor.",
        }, "WORKSPACE_ERROR"), 1
    return emit_workspace(payload, as_json, code)


def unavailable(command, code=None):
    message = "Revisá los permisos de lectura de los recursos instalados o reinstalá la wheel."
    if command == "report":
        message = "Revisá el directorio de informes, sus permisos y el código de diagnóstico."
        details = {
            "REQUEST_KEY_CONFLICT": "La clave ya está vinculada a otro recibo. Usá una clave nueva.",
            "STALE_RECEIPT": "Las fuentes cambiaron entre verificación y generación. Volvé a verificar.",
            "ATTEMPT_IN_PROGRESS_OR_INTERRUPTED": "El informe aún no tiene marcador de finalización.",
            "OUTPUT_OVERLAP": "Elegí un directorio local fuera de la instalación y del repositorio.",
            "UNSAFE_PATH": "Usá una ruta local absoluta con archivos normales y sin enlaces.",
        }
        message = details.get(code, message)
    return result(command, "UNAVAILABLE", {
        "message": message,
    }, code=code)


def backend_result(args, backend, factory):
    command = args.command
    try:
        if command in ("evidence", "verify"):
            backend.identifier(args.package_id)
        elif command == "catalog":
            backend.bounded(args.offset, 0, 100000)
            backend.bounded(args.limit, 1, 20)
        elif command == "report":
            report.validate_args(args, backend)
    except backend.PublicError as exc:
        return result(command, "USAGE_ERROR", {
            "message": "Argumento inválido. Consultá la ayuda del comando.",
        }, code=exc.code), 2

    try:
        store = None
        if command == "report":
            store = report.local_store(args.store, Path(__file__).absolute().parent, backend)
        service = open_profile(factory, store)
    except backend.PublicError as exc:
        return unavailable(command, exc.code), 4

    try:
        data, status = execute(args, service)
    except backend.PublicError as exc:
        if exc.code == "UNKNOWN_PACKAGE" and command in ("evidence", "verify", "report"):
            return result(command, "USAGE_ERROR", {
                "message": "Paquete desconocido. Consultá pgop catalog --examples.",
            }, code=exc.code), 2
        if command == "report" and exc.code == "ARTIFACT_INTEGRITY_ERROR":
            return result(command, "VERIFICATION_INCOMPLETE", {
                "message": "El informe local no pasó el control de integridad.",
            }, status="FAIL", code=exc.code), 3
        return unavailable(command, exc.code), 4
    except OSError as exc:
        code = None
        if command == "report":
            code = "ACCESS_DENIED" if isinstance(exc, PermissionError) else "IO_ERROR"
        return unavailable(command, code), 4
    if status in {"FAIL", "PARTIAL"}:
        return result(command, "VERIFICATION_INCOMPLETE", data, status), 3
    return result(command, "COMPLETED", data, status), 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv == ["--plain"]:
        plain = bool(argv)
        if plain or all(stream is not None and stream.isatty() for stream in (sys.stdin, sys.stdout)):
            try:
                if not plain:
                    try:
                        from .panel_tui import supports_terminal, run_tui
                    except ImportError:
                        supports_terminal = None
                    if supports_terminal and supports_terminal():
                        return run_tui()
                    write_legacy_text(sys.stderr, "Modo lineal · Esta terminal no puede iniciar la pantalla fija.\n")
                from .panel import run

                return run()
            except (ImportError, PackageNotFoundError, OSError):
                write_text(sys.stderr, "No se pudo iniciar el panel. Ejecutá pgop doctor.\n")
                return 1
        parser().print_help()
        return 0
    root = parser()
    as_json = argv[0] == "--json"
    tail = argv[1:] if as_json else argv
    named_command = tail[0] if tail else None
    is_search = named_command == "search"
    command = None
    try:
        args = root.parse_args(argv)
        command = args.command
        if args.plain or (command is None and not args.version):
            raise UsageError
    except UsageError:
        options = tail[:tail.index("--")] if "--" in tail else tail
        if named_command == "context":
            as_json = as_json or "--json" in options
        if is_search:
            search_json = as_json or "--json" in options
            if any(arg == "--file" or arg.startswith("--file=") for arg in options[1:]):
                payload, code = search_failure("INVALID_SOURCE", "USAGE_ERROR")
                return emit_search(payload, search_json, code)
            return dispatch_workspace_error("search", search_json)
        if named_command in product.COMMANDS and "--examples" not in options:
            payload, code = product.usage_error(named_command)
            return emit_product(payload, as_json, code)
        if named_command in ("init", "scan") or (
            named_command == "report" and not any(
                option == "--store" or option.startswith("--store=") for option in options[1:]
            )
        ) or (
            named_command == "verify" and not any(not item.startswith("-") for item in options[1:])
        ):
            return dispatch_workspace_error(named_command, as_json)
        payload = result(command, "USAGE_ERROR", {"message": "Uso inválido. Consultá pgop --help."})
        return emit(payload, as_json, 2)

    if command == "context" and not args.version:
        from . import context_local

        payload, code = context_local.dispatch(args)
        if args.json:
            write_json(payload)
        else:
            from .panel_views import safe_text

            write_text(sys.stderr if code else sys.stdout, safe_text(context_local.human(payload)) + "\n")
        return code
    if command == "search" and not args.version:
        if args.file is None:
            return dispatch_workspace(args, args.json)
        if args.all_matches:
            payload, code = search_failure("INVALID_SOURCE", "USAGE_ERROR")
            return emit_search(payload, args.json, code)
        try:
            from . import search

            payload, code = search.search(args.literal, args.file, limit=args.limit, ignore_case=args.ignore_case)
        except (ImportError, OSError):
            payload, code = search_failure("INTERNAL_ERROR", "INSTALLED_CODE_UNAVAILABLE")
        except Exception:
            payload, code = search_failure("INTERNAL_ERROR", "SEARCH_FAILED")
        return emit_search(payload, args.json, code)

    if not args.version and command == "report":
        own = (args.query is not None or args.package_id is None) if args.report_action == "create" else (
            args.store is None or args.report_id.startswith("ws-report-")
        )
        if own:
            return dispatch_workspace(args, as_json)
    if not args.version and (command in ("init", "scan")
                             or command == "verify" and args.package_id is None
                             or command in product.COMMANDS and not args.examples):
        return dispatch_workspace(args, as_json)
    if command == "catalog" and args.catalog_action is not None:
        payload = result(command, "USAGE_ERROR", {"message": "Usá catalog remove sin --examples."})
        return emit(payload, as_json, 2)

    try:
        if args.version:
            as_json = False
            write_text(sys.stdout, "pgopcore " + version("pgopcore") + "\n")
            return 0
        from ._backend import public_handoff
        from ._backend.i7_api import public_profile

        payload, code = backend_result(args, public_handoff, public_profile)
    except (OSError, PackageNotFoundError, ImportError):
        payload, code = unavailable(command), 4
    except Exception:
        payload = result(command, "ERROR", {"message": "Error inesperado. Ejecutá pgop doctor o revisá la instalación."})
        code = 1
    return emit(payload, as_json, code)
