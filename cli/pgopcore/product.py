"""Installation checks and the local CLI's user-resource view."""

from importlib.metadata import distribution, PackageNotFoundError
import platform
import sys


COMMANDS = ("doctor", "status", "catalog")


def installation():
    try:
        package = distribution("pgopcore")
        installed_version = package.version
        entry_point = any(
            entry.group == "console_scripts" and entry.name == "pgop"
            and entry.value == "pgopcore.cli:main"
            for entry in package.entry_points
        )
    except PackageNotFoundError:
        return None, "DISTRIBUTION_NOT_FOUND"
    except (OSError, ValueError):
        return None, "DISTRIBUTION_UNREADABLE"
    if not installed_version:
        return None, "DISTRIBUTION_UNREADABLE"
    return installed_version, None if entry_point else "ENTRY_POINT_MISSING"


def literal_capability():
    try:
        from . import search
    except (ImportError, OSError, SyntaxError):
        return "FAILED", "INSTALLED_CODE_UNAVAILABLE"

    try:
        search.native_io.api()
        if search.text.code_digest() != search.CODE_SHA256:
            return "FAILED", "CODE_CHANGED"
    except search.native_io.SafeIOError as exc:
        if exc.code.startswith(("UNSUPPORTED_WINDOWS", "UNSUPPORTED_SAFE_READ")):
            return "UNSUPPORTED_PLATFORM", exc.code
        return "FAILED", exc.code
    except (OSError, ValueError, AttributeError):
        return "FAILED", "INSTALLED_CODE_UNAVAILABLE"
    return "READY", None


def response(command, outcome, data, native_code=None):
    return {
        "schema": "pgop.product.v1",
        "command": command,
        "outcome": outcome,
        "native_code": native_code,
        "data": data,
    }


def usage_error(command, code=None):
    return response(command, "USAGE_ERROR", {
        "message": f"Uso inválido. Consultá pgop {command} --help.",
    }, code), 2


def execute(args):
    command = args.command
    if command == "catalog":
        if not (0 <= args.offset <= 100000 and 1 <= args.limit <= 20):
            return usage_error(command, "INVALID_ARGUMENT")
        return response(command, "NOT_CONFIGURED", {
            "registry": "NOT_CONFIGURED", "items": [], "total": 0, "next_offset": None,
            "offset": args.offset, "limit": args.limit,
        }), 0

    installed_version, error = installation()
    data = {
        "distribution_version": installed_version,
        "installation": "AVAILABLE" if error is None else "FAILED",
        "workspace": "NOT_CONFIGURED",
        "user_catalog": "NOT_CONFIGURED",
        "registered_sources": 0,
        "historical_demo": "EXPLICIT_ONLY_NOT_CHECKED",
        "source_verification": "NOT_PERFORMED",
    }
    if command == "doctor":
        python_supported = sys.version_info >= (3, 14)
        capability = "NOT_CHECKED"
        if not python_supported:
            error = error or "PYTHON_UNSUPPORTED"
        if error is None:
            capability, error = literal_capability()
        data.update({
            "python_version": platform.python_version(),
            "python_supported": python_supported,
            "literal_search": capability,
        })
        if capability == "UNSUPPORTED_PLATFORM":
            return response(command, "READY_WITH_LIMITS", data, error), 0
    if error:
        return response(command, "FAILED", data, error), 4
    outcome = "READY" if command == "doctor" else "NOT_CONFIGURED"
    return response(command, outcome, data), 0


def human_lines(payload):
    command, outcome, data = payload["command"], payload["outcome"], payload["data"]
    if command == "catalog":
        if data["registry"] == "NOT_CONFIGURED":
            return ["No hay fuentes registradas en esta carpeta.",
                    "Desde la raíz de un proyecto separado de la instalación, ejecutá pgop init y luego pgop scan."]
        lines = [f'Espacio de trabajo: {data["root"]} · revisión {data["revision"]}.',
                 f'Fuentes activas: {data["registered_sources"]} · retiradas: {data["removed_sources"]}.']
        lines.extend(f'  {item["id"]} · {item["path"]} · {item["status"]}' for item in data["items"])
        if data["next_offset"] is not None:
            lines.append(f'Página siguiente: pgop catalog --offset {data["next_offset"]}')
        if not data["scanned_at"]:
            lines.append("Para registrar archivos propios, ejecutá pgop scan.")
        return lines

    lines = [f'Estado: {outcome}',
             f'Instalación: {data["installation"]} · pgopcore {data["distribution_version"] or "sin versión"}']
    if command == "doctor":
        lines.extend([f'Python {data["python_version"]} · mínimo 3.14',
                      f'Búsqueda literal: {data["literal_search"]}',
                      "Alcance de búsqueda: Windows 10 x64 (build 19045), NTFS y rutas ASCII."])
    if data["workspace"] == "CONFIGURED":
        lines.append(f'Espacio de trabajo: {data["root"]} · revisión {data["revision"]}.')
        lines.append(f'Fuentes registradas: {data["registered_sources"]} · retiradas: {data["removed_sources"]}.')
    else:
        lines.append("Desde la raíz de tu proyecto, ejecutá pgop init y luego pgop scan para trabajar con un registro.")
    lines.extend(["Demostración histórica bajo petición: pgop catalog --examples.",
                  "Verificación de fuentes: sin ejecutar en este comando."])
    if payload["native_code"]:
        lines.append(f'Diagnóstico: {payload["native_code"]}.')
    if outcome == "FAILED":
        lines.append("Revisá el requisito de Python y la instalación en el entorno virtual.")
    return lines
