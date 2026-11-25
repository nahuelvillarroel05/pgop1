"""Output contract available even when the private search backend cannot load."""

SCHEMA = "pgop.search.v1"
OPTIONS_SCHEMA = "pgop.search.v2"
MAX_BYTES = 262144
MAX_LINES = 16384
MAX_QUERY_CHARACTERS = 256
LIMITS = {"source_bytes": MAX_BYTES, "source_lines": MAX_LINES,
          "results": 1, "query_characters": MAX_QUERY_CHARACTERS}
LIMITATIONS = (
    "Coincidencia literal sensible a mayúsculas. La validez semántica queda sin evaluar.",
    "Integridad comprobada durante las lecturas de esta ejecución. La vigencia posterior queda sin verificar.",
)
ERRORS = {
    "INVALID_SOURCE": (2, "Revisá la selección, el formato, la consulta y los límites."),
    "UNSUPPORTED_PATH": (2, "Usá una ruta local NTFS, con el nombre exacto y sin enlaces ni componentes ambiguos."),
    "FILE_NOT_FOUND": (4, "Comprobá que el archivo exista y que la ruta use las mayúsculas exactas."),
    "PERMISSION_DENIED": (4, "Windows denegó la lectura efectiva de la fuente."),
    "STALE": (3, "La fuente cambió o dejó de estar disponible durante la búsqueda."),
    "INTERNAL_ERROR": (1, "No se pudo comprobar la lectura o la instalación."),
}


def add_search_options(parser, limit_help):
    parser.add_argument("--limit", type=int, metavar="N", help=limit_help)
    parser.add_argument("--ignore-case", action="store_true", help="Ignorá mayúsculas ASCII (A–Z).")
    parser.add_argument("--all-matches", action="store_true",
                        help="Devolvé varias citas por fuente en el workspace. Con --file, usá --limit.")


def failure(status, code, winerror=None):
    exit_code, message = ERRORS[status]
    message = {
        "UNSUPPORTED_FORMAT": "Elegí un .txt, .md, .json, .py o .csv en UTF-8.",
        "OUTPUT_LIMIT": "Usá un límite entre 1 y 10 citas.",
        "SENSITIVE_PATH": "Elegí un archivo de proyecto fuera de carpetas protegidas.",
        "EXACTLY_ONE_EXPLICIT_FILE_REQUIRED": "Indicá una sola ruta con --file.",
    }.get(code, message)
    return {
        "schema_version": SCHEMA, "status": status, "results": [], "source": None,
        "timestamp": None, "integrity_scope": None, "truncated": False,
        "remaining_occurrences": 0, "limits": dict(LIMITS), "limitations": list(LIMITATIONS),
        "error": {"code": code, "winerror": winerror, "message": message},
    }, exit_code
