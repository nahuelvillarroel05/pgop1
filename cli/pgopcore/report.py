"""Command options and local storage policy for public reports."""

import os
from pathlib import Path, PureWindowsPath
import re
import site
import stat
import sys

from .search_contract import add_search_options

ARTIFACTS = ("FINAL_HANDOFF.md", "REPORT.json", "MANIFEST.json")
REPORT_ID = re.compile(r"report-[0-9a-f]{40}\Z")


def add_commands(commands):
    root = commands.add_parser("report", help="Generá y recuperá informes locales.",
                               description="Exportá una búsqueda del workspace o seleccioná el perfil histórico mediante un ID y --store.",
                               allow_abbrev=False)
    actions = root.add_subparsers(dest="report_action", required=True)
    for name, label in (("create", "Generá un informe con --query o indicá un paquete histórico."),
                        ("show", "Comprobá y mostrá un informe por su ID."),
                        ("read", "Leé una página de un informe verificado.")):
        sub = actions.add_parser(name, help=label, description=label, allow_abbrev=False)
        if name == "create":
            sub.add_argument("package_id", nargs="?", metavar="ID", help="ID del paquete histórico.")
            sub.add_argument("--query", metavar="TEXTO", help="Búsqueda literal en fuentes del workspace.")
            sub.add_argument("--request-key", metavar="CLAVE", help="Requerida solo para un paquete histórico.")
            add_search_options(sub, "Tope de fuentes con citas o de citas en modo múltiple (1–10).")
        else:
            sub.add_argument("report_id", metavar="ID")
        sub.add_argument("--store", metavar="RUTA",
                         help="Directorio local absoluto para informes del perfil histórico.")
        if name == "read":
            sub.add_argument("--artifact", choices=ARTIFACTS,
                             help="El workspace solo usa REPORT.json.")
            sub.add_argument("--offset", type=int, default=0)
            sub.add_argument("--limit", type=int, default=8000)


def validate_args(args, backend):
    if args.report_action == "create":
        if args.ignore_case or args.all_matches or args.limit is not None:
            raise backend.PublicError("INVALID_ARGUMENT", "Options apply to workspace reports only")
        backend.identifier(args.package_id)
        if args.request_key is None:
            raise backend.PublicError("INVALID_ARGUMENT", "Historical reports require --request-key")
        backend.identifier(args.request_key)
    elif not REPORT_ID.fullmatch(args.report_id):
        raise backend.PublicError("INVALID_ID", "Invalid report identifier")
    if args.store is None:
        raise backend.PublicError("INVALID_ARGUMENT", "Historical reports require --store")
    if args.report_action == "read":
        backend.bounded(args.offset, 0, backend.MAX_BYTES)
        backend.bounded(args.limit, 1, 16000)


def local_store(raw, installed, backend):
    def unsafe():
        return backend.PublicError("UNSAFE_PATH", "Expected a safe absolute local report store")

    if not raw or any(ord(c) < 32 for c in raw) or raw.startswith(("//", "\\\\")):
        raise unsafe()
    path = Path(raw)
    if not path.is_absolute() or path == Path(path.anchor):
        raise unsafe()
    if os.name == "nt":
        import ctypes

        win = PureWindowsPath(raw)
        parts = re.split(r"[/\\]", raw[3:])
        if (not re.fullmatch(r"[A-Za-z]:", win.drive)
                or any(os.path.isreserved(part) or part in (".", "..") for part in parts if part)
                or ctypes.windll.kernel32.GetDriveTypeW(win.anchor) != 3):
            raise unsafe()
    elif any(part in (".", "..") for part in raw.split("/")) or "\\" in raw:
        raise unsafe()

    try:
        # Check before resolving so a reparse point cannot disappear into its target.
        checked = backend.checked(path)
        store = backend.checked(os.path.realpath(checked, strict=os.path.ALLOW_MISSING))
        protected = (installed.parent, Path(sys.prefix), Path(sys.base_prefix),
                     Path(site.getusersitepackages()))
        for item in protected:
            anchor = Path(os.path.realpath(item, strict=os.path.ALLOW_MISSING))
            if store.is_relative_to(anchor) or anchor.is_relative_to(store):
                raise backend.PublicError("OUTPUT_OVERLAP", "Store overlaps the installation")
        for ancestor in (*reversed(store.parents), store):
            try:
                info = ancestor.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise unsafe()
            try:
                (ancestor / ".git").lstat()
            except FileNotFoundError:
                continue
            raise backend.PublicError("OUTPUT_OVERLAP", "Store is inside a Git checkout")
        return store
    except PermissionError as exc:
        raise backend.PublicError("ACCESS_DENIED", "Store access denied") from exc
    except OSError as exc:
        raise backend.PublicError("IO_ERROR", "Store inspection failed") from exc


def execute(args, service):
    if args.report_action == "create":
        verification = service.verify(args.package_id)
        created = service.generate(args.package_id, verification["receipt_id"], args.request_key)
        return {**created, "verification": verification}, verification["status"]
    if args.report_action == "show":
        return service.completed(args.report_id), None
    return service.read(args.report_id, args.artifact or ARTIFACTS[0], args.offset, args.limit), None
