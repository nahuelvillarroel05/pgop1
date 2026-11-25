"""Local NTFS workspace authority, registry and bounded source discovery."""

from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import os
from pathlib import PureWindowsPath
import re
import time
from uuid import uuid4

from . import search
from .source_paths import canonical, excluded_name, path_parts, protected_name
from .text_bytes import content_start
from .runtime.candidate import acquisition_text_v1 as text
from .runtime.candidate import selection_contract_v1 as contract
from .runtime.candidate import windows_directory_enumeration_v1 as native
from .runtime.candidate import windows_safe_io_v2 as io

SCHEMA = "pgop.workspace.v1"
POLICY = "local-ntfs-text-v1"
TEXT_POLICY = "local-ntfs-text-v2"
BOM_POLICY = "local-ntfs-text-utf8-bom-v3"
STATE = ".pgopcore"
MAX_ANCESTORS = 5
LIMITS = {
    "directories_deep": 5, "path_characters": 1024, "entries": 1000, "pages": 256,
    "registered_rows": 100, "corpus_bytes": 8 * 1024 * 1024,
    "source_bytes": search.MAX_BYTES, "source_lines": search.MAX_LINES,
    "query_characters": search.MAX_QUERY_CHARACTERS, "results": 10,
    "cooperative_seconds": 30, "journal_entries": 512,
}
STATE_BYTES = 256 * 1024
EXCLUDED_ATTRIBUTES = native.UNSAFE_ATTRIBUTES | 0x2 | 0x4
safe_meta = native.visible_metadata
visible_directories = native.validate_visible
MARKER = re.compile(r"commit-([0-9]{4})-([0-9a-f]{32})-([0-9a-f]{64})")
DRAFT = re.compile(r"draft-([0-9a-f]{32})\.json")
SOURCE_ID = re.compile(r"src-[0-9a-f]{32}")


class WorkspaceError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def now():
    return datetime.now(timezone.utc).isoformat()


def payload(command, outcome, data, native_code=None):
    return {"schema": SCHEMA, "command": command, "outcome": outcome,
            "native_code": native_code, "data": data}


def error_result(command, exc):
    if isinstance(exc, WorkspaceError):
        code, message, exit_code = exc.code, str(exc), exc.exit_code
    elif isinstance(exc, io.SafeIOError):
        code = exc.code
        if exc.winerror in (32, 33):
            code, message, exit_code = "WORKSPACE_BUSY", "Hay otra operación activa. Volvé a intentar.", 4
        elif exc.winerror == 5:
            code, message, exit_code = "ACCESS_DENIED", "Windows denegó el acceso al espacio de trabajo.", 4
        elif exc.code.startswith(("UNSAFE_PATH", "UNSUPPORTED_")) or exc.winerror in (1920, 1921, 267):
            code = exc.code if exc.code != "SOURCE_UNAVAILABLE_OR_UNSAFE" else "UNSAFE_PATH"
            message, exit_code = "Usá una ruta NTFS local, con el nombre exacto y sin enlaces ni componentes ambiguos.", 2
        else:
            message, exit_code = "No se pudo abrir o comprobar el espacio de trabajo. Ejecutá pgop doctor.", 4
    elif isinstance(exc, PermissionError):
        code, message, exit_code = "ACCESS_DENIED", "Elegí una carpeta con los permisos necesarios para esta operación.", 4
    elif isinstance(exc, FileExistsError):
        code, message, exit_code = "STATE_CONFLICT", "Ya existe estado en esa ubicación. Revisá pgop status.", 4
    else:
        code, message, exit_code = "WORKSPACE_IO_ERROR", "No se pudo leer o escribir el estado local.", 4
    outcome = {2: "USAGE_ERROR", 3: "STALE", 4: "UNAVAILABLE"}.get(exit_code, "ERROR")
    return payload(command, outcome, {"message": message}, code), exit_code


def state_error():
    return WorkspaceError("INVALID_WORKSPACE_STATE",
                          "El estado local está incompleto o no coincide con esta raíz. Conservá .pgopcore para revisarlo.", 3)


def configured_root(raw="."):
    drive, parts = path_parts(raw, current_directory=True)
    path = canonical(drive, parts)
    if not allowed_root(path, parts, profile_paths()):
        raise root_error()
    return path


def allowed_root(path, parts, profile):
    if not parts or excluded_name(parts[-1]) or any(protected_name(p) for p in parts[:-1]):
        return False
    root = PureWindowsPath(path)
    profiles, home = profile
    inherited = os.environ.get("USERPROFILE")
    return not (profiles.is_relative_to(root) or root.parent == profiles
                or (home is not None and home.is_relative_to(root))
                or (inherited and PureWindowsPath(inherited).is_relative_to(root)))


def root_error():
    return WorkspaceError("ROOT_NOT_ALLOWED", "Elegí una carpeta de proyecto local específica.")


def profile_paths():
    import ctypes as c
    from ctypes import wintypes as w

    k, _ = io.api()
    userenv = c.WinDLL("userenv", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = (w.HANDLE, w.DWORD, c.POINTER(w.HANDLE))
    advapi.OpenProcessToken.restype = w.BOOL
    userenv.GetProfilesDirectoryW.argtypes = (w.LPWSTR, c.POINTER(w.DWORD))
    userenv.GetProfilesDirectoryW.restype = w.BOOL
    userenv.GetUserProfileDirectoryW.argtypes = (w.HANDLE, w.LPWSTR, c.POINTER(w.DWORD))
    userenv.GetUserProfileDirectoryW.restype = w.BOOL

    def unavailable():
        return WorkspaceError("PROFILE_UNAVAILABLE", "Windows no pudo identificar la carpeta de perfiles.", 4)

    path = c.create_unicode_buffer(1024)
    size = w.DWORD(len(path))
    if not userenv.GetProfilesDirectoryW(path, c.byref(size)):
        raise unavailable()
    profiles = PureWindowsPath(path.value)
    token = w.HANDLE()
    if not advapi.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)):
        raise unavailable()
    with io.Handle(token.value):
        size.value = len(path)
        if userenv.GetUserProfileDirectoryW(token, path, c.byref(size)):
            return profiles, PureWindowsPath(path.value)
        if c.get_last_error() == 2:
            # The restricted token has no registered profile. The system profiles root still applies.
            return profiles, None
        raise unavailable()


def supported_path(root, relative, *, legacy=False):
    parts = io.relative(relative)
    if any(excluded_name(part) for part in parts):
        raise io.SafeIOError("SENSITIVE_PATH")
    if len(root) + len(relative) + 1 > LIMITS["path_characters"]:
        raise io.SafeIOError("PATH_BUDGET")
    return text.path(relative, legacy=legacy)


@contextmanager
def child(parent, name, *, create=False, source=False, probe_case=False):
    # The child owns only newly opened handles. Ancestors stay held by the caller.
    directory = io.Directory(str(PureWindowsPath(parent.path, name)))
    directory.handles = parent.handles.copy()
    directory.ids = parent.ids.copy()
    with directory.stack:
        directory.add(io.open_component(parent.handle, name, directory=True, create=create,
                                        probe_case=probe_case))
        if source:
            safe_meta(directory.handle, True)
        yield directory


def read_bytes(directory, name, cap):
    with native.open_metadata(directory.handle, name, directory=False) as retained:
        meta = io.metadata(retained, False)
        if meta.size > cap:
            raise io.SafeIOError("SIZE_LIMIT")
        raw = native.capture(directory.handle, name, retained, meta, cap)
        directory.validate()
        return raw


@contextmanager
def project(raw="."):
    path = configured_root(raw)
    with ExitStack() as stack:
        installed = stack.enter_context(io.Directory(text.PRODUCT))
        try:
            root = stack.enter_context(io.Directory(path))
        except io.SafeIOError as exc:
            if exc.winerror in (2, 3):
                raise WorkspaceError("ROOT_NOT_FOUND_OR_CASE", "Comprobá que la carpeta exista y que coincidan las mayúsculas.") from exc
            raise
        io.reject_membership(root, installed)
        io.reject_membership(installed, root)
        visible_directories(root)
        yield root, installed


def ancestor_roots(root, installed, first):
    drive, parts = io.absolute(root.path)
    profile = profile_paths()
    for distance in range(first, len(parts) + 1):
        length = len(parts) - distance
        path = canonical(drive, parts[:length])
        if not allowed_root(path, parts[:length], profile):
            return
        # Borrow the held prefix. Its handles stay owned by project().
        parent = io.Directory(path)
        parent.handles = root.handles[:length + 1]
        parent.ids = root.ids[:length + 1]
        if parent.ids[-1] in installed.ids:
            return
        if distance > MAX_ANCESTORS:
            raise WorkspaceError("WORKSPACE_SEARCH_LIMIT",
                                 "Buscá desde una carpeta más cerca de la raíz del proyecto.")
        yield parent


def reject_initialized_ancestor(root, installed):
    for parent in ancestor_roots(root, installed, 1):
        with open_registry(parent, optional=True) as registry:
            if registry is not None:
                raise WorkspaceError("NESTED_WORKSPACE",
                                     "Ya hay un workspace ancestro. Usalo desde esta carpeta o elegí otro proyecto.")


@contextmanager
def discover(*, write=False, optional=False, load_journal=True):
    with project() as (cwd, installed):
        for root in ancestor_roots(cwd, installed, 0):
            with open_registry(root, write=write, optional=True, load_journal=load_journal) as registry:
                if registry is not None:
                    yield registry
                    return
        if optional:
            yield None
            return
        raise init_required()


def init_required():
    return WorkspaceError("INIT_REQUIRED", "Desde la raíz del proyecto ejecutá pgop init y después pgop scan.")


def empty_registry():
    return {"scanned_at": None, "scan": None, "rows": []}


def create(root):
    # Create-new at every boundary. A failed init leaves identifiable partial state.
    try:
        with child(root, STATE, create=True) as state:
            with child(state, "registry", create=True) as journal, child(state, "reports", create=True) as reports:
                with io.created_file(state, "lock", b"") as lock:
                    binding = anchor(root, state, journal, reports, lock)
                    with io.created_file(state, "workspace.json", contract.canonical(binding)):
                        pass
        return True
    except FileExistsError:
        return False


def anchor(root, state, journal, reports, lock):
    return {"schema": SCHEMA, "policy": POLICY, "root": root.path,
            "root_identity": list(root.ids[-1]), "state_identity": list(state.ids[-1]),
            "registry_identity": list(journal.ids[-1]), "reports_identity": list(reports.ids[-1]),
            "lock_identity": list(lock.identity)}


def source_id(root, path):
    return "src-" + contract.digest(contract.canonical([list(root.ids[-1]), path.lower()]))[:32]


def validate_scan_summary(root, scan):
    required = {"partial", "reasons", "excluded"}
    contract.need(type(scan) is dict and required <= scan.keys() <= required | {"excluded_paths"}, "REGISTRY_SCAN")
    excluded_paths = scan.get("excluded_paths", [])
    contract.need(type(excluded_paths) is list and len(excluded_paths) <= LIMITS["registered_rows"], "REGISTRY_EXCLUSIONS")
    for item in excluded_paths:
        contract.need(type(item) is dict and set(item) == {"path", "reason"}, "REGISTRY_EXCLUSION")
        path = item["path"]
        contract.need(type(path) is str, "REGISTRY_EXCLUSION")
        contract.need(item["reason"] in ("UNSUPPORTED_FORMAT", "HARDLINK")
                      and len(root.path) + len(path) + 1 <= LIMITS["path_characters"]
                      and all(not excluded_name(part) for part in io.relative(path)), "REGISTRY_EXCLUSION")
    for name in ("reasons", "excluded"):
        counts = scan[name]
        contract.need(type(counts) is dict and len(counts) <= 64 and all(
            re.fullmatch("[A-Z0-9_]{1,80}", k) and type(n) is int and 0 < n <= 1000
            for k, n in counts.items()), "REGISTRY_SCAN")
    contract.need(type(scan["partial"]) is bool and scan["partial"] == bool(scan["reasons"]), "REGISTRY_SCAN")


def validate_registry(root, value):
    contract.need(type(value) is dict and set(value) == {"scanned_at", "scan", "rows"}, "REGISTRY_SCHEMA")
    contract.need(type(value["scanned_at"]) is str and len(value["scanned_at"]) <= 40, "REGISTRY_DATE")
    validate_scan_summary(root, value["scan"])
    rows = value["rows"]
    contract.need(type(rows) is list and len(rows) <= LIMITS["registered_rows"], "REGISTRY_LIMIT")
    paths, ids, total = set(), set(), 0
    for row in rows:
        contract.need(type(row) is dict and set(row) == {
            "path", "id", "sha256", "bytes", "identity", "times", "captured_at", "status", "policy",
        }, "REGISTRY_ROW")
        path = row["path"]
        fmt = supported_path(root.path, path)
        contract.need(row["id"] == source_id(root, path) and path.lower() not in paths, "REGISTRY_PATH")
        contract.need(type(row["bytes"]) is int and 0 <= row["bytes"] <= LIMITS["source_bytes"]
                      and contract.hash_value(row["sha256"]), "REGISTRY_BYTES")
        text.identity(row["identity"])
        physical = tuple(row["identity"])
        contract.need(physical[0] == root.ids[-1][0], "REGISTRY_VOLUME")
        contract.need(type(row["times"]) is list and len(row["times"]) == 3
                      and all(type(t) is int for t in row["times"]), "REGISTRY_TIMES")
        contract.need(type(row["captured_at"]) is str and len(row["captured_at"]) <= 40
                      and row["status"] in ("REGISTERED", "REMOVED")
                      and row["policy"] in (row_policy(fmt), BOM_POLICY),
                      "REGISTRY_ADMISSION")
        paths.add(path.lower())
        if row["status"] == "REGISTERED":
            contract.need(physical not in ids, "REGISTRY_IDENTITY")
            ids.add(physical)
            total += row["bytes"]
    contract.need(total <= LIMITS["corpus_bytes"], "REGISTRY_BYTE_LIMIT")
    contract.need([r["path"] for r in rows] == sorted(r["path"] for r in rows), "REGISTRY_ORDER")


class Registry:
    def __init__(self, root, journal, reports):
        self.root, self.journal, self.reports = root, journal, reports
        self.revision, self.entries = 0, 0
        self.value = empty_registry()

    def load(self):
        try:
            entries = native.enumerate_directory(self.journal.handle, {"max_entries": LIMITS["journal_entries"]})
            self.entries = len(entries)
            markers, drafts = {}, set()
            for entry in entries:
                name = entry["name"]
                match = MARKER.fullmatch(name)
                if match:
                    number, suffix, sha = match.groups()
                    number = int(number)
                    if number in markers or not entry["attributes"] & 16:
                        raise state_error()
                    if entry["tag"] or entry["attributes"] & EXCLUDED_ATTRIBUTES:
                        raise state_error()
                    markers[number] = (name, suffix, sha)
                elif draft := DRAFT.fullmatch(name):
                    if not entry["tag"] and not entry["attributes"] & (EXCLUDED_ATTRIBUTES | 16):
                        drafts.add(draft[1])
                else:
                    raise state_error()
            self.revision = len(markers)
            published = [suffix for _, suffix, _ in markers.values()]
            if (sorted(markers) != list(range(1, self.revision + 1))
                    or len(set(published)) != self.revision or not set(published) <= drafts):
                raise state_error()
            if self.revision:
                name, suffix, sha = markers[self.revision]
                with child(self.journal, name):
                    raw = read_bytes(self.journal, f"draft-{suffix}.json", STATE_BYTES)
                if contract.digest(raw) != sha:
                    raise state_error()
                self.value = contract.strict(raw)
                validate_registry(self.root, self.value)
        except (ValueError, FileNotFoundError, RecursionError, TypeError, OverflowError) as exc:
            if isinstance(exc, io.SafeIOError) and exc.winerror in (5, 32, 33):
                raise
            raise state_error() from exc

    def save(self, value):
        if self.entries + 2 > LIMITS["journal_entries"]:
            raise WorkspaceError("JOURNAL_LIMIT", "El diario alcanzó su límite. Conservá este espacio y usá otro para nuevas altas.", 3)
        validate_registry(self.root, value)
        suffix = uuid4().hex
        body = contract.canonical(value)
        if len(body) > STATE_BYTES:
            raise WorkspaceError("JOURNAL_SIZE", "El catálogo supera el tamaño permitido.", 3)
        with io.created_file(self.journal, f"draft-{suffix}.json", body):
            name = f"commit-{self.revision + 1:04d}-{suffix}-{contract.digest(body)}"
            self.root.validate()
            with child(self.journal, name, create=True):
                pass
        self.value = value
        self.revision += 1
        self.entries += 2


@contextmanager
def open_registry(root, *, write=False, optional=False, load_journal=True):
    with ExitStack() as stack:
        try:
            state = stack.enter_context(child(root, STATE, probe_case=True))
        except io.SafeIOError as exc:
            if exc.winerror in (5, 32, 33):
                raise
            if exc.winerror != 2:
                raise state_error() from exc
            if optional:
                yield None
                return
            raise init_required() from exc
        try:
            safe_meta(state.handle, True)
            journal = stack.enter_context(child(state, "registry", source=True))
            reports = stack.enter_context(child(state, "reports", source=True))
            lock = stack.enter_context(io.open_component(state.handle, "lock", directory=False, write=write))
            lock_meta = io.metadata(lock, False)
            pinned = contract.strict(read_bytes(state, "workspace.json", 4096))
            if lock_meta.size or pinned != anchor(root, state, journal, reports, lock_meta):
                raise state_error()
        except (ValueError, FileNotFoundError, RecursionError) as exc:
            if isinstance(exc, io.SafeIOError) and exc.winerror in (5, 32, 33):
                raise
            raise state_error() from exc
        registry = Registry(root, journal, reports)
        if load_journal:
            registry.load()
        yield registry


def reviewable_registry(registry):
    rows = registry.value["rows"]
    return {"root": registry.root.path, "revision": registry.revision,
            "scanned_at": registry.value["scanned_at"],
            "registered_sources": sum(row["status"] == "REGISTERED" for row in rows),
            "removed_sources": sum(row["status"] == "REMOVED" for row in rows),
            "scan": registry.value["scan"], "source_verification": "NOT_PERFORMED"}


def classify(exc):
    code = getattr(exc, "code", str(exc))
    if not re.fullmatch("[A-Z][A-Z0-9_]{0,79}", code):
        code = "ACCESS_DENIED" if isinstance(exc, PermissionError) else "SOURCE_UNAVAILABLE"
    status = search.failed_read(code, getattr(exc, "winerror", None), admitted=True)[0]
    return {"status": status["status"], "code": status["error"]["code"], "winerror": status["error"]["winerror"]}


def validated_text(raw, fmt):
    contract.need(type(raw) is bytes and len(raw) <= LIMITS["source_bytes"], "SOURCE_LIMIT")
    contract.need(search.NON_TEXT_BYTES.search(raw) is None, "BINARY_CONTROLS")
    breaks = search.line_breaks(raw)
    lines = len(breaks) + bool(raw and (not breaks or breaks[-1] != len(raw)))
    contract.need(lines <= LIMITS["source_lines"], "LINE_LIMIT")
    start = content_start(raw)
    report = text.extract(raw[start:], fmt)
    if start:
        report = {**report, "extractor_version": "strict-utf8-bom-v3", "content_byte_start": start}
    return report, breaks


def row_policy(fmt, raw=b""):
    if content_start(raw):
        return BOM_POLICY
    return POLICY if fmt in text.LEGACY_FORMATS else TEXT_POLICY


def capture_candidate(directory, entry, retained, meta, path, root):
    visible_directories(directory)
    raw = native.capture(directory.handle, entry["name"], retained, meta, LIMITS["source_bytes"])
    safe_meta(retained, False)
    visible_directories(directory)
    fmt = supported_path(root.path, path)
    validated_text(raw, fmt)
    return {"path": path, "id": source_id(root, path), "sha256": contract.digest(raw),
            "bytes": len(raw), "identity": list(meta.identity), "times": list(meta.times),
            "captured_at": now(), "policy": row_policy(fmt, raw), "status": "REGISTERED"}


class Scan:
    def __init__(self, registry, preview, refresh, *, folder=(), suffix="", name="", approved=None, cancel=None):
        self.registry, self.preview, self.refresh = registry, preview, refresh
        self.folder, self.suffix, self.name = folder, suffix, name
        self.approved, self.candidate_metadata = approved, {}
        self.cancel = cancel
        self.rows = {row["path"].lower(): row for row in registry.value["rows"]}
        active = [row for row in self.rows.values() if row["status"] == "REGISTERED"]
        self.active_bytes = sum(row["bytes"] for row in active)
        self.identities = {tuple(row["identity"]): row["path"].lower() for row in active}
        self.deadline = time.monotonic() + LIMITS["cooperative_seconds"]
        self.excluded, self.reasons = Counter(), Counter()
        self.candidates, self.failures, self.excluded_paths = [], [], []
        self.pages = self.entries = self.decoded_entries = self.attempted_bytes = self.captured_bytes = 0

    def excluded_source(self, path, reason):
        self.excluded[reason] += 1
        if len(self.excluded_paths) < LIMITS["registered_rows"]:
            self.excluded_paths.append({"path": path, "reason": reason})

    def check_time(self):
        if self.cancel is not None and self.cancel.is_set():
            raise io.SafeIOError("DISCOVERY_CANCELED")
        if time.monotonic() >= self.deadline:
            raise io.SafeIOError("DISCOVERY_COOPERATIVE_TIMEOUT")

    def walk(self, directory, prefix=""):
        remaining_entries = LIMITS["entries"] - self.entries
        remaining_pages = LIMITS["pages"] - self.pages
        if remaining_entries <= 0 or remaining_pages <= 0:
            self.reasons["ENTRY_OR_PAGE_LIMIT"] += 1
            return
        trace = []
        try:
            entries = native.enumerate_directory(directory.handle, {
                "max_entries": remaining_entries, "max_pages": remaining_pages,
            }, trace, deadline=self.check_time, allow_unsupported_names=True)
        except io.SafeIOError as exc:
            self.reasons[exc.code] += 1
            self.failures.append({"path": prefix or ".", **classify(exc)})
            return
        finally:
            self.pages += len(trace)
            decoded = sum(event["decoded_entries"] or 0 for event in trace)
            self.decoded_entries += decoded
            self.entries += min(remaining_entries, decoded)
        for entry in entries:
            name = entry["name"]
            path = f"{prefix}/{name}" if prefix else name
            is_dir = bool(entry["attributes"] & 16)
            # Do not echo an unsupported or policy-sensitive name in preview or diagnostics.
            try:
                self.check_time()
                io.component(name)
            except io.SafeIOError as exc:
                self.reasons[exc.code] += 1
                if exc.code in {"DISCOVERY_COOPERATIVE_TIMEOUT", "DISCOVERY_CANCELED"}:
                    return
                continue
            if excluded_name(name):
                self.excluded["NAME_POLICY"] += 1
            elif entry["tag"] or entry["attributes"] & EXCLUDED_ATTRIBUTES:
                self.excluded["ATTRIBUTES_OR_REPARSE"] += 1
            elif len(self.registry.root.path) + len(path) + 1 > LIMITS["path_characters"]:
                self.reasons["PATH_BUDGET"] += 1
            elif is_dir and path.count("/") + 1 > LIMITS["directories_deep"]:
                self.reasons["DEPTH_LIMIT"] += 1
            elif is_dir:
                try:
                    with child(directory, name, source=True) as sub:
                        native.matches(entry, safe_meta(sub.handle, True))
                        self.walk(sub, path)
                except io.SafeIOError as exc:
                    self.reasons[exc.code] += 1
                    self.failures.append({"path": path, **classify(exc)})
            elif ((self.suffix and PureWindowsPath(name).suffix != self.suffix)
                  or (self.name and self.name.lower() not in name.lower())):
                continue
            elif PureWindowsPath(name).suffix not in text.FORMATS:
                self.excluded_source(path, "UNSUPPORTED_FORMAT")
            else:
                self.file(directory, entry, path)

    def file(self, directory, entry, path):
        key = path.lower()
        existing = self.rows.get(key)
        if existing and existing["status"] == "REMOVED":
            self.excluded["REMOVED"] += 1
            return
        if existing and not self.refresh:
            self.excluded["ALREADY_REGISTERED"] += 1
            return
        if self.approved is not None and path not in self.approved:
            self.reasons["NEW_SINCE_PREVIEW"] += 1
            return
        try:
            with native.open_metadata(directory.handle, entry["name"], directory=False) as retained:
                meta = safe_meta(retained, False)
                native.matches(entry, meta)
                if self.approved is not None and meta != self.approved[path]:
                    raise io.SafeIOError("SOURCE_CHANGED")
                if meta.size > LIMITS["source_bytes"]:
                    self.reasons["SOURCE_LIMIT"] += 1
                    return
                if not existing and len(self.rows) == LIMITS["registered_rows"]:
                    self.reasons["REGISTRY_LIMIT"] += 1
                    return
                previous_size = existing["bytes"] if existing else 0
                projected = self.active_bytes - previous_size + meta.size
                if max(projected, self.attempted_bytes + meta.size) > LIMITS["corpus_bytes"]:
                    self.reasons["CORPUS_BYTE_LIMIT"] += 1
                    return
                if self.identities.get(meta.identity, key) != key:
                    self.reasons["IDENTITY_COLLISION"] += 1
                    return
                self.attempted_bytes += meta.size
                if self.preview:
                    row = {"path": path, "status": "PREVIEW", "bytes": meta.size}
                else:
                    row = capture_candidate(directory, entry, retained, meta, path, self.registry.root)
                    self.captured_bytes += meta.size
                self.candidate_metadata[path] = meta
                self.candidates.append({"path": path, "bytes": meta.size, "status": row["status"]})
                if existing:
                    self.identities.pop(tuple(existing["identity"]), None)
                self.identities[meta.identity] = key
                self.rows[key], self.active_bytes = row, projected
        except (io.SafeIOError, OSError, ValueError) as exc:
            detail = classify(exc)
            if detail["code"] == "UNSAFE_PATH_HARDLINK":
                self.excluded_source(path, "HARDLINK")
            else:
                self.reasons[detail["code"]] += 1
                self.failures.append({"path": path, **detail})

    def run(self):
        if self.folder:
            with ExitStack() as stack:
                directory = self.registry.root
                for part in self.folder:
                    directory = stack.enter_context(child(directory, part, source=True))
                self.walk(directory, "/".join(self.folder))
        else:
            self.walk(self.registry.root)
        if self.folder or self.suffix or self.name:
            self.reasons["USER_SELECTED_SCOPE"] += 1
        if self.approved is not None:
            unseen = self.approved.keys() - self.candidate_metadata.keys()
            if unseen:
                self.reasons["PREVIEW_FILES_UNAVAILABLE"] += len(unseen)
        self.registry.root.validate()
        summary = {"partial": bool(self.reasons), "reasons": dict(self.reasons), "excluded": dict(self.excluded),
                   "excluded_paths": sorted(self.excluded_paths, key=lambda row: row["path"])}
        if not self.preview:
            self.registry.save({"scanned_at": now(), "scan": summary,
                                "rows": sorted(self.rows.values(), key=lambda row: row["path"])})
        return {"preview": self.preview, "refresh": self.refresh, "policy": POLICY, "limits": LIMITS,
                "examined_entries": self.entries, "native_decoded_entries": self.decoded_entries,
                "native_pages": self.pages,
                "candidates": sorted(self.candidates, key=lambda row: row["path"]),
                "failures": self.failures, "candidate_bytes": self.attempted_bytes,
                "captured_valid_bytes": self.captured_bytes, **summary, **reviewable_registry(self.registry)}
