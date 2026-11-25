"""Immutable observations and a derived index for the local product profile.

Derived from Package-G Context Engine (Search003, 0416f1c5), Apache-2.0.
The journal is authoritative within the selected, OS-protected local store.
"""
import hashlib
import json
import os
from pathlib import PureWindowsPath
import re
import sys
from contextlib import ExitStack, contextmanager
from uuid import uuid4

from . import workspace as ws
from .panel import overlap
from .source_paths import canonical, excluded_name, path_parts

SCHEMA = "pgop.context-local.v1"
AUTHORITY = "LOCAL_OPERATOR_CONSENT"
DIRECTORY = ".pgop-context-v1"
MAX_RECORDS = 128
MAX_ROOTS = 4
MAX_EVENTS = 2 * MAX_RECORDS
MAX_RECORD_BYTES = 96 * 1024
MAX_STORE_BYTES = 64 * 1024 * 1024
COMMIT = re.compile(r"commit-([0-9]{4})-([0-9a-f]{32})-([0-9a-f]{64})")
OBJECT = re.compile(r"object-([0-9a-f]{32})\.json")
ID = re.compile(r"ctx-[0-9a-f]{64}")


# Canonical encoding and content addressing from the historical engine.
def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def corrupt():
    return ws.WorkspaceError("CORRUPT_RECORD", "El almacén no coincide con su historial verificado.", 3)


def store_parent(raw):
    drive, parts = path_parts(raw, current_directory=True)
    path = canonical(drive, parts)
    for index, part in enumerate(parts):
        if not excluded_name(part):
            continue
        if part.casefold() == "appdata" and len(parts) > index + 1:
            _, profile = ws.profile_paths()
            candidate = PureWindowsPath(canonical(drive, parts[:index + 2]))
            if profile is not None and candidate == profile / "AppData" / "Local":
                continue
        raise ws.WorkspaceError("STORE_PROTECTED_PATH", "Elegí una carpeta local fuera de rutas reservadas.", 3)
    return path


def anchor(parent, directory, lock):
    return {"schema": SCHEMA, "parent": parent.path, "parent_identity": list(parent.ids[-1]),
            "store_identity": list(directory.ids[-1]), "lock_identity": list(lock.identity)}


def destination_identity(path):
    with ws.io.Directory(path) as parent:
        identity = None
        try:
            with ws.child(parent, DIRECTORY, source=True) as directory:
                identity = list(directory.ids[-1])
        except ws.io.SafeIOError as exc:
            if exc.winerror != 2:
                raise
        return {"parent": list(parent.ids[-1]), "store": identity}


def changed_destination():
    return ws.WorkspaceError("STORE_CHANGED", "Cambió la carpeta del almacén. Volvé a revisar el destino.", 3)


@contextmanager
def open_store(raw, project, *, write=False, create=False, expected=None):
    path = store_parent(raw)
    # LocalAppData is allowed as a store, but never a source. Retain all native
    # handles and compare both path and physical ancestry before opening state.
    dest = PureWindowsPath(path, DIRECTORY)
    protected = (project.path, sys.prefix, sys.base_prefix, os.environ.get("PGOP_PANEL_INSTALL_DIR"),
                 os.environ.get("SystemRoot"), os.environ.get("PUBLIC"))
    if any(item and overlap(dest, item) for item in protected):
        raise ws.WorkspaceError("STORE_OVERLAP", "Elegí un almacén separado del proyecto y la instalación.")
    with ExitStack() as stack:
        parent = stack.enter_context(ws.io.Directory(path))
        if expected is not None and list(parent.ids[-1]) != expected["parent"]:
            raise changed_destination()
        if project.ids[-1] in parent.ids:
            raise ws.WorkspaceError("STORE_OVERLAP", "Elegí un almacén fuera del proyecto.")
        try:
            directory = stack.enter_context(ws.child(parent, DIRECTORY, source=True))
        except ws.io.SafeIOError as exc:
            if exc.winerror != 2:
                raise
            if not create:
                raise ws.WorkspaceError("STORE_NOT_FOUND", "No hay contextos en esa carpeta.", 3) from None
            if expected is not None and expected["store"] is not None:
                raise changed_destination() from exc
            directory = stack.enter_context(ws.child(parent, DIRECTORY, create=True, source=True))
            with ws.io.created_file(directory, "lock", b"") as lock:
                with ws.io.created_file(directory, "store.json", canonical_json(anchor(parent, directory, lock))):
                    pass
        else:
            if expected is not None and list(directory.ids[-1]) != expected["store"]:
                raise changed_destination()
        ws.io.reject_membership(project, directory)
        try:
            lock = stack.enter_context(ws.io.open_component(directory.handle, "lock", directory=False, write=write))
            meta = ws.safe_meta(lock, False)
            binding = anchor(parent, directory, meta)
            if meta.size or ws.read_bytes(directory, "store.json", 4096) != canonical_json(binding):
                raise corrupt()
        except ws.io.SafeIOError as exc:
            if exc.winerror in (5, 32, 33):
                raise
            raise corrupt() from exc
        engine = Engine(directory, binding)
        yield engine


def record_id(project, name, purpose, entries):
    stable_entries = [{key: value for key, value in item.items() if key != "checked_at"} for item in entries]
    return "ctx-" + sha256_bytes(canonical_json([project, name, purpose, stable_entries]))


class Engine:
    """A bounded content-addressed journal with a reconstructible in-memory index."""

    def __init__(self, directory, binding):
        self.directory, self.binding = directory, binding
        self.rebuild_index()

    def rebuild_index(self):
        try:
            items = ws.native.enumerate_directory(self.directory.handle, {"max_entries": 2 * MAX_EVENTS + 2})
            markers, objects = {}, set()
            total = 0
            for item in items:
                name, attributes = item["name"], item["attributes"]
                if item["tag"] or attributes & ws.EXCLUDED_ATTRIBUTES:
                    raise corrupt()
                if match := COMMIT.fullmatch(name):
                    index = int(match[1])
                    if index in markers or not attributes & 16:
                        raise corrupt()
                    markers[index] = (name, match[2], match[3])
                elif match := OBJECT.fullmatch(name):
                    if attributes & 16:
                        raise corrupt()
                    objects.add(match[1])
                    total += item["size"]
                elif name not in {"lock", "store.json"} or attributes & 16:
                    raise corrupt()
            if (len(markers) > MAX_EVENTS or total > MAX_STORE_BYTES
                    or sorted(markers) != list(range(1, len(markers) + 1))):
                raise corrupt()
            self.records, self.latest, self.revoked = {}, {}, set()
            self.entries, self.sequence, self.total = len(items), 0, total
            self.parent = None
            used = set()
            for _, (name, token, pin) in sorted(markers.items()):
                if token not in objects or token in used:
                    raise corrupt()
                with ws.child(self.directory, name, source=True):
                    raw = ws.read_bytes(self.directory, f"object-{token}.json", MAX_RECORD_BYTES)
                if sha256_bytes(raw) != pin:
                    raise corrupt()
                event = json.loads(raw)
                if (canonical_json(event) != raw or event["store"] != self.binding
                        or event["previous"] != self.parent):
                    raise corrupt()
                self.apply(event)
                self.parent = pin
                self.sequence += 1
                used.add(token)
            self.directory.validate()
        except ws.io.SafeIOError as exc:
            if exc.winerror in (5, 32, 33):
                raise
            raise corrupt() from exc
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
            raise corrupt() from exc
        return {"versions": len(self.records), "revocations": len(self.revoked)}

    def apply(self, event):
        if event["schema"] != SCHEMA:
            raise corrupt()
        if event["type"] == "revoke":
            key = event["id"]
            if key not in self.records or key in self.revoked:
                raise corrupt()
            self.revoked.add(key)
            return
        if event["type"] != "observation" or event["authority_scope"] != AUTHORITY:
            raise corrupt()
        key, project, name = event["id"], event["project"], event["name"]
        logical = (project["path"], tuple(project["identity"]), name.casefold())
        if (key != record_id(project, name, event["purpose"], event["entries"])
                or key in self.records or self.latest.get(logical) != event["supersedes"]
                or len(self.records) >= MAX_RECORDS):
            raise corrupt()
        for entry in event["entries"]:
            if sha256_bytes(entry["text"].encode("utf-8")) != entry["projection_sha256"]:
                raise corrupt()
        self.records[key], self.latest[logical] = event, key

    def commit(self, event):
        event = {**event, "schema": SCHEMA, "store": self.binding, "previous": self.parent}
        body = canonical_json(event)
        if (self.sequence >= MAX_EVENTS or self.entries + 2 > 2 * MAX_EVENTS + 2
                or len(body) > MAX_RECORD_BYTES or self.total + len(body) > MAX_STORE_BYTES):
            raise ws.WorkspaceError("CONTEXT_LIMIT", "El almacén llegó a su límite. Elegí otra carpeta.", 3)
        # A draft that did not reach its commit stays as bounded evidence.
        # The exclusive native lock spans read, validation and publication.
        token, pin = uuid4().hex, sha256_bytes(body)
        with ws.io.created_file(self.directory, f"object-{token}.json", body):
            with ws.child(self.directory, f"commit-{self.sequence + 1:04d}-{token}-{pin}", create=True):
                pass
        self.apply(event)
        self.sequence += 1
        self.entries += 2
        self.total += len(body)
        self.parent = pin

    def ingest(self, plan, code_sha256):
        project, name, purpose, entries = (plan[key] for key in ("project", "name", "purpose", "entries"))
        key = record_id(project, name, purpose, entries)
        if key in self.revoked:
            raise ws.WorkspaceError("REVOKED", "Esta versión fue revocada.", 3)
        if key in self.records:
            return {"id": key, "duplicate": True, "supersedes": self.records[key]["supersedes"]}
        roots = {tuple(record["project"]["identity"]) for record in self.records.values()}
        roots.add(tuple(project["identity"]))
        if len(roots) > MAX_ROOTS or len(self.records) >= MAX_RECORDS:
            raise ws.WorkspaceError("CONTEXT_LIMIT", "El almacén admite 128 versiones y cuatro proyectos.", 3)
        previous = self.latest.get((project["path"], tuple(project["identity"]), name.casefold()))
        self.commit({**plan, "type": "observation", "id": key, "supersedes": previous,
                     "stored_at": ws.now(), "consent_receipt": uuid4().hex,
                     "authority_scope": AUTHORITY, "independent_custody": "NOT_PROVEN",
                     "extractor_code_sha256": code_sha256})
        return {"id": key, "duplicate": False, "supersedes": previous}

    def query(self, project, fragment=""):
        return [{"id": record["id"], "name": record["name"], "stored_at": record["stored_at"],
                 "supersedes": record["supersedes"],
                 "state": "REVOKED" if record["id"] in self.revoked else "PENDING_SOURCE_CHECK"}
                for record in reversed(tuple(self.records.values()))
                if record["project"] == project and fragment.casefold() in record["name"].casefold()]

    def observation(self, project, key):
        if not ID.fullmatch(key):
            raise ws.WorkspaceError("INVALID_CONTEXT_ID", "Elegí un ID del catálogo de contextos.")
        record = self.records.get(key)
        if record is None or record["project"] != project:
            raise ws.WorkspaceError("CONTEXT_NOT_FOUND", "El contexto no pertenece a este proyecto.", 3)
        return record

    def revoke(self, project, key):
        self.observation(project, key)
        if key not in self.revoked:
            self.commit({"type": "revoke", "id": key, "revoked_at": ws.now()})
        return {"id": key, "state": "REVOKED"}

