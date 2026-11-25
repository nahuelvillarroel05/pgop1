"""Resolve user spelling without weakening the handle-relative NTFS backend."""

import os
from pathlib import PureWindowsPath
import re

from .runtime.candidate import selection_contract_v1 as contract
from .runtime.candidate import windows_safe_io_v2 as io


EXCLUDED_NAMES = frozenset({
    "node_modules", "dist", "build", "out", "target", "vendor", "deps", "site-packages",
    "packages", "authorized_keys", "id_rsa", "id_ed25519", "appdata", "windows",
    "programdata", "program files", "program files (x86)", ".ssh", ".aws", ".codex",
    ".agents", ".gnupg", ".azure", ".kube", ".config", ".pgopcore", ".claude",
    ".cursor", ".npmrc", ".netrc", ".pypirc", ".env",
})
EXCLUDED_PARTS = (*contract.SENSITIVE, "passwd", "password", "private-key", "api-key", "apikey")


def path_parts(raw, *, current_directory=False):
    if not isinstance(raw, str) or not raw or len(raw) > 1024:
        raise io.SafeIOError("UNSAFE_PATH")
    if re.match(r"^[A-Za-z]:[/\\]", raw):
        return io.absolute(raw)

    # A single leading dot is the only accepted navigation component.
    parts = re.split(r"[/\\]", raw)
    if raw == "." and current_directory:
        parts = []
    elif parts[0] == ".":
        parts = parts[1:]
    parts = [io.component(part) for part in parts]
    drive, cwd = io.absolute(os.getcwd())
    return drive, cwd + parts


def canonical(drive, parts):
    path = str(PureWindowsPath(drive.upper(), *parts))
    if len(path) > 1024:
        raise io.SafeIOError("UNSAFE_PATH")
    return path


def protected_name(name):
    lower = name.lower()
    return lower in EXCLUDED_NAMES or lower.startswith(".env.") or any(
        fragment in lower for fragment in EXCLUDED_PARTS)


def excluded_name(name):
    return name.startswith(".") or protected_name(name)


