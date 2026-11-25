"""Install or remove the PGOPCore wheel for the current Windows user."""

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import winreg


VERSION = "0.1.0a4"
WHEEL = f"pgopcore-{VERSION}-py3-none-any.whl"
STATE = "installation.json"
STATE_SCHEMA = "pgopcore.windows-install.v2"
USER_ENV = "Environment"
MACHINE_ENV = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
MAX_WHEEL_BYTES = 2_000_000
MAX_STATE_BYTES = 2_000_000


def local_path(path):
    if (not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive)
            or ctypes.windll.kernel32.GetDriveTypeW(path.anchor) != 3
            or any(os.path.isreserved(part) or part == ".." for part in path.parts[1:])):
        raise ValueError("Expected a fixed local Windows path without reserved components")
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Reparse points and links are not supported")
    return path


def dir_id(path):
    info = local_path(path).lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Expected an installation directory")
    return [info.st_dev, info.st_ino]


@contextmanager
def exclusive_installer():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.ReleaseMutex.argtypes = kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateMutexW(None, False, r"Local\PGOPCore-Windows-Installer-v1")
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.WaitForSingleObject(handle, 0) not in (0, 0x80):
            raise ValueError("Another PGOPCore installer is active")
        try:
            yield
        finally:
            kernel.ReleaseMutex(handle)
    finally:
        kernel.CloseHandle(handle)


def path_value(key):
    try:
        raw, kind = winreg.QueryValueEx(key, "Path")
    except FileNotFoundError:
        return "", None
    if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        raise ValueError("Unexpected Windows PATH registry value type")
    return raw, kind


def norm(entry):
    return os.path.normcase(os.path.normpath(os.path.expandvars(entry.strip().strip('"'))))


def check_collision(launcher_root, user_raw):
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_ENV) as machine:
        machine_raw, _ = path_value(machine)
    target = norm(str(launcher_root))
    if any(norm(entry) == target for entry in user_raw.split(";")):
        raise ValueError("The destination already exists in user PATH")
    extensions = {".exe", ".com", ".cmd", ".bat", ".ps1", ""}
    extensions.update(ext for ext in os.environ.get("PATHEXT", "").lower().split(";")
                      if re.fullmatch(r"\.[a-z0-9]{1,12}", ext))
    path_entries = (str(Path.cwd()), *machine_raw.split(";"), *user_raw.split(";"),
                    *os.environ.get("PATH", "").split(";"))
    for entry in {norm(entry) for entry in path_entries if entry}:
        folder = Path(entry)
        if not folder.anchor:
            folder = Path.cwd() / folder
        if (folder.is_absolute() and re.fullmatch(r"[a-z]:", folder.drive, re.I)
                and ctypes.windll.kernel32.GetDriveTypeW(folder.anchor) == 3
                and any((folder / ("pgop" + ext)).exists() for ext in extensions)):
            raise ValueError("A pgop command already exists on a local command search path")


def notify_environment():
    sender = ctypes.WinDLL("user32", use_last_error=True).SendMessageTimeoutW
    sender.argtypes = (wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_wchar_p,
                       wintypes.UINT, wintypes.UINT, ctypes.c_void_p)
    sender.restype = ctypes.c_ssize_t
    sender(0xffff, 0x001a, 0, "Environment", 0x0002, 200, None)


def wheel_bytes():
    folder = Path(__file__).absolute().parent
    pin_path = local_path(folder / "PGOPCORE_WHEEL.sha256")
    with pin_path.open("rb") as stream:
        pin = stream.read(256).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("Invalid wheel SHA-256 receipt")
    wheel = local_path(folder / WHEEL)
    with wheel.open("rb") as stream:
        body = stream.read(MAX_WHEEL_BYTES + 1)
    if len(body) > MAX_WHEEL_BYTES or hashlib.sha256(body).hexdigest() != pin:
        raise ValueError("Wheel SHA-256 does not match the bundle receipt")
    return body, pin


def inventory(root, folders):
    def raise_error(exc):
        raise exc

    entries = {}
    for folder in folders:
        local_path(folder)
        if not folder.exists():
            continue
        for current, dirs, files in folder.walk(on_error=raise_error):
            entries[current.relative_to(root).as_posix()] = "directory"
            for name in dirs + files:
                path = current / name
                info = path.lstat()
                if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("Unexpected reparse point in managed installation")
                if name in files:
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ValueError("Unexpected nonregular file in managed installation")
                    with path.open("rb") as stream:
                        entries[path.relative_to(root).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
    return entries


def write_state(root, state, *, initial=False):
    body = json.dumps(state, sort_keys=True).encode("utf-8")
    if len(body) > MAX_STATE_BYTES:
        raise ValueError("Managed file inventory exceeds the receipt limit")
    marker = root / STATE
    path = marker if initial else marker.with_suffix(".pending")
    with path.open("xb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    if not initial:
        os.replace(path, marker)


def remove_owned_files(root, entries):
    # Deepest entries first. rmdir leaves an unfamiliar concurrent addition intact.
    for relative, digest in sorted(entries.items(), key=lambda item: (-item[0].count("/"), item[0])):
        path = local_path(root / relative)
        if digest == "directory":
            path.rmdir()
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Managed file identity changed during uninstallation")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Managed file content changed during uninstallation")
        path.unlink()


def install(root, key):
    user_before = path_value(key)
    environment = root / "venv"
    scripts = environment / "Scripts"
    launcher_root = root / "bin"
    check_collision(launcher_root, user_before[0])
    body, pin = wheel_bytes()
    root.parent.mkdir(parents=True, exist_ok=True)
    local_path(root)
    root.mkdir()
    environment.mkdir()
    launcher_root.mkdir()
    state = {"schema": STATE_SCHEMA, "wheel_sha256": pin, "path_registered": False,
             "root_id": dir_id(root), "venv_id": dir_id(environment), "bin_id": dir_id(launcher_root),
             "user_path_existed": user_before[1] is not None, "files": None}
    write_state(root, state, initial=True)
    subprocess.run([sys.executable, "-I", "-m", "venv", str(environment)], check=True)
    copy = environment / WHEEL
    with copy.open("xb") as stream:
        stream.write(body)
    try:
        subprocess.run([str(scripts / "python.exe"), "-I", "-m", "pip", "--isolated", "install",
                        "--disable-pip-version-check", "--no-index", "--no-deps", str(copy)], check=True)
    finally:
        copy.unlink()
    launcher = launcher_root / "pgop.exe"
    with (scripts / launcher.name).open("rb") as source, launcher.open("xb") as target:
        shutil.copyfileobj(source, target)
    version = subprocess.check_output([str(launcher), "--version"]).strip()
    if version != f"pgopcore {VERSION}".encode("ascii"):
        raise ValueError("Installed launcher did not report the expected version")
    before, kind = path_value(key)
    check_collision(launcher_root, before)
    state["user_path_existed"] = kind is not None
    state["files"] = inventory(root, (environment, launcher_root))
    write_state(root, state)
    after = before + ";" + str(launcher_root) if before else str(launcher_root)
    if len(after) > 32766:
        raise ValueError("User PATH would exceed the Windows limit")
    if path_value(key) != (before, kind):
        raise ValueError("User PATH changed during installation")
    winreg.SetValueEx(key, "Path", 0, kind if kind is not None else winreg.REG_EXPAND_SZ, after)
    state["path_registered"] = True
    write_state(root, state)
    notify_environment()
    print(f"pgopcore {VERSION} installed for this Windows user. Open a new CMD or PowerShell.")


def uninstall(root, key):
    marker = local_path(root / STATE)
    with marker.open("rb") as stream:
        body = stream.read(MAX_STATE_BYTES + 1)
    if len(body) > MAX_STATE_BYTES:
        raise ValueError("Managed file inventory exceeds the receipt limit")
    state = json.loads(body)
    if (not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA
            or state.get("root_id") != dir_id(root)
            or not re.fullmatch(r"[0-9a-f]{64}", str(state.get("wheel_sha256")))
            or type(state.get("user_path_existed")) is not bool):
        raise ValueError("The installation marker does not own this directory")
    if state.get("path_registered") is not True:
        raise ValueError("PATH registration was not recorded as complete. No changes were made")

    folders = (local_path(root / "venv"), local_path(root / "bin"))
    for folder in folders:
        if folder.exists():
            resolved = folder.resolve(strict=True)
            if resolved.parent != root.resolve(strict=True) or resolved.name != folder.name:
                raise ValueError("Unexpected uninstallation target")
            if state.get(folder.name + "_id") != dir_id(folder):
                raise ValueError("Installation directory identity changed")
    owned_files = state.get("files")
    if not isinstance(owned_files, dict):
        raise ValueError("Installation did not finish recording ownership. Its files were preserved")
    observed = inventory(root, folders)
    if any(owned_files.get(path) != digest for path, digest in observed.items()):
        raise ValueError("Managed files have changed. Move any user files before retrying")

    before, kind = path_value(key)
    target = str(root / "bin")
    entries = before.split(";")
    equivalent = [entry for entry in entries if norm(entry) == norm(target)]
    if equivalent and equivalent != [target]:
        raise ValueError("User PATH no longer has one unambiguous owned entry")
    if equivalent:
        entries.remove(target)
        after = ";".join(entries)
        if path_value(key) != (before, kind):
            raise ValueError("User PATH changed during uninstallation")
        if not after and not state["user_path_existed"]:
            winreg.DeleteValue(key, "Path")
        else:
            winreg.SetValueEx(key, "Path", 0, kind, after)
        notify_environment()

    remove_owned_files(root, observed)
    marker.unlink()
    try:
        root.rmdir()
    except OSError:
        if not any(root.iterdir()):
            raise
    print("PGOPCore uninstalled for this Windows user. User reports were preserved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "uninstall"))
    args = parser.parse_args()
    try:
        if sys.version_info < (3, 14):
            raise ValueError("Python 3.14 or later is required")
        if ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError("Run from a standard, non-elevated terminal")
        base = Path(os.environ.get("LOCALAPPDATA", ""))
        root = local_path(base / "Programs" / "PGOPCore")
        if any(char in str(root) for char in ";%"):
            raise ValueError("The installation path cannot contain semicolons or percent signs")
        with exclusive_installer(), winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, USER_ENV, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            (install if args.action == "install" else uninstall)(root, key)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"PGOPCore {args.action} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
