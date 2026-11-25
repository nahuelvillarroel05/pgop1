"""Check the delivered and installed runtime before opening the local panel."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from zipfile import ZipFile


HERE = Path(os.path.abspath(__file__)).parent
ENV = HERE / "pgop-panel-env"
SITE = ENV / "Lib" / "site-packages"
REQ = re.compile(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+ --hash=sha256:([a-f0-9]{64})")


def local(path):
    if path.resolve() != path or path.is_symlink() or path.is_junction():
        raise ValueError("El paquete y su entorno deben estar en carpetas locales.")
    return path


def digest(path):
    return sha256(local(path).read_bytes()).hexdigest()


def artifacts():
    pin, filename = local(HERE / "WHEEL.sha256").read_text(encoding="ascii").split()
    if not re.fullmatch(r"[a-f0-9]{64}", pin) or not re.fullmatch(
        r"pgopcore-0\.1\.0a12(?:\.post[0-9]+)?-py3-none-any\.whl", filename,
    ):
        raise ValueError("El nombre o la huella de la candidata no son válidos.")
    wheel = HERE / filename
    if digest(wheel) != pin:
        raise ValueError("La wheel de PGOPCore cambió.")
    body = local(HERE / "requirements-tui.lock").read_bytes()
    matches = [REQ.fullmatch(line) for line in body.decode("ascii").splitlines()]
    if not matches or not all(matches):
        raise ValueError("El lock de presentación es inválido.")
    wheelhouse = local(HERE / "wheelhouse")
    entries = tuple(wheelhouse.iterdir())
    if not all(path.is_file() and path.suffix == ".whl" for path in entries) or sorted(
        digest(path) for path in entries
    ) != sorted(match[1] for match in matches):
        raise ValueError("Las wheels de presentación cambiaron.")
    return wheel, [pin, sha256(body).hexdigest()]


def file_state(meta):
    if meta.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError("El entorno contiene un enlace.")
    if not stat.S_ISREG(meta.st_mode):
        raise ValueError("El entorno contiene un tipo de archivo no admitido.")
    return [meta.st_size, meta.st_mtime_ns, meta.st_birthtime_ns]


def inventory():
    local(ENV)
    local(SITE)
    rows = {}
    pending = [(str(SITE), "Lib/site-packages/")]
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as scan:
            for item in scan:
                # pip is only used by the offline installer. Python starts with
                # -S, and PGOPCore and the UI do not import pip at runtime.
                if prefix == "Lib/site-packages/" and (
                    item.name == "pip" or re.fullmatch(r"pip-.*\.dist-info", item.name)
                ):
                    continue
                meta = item.stat(follow_symlinks=False)
                if meta.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("El entorno contiene un enlace.")
                if stat.S_ISDIR(meta.st_mode):
                    pending.append((item.path, prefix + item.name + "/"))
                else:
                    rows[prefix + item.name] = file_state(meta)
    for relative in ("Scripts/python.exe", "Scripts/pgop.exe", "pyvenv.cfg"):
        rows[relative] = file_state((ENV / relative).lstat())
    return rows


def check_core(wheel):
    # Validate the installed product against the archived, verified wheel.
    with ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if entry.filename.startswith("pgopcore/") and not entry.is_dir():
                path = SITE / entry.filename
                if path.read_bytes() != archive.read(entry):
                    raise ValueError("El código o los recursos instalados de PGOPCore cambiaron.")


def main():
    if sys.version_info[:2] != (3, 14) or not (sys.flags.no_site and sys.flags.isolated):
        raise ValueError("Usá pgop-panel.cmd para abrir este paquete.")
    wheel, binding = artifacts()
    saved = json.loads(local(ENV / "PGOP_PANEL_INVENTORY.json").read_bytes())
    if saved != {"binding": binding, "files": inventory()}:
        raise ValueError("El entorno instalado está incompleto o cambió.")
    check_core(wheel)
    sys.path.append(str(SITE))
    # Preserve venv boundaries for the existing product path guards under -S.
    sys.prefix = sys.exec_prefix = str(ENV)
    from pgopcore.cli import main as panel

    return panel()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"No se pudo verificar PGOPCore. {exc} Volvé a extraer el ZIP verificado en otra carpeta.",
              file=sys.stderr)
        sys.exit(1)

