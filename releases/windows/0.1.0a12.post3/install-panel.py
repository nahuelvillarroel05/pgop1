"""Install this delivery and its locked presentation wheels locally, offline."""

import json
import msvcrt
from pathlib import Path
import subprocess
import sys
import venv
from runpy import run_path

bootstrap = run_path(str(Path(__file__).with_name("start-panel.py")))
HERE, ENV, SITE = (bootstrap[name] for name in ("HERE", "ENV", "SITE"))
local, artifacts, inventory = (bootstrap[name] for name in ("local", "artifacts", "inventory"))
PIP = ["-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir"]


def install():
    wheel, binding = artifacts()
    lock = local(HERE / "pgop-panel-install.lock")
    with lock.open("a+b") as guard:
        guard.seek(0)
        msvcrt.locking(guard.fileno(), msvcrt.LK_LOCK, 1)
        setup(binding, wheel, HERE / "requirements-tui.lock", HERE / "wheelhouse")


def setup(binding, wheel, requirements, wheelhouse):
    local(ENV)
    marker = ENV / "PGOP_PANEL_INVENTORY.json"
    python = ENV / "Scripts/python.exe"
    command = ENV / "Scripts/pgop.exe"
    if ENV.exists():
        raise ValueError("Entorno incompleto. Extraé el ZIP verificado en una carpeta nueva.")

    venv.EnvBuilder(with_pip=True).create(ENV)
    with (ENV / "install.log").open("x", encoding="utf-8") as log:
        common = [str(python), *PIP]
        offline = ["install", "--no-index", "--no-compile"]
        for args in (
            [*offline, "--only-binary=:all:", "--require-hashes", "--find-links", str(wheelhouse),
             "-r", str(requirements)],
            [*offline, "--no-deps", str(wheel)],
            ["check"],
        ):
            subprocess.run([*common, *args], stdout=log, stderr=subprocess.STDOUT, check=True)
        hot_packages = ("textual", "rich", "markdown_it", "mdit_py_plugins", "mdurl", "linkify_it",
                        "platformdirs", "typing_extensions.py")
        subprocess.run([str(python), "-I", "-m", "compileall", "-q", "--invalidation-mode", "checked-hash",
                        *(str(SITE / name) for name in hot_packages)], stdout=log, stderr=subprocess.STDOUT,
                       check=True)
    if not command.is_file():
        raise ValueError("No se creó el ejecutable del panel.")
    with marker.open("x", encoding="ascii") as output:
        json.dump({"binding": binding, "files": inventory()}, output, sort_keys=True)


if __name__ == "__main__":
    try:
        install()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"PGOPCore no pudo preparar el panel. {error}", file=sys.stderr)
        sys.exit(1)
