# PGOP1

PGOP1 verifica vínculos entre evidencia, conserva memoria de consultas y genera
informes de auditoría estructural. Sus interfaces CLI y MCP usan el mismo backend.
La rama `main` ofrece el perfil de agregados públicos; `experiment` añade memoria
multifuente y análisis estático de fuentes autorizadas.

## Inicio en tres pasos

Requisitos: Git y Python 3.14. Instalá desde un clon completo con ambas ramas;
[auditoría desde cero](docs/AUDIT.md) explica cómo preparar sus referencias.

**1. Instalá** en un entorno virtual nuevo, desde la raíz del clon.

PowerShell y CMD:

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r public_profile/requirements.lock
```

Bash (Linux; ejecución pendiente en la preparación local):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r public_profile/requirements.lock
```

**2. Consultá** el [ejemplo R1](examples/public-r1/README.md).

PowerShell y CMD:

```bat
.venv\Scripts\python.exe runtime/candidate/pg_i7.py --profile public --json query RUN012_PUBLIC
```

Bash:

```bash
.venv/bin/python runtime/candidate/pg_i7.py --profile public --json query RUN012_PUBLIC
```

**3. Generá y recuperá** `FINAL_HANDOFF.md` mediante el backend real.

PowerShell y CMD:

```bat
.venv\Scripts\python.exe tools/demo_public.py
```

Bash:

```bash
.venv/bin/python tools/demo_public.py
```

El comando imprime la ruta del informe; abrilo con tu editor. Junto a él quedan
`REPORT.json`, `MANIFEST.json` y los recibos de solicitud y finalización.
Los agregados incluidos son declaraciones históricas: no se vuelven a ejecutar.

## Herramientas

| Herramienta | Acceso directo |
|---|---|
| Disponibilidad y catálogo | [availability / catalog](docs/TOOLS.md#consultar) |
| Consulta y verificación | [query / verify](docs/TOOLS.md#consultar) |
| Generar y leer informes | [generate / read](docs/TOOLS.md#informes) |
| Servidor MCP local, stdio | [iniciar MCP](docs/TOOLS.md#mcp) |
| Memoria y auditoría de código sintético | [ejemplos de experiment](examples/source-audit-synthetic/README.md) |
| Integridad de archivos e historia Git completa | [auditoría pública](docs/AUDIT.md) |

## Auditar en un comando

Desde un clon con las dos ramas locales:

```text
python tools/audit_public.py
```

Ejecuta el verificador separado, pruebas y operaciones CLI/API/MCP reales.
Los comandos, versiones, exit codes e inventario de todos los objetos Git quedan
en una carpeta nueva bajo `audit-output/`. Requiere las dependencias instaladas:
usá el Python del entorno virtual (o activalo antes).

Generar un informe no aprueba una tarea; hashes no autentican al productor y
análisis estático no demuestra corrección funcional. [Límites](docs/LIMITATIONS.md).

[Herramientas](docs/TOOLS.md) · [Auditoría](docs/AUDIT.md) ·
[Arquitectura](docs/ARCHITECTURE.md) · [Procedencia](docs/PROVENANCE.md) ·
[Historia](docs/HISTORY.md) · [Licencia Apache-2.0](LICENSE)
