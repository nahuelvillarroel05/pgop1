# Herramientas reales

Ejecutá desde la raíz con el Python del entorno virtual. Abajo se usa `python`
tras activarlo: PowerShell ` .\.venv\Scripts\Activate.ps1` si la política local lo
permite; CMD `.venv\Scripts\activate.bat`; Bash `. .venv/bin/activate`.
También podés usar directamente `.venv\Scripts\python.exe` o `.venv/bin/python`.
No hace falta cambiar políticas del sistema.

## Consultar

```text
python runtime/candidate/pg_i7.py --profile public --json availability
python runtime/candidate/pg_i7.py --profile public --json catalog --offset 0 --limit 10
python runtime/candidate/pg_i7.py --profile public --json query RUN012_PUBLIC
python runtime/candidate/pg_i7.py --profile public --json verify RUN012_PUBLIC
```

`verify` devuelve un `receipt_id`. PASS es integridad/consistencia del agregado,
no repetición ni certificación de los tests declarados en ese agregado.

## Informes

```text
python tools/demo_public.py
```

Este ejemplo hace query, verify, generate y read con paginación. Para uso manual:
`python runtime/candidate/pg_i7.py --profile public --output-root public-handoffs --json generate RUN012_PUBLIC RECEIPT_ID REQUEST_KEY`
y `python runtime/candidate/pg_i7.py --profile public --output-root public-handoffs --json read REPORT_ID --artifact REPORT.json --offset 0 --limit 16000`.
Reemplazá los identificadores por los devueltos; no son valores literales.
Artefactos legibles: REPORT.json, FINAL_HANDOFF.md, MANIFEST.json.
La misma solicitud recupera el mismo informe; un recibo obsoleto falla.
Error de transporte/argumento: exit 2; FAIL/PARTIAL de dominio puede tener exit 0.
Por eso la auditoría examina el contenido, además del exit code.

## MCP

```text
python -m pg_i7_mcp.server --profile public --output-root public-handoffs
```

Servidor local stdio, sin listener de red por defecto. Lo inicia el cliente MCP
con cwd en la raíz del clon y el Python del entorno virtual. Expone availability,
catalog, query, verify, generate, read; backend idéntico al API/CLI. Sin cuenta de
Codex. `python tools/test_public_mcp.py audit-output/sdk-manual` ejecuta un cliente
SDK real separado con reconexión; el directorio debe ser nuevo.

En `experiment`, `--profile engineering-local` y `--profile evidence-local` usan
`--package-root CONFIG_ROOT --output-root REPORT_ROOT` explícitos y disjuntos.
Los catálogos admitidos definen fuentes; no se descubre Engineering del autor.
La auditoría pública crea ejemplos sintéticos y prueba esos perfiles.
Git Governance E1 como adaptador del producto y el perfil legacy no están disponibles.
La herramienta de integridad Git de esta distribución es independiente del motor.

## Auditoría estructural y documental V2 (opt-in)

La herramienta independiente `tools/audit_source_v2.py` genera un informe V2
con manifiesto. No cambia las seis operaciones anteriores.
Ver [AST V2](STATIC_AST_V2.md) y [claims documentales](DOCUMENT_CLAIMS.md)
para contratos, preparación de fuentes autorizadas y comandos reproducibles.

La [memoria de informes V2 capturados](SOURCE_AUDIT_MEMORY_V1.md) tiene API y CLI
opt-in separadas y un verificador de almacenamiento independiente. No amplía los
seis nombres del MCP público. Ver también [diagnóstico Windows](WINDOWS_SETUP.md).


## Code-only E3 (opt-in, Windows)

See [code-only claims](CODE_ONLY_CLAIMS.md) and [static module resolution](STATIC_MODULE_RESOLUTION.md).
Tested separate-process CLI commands from the checkout, using the existing virtual environment:

```text
.venv\Scripts\python.exe -B tools/code_only_v1.py analyze --source-root ABSOLUTE_SOURCE_ROOT --catalog ABSOLUTE_CATALOG --catalog-sha256 EXTERNAL_SHA256 --output NEW_DISJOINT_DIRECTORY
.venv\Scripts\python.exe -B tools/code_only_v1.py query --artifacts ABSOLUTE_BUNDLE --catalog-sha256 EXTERNAL_SHA256 --kind claims --offset 0 --limit 7
.venv\Scripts\python.exe -B tools/verify_code_only_v1.py --artifacts ABSOLUTE_BUNDLE --catalog-sha256 EXTERNAL_SHA256
```

Replace placeholders with caller-authorized pins/paths. Analyze errors exit2; verifier errors exit1.
REJECTED is a query admission result, distinct from INSUFFICIENT_EVIDENCE. Full bundle verification precedes pagination.
MEMORY_INTEGRATION=DEFERRED; six public MCP names unchanged; no target source execution.
SOURCE_CURRENT_AT_ACK and ARTIFACT_CURRENT_AT_ACK remain NOT_PROVEN.
