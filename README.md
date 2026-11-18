# pgopcore

Este repositorio contiene el prototipo de código abierto de **pgopcore**,
desarrollado y coordinado por Nahuel Villarroel. Permite consultar evidencia
identificada y generar informes trazables mediante CLI, API Python y MCP.
La entrega basada en `main` recibe
agregados JSON registrados, comprueba sus hashes y consistencia acotada, y produce
`REPORT.json`, `FINAL_HANDOFF.md` y recibos recuperables con paginación.

[Sitio oficial](https://pgopcore.com) · [nahuel@pgopcore.com](mailto:nahuel@pgopcore.com)

`PGOP1`/`pgop1` es el identificador técnico e histórico de este repositorio.
La identidad pública actual es `pgopcore`.

La hipótesis de usuario son equipos que necesitan revisar qué fuentes respaldan
el trabajo de un agente y conservar sus límites junto al resultado. Esa necesidad
comercial todavía no está validada con clientes. El desarrollo experimental añade
lectura de fuentes autorizadas y contraste de determinadas afirmaciones estáticas.

| Estado | Alcance |
|---|---|
| Disponible en esta entrega de `main` | Consulta, integridad/consistencia de agregados públicos e informes locales. Auditoría independiente R2 del commit, árbol y checkout. |
| Demostrable en `experiment` | Memoria de cuatro fuentes y contraste estático sintético, fijados a `1dca71b232d0c517a4379abeb3661e67caddea49`; [demo reproducible](docs/DEMO.md). |
| Experimental en E8 | Desarrollo posterior en `feature/e8-windows-native-directory-enumeration-001`, observado en `ab93335ff3e843d154eeaaf48e05a281cde7b72e`; fuera de esta entrega, con calificación Windows parcial. |
| Pendiente de medir | Beneficio comparativo en calidad, tiempo, tokens y coste; sin superioridad ni ahorro demostrado por esta entrega. |

## Probar el perfil público

Requisitos: Git, Python 3.14 y un clon completo. Desde la raíz de esta entrega,
en PowerShell o CMD:

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r public_profile/requirements.lock
.venv\Scripts\python.exe runtime/candidate/pg_i7.py --profile public --json query RUN012_PUBLIC
.venv\Scripts\python.exe tools/demo_public.py
```

La demo imprime la ruta del informe. Abrilo con un editor; junto a él quedan
`REPORT.json`, `MANIFEST.json` y los recibos. [Ejemplo público](examples/public-r1/README.md).
En Bash, los comandos equivalentes usan `python3 -m venv .venv` y
`.venv/bin/python` en lugar de `.venv\Scripts\python.exe`. Linux no se ejecutó
en la preparación de esta candidata; el lock incluye MCP 2.3.0.

`RUN012_PUBLIC` contiene declaraciones históricas: leerlo no repite sus pruebas.
Declara cero etiquetas independientes y métricas independientes no computables;
sus decisiones no representan precisión del 100 %.

## Verificar una entrega concreta

Obtené el SHA completo esperado del recibo externo de la entrega, por un canal
confiable. En PowerShell, sustituyendo el texto entre comillas por ese SHA:

```powershell
$ExpectedCommit = 'SHA_COMPLETO_DEL_RECIBO_EXTERNO'
python tools/audit_release.py --expected-commit $ExpectedCommit --output audit-output/release-r2.json
```

Este control sólo requiere Python estándar y Git. R2 verifica el árbol completo,
el manifiesto y el checkout frente al commit fijado. Permite otras referencias,
como E8, fuera de su alcance: no certifica todo el historial ni todos los objetos.
No obtengas el ancla esperada del mismo checkout que pretendés autenticar.

Para añadir pruebas, CLI/API y MCP real, con el Python del venv y el mismo SHA:

```powershell
.venv\Scripts\python.exe tools/audit_public.py --contract release-r2 --expected-commit $ExpectedCommit
```

El recibo de integridad y los resultados de pruebas son controles distintos.
Una dependencia ausente conserva el fallo de la comprobación afectada.
[Contrato R2 y auditoría histórica R1](docs/AUDIT.md).

## Interpretar los informes

La integridad de una fuente y el estado de una afirmación son cosas distintas:
una demo puede tener integridad `PASS` y una afirmación `CONTRADICTED`.
`UNKNOWN` e `INSUFFICIENT_EVIDENCE` conservan lo que no se pudo establecer.
Un informe generado no aprueba una tarea; un hash no autentica al productor y
una propiedad sintáctica no demuestra corrección funcional. [Límites](docs/LIMITATIONS.md).

[CLI/API/MCP](docs/TOOLS.md) · [Demo experimental](docs/DEMO.md) ·
[Arquitectura](docs/ARCHITECTURE.md) · [Procedencia](docs/PROVENANCE.md) ·
[Historia](docs/HISTORY.md) · [Licencia Apache-2.0](LICENSE)
