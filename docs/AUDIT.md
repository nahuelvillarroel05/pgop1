# Auditoría pública desde cero

Obtené este repositorio nuevo completo, nunca con --depth ni --filter.
Para la entrega local: `git clone --no-local --no-hardlinks RUTA_GIT_NUEVO pgop1`.
RUTA_GIT_NUEVO es la ubicación entregada por el Owner; no un dato privado necesario
para ejecutar el producto. Para publicación futura usá la URL que autorice el Owner.
Un ZIP de fuentes no contiene historia: obtené también el Git bundle de entrega
o un clon completo. No se requiere Engineering privado.

Entrá al clon y materializá ambas ramas locales antes de auditar:

```text
git branch --no-track experiment origin/experiment
git switch main
```

Si clonaste `--branch experiment`, creá `main` desde `origin/main` en su lugar.
No ejecutes el comando de creación si la rama local ya existe.
Instalá en un venv nuevo con los comandos del README y usá ese Python:

```text
python tools/audit_public.py
```

La salida audit-output/UUID incluye versiones de Python/SO/dependencias, comandos,
exit codes, stdout/stderr, TEST_RESULTS.json, HISTORY_GRAPH_AND_OBJECTS.json,
MCP_TRACE.json y el handoff generado con sus vínculos verificados por un programa
separado. Sólo se ejecutan herramientas y tests de esta distribución; los módulos
objeto del análisis estático son datos inertes. El test de enlaces que requiere
POSIX se omite en Windows con motivo explícito; otras denegaciones se conservan.
Linux integral no fue ejecutado en la preparación local (WSL denegado, Docker
sin motor). No se afirma CI hospedado ni cliente Codex probado.

El verificador independiente también puede ejecutarse solo (Python stdlib + Git):

```text
python tools/audit_distribution.py --output audit-output/integrity.json
```

Acepta `--expected-main SHA --expected-experiment SHA` y
`--expected-inventory INVENTARIO_JSON` para comparar con identidades obtenidas
por un canal confiable de entrega. Un atacante que sustituye código y manifiestos
podría fabricar un conjunto coherente; sin ancla externa no se prueba autenticidad.
Se revisan las dos ramas completas aunque el worktree esté en main.

Contrato del manifiesto: todos los archivos de fuentes/documentación/pruebas,
por ruta ordenada, bytes y SHA-256. Sólo se excluye el propio manifiesto y los
directorios generados enumerados en su campo exclusions (más __pycache__ a cualquier
nivel). Los excluidos no se auditan como fuentes. No hay exclusión genérica para
archivos nuevos. No enlaces, reparse points ni submódulos entre miembros.
El manifiesto y SOURCE_PROVENANCE son blobs vinculados por el tree Git; su propio
OID/SHA-256 aparece en el inventario externo para evitar autorreferencia imposible.

Historia admitida: main raíz sin padres y experiment único hijo directo. Sólo
esas ramas y, en clones, refs origin/main, origin/experiment y origin/HEAD->main.
Tags, refs adicionales, historia parcial, alternates, grafts y objetos locales
extra fallan explícitamente. Se enumeran todos los commits/trees/blobs por rama,
unión, modos, pertenencia, tamaños, OID Git SHA-1 y SHA-256 del contenido sin header.
Se recalcula cada OID y se ejecuta git fsck --full --strict. OID no es SHA-256.

Controles negativos incluyen manifestación incompleta/falsificada, cambios,
faltantes, enlaces de escape, padre/ref/objeto extra, credencial simulada y objeto
Git perdido; los tests del motor cubren IDs/JSON inválidos, lecturas cruzadas y
artefactos truncados/obsoletos. Los intentos quedan en audit-output.
La búsqueda automática de patrones no sustituye revisar manualmente TODOS los
objetos y licencias. Revisá el inventario y `git cat-file TIPO OID` usando sólo
sus OIDs fijados. Los dos commits fueron seleccionados y revisados, sin heredar
el historial original. Consultá PROVENANCE e HISTORY.
