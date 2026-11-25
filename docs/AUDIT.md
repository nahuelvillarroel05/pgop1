# Auditoría de distribución

## R2: una entrega fijada, en un clon ordinario

`tools/audit_release.py` implementa **PGOP1_RELEASE_R2**, independiente del productor,
con biblioteca estándar y Git. R1 permanece en `tools/audit_distribution.py` sin
modificar. La selección no cambia automáticamente cuando una comprobación falla.

Cloná sin `--depth` ni `--filter`, usando un directorio nuevo:

```text
git clone --no-hardlinks https://github.com/nahuelvillarroel05/pgop1.git pgop1-release
cd pgop1-release
```

Si el recibo identifica una candidata disponible sólo como repositorio local,
usá `git clone --no-local --no-hardlinks RUTA_CANDIDATA pgop1-release`.
Sustituí `RUTA_CANDIDATA` por la ubicación del repositorio entregado.
Obtené el commit esperado del recibo externo, verificá su procedencia y seleccioná
esa identidad. En PowerShell, desde el clon:

```powershell
$ExpectedCommit = 'SHA_COMPLETO_DEL_RECIBO_EXTERNO'
git switch --detach $ExpectedCommit
python tools/audit_release.py --expected-commit $ExpectedCommit --output audit-output/release-r2.json
```

En Bash: `ExpectedCommit='SHA_COMPLETO_DEL_RECIBO_EXTERNO'`, seguido de
`git switch --detach "$ExpectedCommit"` y
`python3 tools/audit_release.py --expected-commit "$ExpectedCommit" --output audit-output/release-r2.json`.
Los marcadores requieren el SHA real; no son comandos para ejecutar literalmente.
El archivo de salida debe ser nuevo. Puede quedar fuera del clon o en una carpeta
generada admitida, nunca sobre archivos auditados ni dentro de `.git`.

### Contrato y cobertura

- `--commit` (por defecto HEAD) se resuelve una sola vez a un OID inmutable.
  `--expected-commit` es obligatorio, SHA-1 completo en minúsculas obtenido fuera
  del árbol. `--expected-tree` permite además comprobar un árbol esperado.
- Se comprueba el OID del commit seleccionado y de todos los trees/blobs de su
  árbol, con tamaño, SHA-256, modo y tipo. El límite por cuerpo es 2.000.000 bytes.
  No enlaces, reparse points ni submódulos entre miembros o almacenamiento Git.
- El manifiesto `manifests/PUBLIC_SOURCE_MANIFEST.json`, esquema v1 conservado,
  debe listar exactamente todos los archivos del árbol menos él mismo, por ruta
  ordenada, tamaño y SHA-256. Duplicados, JSON no finito, rutas inseguras,
  inventario incompleto y hashes inconsistentes fallan. También se preservan los
  controles de procedencia del verificador independiente R1.
- El manifiesto está vinculado por su blob Git al árbol esperado; su OID y hash
  aparecen en el recibo externo. No intenta incluir su propio hash ni el SHA del
  futuro commit. Todos los documentos, scripts y tests nuevos están inventariados.
- El checkout completo, incluido el manifiesto, debe coincidir byte a byte y en
  membresía con el árbol, y HEAD debe ser el commit fijado. Se contrastan modos
  ejecutables en POSIX; en Windows ese control se marca NOT_APPLICABLE_WINDOWS.
  No existe un éxito objects-only que oculte modificaciones del runtime.
- Exclusiones de fuentes: sólo el propio manifiesto y los generados declarados
  `.git`, `.venv`, `audit-output`, `public-handoffs`, `verification-output` y
  `__pycache__` (este último también anidado). No se pueden incorporar archivos
  de producto versionados bajo esos directorios para ocultarlos del inventario.
  El entorno instalado y los caches excluidos no quedan certificados por R2.
- Se exige almacenamiento Git autónomo, sin shallow/partial clone, alternates,
  grafts, commondir externo, replacements ni enlaces duros en objects. Se comprueba
  disponibilidad de ancestros; su contenido no se audita. Variables GIT heredadas
  no redirigen las lecturas. Para el cierre usá `--no-local --no-hardlinks`.
- Otras refs son admisibles y se enumeran como fuera de la auditoría de contenido.
  R2 no certifica esas ramas, los objetos ajenos, todo el historial, licencias,
  autenticidad del productor, seguridad o corrección semántica. Es una observación
  puntual, sin bloqueo contra escrituras concurrentes o posteriores.

La salida declara contrato, alcance, identidad observada/esperada, manifiesto,
cobertura, objetos y controles NOT_RUN/NOT_PROVEN. Un fallo conserva exit 1 y su
causa; argumentos inválidos reciben exit 2. Sin ancla confiable, un conjunto de
código y manifiesto coherente no prueba autenticidad. Revisá también el verificador
por un canal confiable antes de ejecutar código de un origen desconocido.

### Pruebas e interfaces

Desde la raíz del clon, creá un entorno dedicado a la auditoría con Python 3.14.
Usá un directorio de entorno distinto del de la instalación de prueba de `pgop`.

```powershell
py -3.14 -m venv ..\pgop-audit-venv
..\pgop-audit-venv\Scripts\python.exe -m pip install -r public_profile/requirements.lock
..\pgop-audit-venv\Scripts\python.exe tools/audit_public.py --contract release-r2 --expected-commit $ExpectedCommit
```

`audit-output/ID/TEST_RESULTS.json` conserva entorno, dependencias, comandos y
exit codes. `INTEGRITY.json` es el control stdlib/Git; las pruebas unittest, CLI,
API y MCP stdio real se ejecutan por separado y conservan stdout/stderr.
`ARTIFACT_VERIFICATION.json` añade el control independiente del informe generado.
Falta de SDK no es una auditoría completa aprobada. Windows y Linux se declaran
separadamente; un test que requiere enlaces POSIX conserva su omisión en Windows.

### Cierre sin circularidad

Finalizá archivos; ejecutá `python tools/update_manifest.py`; revisá el diff y
creá el commit local; anotá commit/árbol fuera del producto; cloná sin enlaces
duros ni alternates y verificá R2 con ese anclaje. Guardá el recibo externo.
Si cambia cualquier archivo, regenerá el manifiesto y repetí los controles
invalidados con la nueva identidad. Integrar o publicar requiere una decisión
posterior: la verificación de este candidato no verifica un futuro merge.

## R1: contrato histórico congelado

R1 comprueba dos ramas completas: `main` raíz y `experiment` único hijo directo.
Rechaza refs/tags adicionales, objetos extras, historia parcial y almacenamiento
externo. No se exige PASS de R1 sobre el clon moderno con E8. Su fallo
`unexpected ref/tag` refleja el contrato de distribución, no un fallo del motor.

Para obtener sólo la distribución histórica desde un directorio de trabajo nuevo
(estos commits deben seguir disponibles en el servidor):

```text
git init --initial-branch=r1-setup pgop1-r1
git -C pgop1-r1 fetch --no-tags https://github.com/nahuelvillarroel05/pgop1.git 04d469c0ef8e4b59209e7903f040f6635044ca89:refs/heads/main 1dca71b232d0c517a4379abeb3661e67caddea49:refs/heads/experiment
git -C pgop1-r1 switch main
cd pgop1-r1
python tools/audit_distribution.py --expected-main 04d469c0ef8e4b59209e7903f040f6635044ca89 --expected-experiment 1dca71b232d0c517a4379abeb3661e67caddea49 --output audit-output/r1.json
```

El wrapper histórico de esos commits se invoca sin argumentos. El wrapper nuevo
expone `--contract historical-r1` explícito, pero no vuelve compatible con R1 un
candidato que tenga otro grafo. No borres refs u objetos del clon moderno para
ocultar el fallo. R1 conserva `--expected-inventory` y su revisión de todos los
objetos; sus evidencias anteriores pertenecen exclusivamente a su distribución.
