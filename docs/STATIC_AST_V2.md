# AST V2: observaciones sintácticas opt-in

`runtime/candidate/static_ast_v2.py` implementa `pgop1.static-ast.v2`, independiente
de `pgop1.static-ast.v1` y del inventario legacy `pgop1.static-ast.inventory.v2`.
No cambia los perfiles, los recibos ni las seis operaciones públicas existentes.
El analizador nunca importa ni ejecuta el código examinado. `compile` valida
restricciones sintácticas de ámbito; no prueba comportamiento ni seguridad.

## Admisión y ejecución

El llamador autoriza cada archivo mediante raíz, ruta relativa normalizada y
SHA-256 esperado. `read_registered` abre cada componente con descriptores relativos
y `O_NOFOLLOW`, rechaza enlaces, traversal, archivos especiales y cambios de
identidad/tamaño/mtime/ctime durante la lectura; verifica el hash de los bytes.
El snapshot representa esos bytes capturados. Cambios posteriores requieren una
nueva admisión con el hash correspondiente. No se escribe en la fuente.
Esta implementación de lectura segura requiere `O_NOFOLLOW` y directorios POSIX;
en plataformas sin esa capacidad se abstiene con un código fijo. No se atribuye
validación Windows a esta intervención.

El proceso padre limita bytes antes del parse. Un subprocess nuevo con `-I`
recibe exclusivamente los bytes admitidos; el timeout abarca parse,
`tokenize.detect_encoding`, decodificación estricta, `ast.parse`, `compile` y
extracción. Los errores no incluyen texto del código ni detalles de excepciones.
La salida usa páginas de transporte, cada una limitada antes de escribir a
`output_bytes` (64 MB por defecto), con snapshot, colección y offset. El padre
reconstruye las colecciones verificando continuidad, total de filas y cierre. Cada
página contiene como máximo 100 filas; se reduce ese número si su tamaño lo exige.
El total de filas transportadas está limitado a cuatro veces el presupuesto de
nodos. El archivo temporal puede superar 64 MB en total: no es una cuota de disco.
Una sola fila que no quepa produce un error de recursos, sin inventar cobertura.
No hay aislamiento de memoria a nivel SO: `memory_isolation=NOT_IMPLEMENTED`.
El timeout y los errores de recursos producen `RESOURCE_ERROR` y sintaxis
`UNKNOWN`, nunca un fallo sintáctico inventado.

Presupuestos máximos y predeterminados:

| Recurso | Límite |
|---|---:|
| Bytes por archivo | 262144 |
| Nodos AST globales | 50000 |
| Profundidad AST | 160 |
| Nodos propios por unidad | 12000 |
| Bytes por página de transporte | 64000000 |
| Tiempo de worker | 6 segundos |

El llamador puede reducirlos mediante `budgets`; no puede ampliarlos. Son límites
independientes. El límite global finito de 50000 permite contar los 21657 nodos
reales de `pg_i7.py`, manteniendo el límite por unidad de 12000. La profundidad
160 sigue siendo finita; no representa una equivalencia de tamaño en bytes.
La memoria y el tiempo no se deducen del número de nodos.

## Contrato y cobertura

`analyze_source(root, relative_path, expected_sha256, budgets=None)` devuelve el
informe completo. `validate_report` comprueba esquema, snapshot, identidades,
estados y aritmética; no sustituye al verificador separado sobre fuentes.

El informe incluye `schema`, `source` (ruta, bytes y hash), `source_sha256`,
`parser`, `python_version`, `budgets`, `status`, `PYTHON_SYNTAX`, `AST_COVERAGE`,
`units`, `declarations`, `relations`, `total_detected`, `returned`, `remaining`,
`omitted_by_budget`, `units_complete`, `units_unknown` y `snapshot_id`.
`execution_metrics` contiene tiempo real medido y memoria no medida (`null`).
Se excluye del hash y de las comparaciones deterministas; el resto es canónico.

La unidad módulo usa línea/columna 0. Cada clase, función y función async abre una
unidad léxica. Cada nodo pertenece exactamente a su declaración más cercana; los
nodos de declaraciones anidadas pertenecen a su propia unidad. `owned_nodes`
cuenta esa partición, incluyendo argumentos, decoradores y anotaciones de la
propia declaración. Es una partición sintáctica, no un modelo de evaluación Python.
`own_status` expresa el presupuesto de esos nodos y `status` incluye descendientes:
una unidad con un descendiente omitido no tiene cobertura integral.
`units_complete/units_unknown` cuentan `own_status`, y su suma da todas las unidades.

Primero se enumera todo el árbol bajo los límites globales, después se aplica el
presupuesto por unidad. Una unidad excedida omite sus declaraciones y relaciones,
conserva su identidad y conteo y produce archivo `PARTIAL`; las unidades pequeñas
siguen disponibles. `total_detected` cuenta todas las declaraciones enumeradas;
`omitted_by_budget` las declaraciones no emitidas por unidad excedida.
Los campos no conocidos son `null`, nunca un total supuesto. Si se corta el
recorrido global, `observed_nodes` es el prefijo contado, `total_nodes=null`,
`pending_nodes` cuenta nodos pendientes y `pending_units=null` porque aún no se
conoce cuántas unidades hay. No se emiten hechos de ese recorrido incompleto.

Estados: `COMPLETE`, `PARTIAL`, `BUDGET_EXCEEDED`, `PARSE_FAILED`, `RESOURCE_ERROR`,
`UNSUPPORTED`, `UNKNOWN`. Los dos últimos están reservados para abstenciones de
consumidores; una admisión inválida falla con `AdmissionError` de código fijo.
`PYTHON_SYNTAX=PASS` se conserva si parse y compile integrales terminaron, aunque
la cobertura estructural posterior sea parcial. Nunca prueba ejecución.
Ausencias requieren ámbito íntegro; una lista vacía parcial no prueba ausencia.

## Inventario, identidades y páginas

Se inventarían todas las clases y definiciones sync/async, incluidos métodos,
funciones anidadas, redefiniciones y declaraciones bajo condiciones. El módulo
está representado en `units`; asignaciones y demás instrucciones se cuentan como
nodos del ámbito, sin fingir que sean definiciones de funciones. Las condiciones
se registran mediante `conditional`; los decoradores mediante `decorated`.
También deben examinarse los ancestros antes de interpretar incondicionalidad.
Sobrecargas y redefiniciones son entradas distintas, sin resolver cuál se ejecuta.

Cada ID es `node-` seguido del SHA-256 del JSON canónico de:
`[source_sha256, path, scope_chain, line, column, node_type]`.
La cadena contiene por ancestro nombre, línea, columna y tipo. Por ello `A.m`,
`B.m` y dos redefiniciones de `A.m` no colisionan. Las columnas del AST de CPython
son offsets de bytes UTF-8, incluso cuando la fuente se decodificó con otra
codificación. Declaraciones y relaciones se ordenan por ubicación en fuente antes
de paginar; los desempates son deterministas.

`page(report, kind='declarations', cursor=None, limit=100)` acepta límites 1–1000.
El cursor incluye snapshot, colección y offset. No se reutiliza con otra fuente,
configuración o colección. Cada página lleva schema, hash, snapshot, status,
analysis_status, total_detected, returned, remaining, offset, cursor,
omitted_by_budget, units_complete y units_unknown. Una página que omite cualquier
tramo tiene `status=PARTIAL`; `analysis_status` describe el análisis completo.
La colección completa solo se acredita al reunir todas las páginas del snapshot.
Para relaciones `total_detected` cuenta las relaciones emitidas; las relaciones
de una unidad omitida no se enumeraron, y `analysis_status=PARTIAL` lo hace visible.

## Relaciones y exposición

`defines` resuelve únicamente contención léxica (`RESOLVED_STATIC`). `imports`
conserva módulo, nivel relativo y alias; no resuelve paquetes, hooks ni ejecución.
Un star import es `AMBIGUOUS`; los demás imports son `UNRESOLVED`.
`inherits` conserva la forma de la expresión de base, siempre `UNRESOLVED`.
`calls` conserva un candidato de callee; nombres simples son `UNRESOLVED` y
atributos/expresiones dinámicas o `getattr` son `AMBIGUOUS`. Nunca se une una llamada
con una función ejecutada: decoradores, sombreado, alias mutables y monkeypatching
no se presentan como vínculos demostrados.

Se permiten identificadores públicos Unicode y nombres de import de hasta 120
caracteres; otros nombres se sustituyen por `WITHHELD`. Expresiones conservan
únicamente tipos de nodo e identificadores; literales, argumentos y cuerpos no
aparecen. La ruta admitida sí forma parte de la procedencia. El informe puede
contener nombres públicos del código; no es un mecanismo de anonimización.

El grafo del analizador se serializa independientemente con snapshot. La inspección
de `Engine._validate`, `_binding` e `ingest` mostró contratos de evidencia distintos;
el analizador no inserta directamente relaciones V2 en Context Engine.
La integración a `RealEvidenceProfile` y a `generate/read` legacy queda diferida.

Existe ahora un [adaptador opt-in de informes capturados](SOURCE_AUDIT_MEMORY_V1.md)
que conserva registros V2 como observaciones del Context Engine. No cambia este
analizador, su admisión POSIX ni las relaciones del Engine; tampoco completa la
integración nativa de fuentes ni las operaciones legacy mencionadas arriba.

## Comando reproducible de API

Desde la raíz, con el venv local y un archivo expresamente autorizado:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from runtime.candidate.static_ast_v2 import analyze_source, digest, page
name = 'runtime/candidate/pg_i7.py'
report = analyze_source('.', name, digest(Path(name).read_bytes()))
print(report['status'], report['AST_COVERAGE'])
print(page(report, limit=10)['returned'])
PY
.venv/bin/python -m unittest discover -s tests -p test_static_ast_v2.py -v
```

El ejemplo obtiene el pin de bytes locales para autorizar esta lectura concreta;
para contrastar una distribución, usar el hash confiable de su manifiesto.
Las pruebas incluyen 400 funciones paginadas, ámbitos repetidos, Unicode,
relaciones dinámicas, límites, timeout simulado, links/traversal y TOCTOU.
La cobertura estructural no equivale a precisión, corrección funcional ni seguridad.
