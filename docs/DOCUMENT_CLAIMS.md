# Claims documentales tipados (opt-in)

`pgop1.doc-claims.v1` vincula una propuesta manual a un intervalo exacto de bytes
de documento y a fuentes autorizadas fijadas por SHA-256. El evaluador es
determinista y no usa LLM, red, modelos locales ni ejecución del código examinado.
No extrae ni interpreta Markdown de forma general. La persona que redacta el
claim conserva la responsabilidad de representar fielmente la prosa citada.

El perfil `RealEvidenceProfile` existente ya acepta fuentes reales. Esta capacidad
usa una herramienta adicional y contratos independientes para conservar sus
recibos y formatos. La integración con sus operaciones `generate/read` y la
persistencia en Context Engine quedan **diferidas**. El grafo estructural continúa
serializado en el informe V2; ninguna relación sintáctica se inserta en categorías
`VERIFIED_*` del Engine.

## Contratos y abstenciones

El catálogo `pgop1.source-audit-catalog.v2` tiene exactamente `schema`, `sources`
y `claims`. Cada fuente registrada tiene `path` relativo portable, `sha256` y
`kind` (`python`, `document`, `file`). Se admiten hasta 64 fuentes y 64 claims;
cada lectura limita 262144 bytes. No se descubre ni autoriza una fuente por una
mención en el documento. Cada documento y cada fuente de contraste del claim
deben estar registrados con el mismo hash.

Un claim contiene exactamente:

- `claim_schema`, `claim_id`, `predicate`;
- `document`: `path`, `sha256`, `start_line`, `end_line`, `span_sha256`;
- `source`: `path`, `sha256`;
- `parameters` y `expected`, explícitamente tipados.

`claim_id` es `claim-` más SHA-256 del JSON canónico del claim sin `claim_id`.
JSON canónico: ASCII con escape Unicode, claves ordenadas, separadores `,` y `:`,
sin espacios ni salto final, sin NaN ni infinitos. Se rechazan claves duplicadas.
El intervalo documental es inclusivo y comienza en línea 1. Su hash se calcula
sobre `b''.join(raw.splitlines(keepends=True)[start_line-1:end_line])`, conservando
los terminadores originales. El informe no copia el contenido del intervalo.

`expected` admite `{"type":"int","value":12000}`, `bool`, `str`,
`{"type":"none"}` o `{"type":"tuple","items":[...]}`. Los enteros se limitan a
100 cifras; las cadenas a 120 caracteres de letras, dígitos, espacios, `_`, `.` o
`-`; las tuplas a 64 elementos y profundidad 8. `True` no equivale a `1`.
Los literales observados se registran mediante hash, nunca como contenido de
fuente. Los valores esperados provienen explícitamente del claim del solicitante.

| Predicado | Parámetros | Demuestra |
|---|---|---|
| `constant_equal` | `scope`, `name`, `definition_line` | Una asignación directa única al nombre tiene un literal inmutable admitido e igual al valor tipado esperado. |
| `symbol_defined` | `scope`, `name` | Existe una declaración sintáctica inmediata de clase, función o función async en el ámbito léxico identificado. |
| `public_operation_declared` | `scope`, `name`, `definition_line`, `operation` | Una tupla estática inmutable de cadenas declara la operación por pertenencia. |
| `declared_file_exists` | `{}` | El archivo registrado fue leído de forma segura y sus bytes coinciden con su hash. |

`scope` admite `<module>`, un ID exacto `node-…` de AST V2, o un nombre calificado
que identifique un único ámbito. Los nombres consultados y cada componente de
un selector calificado deben estar escritos en forma Unicode NFKC canónica, como
los identificadores que produce CPython AST. Por ejemplo, una definición escrita
`def K():` se consulta como `K`; un claim que consulte `K` se rechaza con
`NONCANONICAL_IDENTIFIER`, incluso si pretende demostrar ausencia. Esta regla no
normaliza los valores de cadenas de un registro: la operación se compara como
cadena exacta. Dos clases redefinidas `A` hacen ambiguo `A`;
seleccionar un ID permite distinguirlas. El marcador reservado `WITHHELD` no se
puede interpretar como un nombre observado: consultarlo como nombre o componente
de selector calificado produce abstención, incluso si la fuente declara ese
nombre literalmente. Un ID exacto de un ámbito descendiente conserva su
identidad aunque un nombre de ancestro esté redactado: el worker reconstruye la
misma cadena de ámbitos con la política de privacidad de AST V2. La existencia de una declaración bajo
una condición sigue siendo una observación sintáctica: no afirma que el nombre
exista en una ejecución. No demuestra seguridad, corrección funcional, herencia
resuelta ni que MCP/CLI ejecuten la operación.

Para constantes y registros se exige un único `Assign` de un solo nombre o
`AnnAssign` con valor, directamente en el cuerpo del ámbito y en la línea
indicada. Se admiten `Constant` y tuplas recursivas de valores admitidos; no se
admiten listas, diccionarios, operadores, nombres ni llamadas. Se abstiene ante
redefiniciones, borrados, bindings del mismo nombre incluso en otros ámbitos,
asignaciones condicionales, ámbito con ancestro condicional, `global/nonlocal`,
star-import y llamadas directas a `exec/eval/globals/locals/setattr/delattr/vars`.
Esta política conservadora puede abstenerse ante código inocuo. El alcance es la
declaración estática de la fuente fijada, nunca inmutabilidad durante ejecuciones
con imports o mutaciones externas.

Se exige cobertura íntegra del ámbito relevante para cualquier resultado de
símbolos, incluido el negativo. Cobertura `PARTIAL`, `BUDGET_EXCEEDED`,
`RESOURCE_ERROR` o ámbito no identificable producen `INSUFFICIENT_EVIDENCE`.
Una fuente ausente, ilegible o cuyo hash cambió tampoco prueba ausencia: incluso
`declared_file_exists=false` se abstiene. Una fuente presente con pin verificado
contradice ese claim negativo. El catálogo no es una garantía de existencia ni
un manifiesto cerrado que autorice inferencias sobre archivos no registrados.

Los veredictos son `SUPPORTED`, `CONTRADICTED` e `INSUFFICIENT_EVIDENCE`, con
`rule_version=pgop1.doc-claims.evaluator.v1`, razón, cobertura y vínculos a hash,
snapshot, ámbito y posición cuando correspondan. No se implementa `STALE` ni
`execution_receipt_supports`: la edad de un documento no crea genealogía temporal.
Un `SUPPORTED` demuestra únicamente el predicado tipado y su alcance declarado.

## Ejemplo reproducible

Desde la raíz del clon, con Python 3.14 en `.venv`. El siguiente ejemplo construye
un catálogo manual sobre la afirmación de límites en `docs/LIMITATIONS.md`
(líneas 7–8), vinculada a `MAX_NODES` en `evidence_handoff.py` (línea 28).
El archivo de catálogo y la salida quedan fuera de las fuentes. El directorio
padre de salida debe existir; el directorio final debe ser nuevo.

```bash
mkdir -p ../v2-example
.venv/bin/python - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, 'runtime')
from candidate.document_claims_v1 import make_claim, typed, document_span, CATALOG_SCHEMA
from candidate.static_ast_v2 import canonical, digest
root = Path.cwd()
doc_name = 'docs/LIMITATIONS.md'
source_name = 'runtime/candidate/evidence_handoff.py'
doc_raw = (root/doc_name).read_bytes()
source_raw = (root/source_name).read_bytes()
doc = {'path':doc_name, 'sha256':digest(doc_raw), 'start_line':7, 'end_line':8,
       'span_sha256':digest(document_span(doc_raw, 7, 8))}
source = {'path':source_name, 'sha256':digest(source_raw)}
claim = make_claim('constant_equal', doc, source,
                   {'scope':'<module>', 'name':'MAX_NODES', 'definition_line':28}, typed(12000))
catalog = {'schema':CATALOG_SCHEMA,
           'sources':[{**source, 'kind':'python'},
                      {'path':doc_name, 'sha256':digest(doc_raw), 'kind':'document'}],
           'claims':[claim]}
body = canonical(catalog) + b'\n'
Path('../v2-example/CATALOG.json').write_bytes(body)
print(digest(body))
PY
```

Usá el hash impreso como `CATALOG_SHA256`:

```bash
.venv/bin/python tools/audit_source_v2.py --source-root . \
  --catalog ../v2-example/CATALOG.json --catalog-sha256 CATALOG_SHA256 \
  --output ../v2-example/report
.venv/bin/python tools/verify_source_v2.py --source-root . \
  --artifacts ../v2-example/report
```

El productor escribe `REPORT.json`, `FINAL_HANDOFF.md` y `MANIFEST.json` con
longitud y SHA-256 de los dos artefactos. El exit 0 de generación significa
`ARTIFACTS_WRITTEN`; se deben examinar los veredictos y `source_errors` del informe.
Un error de admisión, contrato o destino devuelve exit 2 y un diagnóstico fijo,
sin traceback ni texto de fuente. No sobreescribe una salida existente. Las
rutas se abren mediante descriptores sin seguir symlinks; el destino debe ser
disjunto de `source_root` y sus ancestros tampoco pueden ser symlinks.

En el productor, la fuente se decodifica y analiza solo en subprocesses con timeout de 6 segundos;
AST V2 mantiene sus presupuestos adicionales. La inspección de literales usa otro
worker acotado a los mismos bytes capturados. No hay aislamiento de memoria a
nivel SO. Las listas de fuentes y claims se ordenan antes del informe, y no se
incluyen relojes ni métricas variables en el artefacto semántico. El verificador
separado no importa este evaluador; comparte `ast` de CPython, por lo que no es
un parser independiente ni una certificación externa de la prosa. El verificador
analiza las fuentes en su propio proceso, sin timeout por fuente ni aislamiento
de memoria (`verifier_resource_isolation=NOT_IMPLEMENTED_NO_PER_SOURCE_TIMEOUT`).
Sus admisiones limitan fuentes a 262144 bytes y artefactos a 512 MB (handoff y
manifiesto: 1 MB). Una abstención histórica por timeout del worker de claims no
se autentica sin recibo: el verificador puede rechazarla si no logra corroborar
el mismo resultado; no convierte ese rechazo en una refutación del evento pasado.

Pruebas focalizadas:

```bash
.venv/bin/python -m unittest discover -s tests -p test_document_claims_v1.py -v
```

El verificador imprime JSON en stdout. Su `--output` opcional exige un archivo
nuevo fuera de `source_root` y del directorio de artefactos, y distinto de las
entradas `--report`/`--pages`. Rechaza archivos existentes y symlinks en cualquier
componente; nunca sobreescribe una fuente o un artefacto para guardar el resultado.
El padre del archivo de salida debe existir. Un destino inválido devuelve exit 1
y `INVALID_NEW_EXTERNAL_OUTPUT`, sin modificar los archivos existentes.
