# Procedencia y licencia

Fuente histórica pública: https://github.com/nahuelvillarroel05/package-g-op1-reusable

| Selección admitida | Commit | Tree |
|---|---|---|
| R1 main | 95400648833c63277039be87e12d18954e0fc1e3 | c969b97177f5f0bd892ed22d8ab6d3546d272acb |
| experiment | 2714ae3c5dca079db696f98a01ba10fbfce9a356 | 66524db2181a60904fd715776964eadb42c5750a |

Estos candidatos fueron preparados localmente; su presencia remota no se afirma.
La nueva raíz es una selección, no la historia original de desarrollo.
manifests/SOURCE_PROVENANCE.json fija por archivo original ruta, commit, tree,
OID, SHA-256 y transformación. El verificador de distribución vincula los bytes
actuales con PUBLIC_SOURCE_MANIFEST y el inventario externo de todos los objetos.
Los archivos R1 reubicados desde experiments/pgop1-tooling/baseline-public-r1
conservan sus bytes originales cuando el manifiesto los declara idénticos.
La alfa adapta únicamente la importación de la fábrica pública en i7_api
para empaquetarla en un espacio de nombres propio junto al motor público.
CLI-002 conserva la fábrica, los agregados y el formato de informes. Añade
un adaptador de terminal y refuerza en el motor público la comprobación de
identidad y la entrega de los mismos bytes verificados al leer un informe.
El manifiesto de fuentes registra los bytes prospectivos de esta revisión.
CLI-003 reutiliza el motor literal, la adquisición de texto y los controles
nativos de archivos del commit `5543d0a7b000b15ea09beb95efa67745faf8975a`,
árbol `d9dec558c7bfd0c3a8e478001ce8fdbab5364725`. La wheel conserva los
módulos seleccionados en el espacio privado `pgopcore.runtime.candidate`.
La adquisición mantiene el mapa de seis huellas y distingue errores de su
propio código de errores de la fuente. La búsqueda usa el mismo algoritmo
literal y readquisición, con una clase de entrada extraída del módulo de
memoria y diagnósticos acotados. El adaptador local establece una concesión
en memoria de un solo archivo. Los módulos y hashes de procedencia quedan
identificados en el manifiesto.
CLI WORKSPACE 006 conserva los motores de lectura segura y extracción de a5.
La enumeración añade un modo de metadatos para excluir nombres no admitidos
sin descartar automáticamente otros archivos de la misma carpeta. El motor
literal comparte la primera posición y el conteo entre las dos rutas CLI.
El manifiesto conserva los anclajes previos y fija ambas adaptaciones locales.

experiment conserva rutas originales y reemplaza los módulos R1 por la evolución
admitida. El Context Engine se seleccionó expresamente del tree experimental.

Adaptaciones nuevas Apache-2.0: README raíz y public_profile/README.md sustituyen
presentación anterior; NOTICE acota el texto original al conjunto efectivamente
incluido, preservando la no atribución de autoría. Las herramientas de auditoría,
orquestación y ejemplos nuevos usan el API real. No se reimplementa el motor.
Las sustituciones documentales no se atribuyen a sus autores históricos.

La publicación de estas fuentes propias está autorizada por el Owner bajo la
licencia original Apache-2.0 (LICENSE, NOTICE). No se inventa titularidad exclusiva.
Los perfiles históricos instalan sus dependencias aparte. El kit offline de
0.1.0a12.post3 incluye la wheel del núcleo Apache-2.0 y nueve wheels de
presentación con sus propios avisos, licencias y lock. El NOTICE histórico
contenido en la wheel aprobada describe el núcleo. El NOTICE de esta raíz
también indica la separación de los componentes visuales.
No se incluyen archivos privados, almacenes, transcripciones ni fuentes reservadas.
Los fixtures usan datos sintéticos y secretos simulados identificados como tales.
Las referencias a identidades históricas son metadatos, no genealogía Git nueva.

## Procedencia de 0.1.0a12.post3

Context Engine Local deriva del Engine histórico de Search003 mediante los
módulos propios `context_local.py` y `context_local_store.py`. Conserva el
direccionamiento por hash, la vinculación de fragmentos y la procedencia.
Su diario y catálogo local tienen una autoridad distinta de Bridge.
[Origen y transformaciones](CONTEXT_LOCAL_POLICY.md)

El [recibo](../RELEASE_RECEIPT.json) fija la identidad del build local. Para
reproducir su wheel byte por byte se requiere el árbol original de compilación.
Reconstruir desde el árbol público actualizado puede generar otros metadatos
porque el README forma parte de la wheel. La entrega distribuye la wheel
aprobada, con el NOTICE original y el hash congelado.

Las dependencias visuales incluidas son linkify-it-py, markdown-it-py,
mdit-py-plugins, mdurl, platformdirs, Rich y Textual bajo MIT, Pygments
bajo BSD-2-Clause y typing_extensions bajo PSF-2.0. El inventario enlaza cada
wheel con su versión, SHA-256 y avisos. Los avisos del kit retienen sus bytes
originales. [Inventario](../releases/windows/0.1.0a12.post3/PRESENTATION_DEPENDENCIES.json)
· [Licencias](../releases/windows/0.1.0a12.post3/licenses/)
