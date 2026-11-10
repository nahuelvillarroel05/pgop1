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
Los archivos del motor, interfaces y tests conservan bytes originales: R1 se
reubica desde experiments/pgop1-tooling/baseline-public-r1 sin cambiar import roots.
experiment conserva rutas originales y reemplaza los módulos R1 por la evolución
admitida. El Context Engine se seleccionó expresamente del tree experimental.

Adaptaciones nuevas Apache-2.0: README raíz y public_profile/README.md sustituyen
presentación anterior; NOTICE acota el texto original al conjunto efectivamente
incluido, preservando la no atribución de autoría. Las herramientas de auditoría,
orquestación y ejemplos nuevos usan el API real. No se reimplementa el motor.
Las sustituciones documentales no se atribuyen a sus autores históricos.

La publicación de estas fuentes propias está autorizada por el Owner bajo la
licencia original Apache-2.0 (LICENSE, NOTICE). No se inventa titularidad exclusiva.
Dependencias fijadas se instalan aparte: no se redistribuyen wheels, SDK ni venv.
Sus licencias siguen aplicando; la auditoría registra metadatos instalados.
No se incluyen archivos privados, almacenes, transcripciones ni fuentes reservadas.
Los fixtures usan datos sintéticos y secretos simulados identificados como tales.
Las referencias a identidades históricas son metadatos, no genealogía Git nueva.
