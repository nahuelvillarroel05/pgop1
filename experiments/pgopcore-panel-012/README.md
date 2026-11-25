# PGOPCore · evolución experimental del panel 009–012

Este informe reúne las capacidades observadas en el desarrollo del panel y sus límites. El producto instalable y su código corresponden al árbol fijado de `main`. Los motores y resultados históricos de esta rama conservan sus propias identidades.

[Código del producto](https://github.com/nahuelvillarroel05/pgop1/tree/cc8384055a2a536155a5fc3a5945a8ba997a5f79/cli/pgopcore) · [Kit de Windows](https://github.com/nahuelvillarroel05/pgop1/tree/cc8384055a2a536155a5fc3a5945a8ba997a5f79/releases/windows/0.1.0a12.post3) · [Recibo de versión](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/RELEASE_RECEIPT.json)

## Evolución

| Entrega | Capacidad observada | Alcance |
| --- | --- | --- |
| 009 · a9.post1 | Comprender un proyecto desde documentación, explorar unidades, buscar texto literal, exportar y revalidar. | T1–T5 aprobados y tres tareas nuevas revisadas. Aislamiento estricto pendiente. |
| 010 · a10.post2 | AST V2 de Python en un subproceso acotado y reapertura de Markdown verificado en su bloque de evidencia. | Pase parcial. Context Engine histórico pendiente de concesiones independientes. |
| 011 · a11.post1 | Cinco pestañas, navegación directa, confirmaciones de lectura, modalidad lineal y TUI. | ConPTY y consola clásica de Windows probadas. Piloto del propietario pendiente. |
| 012 · a12.post3 | Filtro por nombre parcial, extensión o carpeta, ayuda contextual y Context Engine Local persistente. | Cuatro tareas simuladas completas y piloto con alcance. |

El panel final integra vistas de Markdown, TXT, Python, JSON y CSV, búsqueda literal y por nombre, verificación de fuentes, informes Markdown/JSON y contexto local. Mantiene los resultados históricos accesibles desde la demo explícita. [Uso del panel y CLI](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/docs/CLI.md)

## Context Engine histórico y Context Engine Local

| Dimensión | Context Engine de investigación | Context Engine Local en a12.post3 |
| --- | --- | --- |
| Autoridad | Los flujos de Bridge del linaje exigen catálogo, política y concesiones con pins externos. | `LOCAL_OPERATOR_CONSENT` ligado al proyecto, fuentes, selectores y destino. Custodia independiente `NOT_PROVEN`. |
| Almacenamiento | Objetos y observaciones inmutables, snapshots y SQLite derivada para recuperación y relaciones. | Diario persistente encadenado, objetos direccionados por hash y catálogo en memoria reconstruible. |
| Recuperación | Las condiciones del perfil histórico determinan la admisión y reevaluación. | Revalida por archivo al recuperar y al abrir cada referencia. Un cambio o fallo de comprobación oculta el cuerpo de la versión. |
| Cobertura | Motor de investigación y perfiles históricos de la rama. | 128 versiones, cuatro proyectos, ocho referencias de hasta 8 KiB por contexto. El grafo general y la búsqueda híbrida o semántica quedan fuera del perfil local. |

El adaptador y almacén locales son una derivación propia del linaje Search003. El motor que conserva esta rama es el [Context Engine histórico](https://github.com/nahuelvillarroel05/pgop1/blob/52813dc77ead9a04ed1c08f96e46de53efeec9d2/runtime/candidate/context_engine.py). Las anclas de Search003 y la correspondencia de contratos figuran en la [política de contexto local](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/docs/CONTEXT_LOCAL_POLICY.md). La revocación local es lógica y conserva bytes. El diario carece de ancla externa contra rollback integral y la revalidación carece de snapshot multiarchivo atómico y de garantía de vigencia futura.

## Resultados de 012

Serie tranquila en Windows 10 x64 build 19045, Python 3.14 y NTFS local. Se alternó el orden.

| Mediana | a11.post1 | a12.post3 | Observaciones por versión |
| --- | ---: | ---: | ---: |
| Apertura instalada | 966 ms | 850 ms | 10 |
| Cambio de pestaña | 34,5 ms | 37,8 ms | 10 |
| Primera instalación | 12,48 s | 14,20 s | 3 |

Los recibos del contexto instalado registraron 13 operaciones satisfactorias y 13 controles negativos en 26 procesos. Se registraron 69 regresiones aprobadas. Las cuatro tareas simuladas se completaron en 10, 16, 18 y 60 entradas, con una dentro del presupuesto de 12. La separación fue procedimental. El propietario informó mejora y la aceptación humana completa siguió pendiente. La serie describe uso y tiempos bajo esas condiciones, con superioridad, eficacia general y ahorro de tokens sin establecer.

## Reproducción y procedencia

La [demo de investigación](https://github.com/nahuelvillarroel05/pgop1/tree/1dca71b232d0c517a4379abeb3661e67caddea49/examples/source-audit-synthetic) mantiene su ancla histórica. Para comprobar el flujo local, instalá el [kit fijado](https://github.com/nahuelvillarroel05/pgop1/tree/cc8384055a2a536155a5fc3a5945a8ba997a5f79/releases/windows/0.1.0a12.post3), verificá `--version` y `context --help` y usá `preview`, `save` y `get` con un archivo de prueba propio y un almacén separado. La guía documenta la confirmación y la salida JSON. [Guía de contexto](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/docs/CONTEXTOS_LOCALES.md)

El [recibo del producto](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/RELEASE_RECEIPT.json) identifica el build de a12.post3, la wheel y las anclas de métricas. El producto y las ruedas de presentación se distribuyen desde `main`. El núcleo conserva Apache-2.0 y las nueve dependencias visuales conservan cada una su licencia y avisos según el [inventario del kit](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/releases/windows/0.1.0a12.post3/PRESENTATION_DEPENDENCIES.json). [Procedencia](https://github.com/nahuelvillarroel05/pgop1/blob/cc8384055a2a536155a5fc3a5945a8ba997a5f79/docs/PROVENANCE.md)

R1 conserva su alcance, anclas y veredictos históricos. GATE_11 sigue bloqueado, I7 formal incompleto y Physical C2 `DEFERRED_NOT_WAIVED`.
