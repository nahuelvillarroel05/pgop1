# PGOPCore Workspace

## Inicio y selección

La candidata 0.1.0a7 admite Windows 10 x64 build 19045, Python 3.14 y disco NTFS local. Ejecutá `pgop init` en la raíz elegida. También podés indicar una ruta relativa a CWD o absoluta. El resto de las operaciones de workspace busca el estado más cercano, hasta cinco ancestros, comprobando el marcador reservado y los límites de política. Un marcador inválido o inaccesible interrumpe la búsqueda. Init rechaza un workspace ancestro encontrado en su recorrido. No enumera descendientes para detectar estados existentes ni ofrece exclusión mutua entre raíces diferentes. La raíz del disco, el perfil del usuario y sus ancestros, directorios protegidos de la instalación, rutas de red, alias, enlaces y raíces con componentes sensibles quedan excluidos. Las rutas admitidas son ASCII, permiten espacios interiores y respetan el nombre canónico en disco.

| Comando | Acción |
| --- | --- |
| `pgop init [RUTA]` | Crea `.pgopcore` en la raíz, sin enumerar ni leer fuentes. Repetir comprueba el espacio existente. |
| `pgop scan --preview` | Enumera candidatos, topes y exclusiones sin leer sus cuerpos ni cambiar el registro. Combinable con `--refresh`. |
| `pgop scan` | Autoriza explícitamente el alta de los candidatos elegibles. Una versión ya registrada conserva su captura. |
| `pgop scan --refresh` | Autoriza nuevas altas y nuevas capturas de versiones inscritas que resulten elegibles. Una fuente anterior no admitida en el refresco conserva su versión previa para que verificación y búsqueda puedan informar su estado. No reactiva retiradas. |
| `pgop catalog [--offset N] [--limit N]` | Muestra el registro, incluidas retiradas, sin verificar cuerpos. |
| `pgop catalog remove ID` | Retira una ruta registrada hasta un nuevo espacio de trabajo. Repetir es idempotente. |
| `pgop search "texto exacto" [--ignore-case] [--all-matches] [--limit N]` | Busca en las fuentes activas registradas, en orden lexicográfico de ruta relativa. |
| `pgop verify` | Comprueba la identidad y los bytes de todas las fuentes activas registradas. |
| `pgop report create --query "texto exacto" [mismas opciones de búsqueda]` | Ejecuta la búsqueda y crea un informe JSON local, aun si la búsqueda fue parcial. |
| `pgop report show ID` y `pgop report read ID [--offset N] [--limit N]` | Verifican y recuperan el informe exportado. El segundo comando pagina su JSON canónico por carácter. |
| `pgop doctor` y `pgop status` | Muestran la instalación, la capacidad local y el registro observado sin verificar cuerpos. |

`search --file` mantiene su salida predeterminada v1 y admite rutas relativas validadas. `--examples`, `evidence ID`, `verify ID` y los informes históricos con ID de paquete y almacén explícitos conservan su perfil. El flujo nuevo jamás usa el catálogo histórico. Las fuentes son múltiples archivos de una única raíz elegida. Las rutas externas y las raíces adicionales quedan fuera del registro.

## Admisión y presupuestos

Una carpeta de proyecto con nombre visible puede estar debajo de un antecedente con punto ordinario, como `.gemini`. Se valida la cadena NTFS de la ruta elegida. La raíz no puede ser el contenedor con punto ni quedar en almacenes protegidos como `.git`, `.ssh`, `.aws`, `.codex`, directorios de agentes o dependencias. Durante el escaneo se excluyen subdirectorios con punto dentro de la raíz.

Archivos regulares `.txt`, `.md`, `.json`, `.py` y `.csv` en minúsculas, UTF-8 estricto, sin NUL ni controles binarios. Desde a10 el panel y el workspace admiten BOM UTF-8 inicial. Los hashes, tamaños y offsets siguen midiendo los bytes originales. JSON conserva los límites de estructura del extractor existente. La búsqueda del CLI trata Python y CSV como texto. Se excluyen nombres ocultos, sensibles y de dependencias o compilación, atributos NTFS oculto/sistema, redirecciones de proveedor, reparse points y hardlinks. Se aplican estas reglas aun si una fila editada apunta a una ruta excluida. La política nominal no identifica todos los secretos contenidos en archivos de texto elegibles.

Topes de scan: cinco niveles de subdirectorios, 1.024 caracteres por ruta relativa o absoluta, 1.000 entradas, 256 páginas nativas, 30 s cooperativos, 100 filas registradas incluidas retiradas y 8 MiB de corpus activo y de nuevas capturas intentadas por escaneo. Cada archivo tiene límite de 256 KiB y 16.384 líneas. Las exclusiones normales de política se cuentan. Un tope de exploración o admisión, nombre que no puede validarse, error de lectura o candidato rechazado tras la selección deja cobertura parcial. La previsualización clasifica metadatos, y el scan puede encontrar fallos adicionales al abrir el cuerpo. Los candidatos se visitan en profundidad y en orden lexicográfico; se ordenan los resultados antes de mostrarlos. Puede haber una página nativa ya leída cuando se agota un límite; ninguna fila de una página fallida se admite.

El catálogo requiere un escaneo explícito previo a búsqueda, verificación o informe. El alcance observado es el registro activo de una revisión. Archivos nuevos requieren otro scan. La consulta distingue mayúsculas y admite 1–256 caracteres y hasta diez resultados, una primera coincidencia por archivo. `--ignore-case` aplica un plegado ASCII, de modo que los caracteres no ASCII conservan sus bytes y casing. `--all-matches` aplica el tope global de citas en orden de ruta y de offset, con ocurrencias no solapadas. Los offsets son bytes UTF-8 con fin exclusivo, las líneas empiezan en 1 y ambos extremos son inclusivos. Se cuentan todas las coincidencias verificadas, incluidas las que quedan sin cita. Se revalida cada fuente observada en una segunda pasada y se eliminan citas de fuentes que ya no coinciden. El tope total lógico esperado de dos pasadas es 16 MiB, con plazo cooperativo de 30 s. El informe y los resultados son observaciones de intervalos individuales, sin snapshot multiarchivo atómico ni vigencia futura. Una operación síncrona del sistema operativo podría superar el plazo cooperativo.

## Estado y publicación

El ejecutable obtiene la raíz de la invocación y abre la cadena NTFS por handles. El estado exige identidad concordante de raíz, estado, registro, candado y almacén. Cada fila contiene ruta relativa, ID estable de ruta, identidad física, tiempos, tamaño, SHA-256, política y fecha; los cuerpos no se copian al registro. Una raíz distinta o un directorio de estado trasplantado falla antes de leer una fuente. El registro no selecciona ubicaciones externas ni modifica la política del ejecutable.

Un candado nativo excluye cambios de catálogo durante búsquedas o informes; las lecturas pueden compartirlo. Una mutación captura y coteja un archivo nuevo, después publica un marcador de directorio nuevo que vincula la generación con el SHA-256 del archivo. Un borrador anterior a la publicación queda preservado y carece de autoridad. Se comprueban continuidad, nombres y tipos de marcadores y presencia de todos los borradores publicados. Se verifica el hash y esquema de los bytes de la revisión activa. Los cuerpos del diario histórico permanecen fuera de la lectura normal. Hay como máximo 512 entradas de diario; al agotarlas se informa el límite y se conserva el estado. Se confía en la cuenta local y el host. Los hashes detectan incoherencias, no autentican a un adversario con escritura y capacidad de sustituir estado y hashes de forma coherente. El borrado deliberado de la cola del diario no dispone de un ancla externa antirretroceso. Las exclusiones y la validación de raíz se aplican independientemente del diario. La retirada afecta esta instalación del workspace, sin revocación global.

Las exclusiones por formato o hardlink admiten hasta 100 rutas relativas de nombres no sensibles en la salida. Las exclusiones de nombres sensibles, ocultos o entradas con atributos inseguros quedan en motivos y conteos.

Los informes son archivos JSON canónicos de hasta 512 KiB en `.pgopcore/reports`. Su ID `ws-report-<sha256>` vincula los bytes completos; el propio contenido identifica esquema, consulta, política, fuentes por estado, exclusiones de política observadas, citas, cobertura y tiempo. La creación exclusiva conserva informes previos. Mostrar y leer verifican identidad de almacén, tamaño, contenido, esquema e ID. La consulta del informe mide consistencia e integridad de bytes. Su autoría, vigencia, validez semántica y ejecución quedan sin evaluar. Un archivo incompleto o alterado falla la recuperación. Una copia legítima del informe puede conservarse fuera del workspace.

a7 abre el estado a6 en su raíz original y mantiene el anclaje `pgop.workspace.v1` y las filas `local-ntfs-text-v1`. Para admitir `.py` o `.csv`, ejecutá un nuevo scan. Sólo esas filas usan `local-ntfs-text-v2` en una revisión nueva. Los informes v1 se leen con su contrato histórico incluso si la fuente cambió. Los informes v2 se leen con a7. Para probar ambas versiones sin afectar tu recuperación, usá workspaces separados o consultá el workspace a6 con a7 antes de escribir. Conservá a7 para un workspace cuyo registro ya incluye formatos nuevos. Para volver a operar en a6, usá un workspace independiente y registrá allí sus formatos v1.

a10 conserva las filas v1/v2. Las nuevas capturas con BOM usan
`local-ntfs-text-utf8-bom-v3`. Usá un workspace independiente para operar
con una versión anterior después de admitir archivos con esa política.
`pgop search --file` mantiene el contrato anterior sin BOM.

## Salidas

`--json` antes del comando produce un objeto. `doctor/status/catalog` conservan `pgop.product.v1` donde ya aplicaba y añaden datos para un registro válido. Las operaciones nuevas usan `pgop.workspace.v1` con `command`, `outcome`, `native_code` y `data`. Las opciones nuevas de matching usan `pgop.workspace-search.v2` para workspace y `pgop.search.v2` para archivos explícitos con opciones. Los informes nuevos usan `pgop.workspace-search-report.v2` y el lector conserva el esquema v1. Códigos:

- **0** operación completada, `FOUND`, `NO_MATCH` dentro del alcance registrado, `PASS` de verificación o consulta informativa. Una verificación sin fuentes activas devuelve EMPTY.
- **2** uso, plataforma/ruta incompatible, falta de init/scan o argumento inválido.
- **3** cobertura `PARTIAL`, salida `TRUNCATED` o integridad del estado/informe `STALE`. El detalle por fuente distingue cambio, ausencia y permiso.
- **4** acceso al estado o informe denegado, recurso no disponible o workspace ocupado. Reintentar después de cerrar la otra operación.
- **1** fallo interno de instalación o ejecución.

Los mensajes de terminal escapan controles de texto recuperado. Los datos de fuente son contenido sin autoridad ni ejecución.

## Criterios de hitos

- H0 — base, árbol, wheel y recibos cotejados, contrato y matriz W01–W18 fijados antes del diseño ejecutable.
- H1 — W02–W06 para selección y estado, pruebas de autorización, transacción y exclusión. Examen crítico de Astra.
- H2 — W07–W12 y W16, wheel en venv, separación de demo, verificación, regresiones y cierre de citas. Examen crítico de Astra.
- H3 — W01 y W13–W18, informe recuperable desde otro proceso, medición técnica en CMD y PowerShell, rueda y fuente exactas, revisión final. Cero participantes humanos hasta una prueba humana.


La resolución del perfil efectivo usa el directorio de perfiles de Windows y el perfil registrado del token cuando existe. Los atributos de fuente se consultan antes y después de la captura; Windows puede cambiar atributos entre observaciones. El conteo de entradas decodificadas puede superar las entradas debitadas en la última página.
