# Referencia de pgop · 0.1.0a12.post3

Abrí el kit con `pgop-panel.cmd` desde la carpeta copiada. Para las operaciones de esta guía, podés reemplazar `pgop` por `pgop-panel.cmd` en CMD o `.\pgop-panel.cmd` en PowerShell. `--version` identifica la distribución instalada. [Instalación offline](WINDOWS_INSTALL.md)

El panel usa las pestañas **Inicio**, **Archivos**, **Buscar**, **Informes** y **Verificar**. Las teclas 1–5 cambian de pestaña, F1 muestra ayuda y 0/Esc vuelve. `--plain` abre la modalidad lineal. Los subcomandos con JSON pueden usarse sin el panel.

## Panel interactivo

`pgop` abre el panel si la entrada y la salida son una terminal. Con una
tubería o salida redirigida muestra ayuda y sale con código 0. Usá los
subcomandos y `--json` para automatizar sin interacción.

**¿Qué es PGOPCore?** explica la lectura, búsqueda y verificación local antes
de elegir una carpeta. **Abrir proyecto o archivo** acepta la ruta de un archivo
compatible. También podés elegir un archivo de la vista previa del proyecto.
Ambas selecciones piden confirmación antes de leerlo. La captura individual
queda en la sesión. El registro de fuentes se confirma por separado.
Enter abre la vista previa de la carpeta actual. El panel conserva el
directorio de la consola y aplica las rutas y los límites del
[contrato de workspace](WORKSPACE_CONTRACT.md), además de excluir el entorno
Python y la ubicación del lanzador.

**Comprender el proyecto** inspecciona metadatos en la raíz y carpetas
habituales de documentación y código. Podés elegirlo al abrir la carpeta,
antes de registrar fuentes. Tras confirmar la selección visible, lee una
muestra de hasta seis archivos. Muestra el propósito documentado cuando
encuentra una fuente pertinente, las áreas y formatos observados y la
cobertura. Cuando el propósito proviene de Markdown, ofrece las secciones
completas de ese documento desde el resumen. Los posibles puntos de entrada
se identifican por nombre.

**Explorar archivos** ofrece Markdown por secciones. El panel distingue
metadatos iniciales delimitados por `---` y cerrados con `---` o `...` si
contienen claves planas, únicas y valores simples en una línea. Admite texto
plano, cadenas entre comillas y listas en línea de estos valores. Los demás
preámbulos con forma de metadatos se muestran como texto literal. Python se analiza
con AST V2 aislado en un subproceso, con presupuesto y un máximo de seis
segundos. Podés abrir ámbitos, declaraciones completas e imports declarados.
La vista por líneas sigue disponible ante sintaxis inválida o análisis
incompleto. JSON conserva lexemas numéricos y referencias JSON Pointer.
CSV admite coma, punto y coma, tabulación y barra vertical, con selección
manual si el delimitador es ambiguo. La vista CSV admite hasta 4.096
registros, 128 columnas y 32.768 celdas. En listas y unidades largas, `n` y
`p` cambian de página y `0` vuelve.

**Buscar información y evidencia** recupera coincidencias literales con
contexto en el registro o en un archivo abierto. Podés acotar la ruta y el
formato y elegir el plegado ASCII. El panel prioriza una cita por archivo
antes de mostrar una segunda del mismo archivo. Las citas permiten
revalidar y abrir la sección Markdown, la declaración Python o la fila CSV
que contiene la coincidencia, si está disponible. Los conteos incluyen las
coincidencias comprobadas que quedan fuera del tope de diez citas.

**Ver o guardar informes** exporta una selección, un resumen del proyecto
o una búsqueda como `INFORME.md` y `INFORME.json` (`pgop.panel-report.v3`).
El Markdown abre con objetivo, resultado y evidencias. Si hay un registro,
podés guardar en su almacén. También podés indicar una carpeta existente
y separada. La publicación crea un directorio de informe nuevo,
con verificación de bytes y un marcador final. Un intento interrumpido puede
dejar archivos parciales, que el panel rechaza al reabrir. Podés reabrir
informes del proyecto desde su lista o dar la ruta de una exportación externa.
Las referencias corresponden a los bytes capturados en el momento indicado.
Al reabrir, se coteja el Markdown con la proyección exacta del JSON ligado
al ID. Al guardar una unidad completa, el panel abre el Markdown verificado
en la evidencia, con el archivo, el rango y el texto que se guardó. Desde
esa vista se puede leer el Markdown completo desde el comienzo. Las unidades
largas se muestran en varias páginas. Los informes v2 conservan su
proyección exacta. Para v1 se puede leer el JSON verificado y una vista
Markdown regenerada desde ese JSON.

El panel escapa controles de pantalla y bloquea contenido con indicadores de
credenciales conocidos. Revisá qué fuentes autorizás y solo exportá a un
destino bajo tu control. La wheel conserva los agregados de demostración
exigidos por los comandos históricos explícitos. Las operaciones normales
del panel y `doctor` usan el código local y las fuentes elegidas.

En **Archivos**, el filtro por nombre parcial, extensión o carpeta se aplica antes del tope de candidatos. **Buscar** distingue nombres y texto literal. TXT se abre por líneas. **Verificar** muestra el estado y la cobertura de las fuentes registradas.

## Contextos locales

Desde una unidad abierta, añadí una referencia al borrador. En **Informes → Guardar contexto**, revisá las selecciones y confirmá el destino. El diario conserva versiones y permite recuperarlas después de reiniciar. La apertura individual recaptura todas las fuentes. Usá `pgop context --help` para ver `preview`, `save`, `list`, `get` y `revoke`. En modo JSON, pasá `--json` al subcomando. `preview` vincula la confirmación al proyecto, destino y selecciones que `save` vuelve a comprobar. [Guía](CONTEXTOS_LOCALES.md) · [Contrato](CONTEXT_LOCAL_POLICY.md)

## Espacios de trabajo

Desde la raíz elegida, `pgop init` crea el estado y `pgop scan` registra
archivos elegibles. `pgop scan --preview` enumera sin abrir cuerpos y
`pgop scan --refresh` revalida para registrar versiones nuevas.
`pgop catalog remove ID` retira una fuente del registro activo.

`pgop search "texto exacto" --limit 10` cita el primer hallazgo de cada
fuente vigente. `pgop verify` comprueba identidad y bytes de las fuentes
inscritas. `pgop report create --query "texto exacto"` guarda en
`.pgopcore/reports`. `report show ID` verifica el informe completo y
`report read ID --offset N --limit N` entrega una página. Los informes
conservan el estado de cada fuente durante la búsqueda que los originó.
`--json` antes del comando devuelve un objeto versionado. Los topes, estados,
códigos y alcance están en el [contrato](WORKSPACE_CONTRACT.md).

| Operación | Resultado |
| --- | --- |
| `pgop doctor` | Comprueba metadatos y punto de entrada de la distribución, Python y los prerrequisitos nativos y archivos instalados del motor literal. |
| `pgop status` | Muestra la instalación y el estado del espacio de trabajo. La demo se indica como disponible bajo petición, con sus archivos sin comprobar. |
| `pgop catalog [--offset N] [--limit N]` | Muestra el registro de recursos propios, en el directorio actual. Posición inicial entre 0 y 100000, predeterminada 0. Página de 1 a 20, predeterminada 10. |
| `pgop doctor --examples`, `pgop status --examples`, `pgop catalog --examples` | Recuperan el diagnóstico, el perfil y el listado de la demostración congelada con el esquema histórico. Conservan los argumentos de paginación de `catalog`. |
| `pgop evidence ID` | Devuelve las métricas y sus denominadores y localizadores, junto con el estado de la verificación actual y la declaración histórica. |
| `pgop verify ID` | Coteja hashes y consistencia de determinados conteos. Devuelve cobertura, causas, snapshot y recibo. El recibo se muestra en la salida y no se guarda. |
| `pgop report create ID --request-key CLAVE --store RUTA` | Verifica el paquete y genera un informe local para el recibo actual. Devuelve el `report_id` y el estado de integridad del paquete. |
| `pgop report show ID --store RUTA` | Comprueba los artefactos guardados y muestra su lista y el hash del manifiesto. |
| `pgop report read ID --store RUTA` | Lee una página del artefacto histórico verificado. |
| `pgop search LITERAL --file RUTA` | Recupera la primera coincidencia literal de un archivo elegido para esa ejecución. |

Los IDs admiten de 1 a 80 caracteres ASCII. El primero es alfanumérico, y los
demás pueden ser también guion y guion bajo. El paquete de demostración incluido es
`RUN012_PUBLIC`. Los hashes corresponden a archivos registrados y a un
snapshot puntual. Los datos históricos conservan su estado original y su
cobertura; su consulta no repite tests ni certifica conclusiones semánticas.

## Informes del perfil histórico

Usá una ruta absoluta de un disco local, en un directorio privado de tu usuario.
Puede contener espacios y caracteres como `ñ`. `create` crea las carpetas
faltantes. Usá el mismo `--store` para las tres operaciones. Elegí una ruta
fuera del entorno Python, de los recursos instalados y de cualquier checkout Git.
Los componentes con enlaces o puntos de reanálisis, las rutas de red y las rutas
con `..` se rechazan.

```text
pgop --json report create RUN012_PUBLIC --request-key primer-informe --store "D:\Mis informes ñ"
```

Copiá el valor `data.report_id`. Pasalo a `report show` o `report read` como ID.
`read` admite `--artifact FINAL_HANDOFF.md` (predeterminado), `REPORT.json`
o `MANIFEST.json`. En JSON, `data.content` contiene el texto exacto de la página.
Pedí las páginas siguientes con `--offset` igual al `data.next_offset` anterior
hasta que valga `null`. `--offset` cuenta caracteres desde 0 y admite hasta
262144. `--limit` admite 1 a 16000, con 8000 por defecto. Conservá el hash del
artefacto si comparás páginas entre procesos.

Repetir una clave con el mismo paquete y recibo devuelve el mismo ID.
Si cambió el recibo, una clave ya utilizada da `REQUEST_KEY_CONFLICT`.
Los intentos incompletos permanecen en el almacén y devuelven
`ATTEMPT_IN_PROGRESS_OR_INTERRUPTED`. Usá otra clave para un intento nuevo.
`REPORT_GENERATED` describe la creación. Un informe puede conservar un
`verification.status` de `FAIL` o `PARTIAL` y salir con código 3.

`show` y `read` funcionan con permisos de solo lectura. Comprueban la
consistencia de los artefactos históricos con el marcador local. Usá un
directorio y ancestros bajo control de tu usuario. El marcador de
finalización no acredita durabilidad ante una caída del sistema, autoría
externa ni autoridad vigente de las fuentes.

## Búsqueda en un archivo explícito

`pgop search "cita exacta" --file "fuente.txt" --ignore-case --limit 10 --json`
lee una fuente regular local en Windows 10 cliente x64, build 19045, sobre
disco fijo NTFS. Usá la escritura canónica, con mayúsculas y minúsculas
exactas en los nombres, y rutas ASCII para el archivo y la instalación.
Se rechazan enlaces simbólicos, junctions, enlaces duros, puntos de
reanálisis, rutas de red, ADS, alias y componentes protegidos como `.git`.
Elegí una carpeta que quede fuera del árbol del paquete instalado y de
sus ancestros directos.

Admite `.txt`, `.md`, `.json`, `.py` y `.csv` en UTF-8 sin BOM, bytes NUL ni controles
binarios. `.json` exige sintaxis válida y acotada. El archivo admite hasta
262144 bytes y 16384 líneas. Python y CSV se leen como texto. El literal admite
1–256 caracteres. Por defecto distingue mayúsculas y devuelve la primera cita.
`--ignore-case` pliega sólo ASCII A–Z. Con `--file`, `--limit N` devuelve hasta N citas
en orden de offset, de 1 a 10. `truncated` y
`remaining_occurrences` informan las ocurrencias adicionales omitidas.
Las líneas son inclusivas y comienzan en 1, con CRLF, LF o CR como separadores.
Los offsets en bytes empiezan en 0 y el final es exclusivo.

`--file` autoriza sólo el archivo explícito durante esa ejecución. Se
comprueban permisos, identidad y hash al capturar y revalidar. Si el acceso
se pierde o el archivo cambia durante la operación, se descarta el resultado.
Una búsqueda posterior vuelve a solicitar y comprobar la fuente. El hash
corresponde a los bytes leídos. El resultado cubre el intervalo de lecturas
de esa ejecución. La validez semántica y la vigencia posterior quedan sin
evaluar. La búsqueda trabaja sin índices, modelos o servicios.

Los esquemas JSON `pgop.search.v1` (predeterminado) y `pgop.search.v2`
(para resultados válidos con `--ignore-case` o `--limit`) aceptan `--json` antes o después de
`search`. Escribe un objeto UTF-8 con `schema_version`, `status`,
`results`, `source`, `limitations` y `error`. Los resultados incluyen
un instante UTC y el alcance de integridad. Los errores conservan el sobre v1. `results` queda
vacío, `source` es `null` y `error` contiene el código de diagnóstico.
La salida redirigida usa UTF-8. Configurá el lector de la salida con esa
codificación si tu entorno de automatización presupone otra.

| Código | Estados de `search` |
| --- | --- |
| 0 | `FOUND` o `NO_MATCH` con fuente comprobada. |
| 2 | `INVALID_SOURCE` o `UNSUPPORTED_PATH`. |
| 3 | `STALE` por cambio, conflicto o desaparición durante la operación. |
| 4 | `FILE_NOT_FOUND` o `PERMISSION_DENIED`. |
| 1 | `INTERNAL_ERROR` de lectura o de instalación. |

## JSON y códigos de salida de producto

`pgop --json doctor`, `pgop --json status` y `pgop --json catalog` devuelven
un objeto `pgop.product.v1` con `schema`, `command`, `outcome`, `native_code`
y `data`. `native_code` es `null` cuando el resultado carece de diagnóstico.

| Resultado | Código | Alcance |
| --- | --- | --- |
| `READY` | 0 | El preflight local del motor literal pudo ejecutarse y los archivos fijados coinciden. |
| `READY_WITH_LIMITS` | 0 | La instalación es accesible. El motor literal carece de plataforma compatible. |
| `NOT_CONFIGURED` | 0 | No hay registro ni espacio de trabajo configurado. Elegí un archivo con `search --file`. |
| `USAGE_ERROR` | 2 | Error de argumentos. |
| `FAILED` | 4 o 1 | Componente de instalación o motor defectuoso (4), o error inesperado (1). |

El preflight valida archivos del motor, el ABI y el mínimo de Python. La
lectura y la vigencia de un archivo propio se comprueban al ejecutar
`search --file` o las operaciones de workspace que observan el registro.

## JSON y códigos de salida del perfil público

Pasá `--json` antes del subcomando, por ejemplo
`pgop --json evidence RUN012_PUBLIC`. Con esta opción se emite un único
objeto JSON UTF-8 en stdout y los diagnósticos adicionales se emiten en stderr.
Ayuda y versión siempre salen como texto humano, incluso con `--json`.
`pgop --json` sin subcomando devuelve un error de uso en JSON.

Si una automatización leía `pgop.result.v1` de `doctor`, `status` o
`catalog`, agregá `--examples` al subcomando. `evidence`, `verify` y
`report` conservan sus argumentos y datos en ese esquema. El envoltorio
añade un aviso a la lista `limitations` para identificar la demostración.
`pgop report read` conserva el texto original de cada artefacto.

| Campo | Tipo en `pgop.result.v1` |
| --- | --- |
| `schema` | Cadena fija `pgop.result.v1`. |
| `command` | Cadena con el subcomando, o `null` si el parser no pudo resolverlo. |
| `profile`, `scope` | Cadenas `public-aggregate-v1` y `PUBLIC_AGGREGATES_ONLY`. |
| `outcome` | Cadena. Resultado de esta invocación: `COMPLETED`, `USAGE_ERROR`, `VERIFICATION_INCOMPLETE`, `UNAVAILABLE` o `ERROR`. |
| `native_status` | Cadena de estado del backend, o `null` si no aplica. |
| `native_code` | Cadena de error del backend, o `null` si no aplica. |
| `data` | Objeto con el resultado de la operación, o un diagnóstico `message` en errores sin resultado. Los valores y estados históricos pertenecen a este objeto. |
| `limitations` | Lista de cadenas con el alcance interpretativo de la operación. |

| Código | Significado |
| --- | --- |
| 0 | Operación completada. Cuando hay verificación actual, el resultado es `PASS`. |
| 2 | Error de uso, argumento inválido o ID desconocido. |
| 3 | Verificación actual `FAIL` o `PARTIAL`, o error de integridad de un informe local. Consultá el estado y el código nativo. |
| 4 | Un problema de acceso, fuente o configuración impidió obtener el resultado. |
| 1 | Error inesperado, con un mensaje que omite detalles privados. |

`UNKNOWN` y `NOT_VERIFIED` conservan su significado dentro de los datos.
Una fuente perdida puede producir 3 si el backend devuelve un recibo parcial.
En el [script anterior](TOOLS.md), un resultado de dominio `FAIL` o
`PARTIAL` aún puede salir con 0. Los códigos de esta página corresponden a
`pgop`.
