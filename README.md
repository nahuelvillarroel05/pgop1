# PGOPCore · alfa pública 0.1.0a12.post3

PGOPCore ayuda a encontrar, leer y volver a comprobar evidencia de un proyecto local. Podés buscar una cita, abrir su ubicación en el archivo, guardar referencias y exportar un informe con las fuentes y el alcance de la comprobación.

## Instalar y abrir en Windows

La configuración probada es **Windows 10 x64 build 19045, NTFS local y Python 3.14** disponible mediante `py`. En GitHub, elegí **Code → Download ZIP** en `main` o cloná el repositorio. Copiá completa la carpeta [releases/windows/0.1.0a12.post3](releases/windows/0.1.0a12.post3/) a una carpeta local independiente. Abrí **pgop-panel.cmd** desde esa copia. La primera apertura instala las wheels incluidas en un entorno propio y offline.

Usá `pgop-panel.cmd --plain` para la modalidad lineal. Para scripts y agentes, el mismo lanzador acepta subcomandos y salidas JSON. [Instalación](docs/WINDOWS_INSTALL.md) · [Referencia CLI](docs/CLI.md)

## Usar el panel

| Tecla | Pestaña | Operación |
| --- | --- | --- |
| 1 | Inicio | Elegir un proyecto o archivo y revisar su vista previa. |
| 2 | Archivos | Filtrar por nombre parcial, extensión o carpeta y confirmar la lectura. |
| 3 | Buscar | Buscar por nombre o por texto literal y abrir la evidencia. |
| 4 | Informes | Consultar observaciones, exportar o abrir informes y guardar o recuperar contextos locales. |
| 5 | Verificar | Comprobar el registro, las fuentes y la cobertura. |

**F1** abre la ayuda de la vista y **0/Esc** vuelve. Se admiten Markdown por secciones, TXT por líneas, Python con AST V2 y vista por líneas, JSON por valores y CSV por filas y celdas. Inspeccionar una declaración de Python no ejecuta el archivo. [Formatos y topes](docs/CLI.md#panel-interactivo)

Para guardar contexto, elegí referencias dentro de los archivos y revisá el borrador en **Informes → Guardar contexto**. Confirmá nombre, propósito y un almacén local separado. Después de reiniciar, recuperá el contexto desde el mismo proyecto. La recuperación y la apertura individual vuelven a comprobar todas las fuentes. [Guía de contextos](docs/CONTEXTOS_LOCALES.md)

## Evidencia y alcance

En Windows, la apertura instalada pasó de 966 a 850 ms de mediana (10 por versión). El cambio de pestaña pasó de 34,5 a 37,8 ms y la primera instalación, de 12,48 a 14,20 s (3 por versión). Se registraron 69 regresiones aprobadas y 26 procesos de contexto, 13 satisfactorios y 13 controles negativos. Las cuatro tareas simuladas terminaron en 10, 16, 18 y 60 entradas. Una quedó dentro de 12. La separación fue procedimental y la aceptación humana completa sigue pendiente. [Resultados](docs/HISTORY.md#panel-009-a-012)

Context Engine Local usa consentimiento del operador y revalida por archivo en el momento de la lectura. La custodia independiente sigue `NOT_PROVEN`. GATE_11 sigue bloqueado, I7 formal incompleto y Physical C2 `DEFERRED_NOT_WAIVED`. [Limitaciones](docs/LIMITATIONS.md)

La [demo histórica](docs/DEMO.md) conserva sus requisitos, anclas y resultados. La rama [experiment](https://github.com/nahuelvillarroel05/pgop1/tree/experiment) conserva el motor experimental y describe la evolución del panel. El [recibo de versión](RELEASE_RECEIPT.json) fija el origen de compilación y los bytes distribuidos. La [auditoría R2](docs/AUDIT.md) verifica una entrega fijada con un ancla externa.

[Sitio oficial](https://pgopcore.com/) · [Repositorio](https://github.com/nahuelvillarroel05/pgop1) · [Arquitectura](docs/ARCHITECTURE.md) · [Procedencia y avisos](docs/PROVENANCE.md) · [Apache-2.0 del núcleo](LICENSE)
