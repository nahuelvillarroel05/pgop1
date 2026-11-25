# Contextos locales de PGOPCore

En Archivos, buscá por una parte del nombre. Abrí el archivo con tu permiso y elegí una referencia, como una sección Markdown, una función de Python, un valor JSON o una celda CSV. Podés añadir referencias de distintos archivos del mismo proyecto.

En Informes, elegí **Guardar contexto**, revisá las referencias, asignales un nombre y un propósito, y elegí una carpeta para el almacén. El panel propone la carpeta local de datos de tu cuenta. También podés configurar `PGOP_CONTEXT_HOME` con una carpeta local existente. Conservá el almacén fuera del proyecto y de la instalación. La vista previa muestra el texto y el destino. La confirmación de escritura crea `.pgop-context-v1` en esa carpeta.

Después de reiniciar, seleccioná el mismo proyecto y elegí **Contextos guardados** en Informes. Cada recuperación vuelve a comprobar las fuentes y muestra una lista de referencias. Usá las flechas y Enter para abrir una, y 0 o Esc para volver a la lista. El panel vuelve a comprobar todas las fuentes al abrir cada referencia. Si cambió un archivo o no se puede verificar, se ocultan las referencias de esa versión. El menú permite revocar el acceso local a una versión. Los archivos del proyecto se abren en modo de lectura.

Desde una terminal sin la interfaz, `pgop context --help` explica los subcomandos `preview`, `save`, `list`, `get` y `revoke`. Todos requieren que el operador seleccione proyecto y carpeta del almacén, y confirme explícitamente con `--allow-local`. `preview` devuelve una confirmación vinculada a las selecciones, su contenido y el destino. `save` vuelve a capturar las mismas selecciones antes de escribir. Agregá `--json` al subcomando para obtener la respuesta estructurada.

Si usás el ZIP offline, el mismo acceso por terminal comienza con `pgop-panel.cmd context`.

El almacén admite 128 versiones de hasta cuatro proyectos. Cada contexto puede tener ocho fragmentos de hasta 8 KiB cada uno. La revocación es lógica. La protección del almacén frente a otras cuentas depende de los permisos aplicados a la carpeta local; elegí una carpeta privada de tu cuenta.

