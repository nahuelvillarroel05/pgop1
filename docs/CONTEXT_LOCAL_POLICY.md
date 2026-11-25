# Contrato de Context Engine local

Perfil `pgop.context-local.v1`, autoridad `LOCAL_OPERATOR_CONSENT`, custodia independiente `NOT_PROVEN`. Se deriva de Search003, commit `0416f1c5081a5f84fae69bc10f6c7c82a3ad61e8`, árbol `ae0e64c694c6a2fe261075486b4dd8fbd2fbfd80`. El Engine original lleva Apache-2.0 y SHA-256 `21ce7dec011707d7119134714e8a540fb61d131613ae237d0ae0fac888403aee`. El adaptador Bridge original lleva SHA-256 `e219381348f6b3248e65b8bf356cd98293990c0b64547425185248b7f5cc2dde`.

| Contrato histórico | Decisión de producto | Evidencia operativa |
| --- | --- | --- |
| Bridge._grant verifica pins externos de fuente/proyección, autorización externa y raíz de almacenaje | El perfil local usa elección explícita de proyecto, selección y destino, y consentimiento por operación. La vista previa vincula la identidad física del padre y del almacén, y la escritura las comprueba con handles nativos. Se excluyen rutas reservadas con una excepción para AppData\Local del perfil efectivo. | Una confirmación ausente o inválida no escribe. Un destino sustituido requiere otra vista previa. |
| Engine.admit_source vincula artefactos admitidos por scope y hash. Bridge reobserva con autoridad vigente | El adaptador invoca captura nativa relativa a handles, política de nombres y contenido, verificación de código y proyección verificable de fragmentos. La identidad de archivo, raíz, tiempos, hash y selector siguen vinculados. | Al cambiar, sustituir o eliminar una fuente se suprime el paquete. |
| Engine conserva objetos, observaciones y procedencia inmutables | Se reutiliza la codificación canónica y el direccionamiento SHA-256. Un objeto validado se publica con un marcador de secuencia y hash, bajo el bloqueo nativo del almacén, con enlace al evento anterior. | El sistema reconstruye el índice en cada apertura. Tras manipular un objeto devuelve `CORRUPT_RECORD`. |
| SQLite derivado y grafo de relaciones de investigación | El índice de catálogo se reconstruye en memoria a partir del diario acotado. Las versiones guardan la relación de supersesión entre selecciones del mismo proyecto y nombre. | Se verifican duplicación, reinicio y supersesión sin base de datos externa. |
| Bridge exige autorización externa para tombstone y rename | El operador puede revocar lógicamente una versión en el almacén local. No se infiere borrado ni traslado del archivo. | La recuperación posterior devuelve `REVOKED` sin cuerpo. |

El paquete devuelve una comprobación puntual de cada fuente. El modelo local no acredita una instantánea multiarchivo, autenticidad de custodia, equivalencia con Bridge ni verificación histórica global. El diario detecta errores y alteraciones en las relaciones que conserva. No establece un ancla externa contra la restauración del almacén completo o el truncado de su cola. Los estados de investigación previos conservan su autoridad propia.

Las nueve wheels de presentación siguen separadas del núcleo y el flujo de contexto JSON funciona con la wheel PGOPCore solamente.

