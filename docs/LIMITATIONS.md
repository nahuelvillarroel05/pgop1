# Límites de PGOPCore

## Producto 0.1.0a12.post3

- Windows 10 x64 build 19045, Python 3.14 y disco fijo NTFS local constituyen la configuración probada. Linux, otros builds, PATH persistente y uso humano general siguen pendientes.
- El panel y el workspace admiten MD, TXT, PY, JSON y CSV según sus contratos. Las rutas de red, enlaces y nombres reservados quedan fuera de admisión. Los indicadores de credenciales tienen cobertura acotada. [Formatos y presupuestos](WORKSPACE_CONTRACT.md)
- AST V2 describe sintaxis observada dentro de límites de tiempo y tamaño. Las propiedades estáticas requieren evidencia adicional para afirmar comportamiento. La vista por líneas queda disponible ante análisis incompleto.
- La revalidación comprueba identidad y bytes por archivo dentro de la operación. Una instantánea multiarchivo atómica y la vigencia futura quedan fuera del alcance.
- El contexto admite 128 versiones de hasta cuatro proyectos y ocho referencias de hasta 8 KiB cada una. La revocación lógica conserva bytes. El diario carece de ancla externa contra el rollback completo del almacén o truncado de su cola. La custodia independiente sigue `NOT_PROVEN`. [Contrato de contexto](CONTEXT_LOCAL_POLICY.md)
- Las métricas son descriptivas y acotadas a sus pruebas. Superioridad, ahorro de tokens, aceptación humana general y seguridad absoluta quedan sin establecer. [Resultados](HISTORY.md#panel-009-a-012)

## Perfil histórico y auditoría

- Los agregados históricos son declaraciones. El cotejo actual conserva la cobertura original. Un hash identifica bytes. Ejecución histórica, verdad semántica y custodia externa requieren su propia evidencia.
- `REPORT_GENERATED` identifica un informe creado. Los estados `FAIL` y `PARTIAL` siguen visibles. Los IDs son locales al almacén y reabrir un informe preserva el alcance de la captura.
- Los límites del AST legado pertenecen a ese perfil. El AST V2 del panel usa otro presupuesto. MCP se comprobó por stdio con procesos separados. Los demás clientes requieren su propia prueba.
- Los perfiles distribuidos excluyen el productor legado, los evaluadores oficiales, el entrenamiento y el adaptador Git Governance E1. R1 y R2 tienen ámbitos distintos. [Auditoría](AUDIT.md)

- R2 histórico aplica un escaneo UTF-8 a todos los blobs. La preparación anterior de a12.post3 conserva su FAIL. El sucesor versionado coteja las diez wheels por ruta, OID y pin externo, e inspecciona su contenido de forma acotada. [Auditoría para wheels aprobadas](AUDIT.md#r2-con-wheels-aprobadas)

GATE_11 sigue bloqueado, I7 formal incompleto y Physical C2 `DEFERRED_NOT_WAIVED`.
