# Historia propia

## Evolución de la entrega

La candidata R2 es un hijo local de main histórico; no integra experiment ni E8.
Su identidad final está en el recibo externo, para evitar autorreferencia.
El repositorio público incluye otras referencias: R2 verifica sólo la entrega
fijada y su checkout. [Contrato vigente e histórico](AUDIT.md).

## Distribución histórica R1

main: un commit raíz de PGOP1 sin padres. experiment: un hijo directo que añade
perfiles de evidencia/memoria/AST. No se importó .git, objetos, refs, hooks,
alternates ni worktrees del repositorio histórico. Las fuentes seleccionadas
conservan su procedencia, sin fingir autoría nueva ni cierre de asuntos históricos.
Las identidades completas finales y su revisión se entregan en inventario externo;
cada clon puede producir el suyo con tools/audit_distribution.py.
No hay remoto configurado en la preparación original. Las refs origin son
permitidas sólo al clonar y deben coincidir exactamente con las dos ramas.
Nuevas evoluciones requieren un contrato de historia versionado y nueva revisión;
el verificador histórico R1 rechaza cualquier commit adicional. Estas frases
describen la preparación original; no el conjunto de referencias público posterior.

## Panel 009 a 012

| Entrega | Evolución comprobada |
| --- | --- |
| 009 · a9.post1 | Flujo local de proyecto, exploración, búsqueda y verificación. T1–T5 aprobados y tres tareas nuevas revisadas; aislamiento estricto pendiente. |
| 010 · a10.post2 | AST V2 para Python y reapertura de Markdown verificado en el bloque de evidencia. Context Engine histórico seguía sujeto a concesiones externas. |
| 011 · a11.post1 | Panel con cinco pestañas, teclas directas, modalidad lineal y pruebas en ConPTY y consola clásica. El piloto del propietario quedaba pendiente. |
| 012 · a12.post3 | Filtrado por nombre, ayuda contextual, optimización del arranque y Context Engine Local derivado con guardado, versiones, recaptura y revocación lógica. |

La serie tranquila en Windows 10 comparó a11.post1 con a12.post3, alternando el orden. Mediana de apertura instalada 966 → 850 ms y de cambio de pestaña 34,5 → 37,8 ms, con 10 aperturas por versión. Mediana de primera instalación 12,48 → 14,20 s, con tres instalaciones por versión. La primera apertura también prepara bytecode visual.

El contexto instalado produjo 26 recibos de procesos, con 13 operaciones satisfactorias y 13 controles negativos. Se registraron 69 regresiones aprobadas. Las cuatro tareas simuladas terminaron en 10, 16, 18 y 60 entradas. Una quedó dentro de las 12 entradas previstas. Hubo separación procedimental. El propietario informó una mejora y la aceptación humana completa quedó pendiente. Estos resultados conservan su alcance de ingeniería. [Anclas de medición](../RELEASE_RECEIPT.json)

El árbol de compilación a12.post3 se identifica en el recibo. La integración pública conserva los bytes de código de ese árbol y deja sus commits intermedios en el expediente local. Los documentos y el kit offline forman parte del árbol de publicación.
