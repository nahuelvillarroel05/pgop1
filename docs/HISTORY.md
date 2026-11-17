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
