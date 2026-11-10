# Límites de la distribución

- Agregados históricos son declaraciones. Su lectura/hash actual no repite tests
  ni demuestra verdad semántica, ejecución o custodia externa.
- REPORT_GENERATED significa informe creado. Una verificación FAIL/PARTIAL sigue
  visible y nunca se convierte en aprobación por generar un handoff.
- Sintaxis y AST no demuestran comportamiento. El lector limita 262144 bytes,
  12000 nodos AST y profundidad 80; coberturas incompletas conservan UNKNOWN.
- Los IDs de informes son locales al almacén. No mezclar catálogos/perfiles ni
  reutilizar recibos después de cambiar entradas. Los permisos siguen siendo del SO.
- Sólo se distribuyen los perfiles documentados. No hay productor legacy,
  evaluadores oficiales, entrenamiento ni adaptador Git Governance E1 incluido.
- Windows Python 3.14 fue el entorno de preparación. Linux integral NOT_EXECUTED;
  comandos Bash propuestos, sin afirmar ejecución Linux o compatibilidad total.
- El SDK MCP real prueba stdio con procesos separados; no califica todos los clientes.
- Manifiestos, OIDs, escáner y auditoría técnica no certifican autenticidad,
  exclusividad de derechos ni seguridad absoluta. Usá anclas externas para identidad.
- La auditoría ejecuta tests propios controlados; leé herramientas y licencias
  antes de ejecutar un clon no confiable.
