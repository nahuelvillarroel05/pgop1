# Arquitectura

CLI runtime/candidate/pg_i7.py -> dispatcher public_handoff -> API de perfiles.
MCP pg_i7_mcp/server.py -> los mismos factories de i7_api y seis operaciones.
main incluye PublicProfile y agregados declarados R1, sin productor de campañas.
experiment añade EngineeringProfile, EvidenceProfile, RealEvidenceProfile y el
Context Engine original (snapshot, SQLite derivada, recuperación). No se cambian
los import roots, reglas AST ni límites del motor. El índice no autentica fuentes.
Los datos registrados son inertes; no se ejecuta el código objeto de auditoría.
tools/audit_distribution.py verifica hashes/historia sin importar el productor.
tools/audit_public.py orquesta pruebas propias y ejemplos, registra sus procesos.
Los módulos heredados conservan entradas legacy; sus dependencias protegidas no
se distribuyen. Sólo los perfiles documentados están disponibles.
