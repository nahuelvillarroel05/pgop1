# Arquitectura de PGOPCore

## Producto 0.1.0a12.post3

`pgopcore.cli` sirve a la CLI, la interfaz lineal y el panel Textual. El panel comparte el controlador y los servicios de lectura, búsqueda, informes y contexto. [Instalación](WINDOWS_INSTALL.md)

El workspace opera sobre una raíz elegida. La enumeración por nombre examina metadatos. La lectura aplica admisión y, según el flujo, confirmación explícita. Los servicios nativos de Windows comprueban acceso, identidad y bytes. Markdown, TXT, JSON y CSV se proyectan desde los bytes observados. AST V2 analiza Python en un subproceso acotado. La búsqueda de texto es literal.

Los informes del panel guardan un par Markdown/JSON con identificador, huellas y marcador de cierre. Al reabrir, se coteja la proyección y se conserva el alcance de la captura original. [Contrato de workspace](WORKSPACE_CONTRACT.md)

### Context Engine Local

`context_local.py` liga el consentimiento al proyecto, la identidad de cada fuente, bytes, selector y destino. `context_local_store.py` conserva objetos direccionados por SHA-256 y un diario persistente con secuencia, marcadores y enlaces entre eventos. El catálogo en memoria se reconstruye al abrir el diario. El límite es de 128 versiones de hasta cuatro proyectos, con ocho fragmentos de hasta 8 KiB por versión.

Recuperar un contexto y abrir una referencia recapturan las fuentes. Un cambio, revocación o fallo de comprobación suprime el cuerpo de la versión. La revocación es lógica y conserva los bytes del almacén. [Contrato de contexto](CONTEXT_LOCAL_POLICY.md)

## Perfiles históricos y auditoría

`runtime/candidate/pg_i7.py` despacha a `public_handoff` y a las fábricas de `i7_api`. El MCP histórico usa esas fábricas y expone seis operaciones del perfil público. `main` conserva agregados declarados y la demo R1 explícita. La wheel incorpora el backend público para esos comandos.

La rama `experiment` mantiene sus perfiles de investigación y el Context Engine histórico con snapshots, SQLite derivada y recuperación. El Bridge exige pins y concesiones externos. El perfil local deriva del Engine con un contrato acotado de diario, referencias y versiones. El grafo general y la búsqueda híbrida o semántica quedan fuera del producto.

`tools/audit_release.py` verifica la entrega R2 fijada sin importar el productor. `tools/audit_distribution.py` conserva R1. `tools/audit_public.py` registra las pruebas y ejemplos que ejecuta. [Contrato de auditoría](AUDIT.md)
