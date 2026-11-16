# Auditoría de código sintético (experiment)

En main: UNAVAILABLE; usá el [clon fijado independiente](../../docs/DEMO.md).
`python tools/create_evidence_demo.py audit-output/source-demo` usa las fixtures
incluidas para construir catálogos nuevos, memoria multifuente y código inerte.
El directorio debe ser nuevo. El ejemplo contrasta un retorno `a-b` con una
afirmación de suma; el análisis AST no ejecuta esa función. La salida incluye
paths de configuración/informes y FINAL_HANDOFF.md.
El wrapper histórico de experiment automatiza MCP/CLI/API, pero su auditoría R1
requiere la distribución histórica de dos ramas; un clon actual con E8 la rechaza.
Seguí [la demo fijada](../../docs/DEMO.md) para generar los informes sin confundir
esa demostración con una aprobación de distribución.
