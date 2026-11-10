# Auditoría de código sintético (experiment)

En main: UNAVAILABLE; cambiá a experiment con un worktree limpio.
`python tools/create_evidence_demo.py audit-output/source-demo` usa las fixtures
incluidas para construir catálogos nuevos, memoria multifuente y código inerte.
El directorio debe ser nuevo. El ejemplo contrasta un retorno `a-b` con una
afirmación de suma; el análisis AST no ejecuta esa función. La salida incluye
paths de configuración/informes y FINAL_HANDOFF.md.
`python tools/audit_public.py` automatiza también MCP/CLI/API y lectura recuperada.
