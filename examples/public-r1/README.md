# Ejemplo R1 autocontenido

`python tools/demo_public.py` consulta RUN012_PUBLIC, verifica hashes/consistencia,
genera y recupera por páginas los tres artefactos. Los datos se encuentran en
runtime/public_profile y son agregados históricos declarados, sin originales
privados. El resultado actual esperado es verification=PASS, generation=REPORT_GENERATED.
La prueba negativa de discrepancia genera un informe con verification=FAIL;
generación y aprobación son estados separados. Revisá REPORT.json y sus fuentes.
