# Demo experimental fijada

Es un ejemplo **sintético** de `experiment`, commit completo
`1dca71b232d0c517a4379abeb3661e67caddea49`. No está incorporado en main.
Ejecutalo en un clon independiente. Desde un directorio padre, con Git y Python
3.14, en PowerShell (las carpetas de destino deben ser nuevas):

```powershell
git clone --no-hardlinks --branch experiment https://github.com/nahuelvillarroel05/pgop1.git pgop1-demo
cd pgop1-demo
git switch --detach 1dca71b232d0c517a4379abeb3661e67caddea49
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r public_profile/requirements.lock
.venv\Scripts\python.exe tools/create_evidence_demo.py ../pgop1-demo-output
$Demo = Get-Content ../pgop1-demo-output/DEMO_RESULTS.json -Raw | ConvertFrom-Json
Get-Content $Demo.SOURCE_ONLY.handoff
Get-Content $Demo.MULTISOURCE.handoff
```

En Bash, mismos clone/cd/switch, luego (comandos propuestos; Linux no ejecutado):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r public_profile/requirements.lock
.venv/bin/python tools/create_evidence_demo.py ../pgop1-demo-output
.venv/bin/python -c 'import json,pathlib; d=json.loads(pathlib.Path("../pgop1-demo-output/DEMO_RESULTS.json").read_text()); print(pathlib.Path(d["SOURCE_ONLY"]["handoff"]).read_text()); print(pathlib.Path(d["MULTISOURCE"]["handoff"]).read_text())'
```

`DEMO_RESULTS.json` localiza los dos informes, sus catálogos y recibos. No se copian
módulos de experiment a main. La demo multifuente registra y recupera cuatro
fuentes. El caso estático usa esta entrada inerte:

```python
def sumar(a,b):
    return a-b
```

La afirmación `return_binop`, función `sumar`, operador `Add`, recibe
`CONTRADICTED`; la afirmación más amplia `behavior` recibe
`INSUFFICIENT_EVIDENCE`. Una verificación de integridad/cobertura `PASS` no elimina
la contradicción: el contenido identifica resta y la afirmación esperaba suma.
No prueba corrección funcional general ni precisión del producto.

La versión limita 262.144 bytes por archivo, 12.000 nodos AST y profundidad 80.
Los informes de esta demo son evidencia sintética, separada de RUN012, E8 y
Promptfoo; no aportan métricas comparativas de calidad, tokens, tiempo o USD.
