$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '../.venv/Scripts/python.exe') (Join-Path $PSScriptRoot '../runtime/candidate/pg_i7.py') --profile public @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
