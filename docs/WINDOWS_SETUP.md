# Windows Python and Codex MCP diagnostics

Use the venv interpreter directly from the repository root:

```powershell
& .\.venv\Scripts\python.exe --version
& .\.venv\Scripts\python.exe -m pip install -r public_profile/requirements.lock
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe -c "import mcp, mcp_types, pg_i7_mcp.server"
```

`Activate.ps1` can fail under PowerShell script policy while the interpreter and
all dependencies work. Preserve the actual error and distinguish activation from
interpreter failure. Direct invocation needs no policy change. If recreation is
necessary, first preserve the previous environment under a unique backup name.
The integration intervention did not need to recreate or delete its venv.

PowerShell can likewise select a blocked `codex.ps1` shim. The installed
`codex.cmd` shim supports the CLI without changing execution policy:

```powershell
codex.cmd --version
codex.cmd mcp list
codex.cmd mcp get pgop1
```

Identify the actual Windows execution token using `whoami /user`; environment
variables such as USERPROFILE and USERNAME may refer to the owner while the
process token is a sandbox account. Record the effective CODEX_HOME separately.
Do not edit a different user's configuration based only on environment names.
Preserve a private backup before adding only the PGOP1 entry. Use an absolute
venv Python, repository cwd and fresh private output root with stdio transport.
Keep machine paths and account configuration outside Git.

Functional MCP verification has three layers:

1. `tools/test_public_mcp.py NEW_OUTPUT` uses a real SDK subprocess, all six tools,
   CLI/API parity and reconnection.
2. `codex.cmd mcp list/get` proves registration, not a tool call.
3. A **new** Codex session must invoke `pgop1.availability` and `pgop1.catalog` and
   preserve actual call events/results. An already running session may not reload
   newly configured tools. A CLI session result does not by itself prove the
   current desktop session refreshed its tools or its `/mcp` view.

AST V2 remains a separate platform gate. The candidate's descriptor-relative
source admission, V2 artifact writer and independent source verifier require
POSIX facilities. `UNSUPPORTED_SAFE_READ_PLATFORM` is a product platform limit,
not a missing pip package or broken venv. Keep this abstention intact until a
Windows native admission implementation is independently qualified. In
particular, metadata-only Windows handles and sharing flags do not establish the
ancestry locking needed for a safe path-walking substitute.
