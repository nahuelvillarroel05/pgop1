# Execution evidence v1 (experimental, Windows opt-in)

This extension observes fixed reviewed synthetic demonstrations. It does not run
commands supplied by a catalog, documentation or an LLM. The original V1, AST V2,
snapshots, claims, memory and six public MCP tools retain their contracts.

`candidate.execution_evidence_v1.ExecutionEvidenceRunner` requires absolute source
and catalog paths, externally authorized canonical catalog SHA256, a fresh D:
output directory and a unique caller request ID. `run` returns an explicit ACK
only after exclusive native publication closes. Preserve that returned
`trusted_run_sha256` OUTSIDE the packet, together with the request ID. Manifest
existence, stdout text, test success and exit zero are never ACK substitutes.
An unacknowledged sibling work directory is retained, even on failure.

The catalog has exact fields `schema` (`pgop1.execution-catalog.v1`),
`static_catalog` (existing RealStaticV2 catalog), `code_pins`,
`executable_sha256`, `cases`. The case schema is documented in
`execution_contract_v1.validate_catalog`; no free-form command/argv is accepted.
Code pins cover every installed Python file directly in runtime/candidate and
tools. The runner captures those bytes, checks them before/after and rejects
installation membership changes at admission. It hashes the absolute venv
interpreter. CPython DLLs, stdlib, native extensions and OS are trusted and not
fully pinned. Before/after checks do not prove continuous identity during a run.

Closed predicates are `process_exit_observed`, `artifact_bytes_observed`, and
`roundtrip_or_rejection_observed`. Each applies to THIS_RUN_ONLY. Exact non-bool
integer exits compare against the return of a launched process. Artifact bytes
compare independently read hash and length; missing artifacts abstain. The
roundtrip uses actual RealStaticV2 generate/verify in different fixed workers,
exact recovered bytes, and, for rejection, an ordered private-copy mutation plus
the exact independently replayed SOURCE_HASH rejection. A malformed packet
rejects; incomplete observations, timeout, output cap, changed identity, missing
effects or unsupported mapping abstain. GENERAL claims always abstain. Documentary
literal spans are bound by hash. `closed_formulation(case)` defines the only
admitted formulation for each predicate/action/expected value. Any other text
abstains even with THIS_RUN_ONLY scope and a successful process. Every row keeps
`documentary_claim_verdict=NOT_PROVEN`; no documentary prose is certified by the
proposed narrowed mapping. The evaluator independently enforces this finite
language in addition to the actual effect witnesses.

Static demonstrations admit at most eight document/file sources, 65536 total
bytes, no Python-kind sources or static claims. This avoids the existing AST
parser subprocess inside the behavioral worker. The inherited AST V2 integration
is exercised separately by its original regressions/corpus. This feature does not
claim a behavioral execution of AST parsing. Cases use only the fixed worker
without descendants; isolation against a malicious substituted host is NOT_PROVEN.
No Job Object or kernel descendant-termination guarantee is offered.

At most sixteen cases, three actions each, 65536 bytes per stream/action, fixed
timeouts and 64 MB final packet. Raw binary stdout/stderr are separate from
launch, including stderr on successful execution. Overflow retains a marked
prefix and cannot yield a definitive verdict. Source byte/case budgets bound
reviewed demonstration effects; disk quotas and hostile-process resource isolation
are NOT_PROVEN. Failed outputs are never resumed, overwritten or retroactively ACKed.

`tools.verify_execution_evidence_v1.verify_bundle(folder, catalog_sha256,
trusted_run_sha256, expected_request_id)` requires BOTH external anchors and the
caller-held expected request. Never obtain trusted hashes from the attacked bundle.
The run anchor is the SHA256 of the manifest returned by a trusted live local
runner. It binds the complete packet, start/close receipts, source/test bytes,
streams and effects. It is NOT a signature, process attestation or independent
custody. An attacker controlling the caller trust roots or local host can fabricate
a fully self-consistent packet. This verifier establishes historical consistency
relative to trusted caller roots; it cannot authenticate imported execution. No
receipt importer is provided. Do not relabel arbitrary supplied logs as observed.

The evaluator imports neither producer nor worker, reconstructs the inherited
static bundle, rederives the predicates and checks exhaustive Engine archive
membership before pagination. It shares CPython, the native provider and Engine;
this is evaluator/process separation, not independent host/parser attestation.
Versioned immutable Engine exports retain typed execution claim rows. Recovery
opens only packet bytes and private reconstructed stores, never original sources.
Double ingestion is idempotent. Historical TEMP locators are inert, not authority.

CLI (repo and runtime imports handled by the script):

```
.venv\Scripts\python.exe tools\execution_evidence_v1.py --catalog-sha256 HASH run --source-root D:\fixture --catalog D:\config\catalog.json --output D:\new-output --request-id unique-request
.venv\Scripts\python.exe tools\execution_evidence_v1.py --catalog-sha256 HASH verify --artifacts D:\new-output --trusted-run-sha256 CALLER_HELD_RUN_HASH --request-id unique-request
```

`query` accepts the same verifier arguments plus `--offset` and `--limit` (1–100).
It verifies the entire packet before every page. Exit 0 means completed operation,
including CONTRADICTED/abstentions; exit 2 means rejection/invalid input. Captures,
catalogs, snapshots and real documentary evidence remain private outside Git.

`SOURCE_CURRENT_AT_ACK=NOT_PROVEN`; `ARTIFACT_CURRENT_AT_ACK=NOT_PROVEN`;
`WINDOWS_SECURITY_QUALIFICATION=PARTIAL`. No universal functional, causal,
security or authentic-execution guarantee. Linux remains deferred by Owner.
