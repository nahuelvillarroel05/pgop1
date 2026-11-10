# Captured AST V2 / claims memory: opt-in integration

`pgop1.source-audit-memory.v1` imports explicitly supplied **captured report bytes**
and their expected SHA-256 into the existing Context Engine. It does not discover,
open or execute the original audited sources. Hash and schema validation are not
independent source recomputation. Every record and response retains
`CAPTURED_REPORT_NOT_SOURCE_RECOMPUTED`, `source_recomputation=NOT_PERFORMED` and
`authority_effect=NONE` where applicable.

## Compatibility map

| Component | Existing contract | Integration in this candidate |
|---|---|---|
| `static_ast_v2.analyze_source` | Explicit root/path/hash, bounded worker, coverage and snapshot | Unchanged; secure source admission remains POSIX-only. |
| `document_claims_v1.audit_catalog` | Manual typed claims, exact document spans and pins | Unchanged; its captured report is an opt-in adapter input. |
| `RealEvidenceProfile` | `real-evidence-catalog.v1`, V1 receipts, scoped generate/read | Unchanged; native V2 dispatch is deferred. |
| `Context Engine` | Immutable JSON, exact source/pointer commitments, derived SQLite | New adapter stores report scope, complete structures, units, declarations, relations, claims and source errors as observations. |
| Engine relationship enum | `VERIFIED_CAUSAL`, `VERIFIED_ASSOCIATION`, etc. | Unchanged. Adapter creates no edges; `defines/imports/inherits/calls` remain typed values of observations. |
| API | Existing profile factories | Adds `i7_api.source_audit_memory_v1(memory_root=...)`. |
| CLI | Existing public profile dispatcher | Adds separate `tools/source_audit_memory_v1.py`; no dispatcher changes. |
| Public MCP | Six names and schemas | Unchanged; the memory adapter is not exposed through these tools. |
| V2 artifact generation/read | Independent producer and verifier | Unchanged; legacy reports are not rewritten. Adapter `read` returns memory records, not legacy report artifacts. |

This is **partial integration**, not a completed Windows V2 pipeline. Native
Windows source admission, V2 artifact writer/source verifier, a versioned
RealEvidenceProfile V2 and experimental MCP exposure remain unimplemented. The
independent storage verifier below does not clear those gates.

## Input and persistence contract

The input is a UTF-8 (optional BOM) `pgop1.source-audit-report.v2` captured report,
at most 16,000,000 bytes. The adapter validates exact envelope fields, catalog
pins/hash, AST envelopes/snapshots, claim identities and typed result metadata.
Every registered Python source must have a structure or an explicit source error.
An error and structure for the same source are rejected. No claims are inferred
from a whole document, a passing test, an empty collection or a partial scope.
Imported verdicts remain producer assertions; they are not independently proven.

The adapter bounds each report to 999 records, including scope and structure
records. Larger inputs fail before creating a store; no truncation is relabeled
as complete. The extra Engine query slot detects unexpected same-task membership.
The immutable report bytes become an owned Engineering metadata source; each
record commits its JSON pointer and value hash. IDs include adapter schema, full
report SHA and pointer. Changed bytes create a new snapshot, even if AST node or
claim IDs recur. Existing reports and their historical scope fields stay intact.

The memory directory is a trusted local metadata store under the existing
Engine's path/ownership contract. It is not a new qualification of hostile
concurrent Windows filesystem access. The CLI rejects existing link/reparse
components for its captured-report input, reads with a finite bound, and checks
the explicit report hash. It must not be used as a replacement for AST source
admission. Private report paths must remain outside public commits.

`read` recovers from the Engine's preserved report object without consulting the
original report path or original sources. It checks graph integrity, exact record
membership and bindings, then orders records by deterministic observation ID.
Pages use report SHA, kind, offset and limit (1–100); they carry total, remaining
and next offset. The caller retains the same SHA and kind between pages. A graph
may gain other reports without changing the selected report's records. Missing
or corrupt storage raises an error; it never silently reconstructs from sources.

## API and CLI

From a caller that already holds authorized captured report bytes:

```python
from runtime.candidate.source_audit_memory_v1 import SourceAuditMemory

memory = SourceAuditMemory(memory_root)
receipt = memory.ingest(captured_report_bytes, expected_report_sha256)
page = memory.read(expected_report_sha256, kind='relations', offset=0, limit=20)
```

With the repository's `runtime` import root, the new factory is also available as
`candidate.i7_api.source_audit_memory_v1(memory_root=...)`.

PowerShell, from the repository root (replace the explicit placeholders):

```powershell
& .\.venv\Scripts\python.exe tools/source_audit_memory_v1.py --memory-root MEMORY_ROOT ingest --captured-report CAPTURED_REPORT --report-sha256 REPORT_SHA256
& .\.venv\Scripts\python.exe tools/source_audit_memory_v1.py --memory-root MEMORY_ROOT read --report-sha256 REPORT_SHA256 --kind relations --offset 0 --limit 20
& .\.venv\Scripts\python.exe tools/verify_source_audit_memory_v1.py --memory-root MEMORY_ROOT --report-sha256 REPORT_SHA256
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p test_source_audit_memory_v1.py -v
```

The separate stdlib verifier imports neither Engine nor producer. It checks
version hashes/ancestry, captured bytes, observation membership/values/pointers
and absence of edges involving these observations. Its PASS scope is
`CAPTURED_REPORT_STORAGE_AND_BINDINGS_ONLY`; it does not qualify the source
analyzer, producer provenance, natural-language truth or operational authority.
It reads trusted local metadata with link checks, not a hostile concurrent store.

The portable tests construct explicitly captured synthetic reports using parser
fixtures. They verify storage behavior on Windows; they do not claim that native
Windows source admission ran. Original V2 Windows failures remain visible in the
full suite rather than being skipped or relabeled.
