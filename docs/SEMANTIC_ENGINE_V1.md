# Real static V2 integration (Windows, opt-in)

The new `candidate.semantic_engine_v1.RealStaticV2Profile` composes snapshot V1,
AST V2, typed document claims and the original Context Engine. It is a separate
versioned real-evidence mode. `RealEvidenceProfile`, real-records-v1,
real-static-v1, source-audit-memory V1 and the six public MCP operations retain
their original implementations and schemas. No user MCP configuration changes.
`MCP_EXPERIMENTAL=DEFERRED`.

This verifies exact typed predicates and syntactic relations. It does not judge
free prose, execute target programs, establish functional correctness, prove
absence of vulnerabilities or authenticate the owner's declarations. SUPPORTED
applies solely to a selected predicate. Manual claims remain the responsibility
of the catalog author, including their correspondence to the cited prose.

## Catalog and API

All operations require the SHA256 of externally authorized, canonical catalog
bytes (ASCII JSON, sorted keys, compact separators, no newline, no duplicate keys,
no nonfinite numbers). Do not obtain the trusted hash from an attacked bundle.
`pgop1.real-static-catalog.v2` has exactly these fields:

* `schema`: `pgop1.real-static-catalog.v2`;
* `profile`: `real-static-v2`;
* `catalog`: unchanged `pgop1.source-audit-catalog.v2`, with sorted `sources`
  and sorted `claims` as documented in [DOCUMENT_CLAIMS.md](DOCUMENT_CLAIMS.md);
* `sources`: descriptors in the same path order as the nested source catalog.

Each descriptor has exactly `path`, `sha256`, `bytes`, `version`, `language`,
`scope`. Path and hash must match the nested source. Bytes is an integer from
0 through 262144. Version is a caller-declared ASCII token of 1–80 characters
from letters, digits, period, underscore and hyphen; it is pinned, not inferred.
Language is `python`, `markdown` or `bytes` for nested kind `python`, `document`
or `file`. Scope is exactly `REGISTERED_FILE_ONLY`. No unregistered discovery.
Up to 64 sources and 64 claims; catalog bytes at most 262144.

```python
from candidate.semantic_engine_v1 import RealStaticV2Profile

profile = RealStaticV2Profile(source_root=absolute_source_directory,
    catalog_path=absolute_catalog_path, catalog_sha256=trusted_external_sha256)
ack = profile.generate(fresh_absolute_output_directory)
verification = profile.verify(acknowledged_output_directory)
page = profile.query(acknowledged_output_directory, kind='claims', offset=0, limit=50)
```

Imports need the repository and `runtime` on `sys.path`; the CLI handles both.
Windows paths must satisfy the existing [safe I/O contract](WINDOWS_SAFE_IO_V2.md).
The parent of output must already exist. Output must be new and physically
outside source, repository and catalog-parent trees. Use a separate config
directory. No overwriting, resuming partial outputs or split writers. Exceptions
mean no ACK. Partial/unacknowledged outputs may remain and must be preserved.

## Reproduction

Use the existing `.venv\Scripts\python.exe`, without activation. Set TEMP/TMP
only in the test PowerShell process to a fresh accessible D: directory outside
source/repository; do not infer compatibility with default C: TEMP.

```powershell
$env:TEMP = 'D:\fresh-private-temp'
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe tools\semantic_engine_v1.py --catalog-sha256 HASH generate --source-root D:\selected-source --catalog D:\selected-config\CATALOG.json --output D:\new-output
.\.venv\Scripts\python.exe tools\semantic_engine_v1.py --catalog-sha256 HASH verify --artifacts D:\new-output
.\.venv\Scripts\python.exe tools\semantic_engine_v1.py --catalog-sha256 HASH query --artifacts D:\new-output --kind declarations --source x.py --limit 100
```

CLI exit codes: 0 completed generate/verify/query, 2 invalid input or failed
operation. Argument-parser errors also return 2. A verification completion means
rederived historical consistency, including any CONTRADICTED or abstaining claims;
it is not a claim-truth aggregate PASS. API failures raise. Query verifies the
whole evidence set and complete Engine membership before returning pages.
Follow `next_offset` to null. Page limits are 1–100. Sources/structures/claims
can be filtered by exact registered source; declarations/units/relations require
one exact source. Unknown sources and invalid offsets reject.

Minimal synthetic input: `x.py` containing `N=7\n` and `DOC.md` containing
`N is seven.\n`. Use `document_claims_v1.make_claim('constant_equal', document,
source, {'scope':'<module>','name':'N','definition_line':1}, typed(7))`.
Document pins include whole-file SHA256, start_line=end_line=1, and the SHA256 of
the exact line including its newline. Source pin has path and whole-file SHA256.
Register both pins in the nested catalog; the document kind is `document` and
Python kind is `python`. Add the corresponding descriptors, sort sources by path
and claims by claim_id, encode with `static_ast_v2.canonical`, and authorize its
hash through your external channel. The integration tests include executable
positive, false-literal and unknown-scope examples without modifying legacy tests.

## Persistence and verification

Generation holds native Windows Directory chains across capture and final
publication. The existing snapshot operation is used in private staging. AST and
claims consume its captured bytes. The original three-member snapshot manifest
is retained byte-for-byte as `SNAPSHOT_MANIFEST.json`. A new outer manifest binds
CATALOG, SNAPSHOT, REPORT, INTEGRATION, MEMORY, snapshot manifest and original
snapshot handoff. Exclusive safe publication writes the outer manifest last,
flushes and reads back through the same handles. The outer operation must return
success after resource close; manifest presence alone is not ACK.

`tools.verify_semantic_engine_v1` imports no integrated producer. It checks the
external catalog, original snapshot manifest, snapshot bytes, independently
recomputed AST/claims, exact derived envelope and the reopened Engine store.
The existing verifier shares CPython AST and the Windows I/O provider with the
producer; it is a distinct evaluator, not an independent parser. Its existing
resource-isolation limitation remains (no per-source verifier subprocess timeout).

The memory adapter exports only immutable object/source/version files. It stores
one bound observation for scope, each source, complete per-source structure, and
each claim including its literal document span. Complete structures retain all
units/declarations/relations; aggregate storage avoids the Engine's 1000-query
cap (at most 193 observations). No Engine edges are created. Defines/imports/
inherits/calls remain typed syntactic payloads, never VERIFIED_CAUSAL. Calls and
external/dynamic targets retain UNRESOLVED/AMBIGUOUS. No runtime target is inferred.

Recovery imports the exact bounded, path-allowlisted archive into a fresh private
temporary Engine store, verifies graph/provenance, compares full membership and
bindings to independently recomputed snapshot evidence, rebuilds SQLite and
checks idempotent reingestion. It never opens native source paths or historical
descriptor locators. Archives do not accept SQLite/locks/staging, extra sources,
versions or edges. Immutable outputs preserve previous evidence when new bytes
create a different snapshot/integration identity. Recovery does not require the
original sources. No legacy private store migration takes place.

Integration/catalog/snapshot/report/claim/observation identities and semantic
content exclude clocks, durations and storage locators. Engine source descriptors
retain inert historical temporary paths, so private archive/graph/provenance and
outer manifest hashes are storage identities and are **not byte-reproducible**
across temp roots. They never authorize a source reopen. Version/language/scope
metadata is owner-declared and externally pinned, not evidence of origin.

`SOURCE_CURRENT_AT_ACK=NOT_PROVEN`; `ARTIFACT_CURRENT_AT_ACK=NOT_PROVEN`.
Source state is `COMMITTED_SNAPSHOT`; `query --kind currency` explicitly abstains
with INSUFFICIENT_EVIDENCE and never opens current native sources.
No signed origin, continuous retention, atomic multi-file capture or universal
Windows security claim. Host qualification remains the original Windows 10
AMD64/local fixed NTFS scope. Stronger attackers, writable mappings, admin/raw
disk, malicious filters and other builds remain unqualified. Reports, literal
spans, source bytes and evaluation catalogs are private artifacts outside Git.

The historical Windows suite remains NOT_PASS with its three preserved negative
tests. New acceptance tests do not relabel them. `LINUX_REGRESSION=DEFERRED_BY_OWNER`.
