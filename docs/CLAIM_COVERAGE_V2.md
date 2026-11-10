# Experimental claim coverage (Windows only)

`candidate.claim_coverage_v2.ClaimCoverageProfile` and
`tools/claim_coverage_v2.py` add an explicit opt-in contract around the unchanged
[RealStaticV2Profile](SEMANTIC_ENGINE_V1.md). The six public MCP tools, all V1
predicates, receipts and reason codes retain their implementations.

`SUPPORTED` proves only the exact syntactic predicate in the registered snapshot.
It does not validate the prose interpretation, resolve a name, invoke a method,
load an import, prove causality or establish security. `CONTRADICTED` disproves
that syntactic predicate only; it does not disprove runtime availability.

## Version and admission

The canonical, externally SHA256-pinned catalog has exactly `schema`, `base`,
`claims`. Schema is `pgop1.claim-coverage-catalog.v1`; `base` is the complete
unchanged `pgop1.real-static-catalog.v2` catalog. It can retain original V1 claims.
The external hash authorizes both catalogs; bundle self-assertions are insufficient.
Catalog bytes <=262144, base sources <=64, new claims <=64. Sources and claims
are sorted exactly as in V1. Every new claim source must be registered Python;
its literal document must be a registered document. Pins cannot name other files.

New claims use `claim_schema=pgop1.doc-claims.v2`, rule
`pgop1.doc-claims.evaluator.v2`, and the original seven claim fields:
`claim_schema`, `claim_id`, `predicate`, `document`, `source`, `parameters`,
`expected`. Pins and line spans follow [DOCUMENT_CLAIMS.md](DOCUMENT_CLAIMS.md).
Expected is exactly `{"type":"bool","value":true}` or its false counterpart;
integers and floats do not substitute for booleans. Claim IDs hash canonical
content excluding claim_id. JSON duplicate keys and nonfinite numbers reject.

All names are NFKC-canonical Unicode identifiers, <=120 characters; `WITHHELD`
queries reject. Scope is `<module>`, exact AST V2 node ID, or qualified lexical
name <=1024 characters. Multiple qualified matches abstain. An exact node ID
distinguishes redefinitions, never identifies an effective runtime binding.

| Predicate | Exact parameters and meaning |
|---|---|
| `class_method_declared` | `scope`, `name`: direct FunctionDef/AsyncFunctionDef in that ClassDef's body |
| `function_parameter_declared` | `scope`, `name`, `kind`: exact argument of that FunctionDef/AsyncFunctionDef; kind `posonly`, `positional`, `vararg`, `kwonly`, `kwarg` |
| `module_import_declared` | `scope=<module>`, `form=import/from`, `module`, `name`, `asname`, `level`: exact alias of a direct module-body Import/ImportFrom |

For `import`, module is empty, level is integer zero, name is the exact dotted
imported spelling. For `from`, module is the exact dotted spelling (empty only
with positive relative level), level is an integer 0..160, name is one identifier.
Asname is null or the exact alias identifier. Star queries are not admitted;
a star import never establishes an individual member. Relative imports are syntax,
not a package resolution claim. Dynamic imports and imports inside conditions,
functions or try blocks do not count as direct module-body imports.

Methods inside conditions or nested functions do not count as direct body
methods. Decorated direct methods count as declarations and retain their AST
position; this says nothing about the resulting decorated value. Duplicate direct
methods each produce distinct evidence. Every matched fact records AST kind,
full start/end UTF8 byte coordinates, selected scope ID and stable fact node ID
hashing rule/source/scope/coordinates. Source pins, literal span bytes and snapshot
ID accompany the result. No scopes are merged by name.

## Completeness and abstention

The entire source structure and selected scope must be COMPLETE for either
decisive verdict. AST V2's byte/node/depth/unit/time budgets remain unchanged.
Partial/resource/syntax failures abstain with `RELEVANT_SCOPE_NOT_COMPLETE`.
Missing or duplicate scopes: `SCOPE_MISSING_OR_AMBIGUOUS`; wrong node kind:
`WRONG_SCOPE_KIND`; unverified document span: `DOCUMENT_SPAN_NOT_VERIFIED`.
Admission failures reject the operation before ACK. This conservative whole-file
policy can abstain even if one small scope was locally complete.

## Capture, recovery and independent verification

The profile holds native Windows directory custody through final publication.
The existing full RealStaticV2Profile transaction captures all bytes once into
private staging. New predicates use its captured bytes and AST V2 structures;
they never reopen source descriptors to infer currency. Final publication is one
exclusive native safe artifact set with its outer manifest written last. Errors
produce no ACK; preserve unacknowledged artifacts. Output must be fresh and
disjoint from source/repository/catalog trees. No split writers or ACL changes.

The bundle retains every base artifact and its original `BASE_MANIFEST.json`.
New `COVERAGE_CATALOG.json`, `COVERAGE.json`, `COVERAGE_MEMORY.json` are bound by
`pgop1.claim-coverage-manifest.v1`. `pgop1.claim-coverage.v1` envelope identities
bind base identity, external catalog, snapshot, scope, source metadata, structures
and all new claim rows. The existing generic semantic-memory V1 adapter stores
this new envelope as immutable typed payloads; its schema is not reinterpreted.
It creates no Engine edges and validates complete graph/provenance membership,
fresh-store recovery, index rebuild and idempotent ingestion.

`tools.verify_claim_coverage_v2` validates native artifact custody and pins,
reconstructs only bounded captured base artifacts in private temporary storage,
calls the unchanged base verifier, then independently evaluates the new predicates
via `tools.verify_claims_v2`. The producer's matching code is not called by the
independent evaluator. Admission, envelope assembly and canonical evidence format
are shared; CPython AST is shared. This is not independent parser implementation
or resource isolation. The existing verifier's no-per-source-timeout limitation
remains. All regenerated fields, positions, relationships and Engine content are
compared by canonical JSON, including exact boolean/integer/float distinctions.

```python
from candidate.claim_contract_v2 import make_claim
# document/source are externally authorized snapshot pins, including literal span.
claim = make_claim('class_method_declared', document, source,
                   {'scope':'Example', 'name':'read'}, True)
```

```text
.venv\Scripts\python.exe tools\claim_coverage_v2.py --catalog-sha256 EXTERNAL_HASH generate --source-root D:\selected-source --catalog D:\selected-config\catalog.json --output D:\new-output
.venv\Scripts\python.exe tools\claim_coverage_v2.py --catalog-sha256 EXTERNAL_HASH verify --artifacts D:\new-output
.venv\Scripts\python.exe tools\claim_coverage_v2.py --catalog-sha256 EXTERNAL_HASH query --artifacts D:\new-output --offset 0 --limit 50
```

Use fresh process TEMP/TMP on D:. CLI exits 0 for completed operations (including
contradictions/abstentions), 2 for invalid input/failed operation. Query verifies
the complete bundle before paging new claims; follow next_offset to null.
Legacy claims and structural pages remain available in the retained base bundle
through the existing base verifier after controlled reconstruction.

Coverage means eligible candidates/inventoried candidates and sufficient-evidence
verdicts/eligible evaluated predicates, with every denominator stated. Extraction
coverage is not truth or accuracy. Independent reviewer samples are scoped tests,
not human arbitration or statistical ground truth. Real/heldout catalogs, complete
source snapshots, labels and reviewer logs stay outside public Git.

`SOURCE_CURRENT_AT_ACK=NOT_PROVEN`, `ARTIFACT_CURRENT_AT_ACK=NOT_PROVEN`,
`WINDOWS_SECURITY_QUALIFICATION=PARTIAL`, `WINDOWS_FULL_SUITE=NOT_PASS` while
the three historical negatives remain. Linux deferred by Owner. SDK MCP results
do not establish Codex Desktop execution. No publication or runtime promotion.
