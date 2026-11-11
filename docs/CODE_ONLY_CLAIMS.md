# Code-only claims v1 (experimental Windows)

`pgop1.code-only-claims.v1` is opt-in. It requires no Markdown document or documentary span. Documentary V1/V2 admission is unchanged. This interface checks exact syntax in pinned captured Python bytes; it grants no behavioral, historical, runtime or source-origin authority.

The canonical external catalog (`pgop1.code-only-catalog.v1`) has exact keys `schema`, `authorized_root`, `mode`, `package_roots`, `sources`, `claims`. Supply its SHA-256 separately. It binds the absolute authorized source root, selected relative `.py` paths, each SHA-256/byte length/kind=python, mode and package roots, and the entire query set. Sources and queries are sorted by path and claim_id. Maxima: 32 files, 262144 bytes/file, 256 queries, 8 package roots; AST V2 fixed default budgets apply. Repeated paths/casefold paths, differently cased module keys, roots or query IDs reject operation. Exact duplicate module keys across distinct roots remain ambiguous.

Each query has exact keys `schema`, `claim_id`, `predicate`, `source_ref`, `scope`, `parameters`, `expected`. Schema is `pgop1.code-only-claims.v1`; claim_id is a unique ASCII identifier; source_ref is an admitted path; scope is `<module>`, a qualified name or exact AST V2 `node-...` identity; expected is a strict boolean. No document field is accepted. Four predicates:

| Predicate | Parameters |
| --- | --- |
| symbol_defined | name, kind (`any`, `ClassDef`, `FunctionDef`, `AsyncFunctionDef`) |
| class_method_declared | name |
| function_parameter_declared | name, kind (`posonly`, `positional`, `kwonly`, `vararg`, `kwarg`) |
| module_import_declared | form (`import`/`from`), module (empty for import), name, asname (null or identifier), level (integer) |

Imports require module scope. Only direct lexical declarations/arguments/aliases count. Comments, strings, docstrings, nested definitions in a different scope and dynamic exports are not declarations. Names use canonical Python identifier spelling and reject WITHHELD.

Admitted rows return SUPPORTED, CONTRADICTED or INSUFFICIENT_EVIDENCE. Malformed/out-of-contract queries return status REJECTED and null verdict with specific reason. An unavailable selected source fails the capture operation (no successful ACK); unregistered query source is REJECTED. Missing/ambiguous/wrong-kind scope, non-COMPLETE trees, conditional/decorated scope/targets, repeated declarations, target rebinding or dynamic hazards abstain. Absence is definitive only within a complete relevant tree with these checks satisfied. expected=false reverses the exact syntactic assertion, without changing its evidentiary scope.

Python API: `candidate.code_only_v1.CodeOnlyProfile(source_root=..., catalog_path=..., catalog_sha256=...).generate(new_output)`, `.verify(artifacts)` and `.query(artifacts, kind='claims', offset=0, limit=50)`. Explicit `PYTHONPATH=<checkout>\runtime;<checkout>` is required for API imports. Query independently verifies the full bundle before slicing. Limits are strict integers, 1–100 rows/page, and 0 <= offset <= total. Exported pages use fixed 17-row chunks, without omissions.

The producer reuses historical snapshot V1 and Windows handle-relative Safe I/O, holds directory custody across capture/publication and publishes only a fresh disjoint artifact directory, manifest last. Existing output fails with FileExistsError; partial failed output grants no successful ACK and must be preserved. SNAPSHOT.json contains private source bytes; keep all derived artifacts private. The external catalog digest must come from caller authorization, never an attacked bundle.

`tools/verify_code_only_v1.py` imports no E3 producer or resolver. It rechecks snapshot V1, source pins/coverage, independently recalculates new predicates and resolution, and compares exact report IDs, ordering, pages, file membership and pins. Shared pure schema/serialization, CPython AST, legacy independent verifier and Windows I/O are declared dependencies; independent parser implementation is NOT_PROVEN. SOURCE_CURRENT_AT_ACK and ARTIFACT_CURRENT_AT_ACK remain NOT_PROVEN. MEMORY_INTEGRATION=DEFERRED; fresh-process verified standalone CLI is available. Existing Context Engine regressions remain separate. Linux/WSL validation NOT_EXECUTED. Public MCP expansion DEFERRED; six public names unchanged.

See [resolution](STATIC_MODULE_RESOLUTION.md) and [tested tools](TOOLS.md).
