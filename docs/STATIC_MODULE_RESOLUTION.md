# Static module resolution v1

`pgop1.static-module-resolution.v1` is a separate additive relation contract. Original AST V2 relations and their identities remain in AST_REPORT.json unchanged. Lexical RESOLVED_STATIC from legacy defines never implies execution.

STRICT_RAW accepts only neutral RAW_0001.py-style aliases, no package roots and no origin map. Its imports remain UNRESOLVED with no to_source. CODE_TREE accepts explicit selected relative Python paths and declared package roots (`.` or relative slash directories), preserving actual structure. Only selected `.py` files enter the closed index; no sys.path or filesystem discovery. __init__.py identifies a package module, and every required package parent must be selected. Namespace packages are not inferred.

| Observation/context | New status |
| --- | --- |
| Unique plain import, complete selected package chain, unconditional module scope, no source-wide dynamic/binding hazard | LOCAL_MODULE_MATCH |
| from-import with unique complete selected syntactic module/submodule candidate | CANDIDATE_ONLY |
| Multiple module keys, conditional/function-local imports, target AST incomplete, star/dynamic imports or rebinding | AMBIGUOUS |
| Missing module/package parent in selected universe | OUTSIDE_SELECTED_UNIVERSE |
| Relative import escapes root or importer module identity ambiguous | AMBIGUOUS |
| Calls | AST V2 AMBIGUOUS/UNRESOLVED retained, no target |
| Base expressions | UNRESOLVED, no class-object target |

Relative resolution first establishes the importing package and selected parent chain. `from pkg import name` tries a selected pkg.name module then selected pkg module, but either is only a candidate because name can be an attribute/reexport. `from pkg.mod import Item` may identify pkg.mod as candidate; no proof of Item destination. Incomplete importer package chain is OUTSIDE_SELECTED_UNIVERSE. Exact duplicate module keys across roots are ambiguous; casefold spelling conflicts reject catalog admission.

Bindings count imported aliases, assignments/deletions, definitions, function parameters, exception-handler aliases and pattern captures across the entire source. Repeated identical imports count separately and conservatively make that name ambiguous. Any star import, reflective exec/eval/globals/locals/vars/setattr/delattr/__import__/getattr call, sys.path attribute or importlib attribute causes source-wide import ambiguity. This deliberately loses useful associations to avoid invented targets.

Rows bind from_source/source_sha256, selected_universe_id (entire external catalog SHA), exact AST scope/line/column, observation kind, legacy_relation_index, alias_index and used_name. Distinct repeated aliases receive distinct relation IDs. A unique selected candidate may carry to_source/to_source_sha256; ambiguous rows never do. Every row retains BEHAVIORAL_LINK=NOT_PROVEN. Local-module match is a structural association only; it proves no import execution, sys.path, importability, invocation, class hierarchy or causal link.

Use [code-only API and verifier](CODE_ONLY_CLAIMS.md). Reports/pins/source captures stay private. No public MCP authority change or historical relabeling.
